//! The full outbox model — port of `src/nostr/nip65.ts` (routeAuthorsToRelays,
//! caps, normalize) + `src/data/feeds.ts` (routeFor shape): route each follow
//! to the relays THEY write to, a greedy set-cover bounding the relay set, ≥3x
//! redundancy per author where their relay list allows it (WS1: Dark Wisp's
//! `relay/RelayScoreBoard.kt` keeps up to MIN_REDUNDANCY = 3 write relays per
//! followed author in `recompute()`, ~line 88 — raised here from the TS port's
//! 2), and orphan recovery — an author whose relays missed the cut is routed
//! to their OWN best relay, never silently dumped on the indexers (whose
//! mirrors may not carry them at all).

use std::collections::{BTreeMap, BTreeSet, HashMap};

/// The light relay-url MAP KEY normalizer (nip65.ts relayKey): lowercase, no
/// trailing slashes, no validation — for keying caches/sets of already
/// relay-shaped urls.
pub fn relay_key(u: &str) -> String {
    u.trim().trim_end_matches('/').to_lowercase()
}

/// The validating normalizer (nip65.ts normalizeRelayUrl): lowercase, no
/// trailing slash, ws/wss schemes ONLY — a wrong scheme must be rejected, not
/// rewritten (prepending wss:// to `http://relay.onion` once produced a
/// `wss://http//relay.onion` that still got dialed).
pub fn normalize_relay_url(url: &str) -> Option<String> {
    let raw = url.trim();
    let lower = raw.to_lowercase();
    let ok = lower.starts_with("ws://") || lower.starts_with("wss://");
    if !ok || raw.len() <= 6 {
        return None;
    }
    Some(lower.trim_end_matches('/').to_string())
}

/// A parsed kind:10002 (NIP-65): the read/write split.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct RelayList {
    pub read: Vec<String>,
    pub write: Vec<String>,
}

impl RelayList {
    pub fn is_empty(&self) -> bool {
        self.read.is_empty() && self.write.is_empty()
    }
}

/// Parse a kind:10002 into the read/write split (NIP-65 r-tag markers;
/// absent marker = both). Port of nip65.ts parseRelayList.
pub fn parse_relay_list(ev: &nostr::prelude::Event) -> RelayList {
    let mut read = BTreeSet::new();
    let mut write = BTreeSet::new();
    for tag in ev.tags.clone().to_vec() {
        let parts = tag.as_slice();
        if parts.first().map(String::as_str) != Some("r") {
            continue;
        }
        let Some(url) = parts.get(1).filter(|u| !u.is_empty()) else {
            continue;
        };
        let Some(url) = normalize_relay_url(url) else {
            continue;
        };
        match parts.get(2).map(String::as_str) {
            Some("read") => {
                read.insert(url);
            }
            Some("write") => {
                write.insert(url);
            }
            _ => {
                read.insert(url.clone());
                write.insert(url);
            }
        }
    }
    RelayList {
        read: read.into_iter().collect(),
        write: write.into_iter().collect(),
    }
}

/// Routing-grade relay screening. A follow's kind:10002 is relay-controlled
/// data: without a screen, a malicious list makes the client dial
/// `ws://127.0.0.1:<port>`, link-local or RFC1918 hosts (the SSRF chain),
/// and plain `ws://` relays would take this client's AUTH responses and
/// subscriptions in cleartext. Relays the user entered themselves
/// (Settings, the session's own NIP-65 via connect_reads) never pass
/// through here — the user chose those.
///
/// The structural checks mirror the SDK's own RelayUrl::parse (nostr
/// types/url.rs): a second "://" anywhere is rejected, then the url-crate
/// parse must succeed. Hand-splitting the prefix let
/// `wss://wss://relay.example` through as host "wss" — and the SDK
/// rejected the WHOLE routed fan-out at subscribe time on that one url,
/// dropping the live bell to indexers-only. The url crate also canonicalizes
/// sneaky IPv4 hosts (decimal `2130706433`, hex `0x7f.0.0.1`, short
/// `127.1`) before the literal check, so they cannot pose as names.
///
/// Names (non-IP hosts) pass for now; pinning resolved IPs per hop is the
/// SSRF-guard M5 item (same gap as the media guard).
pub fn routable_relay(url: &str) -> bool {
    // RelayUrl::parse check 1: at most one "://".
    if url.matches("://").count() > 1 {
        return false;
    }
    // Check 2: a real url-crate parse (schemes, brackets, ports, IPv4 forms).
    let Ok(parsed) = url::Url::parse(url) else {
        return false;
    };
    // Check 3: the scheme (RelayUrlScheme accepts ws/wss; routed relays are
    // wss-only).
    if parsed.scheme() != "wss" {
        return false;
    }
    // Check 4: a host is present ("wss://" is Malformed there).
    let Some(host) = parsed.host() else {
        return false;
    };
    // Screen 5 (ours): IP literals must be public unicast. host() is the
    // typed form (host_str brackets IPv6, which then fails IpAddr::from_str
    // and would pose as a name), and the url crate already canonicalized
    // decimal/hex/short IPv4 into it.
    match host {
        url::Host::Ipv4(v4) => is_public_ip(&std::net::IpAddr::V4(v4)),
        url::Host::Ipv6(v6) => is_public_ip(&std::net::IpAddr::V6(v6)),
        // Domains (incl. IDN) pass for now; resolved-IP pinning is M5.
        url::Host::Domain(_) => true,
    }
}

/// Public unicast only: rejects this-network, RFC1918, loopback, link-local
/// (incl. the 169.254.169.254 metadata endpoint), CGNAT, multicast and
/// reserved ranges; IPv6 additionally unique-local/link-local/multicast,
/// with v4-mapped addresses judged by their embedded v4.
fn is_public_ip(ip: &std::net::IpAddr) -> bool {
    // M5: the rules live in net_guard — one authority, no drift.
    crate::net_guard::is_public_unicast_ip(*ip)
}

// Caps (nip65.ts): 3 write relays per author considered; the greedy set-cover
// stops at 70 relays; redundancy routes each author to up to
// RELAYS_PER_AUTHOR_TARGET of their relays so a note on only one of them
// still surfaces — 3 (Dark Wisp's RelayScoreBoard.kt MIN_REDUNDANCY, WS1),
// gracefully degrading to however many the author actually has; the orphan
// tail may open NEW sockets past the soft cap up to the hard one; past it,
// the indexers.
pub const MAX_RELAYS_PER_AUTHOR: usize = 3;
pub const MAX_RELAYS: usize = 70;
pub const RELAYS_PER_AUTHOR_TARGET: usize = 3;
pub const HARD_MAX_RELAYS: usize = MAX_RELAYS * 2;
/// Relay filters silently truncate around 200 authors (nip65.ts
/// MAX_AUTHORS_PER_FILTER) — split bigger shards. Dark Wisp's
/// `relay/OutboxRouter.kt` enforces the same ceiling
/// (MAX_AUTHORS_PER_FILTER = 200, ~lines 20–31) after big relays rejected
/// oversized REQs with "total filter items too large".
pub const MAX_AUTHORS_PER_FILTER: usize = 200;
/// Same failure class on the id dimension (OutboxRouter.kt
/// MAX_ETAGS_PER_FILTER = 150): an ids filter longer than 150 gets split.
pub const MAX_ETAGS_PER_FILTER: usize = 150;

/// The routing output: relay url → the authors to query on it.
pub type Route = BTreeMap<String, BTreeSet<String>>;

/// Split into size-sized chunks (nip65.ts chunk).
pub fn chunk<T: Clone>(arr: &[T], size: usize) -> Vec<Vec<T>> {
    arr.chunks(size).map(|c| c.to_vec()).collect()
}

/// Route authors to the relays they write to (nip65.ts routeAuthorsToRelays,
/// 1:1): each author gets up to MAX_RELAYS_PER_AUTHOR write relays (or the
/// fallback when they publish no list); a greedy weighted set-cover bounds
/// the set at MAX_RELAYS while routing each author to up to
/// RELAYS_PER_AUTHOR_TARGET of their relays; the uncovered tail recovers to
/// their own best relay (score > 0) until HARD_MAX_RELAYS, then the fallback.
///
/// `relay_score` weights coverage by relay quality (read-latency, seen-on
/// memory): 1.0 = neutral, 0.0 = never pick (read-dead). The default port
/// runs neutral; the M2 memory work feeds real scores in.
pub fn route(
    relay_lists: &HashMap<String, RelayList>,
    authors: &[String],
    fallback_relays: &[String],
    relay_score: impl Fn(&str) -> f64,
) -> Route {
    let fallback: Vec<String> = fallback_relays
        .iter()
        .filter_map(|u| normalize_relay_url(u))
        .collect();

    let mut author_relays: HashMap<&String, Vec<String>> = HashMap::new();
    for author in authors {
        let write: Vec<String> = relay_lists
            .get(author)
            .map(|l| l.write.iter().take(MAX_RELAYS_PER_AUTHOR).cloned().collect())
            .unwrap_or_default();
        author_relays.insert(author, if write.is_empty() { fallback.clone() } else { write });
    }

    // want = how many MORE relays each author still wants. An author stays in
    // the cover pool until they've been routed to TARGET relays — the greedy
    // keeps adding relays per author across passes (WS1: target 3, degrading
    // to the author's relay count when smaller).
    let mut want: HashMap<&String, usize> = HashMap::new();
    for author in authors {
        let n = author_relays[author].len();
        if n > 0 {
            want.insert(author, RELAYS_PER_AUTHOR_TARGET.min(n));
        }
    }
    let mut ever_covered: BTreeSet<&String> = BTreeSet::new();
    let mut chosen: Route = BTreeMap::new();

    while !want.is_empty() && chosen.len() < MAX_RELAYS {
        // Coverage counts only authors still wanting, over unchosen relays.
        let mut coverage: BTreeMap<&str, Vec<&String>> = BTreeMap::new();
        for (author, remaining) in &want {
            if *remaining == 0 {
                continue;
            }
            for relay in &author_relays[author] {
                if chosen.contains_key(relay.as_str()) {
                    continue;
                }
                coverage.entry(relay.as_str()).or_default().push(author);
            }
        }
        if coverage.is_empty() {
            break;
        }

        // Pick by coverage WEIGHTED by quality: a big empty relay loses to a
        // smaller one that delivers; with neutral scores this is exactly
        // highest-coverage-first.
        let mut best: Option<(&str, Vec<&String>)> = None;
        let mut best_score = 0.0f64;
        for (relay, covered) in &coverage {
            let score = covered.len() as f64 * relay_score(relay);
            if score > best_score {
                best_score = score;
                best = Some((relay, covered.clone()));
            }
        }
        let Some((relay, covered)) = best else {
            break;
        };
        chosen.insert(
            relay.to_string(),
            covered.iter().map(|a| a.to_string()).collect(),
        );
        for author in covered {
            ever_covered.insert(author);
            let remaining = want.get_mut(author).expect("author in want");
            *remaining -= 1;
            if *remaining == 0 {
                want.remove(author);
            }
        }
    }

    // Don't silently drop the tail: an author with ZERO chosen relays is
    // recovered to their OWN best live relay (score 0 = read-dead excluded).
    // Past the hard ceiling (a NEW socket each), the indexers take them.
    let add_author = |route: &mut Route, relay: &str, author: &str| {
        route
            .entry(relay.to_string())
            .or_default()
            .insert(author.to_string());
    };
    for author in authors {
        if ever_covered.contains(author) {
            continue;
        }
        let write: Vec<&String> = relay_lists
            .get(author)
            .map(|l| {
                l.write
                    .iter()
                    .take(MAX_RELAYS_PER_AUTHOR)
                    .filter(|r| relay_score(r) > 0.0)
                    .collect()
            })
            .unwrap_or_default();
        // TS picks the FIRST relay on score ties (list order wins).
        let mut best: Option<&String> = None;
        for r in &write {
            let better = match best {
                None => true,
                Some(b) => relay_score(r) > relay_score(b),
            };
            if better {
                best = Some(r);
            }
        }
        if let Some(best) = best
            && (chosen.contains_key(best.as_str()) || chosen.len() < HARD_MAX_RELAYS)
        {
            add_author(&mut chosen, best, author);
            continue;
        }
        for relay in &fallback {
            add_author(&mut chosen, relay, author);
        }
    }
    chosen
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lists(pairs: &[(&str, &str)]) -> HashMap<String, RelayList> {
        pairs
            .iter()
            .map(|(pk, relays)| {
                (
                    pk.to_string(),
                    RelayList {
                        write: relays.split(',').map(str::to_string).collect(),
                        read: Vec::new(),
                    },
                )
            })
            .collect()
    }

    fn authors(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    fn fallback() -> String {
        "wss://idx".to_string()
    }

    /// Each author routes to up to THREE of their own write relays (WS1:
    /// RelayScoreBoard.kt MIN_REDUNDANCY — a note on only one of them still
    /// surfaces), degrading gracefully to however many they actually have,
    /// and the greedy set-cover shares relays across authors.
    #[test]
    fn routes_with_redundancy_and_shares_relays() {
        let l = lists(&[
            ("a", "wss://x,wss://y"),
            ("b", "wss://x,wss://z"),
            ("c", "wss://x"),
        ]);
        let route = route(&l, &authors(&["a", "b", "c"]), &[], |_| 1.0);
        // x covers all three at 1st pick; y and z cover 2 each at 2nd — both
        // make the cap (3 relays << 70). Each author ends on x + one more.
        assert_eq!(route.len(), 3);
        assert_eq!(route["wss://x"], BTreeSet::from(["a".into(), "b".into(), "c".into()]));
        assert_eq!(route["wss://y"], BTreeSet::from(["a".into()]));
        assert_eq!(route["wss://z"], BTreeSet::from(["b".into()]));
    }

    /// WS1 (RelayScoreBoard.kt MIN_REDUNDANCY = 3): an author with three or
    /// more write relays routes onto three of them — and one with fewer is
    /// routed onto ALL they have (graceful degradation), never dropped.
    #[test]
    fn redundancy_target_is_three_with_graceful_fallback() {
        // Three relays: routed to all three.
        let l3 = lists(&[("a", "wss://x,wss://y,wss://z")]);
        let route3 = route(&l3, &authors(&["a"]), &[], |_| 1.0);
        assert_eq!(route3.len(), 3);
        for r in ["wss://x", "wss://y", "wss://z"] {
            assert!(route3[r].contains("a"));
        }
        // Five relays: capped at the target of 3 (greedy: coverage-first,
        // so three distinct relays each covering one author beat repeats).
        let l5 = lists(&[("a", "wss://p,wss://q,wss://r,wss://s,wss://t")]);
        let route5 = route(&l5, &authors(&["a"]), &[], |_| 1.0);
        assert_eq!(route5.len(), 3);
        // Two relays: both (the old target) — fewer known relays never
        // under-route the author.
        let l2 = lists(&[("a", "wss://x,wss://y")]);
        let route2 = route(&l2, &authors(&["a"]), &[], |_| 1.0);
        assert_eq!(route2.len(), 2);
    }
    /// An author whose relays lost the greedy (cap hit) recovers onto their
    /// OWN relay — not the indexers.
    #[test]
    fn orphan_recovers_to_their_own_relay() {
        // 71 distinct relays force the cap at 70: the last author loses.
        let mut l = lists(&[("a", "wss://a0")]);
        for i in 0..70 {
            let pk = format!("p{i:02}");
            l.insert(pk.clone(), RelayList {
                write: vec![format!("wss://r{i:02}")],
                ..Default::default()
            });
            let _ = pk;
        }
        let route = route(&l, &authors(&["a", "p00"]), &[fallback()], |_| 1.0);
        // a routes to a0, then the cap (70) is hit exactly by the p authors;
        // p00's own relay r00 missed the cut, so orphan recovery routes them
        // to r00 (a NEW socket, allowed while under the hard cap).
        assert!(route.contains_key("wss://a0"));
        assert!(route.contains_key("wss://r00"));
        assert!(!route.contains_key("wss://idx"));
    }

    /// A read-dead relay (score 0) is never picked by the greedy, and
    /// orphans skip it too — its authors route to their other relays, or
    /// fall to the indexers when it's their only one.
    #[test]
    fn read_dead_relay_never_picked() {
        let l = lists(&[
            ("a", "wss://dead,wss://live"),
            ("b", "wss://dead-only"),
        ]);
        let route = route(&l, &authors(&["a", "b"]), &[fallback()], |r| {
            if r.contains("dead") { 0.0 } else { 1.0 }
        });
        assert!(route.contains_key("wss://live"));
        assert_eq!(route["wss://live"], BTreeSet::from(["a".into()]));
        // b's only relay is dead: indexers.
        assert!(route.contains_key("wss://idx"));
        assert!(route["wss://idx"].contains("b"));
        assert!(!route.iter().any(|(r, _)| r.contains("dead")));
    }

    /// Authors with no relay list at all fall to the indexers.
    #[test]
    fn listless_authors_use_the_fallback() {
        let l = lists(&[("a", "wss://x")]);
        let route = route(&l, &authors(&["a", "lonely"]), &[fallback()], |_| 1.0);
        assert!(route["wss://idx"].contains("lonely"));
        assert!(!route["wss://idx"].contains("a"));
    }

    /// The hard ceiling: past 2x cap relays, orphan recovery gives up on new
    /// sockets and dumps the tail on the indexers.
    #[test]
    fn tail_past_hard_cap_falls_to_indexers() {
        let mut l = HashMap::new();
        let mut a = Vec::new();
        for i in 0..150 {
            let pk = format!("p{i:03}");
            l.insert(pk.clone(), RelayList {
                write: vec![format!("wss://r{i:03}")],
                ..Default::default()
            });
            a.push(pk);
        }
        let route = route(&l, &a, &[fallback()], |_| 1.0);
        // 70 greedy picks; the remaining 80 orphans each want a NEW socket:
        // 70 more fit under the hard cap (140), the last 10 go to the
        // indexers.
        assert_eq!(route.len(), 141);
        let idx: &BTreeSet<String> = &route["wss://idx"];
        assert_eq!(idx.len(), 10);
    }

    /// REQ chunk ceilings (OutboxRouter.kt): a filter can never exceed the
    /// per-REQ caps — authors 200 (MAX_AUTHORS_PER_FILTER), e-tags 150
    /// (MAX_ETAGS_PER_FILTER) — whatever the caller starts from.
    #[test]
    fn chunk_enforces_ceilings() {
        let ids: Vec<usize> = (0..350).collect();
        let shards = chunk(&ids, MAX_AUTHORS_PER_FILTER);
        assert_eq!(shards, vec![(0..200).collect::<Vec<_>>(), (200..350).collect::<Vec<_>>()]);
        let shards = chunk(&ids, MAX_ETAGS_PER_FILTER);
        assert_eq!(shards.len(), 3); // 150 + 150 + 50
        assert!(shards[..2].iter().all(|s| s.len() == MAX_ETAGS_PER_FILTER));
        assert_eq!(shards[2].len(), 50);
        // Under the ceiling: one shard, nothing split.
        assert_eq!(chunk(&ids[..150], MAX_ETAGS_PER_FILTER).len(), 1);
    }

    /// Normalization: case + trailing slashes fold together; non-ws schemes
    /// are rejected (the http://relay.onion trap), not rewritten.
    #[test]
    fn normalize_folds_and_rejects() {
        assert_eq!(
            normalize_relay_url("WSS://Relay.Example/"),
            Some("wss://relay.example".to_string())
        );
        assert_eq!(normalize_relay_url("http://relay.onion"), None);
        assert_eq!(normalize_relay_url("mailto:x@y"), None);
        assert_eq!(normalize_relay_url("wss://"), None);
        // The map key folds the same way.
        assert_eq!(relay_key("wss://Relay.Example/"), "wss://relay.example");
    }

    /// Parsing: absent marker = both; explicit markers split; junk skipped.
    #[test]
    fn parse_splits_read_write() {
        use nostr::prelude::*;
        let keys = Keys::generate();
        let mut tags = Tags::new();
        tags.push(Tag::custom("r", vec!["wss://both.example/"]));
        tags.push(Tag::custom("r", vec!["wss://read.example/", "read"]));
        tags.push(Tag::custom("r", vec!["wss://write.example/", "write"]));
        tags.push(Tag::custom("r", vec!["http://trap.onion"]));
        tags.push(Tag::custom("r", vec![""]));
        let unsigned = UnsignedEvent::new(
            keys.public_key(),
            Timestamp::from_secs(1),
            Kind::Custom(10002),
            tags,
            String::new(),
        );
        let e = keys.sign_event(unsigned).unwrap();
        let l = parse_relay_list(&e);
        assert_eq!(l.write, vec!["wss://both.example", "wss://write.example"]);
        assert_eq!(l.read, vec!["wss://both.example", "wss://read.example"]);
    }

    /// The SSRF screen: wss only, structurally valid (the SDK's RelayUrl
    /// checks), and IP literals must be public — a followed author's list
    /// cannot aim the client at loopback, the metadata endpoint,
    /// RFC1918/CGNAT space, or plain-ws cleartext, and a mangled url cannot
    /// kill the whole fan-out at subscribe time.
    #[test]
    fn routable_screen() {
        assert!(routable_relay("wss://relay.example.com"));
        assert!(routable_relay("wss://relay.example.com/path"));
        assert!(routable_relay("wss://8.8.8.8:443"));
        assert!(routable_relay("wss://[2606:4700::1111]"));
        assert!(routable_relay("wss://[2606:4700::1111]:7777"));
        // Cleartext / wrong scheme.
        assert!(!routable_relay("ws://relay.example.com"));
        assert!(!routable_relay("http://relay.example.com"));
        // The live-bell killer: a mangled double scheme passed the old
        // hand-split screen as host "wss", then the SDK rejected the WHOLE
        // fan-out at subscribe time ("multiple scheme separators").
        assert!(!routable_relay("wss://wss://relay.example"));
        assert!(!routable_relay("wss://test://again"));
        // Private / reserved IPv4 literals.
        assert!(!routable_relay("wss://127.0.0.1:8080"));
        assert!(!routable_relay("wss://169.254.169.254"));
        assert!(!routable_relay("wss://10.0.0.5"));
        assert!(!routable_relay("wss://192.168.1.2"));
        assert!(!routable_relay("wss://172.16.0.9"));
        assert!(!routable_relay("wss://100.100.1.1"));
        assert!(!routable_relay("wss://0.0.0.0"));
        // Sneaky IPv4 encodings the url crate canonicalizes before the
        // check (all 127.0.0.1).
        assert!(!routable_relay("wss://2130706433"));
        assert!(!routable_relay("wss://0x7f.0.0.1"));
        assert!(!routable_relay("wss://127.1"));
        // IPv6 literals (host_str arrives bracketless) and malformed hosts.
        assert!(!routable_relay("wss://[::1]:7777"));
        assert!(!routable_relay("wss://[fe80::1]:7777"));
        assert!(!routable_relay("wss://[fc00::1]"));
        assert!(!routable_relay("wss://[::ffff:127.0.0.1]"));
        assert!(!routable_relay("wss://2606:4700::1111")); // bare: invalid
        assert!(!routable_relay("wss://[::1")); // unbalanced bracket
        assert!(!routable_relay("wss://")); // empty host
    }
}

