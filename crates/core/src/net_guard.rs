//! net_guard: the ONE ruleset for "is this network address connectable".
//!
//! Two consumers, one authority (M5 WP1 reconciliation: this file used to
//! exist twice — a paste-time URI screen and a resolver-side screen —
//! with DIFFERENT strictness; they are one module now, so they cannot
//! drift apart again):
//!
//! - paste-time URI screens ([`routable_relay`] → [`screen_nwc_uri`] /
//!   [`screen_bunker_uri`], issue #11: the wallet (nwc) and bunker
//!   (nostr-connect) clients build their own transports, outside the
//!   pool's screens; their relay URLs are user-supplied at paste time),
//! - dial-time resolution pinning ([`SafeResolver`], moved here from
//!   media.rs; [`resolve_pinned_public`] for the screening transport).
//!
//! The classifier is the STRICT union — a name that resolves to ANY
//! non-public address yields no connectable address (fail closed: a
//! public/private mix never dials the private leg). The address classes
//! cover RFC1918, loopback, link-local (incl. the 169.254.169.254
//! metadata endpoint), CGNAT, this-network, benchmark (198.18/15),
//! documentation (TEST-NET-1/2/3), 192.0.0.0/24, reserved/multicast/
//! broadcast; v6: ULA, link-local, multicast, documentation 2001:db8,
//! everything outside 2000::/3, v4-mapped judged by the embedded v4,
//! and the transition mechanisms (NAT64 64:ff9b::/96, 6to4 2002::/16,
//! Teredo 2001::/32) screened through their embedded IPv4 — both
//! Teredo legs, the client obfuscated per RFC 4380.
//!
//! The url-crate parse canonicalizes sneaky IPv4 spellings (decimal
//! `2130706433`, hex `0x7f.0.0.1`, short `127.1`) before the literal
//! check, so they cannot pose as names.

use nostr::prelude::*;

/// Public unicast only — THE authority. Strict side: a block is asserted
/// only when the address is demonstrably not globally reachable, so a
/// stricter new rule lands here and every caller (URI screens, resolver,
/// relay routing) tightens together.
pub fn is_public_ip(ip: &std::net::IpAddr) -> bool {
    match *ip {
        std::net::IpAddr::V4(v4) => {
            let o = v4.octets();
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_multicast()
                || v4.is_unspecified()
                || v4.is_documentation()
                || o[0] == 0 // this-network (0.0.0.0/8)
                || (o[0] == 100 && (o[1] & 0xc0) == 64) // CGNAT (100.64/10), not the whole 100/8
                || (o[0] == 192 && o[1] == 0 && o[2] == 0) // 192.0.0.0/24
                || (o[0] == 198 && (o[1] == 18 || o[1] == 19)) // 198.18/15 benchmark
                || o[0] >= 240) // reserved + broadcast
        }
        std::net::IpAddr::V6(v6) => {
            if v6.is_multicast() || v6.is_loopback() || v6.is_unspecified() {
                return false;
            }
            let s = v6.segments();
            // ::ffff:0:0/96 (v4-mapped) dials the embedded v4 on a
            // dual-stack host — screen THAT address.
            if s[..5] == [0, 0, 0, 0, 0] && s[5] == 0xffff {
                return is_public_ip(&std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                    (s[6] >> 8) as u8,
                    s[6] as u8,
                    (s[7] >> 8) as u8,
                    s[7] as u8,
                )));
            }
            // Global unicast lives in 2000::/3; ULA (fc00::/7),
            // link-local (fe80::/10) and everything experimental dies.
            // Transition mechanisms embed IPv4 INSIDE 2000::/3 — screen
            // the embedded leg too, or 64:ff9b::192.0.2.9-style answers
            // ride a NAT64 gateway onto the internal network:
            // - 64:ff9b::/96 (well-known NAT64): v4 in segments 6+7
            // - 2002::/16 (6to4): v4 in segment 1 (hi) + 2 (lo)
            // - 2001::/32 (Teredo): server v4 in segments 2+3, client
            //   v4 obfuscated (XOR 0xffff) in segments 6+7 — screen BOTH
            if s[0] == 0x0064 && s[1] == 0xff9b && s[2] == 0 && s[3] == 0 && s[4] == 0 && s[5] == 0
            {
                return is_public_ip(&std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                    (s[6] >> 8) as u8,
                    s[6] as u8,
                    (s[7] >> 8) as u8,
                    s[7] as u8,
                )));
            }
            if s[0] == 0x2002 {
                return is_public_ip(&std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                    (s[1] >> 8) as u8,
                    s[1] as u8,
                    (s[2] >> 8) as u8,
                    s[2] as u8,
                )));
            }
            if s[0] == 0x2001 && s[1] == 0 {
                let server = is_public_ip(&std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                    (s[2] >> 8) as u8,
                    s[2] as u8,
                    (s[3] >> 8) as u8,
                    s[3] as u8,
                )));
                let client = is_public_ip(&std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                    !(s[6] >> 8) as u8,
                    !(s[6] as u8),
                    !(s[7] >> 8) as u8,
                    !(s[7] as u8),
                )));
                return server && client;
            }
            (s[0] & 0xe000) == 0x2000 && !(s[0] == 0x2001 && s[1] == 0x0db8)
        }
    }
}

/// The relay screen every connectable url passes: wss only, public IP
/// literals only. Domains pass for now; pinning resolved IPs per hop is
/// the SSRF-guard M5 item (the same gap the media guard carries).
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
    // decimal/hex/short IPv4 into it. The authority also sees through the
    // transition mechanisms: a NAT64/6to4/Teredo literal whose embedded
    // IPv4 is internal is refused here, at paste time.
    match host {
        url::Host::Ipv4(v4) => is_public_ip(&std::net::IpAddr::V4(v4)),
        url::Host::Ipv6(v6) => is_public_ip(&std::net::IpAddr::V6(v6)),
        // Domains (incl. IDN) pass for now; resolved-IP pinning is M5.
        url::Host::Domain(_) => true,
    }
}

/// The refusal verdict a screened-out URI's relay gets: names the relay
/// so the dialog shows WHAT was refused, not just that something was.
fn relay_refused(url: &str) -> String {
    format!("the URI's relay {url} is not connectable: private addresses are refused")
}

/// Paste-time screen for a `nostr+walletconnect://` URI (issue #11): every
/// relay it asks the wallet transport to dial must pass the same
/// `routable_relay` screen the pool's routing uses. Err carries the
/// human-readable verdict for the connect dialog.
pub fn screen_nwc_uri(uri: &str) -> Result<(), String> {
    let parsed = nostr::nips::nip47::NostrWalletConnectUri::parse(uri.trim())
        .map_err(|e| format!("not a valid nostr+walletconnect:// URI: {e}"))?;
    for relay in &parsed.relays {
        let url = relay.as_str();
        if !routable_relay(url) {
            return Err(relay_refused(url));
        }
    }
    Ok(())
}

/// Paste-time screen for a `bunker://` URI (issue #11): same screen, the
/// relay list the nostrconnect transport would dial. nostrconnect:// is
/// deliberately not ours (D27: kumaOS owns that verb).
pub fn screen_bunker_uri(uri: &str) -> Result<(), String> {
    let parsed = nostr::prelude::NostrConnectUri::parse(uri.trim())
        .map_err(|e| format!("not a valid bunker:// URI: {e}"))?;
    let NostrConnectUri::Bunker { relays, .. } = &parsed else {
        return Err("expected bunker:// URI".into());
    };
    for relay in relays {
        let url = relay.as_str();
        if !routable_relay(url) {
            return Err(relay_refused(url));
        }
    }
    Ok(())
}

// --- dial-time resolution pinning (WP1) ------------------------------------

/// The DNS-rebinding-safe resolver (issue #3 WS4). The URL guard checks
/// HOST STRINGS — `evil.example.com` resolving to 127.0.0.1 sailed past
/// it. reqwest dials WHATEVER its resolver returns, so the check lives on
/// the address list: a name that resolves anywhere non-global yields NO
/// connectable address (fail closed — a public and private mix fails the
/// whole resolution, so no leg of it leaks onto the internal network).
/// Every connection this client opens — first party, every redirect hop,
/// every retry — re-walks here, so a rebinding rotation between hops
/// re-runs the check. TOCTOU-free by construction: the addresses that
/// passed the filter are the addresses hyper dials.
#[derive(Debug)]
pub struct SafeResolver;

impl reqwest::dns::Resolve for SafeResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let host = name.as_str().to_string();
        Box::pin(async move {
            // Port 0: reqwest replaces it with the scheme's conventional
            // port (the trait contract).
            let addrs: Vec<std::net::SocketAddr> = tokio::net::lookup_host((host.as_str(), 0))
                .await
                .map_err(std::io::Error::other)?
                .filter(|a| is_public_ip(&a.ip()))
                .collect();
            if addrs.is_empty() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    format!("{host} resolved to no public addresses"),
                )
                .into());
            }
            Ok(Box::new(addrs.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

/// Resolve `(host, port)` and hand back ONLY public-unicast addresses.
/// The dial path's front door for transports that resolve on their own
/// (the screening transport, M5 WP2): same fail-closed mix rule as the
/// resolver — one internal answer poisons the name.
pub async fn resolve_pinned_public(
    host: &str,
    port: u16,
) -> Result<Vec<std::net::SocketAddr>, NetGuardError> {
    let addrs: Vec<std::net::SocketAddr> = tokio::net::lookup_host((host, port))
        .await
        .map_err(|_| NetGuardError::Resolve(host.to_string()))?
        .collect();
    if addrs.is_empty() {
        return Err(NetGuardError::Resolve(host.to_string()));
    }
    if !addrs.iter().all(|a| is_public_ip(&a.ip())) {
        // Fail closed on the WHOLE name: no partial dials.
        return Err(NetGuardError::NonPublic(host.to_string()));
    }
    Ok(addrs)
}

/// Why a name was refused. `Resolve` is weather (DNS down, no answers);
/// `NonPublic` is the guard speaking (an internal address answered).
#[derive(Debug, PartialEq)]
pub enum NetGuardError {
    Resolve(String),
    NonPublic(String),
}

impl std::fmt::Display for NetGuardError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Resolve(host) => write!(f, "{host}: no answer"),
            Self::NonPublic(host) => {
                write!(f, "{host}: resolved to a non-public address")
            }
        }
    }
}

// --- the user-relay exemption --------------------------------------------

/// Hosts the USER chose (Settings entries, the session's own NIP-65,
/// login-time bunker/wallet relays): dial direct, no screening — the
/// user may deliberately point at a LAN relay (`wss://umbrel.local`,
/// `ws://192.168.1.10:7777`). Remote data (kind:10002s, hints) can
/// never join this set; its members ride the screening path. Consumers
/// land with the screening transport (M5 WP2).
fn direct_hosts() -> &'static std::sync::RwLock<std::collections::HashSet<String>> {
    use std::collections::HashSet;
    use std::sync::{OnceLock, RwLock};
    static SET: OnceLock<RwLock<HashSet<String>>> = OnceLock::new();
    SET.get_or_init(|| RwLock::new(HashSet::new()))
}

/// Exempt a relay host from the screening path (lowercase host, no
/// port, no trailing dot — `relay_key`-adjacent normalization).
pub fn allow_direct_relay(host: &str) {
    let host = normalize_host(host);
    if host.is_empty() {
        return;
    }
    direct_hosts().write().unwrap().insert(host);
}

/// Drop an exemption (relay retired from the session's lists).
pub fn disallow_direct_relay(host: &str) {
    direct_hosts()
        .write()
        .unwrap()
        .remove(&normalize_host(host));
}

/// Does this relay URL belong to the user-chosen set (direct dial)?
/// Anything NOT in the set must ride the screening transport.
pub fn user_chosen_relay(url: &str) -> bool {
    let Ok(parsed) = url::Url::parse(url) else {
        return false;
    };
    match parsed.host_str() {
        Some(host) => direct_hosts()
            .read()
            .unwrap()
            .contains(&normalize_host(host)),
        None => false,
    }
}

fn normalize_host(host: &str) -> String {
    let host = host.trim().trim_end_matches('.');
    let host = host.trim_start_matches('[').trim_end_matches(']');
    // Strip a ":<port>" suffix. Parsed URLs usually arrive portless via
    // host_str(), but accept(string) callers or login paths may hand us
    // "host:port" — without stripping, the lookup silently never matches.
    // Only strip if the suffix is purely numeric (real port), leaving
    // hostnames that legitimately contain colons (none in practice) intact.
    let host = if let Some(idx) = host.rfind(':') {
        let tail = &host[idx + 1..];
        if !tail.is_empty() && tail.bytes().all(|b| b.is_ascii_digit()) {
            &host[..idx]
        } else {
            host
        }
    } else {
        host
    };
    host.to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- the authority: v4 ------------------------------------------------

    #[test]
    fn v4_screen() {
        // Public unicast passes.
        assert!(is_public_ip(&"8.8.8.8".parse().unwrap()));
        assert!(is_public_ip(&"1.1.1.1".parse().unwrap()));
        // Everything the guard exists for dies.
        for bad in [
            "127.0.0.1",       // loopback
            "10.0.0.1",        // RFC1918
            "192.168.1.1",     // RFC1918
            "172.16.0.1",      // RFC1918
            "169.254.169.254", // cloud metadata
            "100.64.0.1",      // CGNAT
            "0.0.0.0",         // this-network
            "192.0.2.1",       // documentation (TEST-NET-1)
            "198.51.100.7",    // documentation (TEST-NET-2)
            "203.0.113.9",     // documentation (TEST-NET-3)
            "198.18.0.1",      // benchmark
            "192.0.0.9",       // 192.0.0.0/24
            "224.0.0.1",       // multicast
            "240.0.0.1",       // reserved
            "255.255.255.255", // broadcast
        ] {
            assert!(
                !is_public_ip(&bad.parse().unwrap()),
                "{bad} must be refused"
            );
        }
    }

    #[test]
    fn cgnat_only_refuses_the_10_block() {
        assert!(!is_public_ip(&"100.64.0.1".parse().unwrap()));
        assert!(!is_public_ip(&"100.127.255.254".parse().unwrap()));
        assert!(is_public_ip(&"100.63.255.255".parse().unwrap()));
        assert!(is_public_ip(&"100.128.0.1".parse().unwrap()));
    }

    // --- the authority: v6 (incl. transition mechanisms) ------------------

    #[test]
    fn v6_screen() {
        assert!(is_public_ip(&"2606:4700::1111".parse().unwrap()));
        for bad in [
            "::1",              // loopback
            "fe80::1",          // link-local
            "fc00::1",          // ULA
            "ff02::1",          // multicast
            "::ffff:127.0.0.1", // v4-mapped loopback
            "2001:db8::1",      // documentation
            // Transition mechanisms with embedded INTERNAL v4:
            "64:ff9b::192.0.2.9", // NAT64 → TEST-NET-1
            "64:ff9b::127.0.0.1", // NAT64 → loopback
            "2002:7f00:1::1",     // 6to4 → loopback
            "2002:c0a8:101::1",   // 6to4 → 192.168.1.1
            "2001:0:c0a8:101::1", // Teredo server 192.168.1.1
        ] {
            assert!(
                !is_public_ip(&bad.parse().unwrap()),
                "{bad} must be refused"
            );
        }
        // Teredo with an internal CLIENT v4 (obfuscated) also dies —
        // 192.168.1.1 XOR 0xffff = c6:57 → segments 6/7 = 0x39a7,0xfe9f.
        assert!(!is_public_ip(
            &"2001:0:6464:6464:0:0:39a7:fe9f".parse().unwrap()
        ));
        // Transition mechanisms with PUBLIC embedded v4 still pass.
        assert!(is_public_ip(&"64:ff9b::8.8.8.8".parse().unwrap()));
        assert!(is_public_ip(&"2002:0808:0808::1".parse().unwrap()));
    }

    // --- the paste-time URI screens (D51) ----------------------------------

    #[test]
    fn uri_screens_refuse_private_relays() {
        // The hostile spellings the routable screen catches, carried by a
        // real NIP-47 URI — the D51 list, plus the transition-mechanism
        // literals the loose screen used to let through (their embedded
        // IPv4 is internal; the authority sees it).
        let hostile = [
            "127.0.0.1",
            "2130706433", // decimal loopback
            "0x7f.0.0.1", // hex loopback
            "127.1",      // short loopback
            "192.168.1.10",
            "10.0.0.5",
            "172.16.0.9",
            "169.254.169.254", // the metadata endpoint
            "100.64.0.1",      // CGNAT
            "192.0.2.9",       // TEST-NET-1
            "198.18.0.7",      // benchmark
            "[::1]",
            "[fd00::1]",            // ULA
            "[fe80::1]",            // link-local
            "[64:ff9b::192.0.2.9]", // NAT64 → TEST-NET-1
            "[2002:c0a8:101::1]",   // 6to4 → 192.168.1.1
            "[2001:0:c0a8:101::1]", // Teredo server 192.168.1.1
        ];
        for host in hostile {
            let uri = format!(
                "nostr+walletconnect://b889ff5b1513b641e2a139f661a661364979c5beee91842f8f0ef42ab558e9d4?secret=71a8c14c1407c113601079c4302dab36460f0ccd0ad506f1f2dc73b5100e4f3c&relay=wss%3A%2F%2F{host}"
            );
            let err = screen_nwc_uri(&uri).unwrap_err();
            assert!(err.contains("not connectable"), "host {host}: {err}");
        }
    }

    #[test]
    fn uri_screens_pass_public_relays() {
        // The stock test URI (relay.damus.io) passes; a public IP literal
        // passes too, and a transition mechanism with a PUBLIC embedded
        // leg passes — the authority screens the embedded v4, not the
        // prefix.
        let uri = "nostr+walletconnect://b889ff5b1513b641e2a139f661a661364979c5beee91842f8f0ef42ab558e9d4?secret=71a8c14c1407c113601079c4302dab36460f0ccd0ad506f1f2dc73b5100e4f3c&relay=wss%3A%2F%2Frelay.damus.io";
        assert!(screen_nwc_uri(uri).is_ok());
        let uri = "nostr+walletconnect://b889ff5b1513b641e2a139f661a661364979c5beee91842f8f0ef42ab558e9d4?secret=71a8c14c1407c113601079c4302dab36460f0ccd0ad506f1f2dc73b5100e4f3c&relay=wss%3A%2F%2F%5B64%3Aff9b%3A%3A8.8.8.8%5D";
        assert!(screen_nwc_uri(uri).is_ok());
    }

    #[test]
    fn uri_screens_reject_garbage() {
        assert!(screen_nwc_uri("nostr+walletconnect://nope").is_err());
        assert!(screen_bunker_uri("nostrconnect://not-ours").is_err());
    }

    // --- dial-time resolution pinning --------------------------------------

    #[test]
    fn pinned_resolution_fails_closed() {
        // localhost never resolves to a public address — the name is
        // refused outright, whatever the answer list looks like.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let res = resolve_pinned_public("localhost", 8080).await;
            assert!(
                matches!(res, Err(NetGuardError::NonPublic(ref host)) if host == "localhost"),
                "a resolved non-public answer must be NetGuardError::NonPublic, not resolver weather: {res:?}"
            );
        });
    }

    // --- the user-relay exemption ------------------------------------------

    #[test]
    fn user_relay_exemption_roundtrip() {
        let url = "wss://umbrel.local:7777";
        assert!(!user_chosen_relay(url));
        allow_direct_relay("UMBREL.local");
        assert!(user_chosen_relay(url), "normalization folds case");
        allow_direct_relay("Example.COM:7443");
        assert!(
            user_chosen_relay("wss://example.com:7443"),
            "a listener or accept-style host:port grant uses the same normalization as a URL"
        );
        disallow_direct_relay("umbrel.local");
        assert!(!user_chosen_relay(url));
        // Garbage URLs are never "user chosen".
        assert!(!user_chosen_relay("not a url"));
    }
}
