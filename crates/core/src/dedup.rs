//! Duplicate-content spam filter — port of Amethyst's
//! `commons/.../model/cache/AntiSpamFilter.kt` (greenart7c3/Amethyst;
//! research notes `wot-spam-research.md` §2/§4 #1), riding the D34
//! `consume_and_filter` chokepoint in pool.rs.
//!
//! Model (AntiSpamFilter.kt): an event's duplicate key hashes the
//! content WITH its tags (`31 * content.hashCode() + tags`, ~line 47 —
//! identical replies to different people don't collide), recent keys
//! live in a bounded LRU (`events` LRU 2000, ~line 20), and a repeat
//! offender accrues duplicates per relay (`relayStats.newSpam`, ~line
//! 115) until [`DUPLICATES_TO_HIDE`] (5, `Spammer.shouldHide()`,
//! Spammer.kt:38), after which their events are spam. A spammer record
//! LRU of [`SPAMMERS_CAP`] (Amethyst's 1000) bounds the report surface
//! (their `SpammingUsersScreen.kt` reads the same shape).
//!
//! Exemptions (AntiSpamFilter.kt ~lines 57/63 + the account set): the
//! user themself and their follows (spam filtering exists for
//! strangers; you chose your follows), and SHORT content (< 60 chars —
//! "GM" false positives) and short `nostr:`-prefixed bot commands are
//! never spam; repeated invoices/phishing urls are (long enough to
//! trip the length floor).
//!
//! Settings gate: `dedup_enabled` in prefs.json, default ON (the issue
//! posture: dedup is objective and bounded, one of the two allowed
//! auto-actions). Read through the config cache like
//! `store::machine_notes_hidden`.
//!
//! In-memory, per-session (Amethyst's filter is too): the store keeps
//! the events, the LRU only needs recent traffic. Core-clean: no UI
//! deps.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};

use nostr::prelude::*;

/// Duplicates before an author's events stop being stored
/// (AntiSpamFilter.kt `Spammer.shouldHide()`: 5).
pub const DUPLICATES_TO_HIDE: u32 = 5;
/// Recent duplicate-key LRU (AntiSpamFilter.kt: 2000 events/addresses).
const RECENT_CAP: usize = 2000;
/// Spammer-record LRU (AntiSpamFilter.kt: 1000 spammers).
const SPAMMERS_CAP: usize = 1000;
/// Content shorter than this never counts (AntiSpamFilter.kt ~line 57:
/// the "GM" exemption).
const MIN_CONTENT_LEN: usize = 60;

/// The settings gate (`dedup_enabled` in prefs.json, default ON). Read
/// through the config cache per call (one metadata syscall between file
/// changes), so a settings flip lands on the next event.
fn enabled() -> bool {
    crate::config::prefs()
        .and_then(|v| v.get("dedup_enabled").and_then(|b| b.as_bool()))
        .unwrap_or(true)
}

/// One caught spammer, for the report surface (Amethyst
/// `SpammingUsersScreen.kt` shape): the author, duplicate count, the
/// relays that delivered the duplicates, and the last duplicate seen.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SpamRecord {
    /// Author pubkey (hex).
    pub pubkey: String,
    /// Duplicates seen this session (the hide threshold is
    /// [`DUPLICATES_TO_HIDE`]).
    pub count: u32,
    /// relay url → duplicate count attributed to that relay.
    pub relays: BTreeMap<String, u32>,
    /// Last duplicate, unix secs.
    pub last_seen: u64,
}

#[derive(Default)]
struct Spammer {
    count: u32,
    relays: BTreeMap<String, u32>,
    last_seen: u64,
}

struct Filter {
    /// Duplicate keys, recency-ordered (most recent LAST — the seen.rs
    /// insertion convention); the vec is the LRU.
    recent: HashMap<u64, ()>,
    order: VecDeque<u64>,
    spammers: HashMap<String, Spammer>,
    spammer_order: VecDeque<String>,
    /// Exemptions: the user's own key, then their follows' (Amethyst:
    /// account + follows set). Hex.
    exempt: std::collections::HashSet<String>,
}

static FILTER: OnceLock<Mutex<Filter>> = OnceLock::new();

fn filter() -> &'static Mutex<Filter> {
    FILTER.get_or_init(|| {
        Mutex::new(Filter {
            recent: HashMap::new(),
            order: VecDeque::new(),
            spammers: HashMap::new(),
            spammer_order: VecDeque::new(),
            exempt: std::collections::HashSet::new(),
        })
    })
}

/// The exemption set (the user + their follows). The manager re-arms it
/// at every bootstrap, alongside the WoT graph identity.
pub fn set_exemptions(me: PublicKey, follows: &[PublicKey]) {
    let mut f = filter()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    f.exempt.clear();
    f.exempt.insert(me.to_string());
    for pk in follows {
        f.exempt.insert(pk.to_string());
    }
}

/// The duplicate key: content hashed WITH its tags (AntiSpamFilter.kt
/// ~line 47, `31 * content.hashCode() + tags` — identical replies to
/// different people must not collide, so tags are in the mix).
fn dup_key(ev: &Event) -> u64 {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    ev.content.hash(&mut h);
    // Tags order-matter (a `p` list is content); fold each serialized
    // tag's hash in with the 31x mixing of the Kotlin original.
    let mut mix: u64 = 0;
    for tag in ev.tags.iter() {
        let mut th = std::collections::hash_map::DefaultHasher::new();
        match serde_json::to_string(tag) {
            Ok(s) => {
                s.hash(&mut th);
                mix = mix.wrapping_mul(31).wrapping_add(th.finish());
            }
            Err(_) => continue,
        }
    }
    mix.hash(&mut h);
    h.finish()
}

fn note_spammer(f: &mut Filter, pubkey: &str, relay: &str, now: u64) {
    if !f.spammers.contains_key(pubkey) && f.spammers.len() >= SPAMMERS_CAP {
        // LRU evict oldest-recorded spammer.
        if let Some(old) = f.spammer_order.pop_front() {
            f.spammers.remove(&old);
        }
    }
    let s = f.spammers.entry(pubkey.to_string()).or_default();
    // A returning spammer re-arms their LRU slot.
    if !f.spammer_order.contains(&pubkey.to_string()) {
        f.spammer_order.push_back(pubkey.to_string());
    }
    s.count += 1;
    *s.relays.entry(relay.to_string()).or_insert(0) += 1;
    s.last_seen = now;
    mark_dirty();
}

/// Ingest one event at the chokepoint. Returns true when the event is
/// SPAM — drop it from the result set / the bell (the caller decides;
/// at pool.rs every network read walks through this). Non-spam events
/// are recorded (their key joins the recent LRU) and a duplicate ALSO
/// counts toward its author's spammer record with per-relay
/// attribution, even before the hide threshold trips — the receipts
/// the report surface reads.
pub fn observe(ev: &Event, relay: &str) -> bool {
    if !enabled() {
        return false;
    }
    // Cheap gates BEFORE the hashing work (the audit's fix — the
    // chokepoint sees every network event): the length floor needs no
    // lock, and the key is computed OUTSIDE the filter mutex so tag
    // serialization never serializes the hot path behind it.
    if ev.content.chars().count() < MIN_CONTENT_LEN {
        return false;
    }
    let author = ev.pubkey.to_string();
    let key = dup_key(ev);

    let mut f = filter()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    // Exemptions (AntiSpamFilter.kt): account + follows set first —
    // their events never even join the recent LRU.
    if f.exempt.contains(&author) {
        return false;
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let duplicate = {
        // LRU insert (recent keys, oldest-first eviction).
        let dup = f.recent.contains_key(&key);
        if f.recent.insert(key, ()).is_none() {
            f.order.push_back(key);
            mark_dirty(); // a new key only lands once per session
        }
        while f.order.len() > RECENT_CAP {
            if let Some(old) = f.order.pop_front() {
                f.recent.remove(&old);
            }
        }
        dup
    };
    if duplicate {
        note_spammer(&mut f, &author, relay, now);
    }
    f.spammers
        .get(&author)
        .is_some_and(|s| s.count >= DUPLICATES_TO_HIDE)
}

/// The report surface's snapshot: caught spammers with per-relay
/// attribution (Amethyst `SpammingUsersScreen.kt`'s data), newest
/// duplicate first. A `count >= DUPLICATES_TO_HIDE` record is currently
/// hidden; lower counts are the visible receipts.
pub fn snapshot() -> Vec<SpamRecord> {
    let f = filter()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut out: Vec<SpamRecord> = f
        .spammers
        .iter()
        .map(|(pubkey, s)| SpamRecord {
            pubkey: pubkey.clone(),
            count: s.count,
            relays: s.relays.clone(),
            last_seen: s.last_seen,
        })
        .collect();
    out.sort_by_key(|r| std::cmp::Reverse(r.last_seen));
    out
}

/// Is this author currently hidden by the filter? (The read paths'
/// dedup gate: the chokepoint stops their deliveries, but events the
/// SDK already persisted still sit in the store — the cached
/// notification/pane builds must not serve them either. D41's
/// "unreachable through any read path" made true.)
pub fn is_hidden(pubkey: &str) -> bool {
    if !enabled() {
        return false; // the switch is off: the ledger stops deciding
    }
    let f = filter()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    f.spammers
        .get(pubkey)
        .is_some_and(|s| s.count >= DUPLICATES_TO_HIDE)
}

/// The SpammingUsers surface's un-hide affordance: clear one author's
/// spammer record so their events store again (a fresh streak of
/// DUPLICATES_TO_HIDE re-hides them). The duplicate-key LRU is NOT
/// cleared — the same content re-delivered still counts.
pub fn unhide(pubkey: &str) {
    let mut f = filter()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    f.spammers.remove(pubkey);
    f.spammer_order.retain(|p| p != pubkey);
    mark_dirty(); // the durable ledger un-hides them too
}

/// Session teardown: drop the filter's state (the exemption set is
/// session identity, and the LRU maps are this session's traffic). The
/// PERSISTED ledger is untouched — who the filter caught is a durable
/// record, and the next arm reloads it (D48).
pub fn clear() {
    let mut f = filter()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    *f = Filter {
        recent: HashMap::new(),
        order: VecDeque::new(),
        spammers: HashMap::new(),
        spammer_order: VecDeque::new(),
        exempt: std::collections::HashSet::new(),
    };
    LOADED.store(false, Ordering::Relaxed);
}

// --- Persistence (D48) — the ledger outlives the session. Boot used to
// start from zero knowledge: the caught-spammer records were per-session,
// so the store-held spam replies painted on the first notifications
// frame and stayed there until relays re-taught the filter (a minute of
// wrong state, every launch — the maintainer's "still spam replies first
// frame"). Same discipline as wot-sources (D45)/hints: 0600
// temp-sibling + rename, debounced park_timeout flusher. The recent-key
// LRU persists too: identical content re-delivered after a restart
// still counts as duplicates instead of starting a fresh streak.

const FLUSH_SECS: u64 = 10;
static DIRTY: AtomicBool = AtomicBool::new(false);
static FLUSHER: OnceLock<()> = OnceLock::new();
static LOADED: AtomicBool = AtomicBool::new(false);

fn mark_dirty() {
    DIRTY.store(true, Ordering::Relaxed);
    FLUSHER.get_or_init(|| {
        std::thread::Builder::new()
            .name("dedup-flush".into())
            .spawn(|| loop {
                std::thread::park_timeout(std::time::Duration::from_secs(FLUSH_SECS));
                if DIRTY.swap(false, Ordering::Relaxed) {
                    write_disk();
                }
            })
            .ok();
    });
}

fn write_disk() {
    let f = filter()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let spammers: Vec<serde_json::Value> = f
        .spammer_order
        .iter()
        .filter_map(|pk| {
            let s = f.spammers.get(pk)?;
            Some(serde_json::json!({
                "pk": pk,
                "count": s.count,
                "relays": s.relays,
                "last_seen": s.last_seen,
            }))
        })
        .collect();
    let recent: Vec<u64> = f.order.iter().copied().collect();
    drop(f);
    let path = crate::config::state_file(crate::config::files::DEDUP_STATE);
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    let tmp = path.with_extension(format!("tmp-{}-{nanos}", std::process::id()));
    let body = serde_json::json!({ "spammers": spammers, "recent": recent }).to_string();
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt;
    let Ok(mut f) = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)
    else {
        return;
    };
    if f.write_all(body.as_bytes()).is_ok() {
        drop(f);
        let _ = std::fs::rename(&tmp, &path);
    } else {
        let _ = std::fs::remove_file(&tmp);
    }
}

/// Merge the persisted ledger into the live filter (bootstrap arm; the
/// manager calls it at every arm and the guard makes the rest no-ops).
/// Merges are max/insert — idempotent, and a count is never inflated by
/// reloads: the record only grows on real duplicates.
pub fn load_disk() {
    if LOADED.swap(true, Ordering::Relaxed) {
        return;
    }
    let Ok(raw) =
        std::fs::read_to_string(crate::config::state_file(crate::config::files::DEDUP_STATE))
    else {
        return;
    };
    let Ok(v) = serde_json::from_str::<serde_json::Value>(&raw) else {
        return;
    };
    let mut f = filter()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(list) = v.get("spammers").and_then(|x| x.as_array()) {
        for e in list {
            let Some(pk) = e.get("pk").and_then(|x| x.as_str()) else {
                continue;
            };
            let count = e.get("count").and_then(|x| x.as_u64()).unwrap_or(0) as u32;
            let last_seen = e.get("last_seen").and_then(|x| x.as_u64()).unwrap_or(0);
            let pk = pk.to_string();
            // Merge into the record first (the entry borrow ends with
            // the scope)…
            {
                let s = f.spammers.entry(pk.clone()).or_default();
                s.count = s.count.max(count);
                s.last_seen = s.last_seen.max(last_seen);
                if let Some(relays) = e.get("relays").and_then(|x| x.as_object()) {
                    for (url, n) in relays {
                        let n = n.as_u64().unwrap_or(0) as u32;
                        let slot = s.relays.entry(url.clone()).or_insert(0);
                        *slot = (*slot).max(n);
                    }
                }
            }
            // …then the LRU order (a separate field, a separate borrow).
            if !f.spammer_order.contains(&pk) {
                f.spammer_order.push_back(pk);
            }
        }
        while f.spammer_order.len() > SPAMMERS_CAP {
            if let Some(old) = f.spammer_order.pop_front() {
                f.spammers.remove(&old);
            }
        }
    }
    if let Some(list) = v.get("recent").and_then(|x| x.as_array()) {
        for k in list {
            let Some(k) = k.as_u64() else {
                continue;
            };
            if f.recent.insert(k, ()).is_none() {
                f.order.push_back(k);
            }
        }
        while f.order.len() > RECENT_CAP {
            if let Some(old) = f.order.pop_front() {
                f.recent.remove(&old);
            }
        }
    }
}

#[cfg(test)]
pub(crate) fn reset_for_tests() {
    clear();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_env::EnvGuard;

    /// prefs are read once per process for the gate; these tests only
    /// need the data dir isolated (the default is ON).
    struct Fixture {
        me: Keys,
        env: EnvGuard,
    }

    impl Fixture {
        fn new() -> Self {
            let env = EnvGuard::new("dedup");
            let me = Keys::generate();
            set_exemptions(me.public_key(), &[]);
            Self { me, env }
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            reset_for_tests();
        }
    }

    fn signed(keys: &Keys, content: &str, tags: Vec<Vec<String>>) -> Event {
        let mut t = Tags::new();
        for v in tags {
            t.push(Tag::custom(&v[0], v[1..].to_vec()));
        }
        let unsigned = UnsignedEvent::new(
            keys.public_key(),
            Timestamp::from_secs(1),
            Kind::TextNote,
            t,
            content.to_string(),
        );
        keys.sign_event(unsigned).unwrap()
    }

    fn long() -> String {
        "spam message with real length, well over the sixty char floor, \
         repeated verbatim by a lazy spammer across relays"
            .to_string()
    }

    /// Nostr events are content-addressed: a lazy spammer's duplicates
    /// are the SAME event re-delivered (across relays, or re-published
    /// with a new timestamp). Original + 4 duplicates stored; the 5th
    /// DUPLICATE hides the author (AntiSpamFilter.kt
    /// Spammer.shouldHide at 5).
    #[test]
    fn fifth_duplicate_hides_author() {
        let _f = Fixture::new();
        let spammer = Keys::generate();
        let body = long();
        let ev = signed(&spammer, &body, vec![]);
        for i in 1..=6 {
            let spam = observe(&ev, "wss://a.example");
            assert_eq!(spam, i >= 6, "delivery {i}: spam={spam}");
        }
        // Every subsequent event by the author is spam, ANY content.
        let ev = signed(&spammer, &(body + " brand new text entirely"), vec![]);
        assert!(observe(&ev, "wss://a.example"));
    }

    /// Distinct content from the same author is NOT a duplicate (the
    /// count only moves on a repeated content+tags key).
    #[test]
    fn distinct_content_not_duplicate() {
        let _f = Fixture::new();
        let author = Keys::generate();
        for i in 0..10 {
            let ev = signed(&author, &format!("{i}: {}", long()), vec![]);
            assert!(!observe(&ev, "wss://a.example"));
        }
        assert_eq!(snapshot().len(), 0);
    }

    /// Per-relay attribution: the snapshot names which relays carried
    /// the duplicates (AntiSpamFilter.kt relayStats.newSpam) — the same
    /// event flooded across relays.
    #[test]
    fn per_relay_attribution() {
        let _f = Fixture::new();
        let spammer = Keys::generate();
        let ev = signed(&spammer, &long(), vec![]);
        let relays = ["wss://a.example", "wss://b.example", "wss://c.example"];
        for r in relays.iter().cycle().take(6) {
            observe(&ev, r);
        }
        let snap = snapshot();
        assert_eq!(snap.len(), 1);
        let rec = &snap[0];
        assert_eq!(rec.count, 5); // the original isn't a duplicate
        assert_eq!(rec.relays.get("wss://a.example"), Some(&1));
        assert_eq!(rec.relays.get("wss://b.example"), Some(&2));
        assert_eq!(rec.relays.get("wss://c.example"), Some(&2));
        assert!(rec.count >= DUPLICATES_TO_HIDE);
    }

    /// Exemptions: the user themself and their follows never trip the
    /// filter (AntiSpamFilter.kt's account+follows exemption), and
    /// short content ("GM") and short nostr: commands are exempt too.
    #[test]
    fn exemptions() {
        let fx = Fixture::new();
        let follow = Keys::generate();
        set_exemptions(fx.me.public_key(), &[follow.public_key()]);
        let body = long();
        // Follow, duplicated 7x: never spam.
        for i in 0..7 {
            let ev = signed(&follow, &body, vec![vec!["t".to_string(), format!("{i}")]]);
            assert!(!observe(&ev, "wss://a.example"));
        }
        // Short content below the 60-char floor: exempt even duplicated.
        let gm = Keys::generate();
        let gm_ev = signed(&gm, "GM GM GM GM GM GM GM GM GM GM GM GM", vec![]);
        for _ in 0..7 {
            assert!(!observe(&gm_ev, "wss://a.example"));
        }
        // Self: exempt.
        let ev = signed(&fx.me, &body, vec![]);
        assert!(!observe(&ev, "wss://a.example"));
        // (A long nostr: URI inside real content is NOT exempt — the
        // floor is a length floor, and phishing urls are long.)
        let phish = Keys::generate();
        let url = format!("nostr:nevent1{}", "a".repeat(90));
        let phish_ev = signed(&phish, &url, vec![]);
        for i in 1..=6 {
            assert_eq!(observe(&phish_ev, "wss://a.example"), i >= 6);
        }
    }

    /// D48: the ledger persists — caught spammers + the recent duplicate
    /// keys reload at the next arm, so the first frame gates from last
    /// session's knowledge (the store door is warm at boot) and a
    /// restart doesn't start a fresh duplicate streak.
    #[test]
    fn persisted_ledger_reloads() {
        let _env = EnvGuard::new("dedup-persist");
        let spammer = Keys::generate();
        let ev = signed(&spammer, &long(), vec![]);
        observe(&ev, "wss://a.example"); // the original — not a duplicate
        observe(&ev, "wss://b.example"); // duplicate 1
        observe(&ev, "wss://c.example"); // duplicate 2
        assert!(!is_hidden(&spammer.public_key().to_string()));
        write_disk();
        clear();
        assert!(snapshot().is_empty());
        load_disk();
        // The record survived, counts + per-relay attribution intact.
        let snap = snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].count, 2);
        assert_eq!(snap[0].relays.get("wss://b.example"), Some(&1));
        // And the recent-key LRU: the same content re-delivered is still
        // a duplicate (the count moves again; a reload never inflates it
        // on its own).
        assert!(!observe(&ev, "wss://a.example"));
        assert_eq!(snapshot()[0].count, 3);
        clear();
    }

    /// The snapshot is newest-duplicate-first and bounded (the spammer
    /// LRU evicts the oldest-recorded at SPAMMERS_CAP).
    #[test]
    fn snapshot_order_and_lru_cap() {
        let _f = Fixture::new();
        // Receipts before the hide: the record exists (with per-relay
        // attribution of the DUPLICATES — the original's relay isn't
        // blamed) while the author is still under the threshold.
        let spammer = Keys::generate();
        let body = long();
        let ev1 = signed(&spammer, &body, vec![]);
        let ev2 = signed(&spammer, &body, vec![]);
        observe(&ev1, "wss://a.example"); // the original — not a duplicate
        observe(&ev2, "wss://b.example");
        observe(&ev2, "wss://c.example");
        let snap = snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].count, 2);
        assert_eq!(snap[0].relays.get("wss://b.example"), Some(&1));
        assert_eq!(snap[0].relays.get("wss://c.example"), Some(&1));
        assert!(!snap[0].relays.contains_key("wss://a.example"));
        // Pre-hide receipt — the issue's "receipts, never a silent void".
        assert!(snap[0].count < DUPLICATES_TO_HIDE);
    }
}
