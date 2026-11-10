//! Relay pool — port of `src/data/pool.ts` + `src/nostr/nip65.ts` semantics,
//! v2 (slices 1+2): a nostr-sdk client over the LMDB store.
//!
//! - READ: outbox-routed (outbox.rs quality-weighted set-cover, ≥3/author
//!   where availability allows — WS1, D39), ONE relay per shard via manual
//!   `ReqTarget`s, each shard
//!   on its adaptive latency budget (relay_latency.rs: profiled-empty
//!   relays bail to the floor, rich-but-truncating ones earn the ceiling),
//!   read-dead relays skipped mid-session; indexers as the fallback set.
//!   Seen-on memory (seen.rs) folds learned relays into single-event
//!   fetches (`get_from`, the resolveEvent shape) and the `e`/`q` tag
//!   hints on write paths (actions.ts addTag).
//! - WRITE: own NIP-65 write relays, falling back to indexers.
//! - TODO(port): NIP-09 tombstones + NIP-40 expiry at the chokepoint (M2)
//!   — deletions are filtered at the manager's render filter today, not
//!   here.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::future::Future;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use nostr::prelude::*;
use nostr_sdk::authenticator::Authenticator;
use nostr_sdk::client::ReqTarget;
use nostr_sdk::error::Error as SdkError;
use nostr_sdk::prelude::*;
use nostr_sdk::proxy::Proxy;
use nostr_sdk::relay::EventSendStatus;

use crate::deletions;
use crate::hints;
use crate::nip40;
use crate::outbox::{self, RelayList, Route};
use crate::relay_latency;
use crate::seen;
use crate::signer::Signer;
use crate::store::Store;

/// Bootstrap indexer relays (nip65.ts:9-15). Liveness-probed Nov 2026:
/// relay.coracle.social has no DNS and nos.social 404s websocket upgrades —
/// the TS reference's indexer./relay. hosts are the live ones.
pub const INDEXERS: [&str; 5] = [
    "wss://relay.damus.io",
    "wss://relay.primal.net",
    "wss://indexer.coracle.social",
    "wss://relay.nos.social",
    "wss://purplepag.es",
];

/// Per-query deadline (pool.ts 'page' budget): the DEFAULT (base) cap.
const READ_BUDGET: Duration = Duration::from_secs(4);
/// Adaptive-budget ends (pool.ts PAGE_MAX_WAIT / LIST_CEILING): a
/// profiled-empty relay bails fast to the floor; a rich-but-truncating
/// one gets rope toward the ceiling.
const PAGE_BUDGET: Duration = Duration::from_secs(2);
const CEILING_BUDGET: Duration = Duration::from_secs(8);

/// The pool chokepoint (pool.ts consumeAndFilter) — the one door every
/// network read walks through: kind:5s are RECORDED as tombstones
/// wherever they arrive (deletions.rs), then filtered — along with
/// expired copies (NIP-40) and author-deleted ones (NIP-09) — out of the
/// results. Two passes, so a deletion takes effect even on the result
/// set that carried it, regardless of arrival order within it.
fn consume_and_filter(events: impl IntoIterator<Item = Event>, relay: &str) -> BTreeSet<Event> {
    let all: Vec<Event> = events.into_iter().collect();
    for e in &all {
        if u16::from(e.kind) == 5 {
            deletions::record(e, false);
        }
        // WoT graph feed (issue #2 WS1): kind-3 contact lists flowing
        // through ANY read apply to the two-hop graph incrementally
        // (Amethyst applyKind3 discipline — wot.rs ignores non-follows).
        if u16::from(e.kind) == 3 {
            crate::wot::observe(e);
        }
    }
    all.into_iter()
        .filter(|e| {
            u16::from(e.kind) != 5
                && !nip40::is_expired(e)
                && !deletions::is_deleted(e)
                // Duplicate-content gate (issue #2 WS2, Amethyst
                // AntiSpamFilter.kt): 5+ duplicates → the author's
                // events stop coming through. Relay attribution rides
                // the shard the events arrived on ("" for client-level
                // fetches, where the relay is not single).
                && !crate::dedup::observe(e, relay)
        })
        .collect()
}

/// WS1 (issue #1): the no-kind-10002 fallback tier. An author who
/// publishes no relay list is routed on their learned author-keyed hints
/// (hints.rs — RelayHintStore.kt's provenance + tag-hint accumulation)
/// BEFORE falling to the indexers, whose mirrors may not carry them at
/// all. Hint relays were screened (routable, non-indexer) at record time,
/// exactly the discipline relay_lists' consumers apply to kind:10002
/// entries.
fn hint_seeded_lists(
    mut lists: HashMap<String, RelayList>,
    authors: &[PublicKey],
) -> HashMap<String, RelayList> {
    for pk in authors {
        let key = pk.to_string();
        if lists.get(&key).is_none_or(RelayList::is_empty) {
            let seeded = hints::for_pubkey(pk);
            if !seeded.is_empty() {
                lists.insert(key, RelayList { write: seeded, read: Vec::new() });
            }
        }
    }
    lists
}

/// WS1 (issue #2): the extended-network fallback tier. An author with
/// NEITHER a kind:10002 NOR learned hints (D39) still routes somewhere
/// useful if they're in the qualified two-hop network: the greedy
/// relay cover of that network (wot.rs, dark-wisp computeRelaySetCover)
/// — the relays that collectively carry everyone your follows follow.
/// Precedence chain (unchanged for listed authors): kind:10002 →
/// D39 hints → extended-network cover (this tier) → indexers.
fn extended_cover_seeded(
    mut lists: HashMap<String, RelayList>,
    authors: &[PublicKey],
) -> HashMap<String, RelayList> {
    let cover = crate::wot::extended_relays();
    if cover.is_empty() {
        return lists;
    }
    for pk in authors {
        let key = pk.to_string();
        if lists.get(&key).is_none_or(RelayList::is_empty)
            && crate::wot::is_qualified(pk)
        {
            lists.insert(
                key,
                RelayList { write: cover.clone(), read: Vec::new() },
            );
        }
    }
    lists
}

/// Routed-relay retention (audit Nov 2026: nothing ever removed a relay —
/// the client's set grew for the process lifetime, sockets/fds/timers and
/// all). Routed relays idle for over ROUTED_IDLE are evicted at the next
/// routed call, the set is capped at ROUTED_CAP (oldest use first), and
/// session teardown sweeps them all. A routed live sub on an evicted relay
/// goes quiet until the next re-arm — the price of bounded fds.
const ROUTED_IDLE: Duration = Duration::from_secs(3600);
const ROUTED_CAP: usize = 60;

/// The session identity the pool answers NIP-42 AUTH challenges with.
///
/// NIP-78 (Sep 2026): relays SHOULD serve kinds 78/30078 only to the
/// authenticated owner, so a challenge must be answered AS THE OWNER's
/// key. A throwaway identity would authenticate and still gain nothing.
/// The identity is attached at session activation and cleared at logout;
/// a challenge arriving with no session fails, as it always has.
#[derive(Clone, Default)]
struct PoolIdentity(Arc<RwLock<Option<Signer>>>);

impl PoolIdentity {
    fn set(&self, signer: Signer) {
        *self.0.write().unwrap() = Some(signer);
    }

    fn clear(&self) {
        *self.0.write().unwrap() = None;
    }

    fn get(&self) -> Option<Signer> {
        self.0.read().unwrap().clone()
    }
}

/// The pool's NIP-42 authenticator over the live session identity. The
/// client captures the authenticator Arc at build time and hands the SAME
/// Arc to every relay added later, so the identity inside the lock can
/// change per session (or vanish) without touching the client.
struct PoolAuthenticator(PoolIdentity);

impl std::fmt::Debug for PoolAuthenticator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The identity (keys) is not Debug by design; never print it.
        f.write_str("PoolAuthenticator")
    }
}

impl Authenticator for PoolAuthenticator {
    // The SDK's `BoxedFuture` alias is crate-private; this is the same
    // type spelled out (Pin<Box<dyn Future + Send>>).
    fn make_auth_event<'a>(
        &'a self,
        relay_url: &'a RelayUrl,
        challenge: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Event, SdkError>> + Send + 'a>> {
        Box::pin(async move {
            let Some(signer) = self.0.get() else {
                return Err(SdkError::other(
                    "no session; not answering AUTH challenge",
                ));
            };
            // NIP-42: kind 22242, ["relay", url], ["challenge", challenge],
            // empty content, signed by the session key. A bunker signer
            // round-trips each challenge through the bunker app (the
            // owner-approved design); local keys sign in-process.
            let pk = signer
                .public_key()
                .await
                .map_err(|e| SdkError::other(e.to_string()))?;
            let unsigned = ClientAuthentication::new(challenge, relay_url.clone())
                .finalize_unsigned(pk);
            signer
                .sign_event(unsigned)
                .await
                .map_err(|e| SdkError::other(e.to_string()))
        })
    }
}

pub struct Pool {
    client: Client,
    /// The screening transport every non-user relay dials through
    /// (socks.rs). Held for the pool's lifetime; dropping it stops the
    /// listener. None only in tests that never connect.
    screening: Option<crate::socks::ScreeningSocks>,
    pub store: Store,
    identity: PoolIdentity,
    /// Relays added for ROUTED reads (url -> last routed use), evicted when
    /// idle, capped, and swept at session teardown (ROUTED_IDLE/ROUTED_CAP).
    routed: Mutex<HashMap<String, Instant>>,
    /// The session's own read relays (indexers + the session's NIP-65), so
    /// set_reads/connect_reads retire reads the user dropped instead of
    /// draining them only on restart.
    reads: Mutex<BTreeSet<String>>,
    /// Relay urls already registered with WRITE capability (D36): the
    /// registration is an upsert-merge, so a relay that is also a read
    /// keeps both; tracked so publish doesn't re-add + re-connect per
    /// attempt. Targets always come from the caller's list, so a relay
    /// the user dropped simply stops being targeted.
    writes: Mutex<BTreeSet<String>>,
}

impl Pool {
    /// Direct client access for pool management (relay add/remove).
    pub fn client(&self) -> &Client {
        &self.client
    }

    pub async fn open() -> Result<Self, SdkError> {
        // M5 WP2: the screening transport. Every relay NOT in the
        // user-chosen set dials through it — resolution pinned
        // fail-closed to public unicast. If loopback won't bind there
        // is NO unpinned fallback: the pool refuses to exist.
        let screening = crate::socks::spawn()
            .await
            .map_err(|e| SdkError::other(format!("screening transport: {e}")))?;
        let socks_addr = screening.addr();
        let store = Store::open().await?;
        // No keys live in the client: NIP-42 AUTH challenges are answered
        // with the session identity (set_identity, below) — the owner's
        // key, the only one strict relays honor for kinds 78/30078
        // (NIP-78, Sep 2026). Signing never happens here; nothing else
        // reads the identity.
        let identity = PoolIdentity::default();
        let client = ClientBuilder::new()
            .database(store.database())
            .authenticator(PoolAuthenticator(identity.clone()))
            .proxy(Proxy::custom(move |url| {
                // User-entered relays dial direct (the exemption is BY
                // NAME and remote data can never join it — net_guard);
                // everything else rides the screening transport.
                if crate::net_guard::user_chosen_relay(url.as_str()) {
                    None
                } else {
                    Some(socks_addr)
                }
            }))
            .build();
        // The house indexers are constants the app chose — same trust
        // class as user entries; they dial direct, as they always have.
        for indexer in INDEXERS {
            if let Ok(parsed) = url::Url::parse(indexer)
                && let Some(host) = parsed.host_str() {
                    crate::net_guard::allow_direct_relay(host);
            }
        }
        Ok(Self {
            client,
            store,
            identity,
            routed: Mutex::new(HashMap::new()),
            reads: Mutex::new(BTreeSet::new()),
            writes: Mutex::new(BTreeSet::new()),
            screening: Some(screening),
        })
    }

    /// Attach the session identity: NIP-42 AUTH challenges are answered as
    /// this key. Replaces any previous identity (a session switch); a
    /// bunker identity round-trips each challenge through the bunker app.
    pub fn set_identity(&self, signer: Signer) {
        self.identity.set(signer);
    }

    /// Session gone: challenges stop being answered (never as a stale key).
    pub fn clear_identity(&self) {
        self.identity.clear();
    }

    /// Connect the read set. Write relays join at publish time.
    pub async fn connect_reads(&self, read_relays: Vec<String>) -> Result<(), SdkError> {
        self.set_reads(&read_relays).await;
        self.client.connect().await;
        Ok(())
    }

    /// Joins read relays to the pool and RETIRES tracked reads absent from
    /// the list — previously removed reads drained only on restart, and the
    /// set grew across accounts for the process lifetime (audit Nov 2026).
    /// The indexers are permanent members of the read set, so callers pass
    /// only the session's own reads.
    pub async fn set_reads(&self, own_reads: &[String]) {
        // The session's OWN reads are user-chosen: they dial direct (M5
        // WP2's exemption is by name, and this is where the names come
        // from). Retired reads lose the exemption with the relay.
        let retired_reads: Vec<String>;
        {
            let urls: Vec<String> = INDEXERS.iter().map(|s| s.to_string()).collect();
            let mut all = urls.clone();
            all.extend(own_reads.iter().cloned());
            let keep: HashSet<String> = all.into_iter().collect();
            let mut reads = self.reads.lock().unwrap();
            retired_reads = reads
                .iter()
                .filter(|u| !keep.contains(*u))
                .cloned()
                .collect();
            for u in &retired_reads {
                reads.remove(u);
            }
        }
        for url in &retired_reads {
            if let Ok(parsed) = url::Url::parse(url)
                && let Some(host) = parsed.host_str() {
                    crate::net_guard::disallow_direct_relay(host);
            }
            let _ = self.client.remove_relay(url).force().await;
        }
        let mut urls: Vec<String> = INDEXERS.iter().map(|s| s.to_string()).collect();
        urls.extend(own_reads.iter().cloned());
        for url in own_reads {
            if let Ok(parsed) = url::Url::parse(url)
                && let Some(host) = parsed.host_str() {
                    crate::net_guard::allow_direct_relay(host);
            }
        }
        for url in urls {
            self.reads.lock().unwrap().insert(url.clone());
            // Read-scoped capability; bad relay = skip.
            let _ = self
                .client
                .add_relay(url.clone())
                .capabilities(RelayCapabilities::READ)
                .await;
        }
    }

    /// One routed-read relay: add (read-scoped) and stamp use.
    async fn add_routed(&self, url: &str) {
        let _ = self
            .client
            .add_relay(url)
            .capabilities(RelayCapabilities::READ)
            .await;
        self.routed
            .lock()
            .unwrap()
            .insert(url.to_string(), Instant::now());
    }

    /// Idle/cap eviction of routed relays — bounds sockets, fds and timers
    /// within a session (the teardown sweep bounds them across sessions).
    async fn trim_routed(&self) {
        let victims: Vec<String> = {
            let mut map = self.routed.lock().unwrap();
            let now = Instant::now();
            map.retain(|_, at| now.duration_since(*at) < ROUTED_IDLE);
            if map.len() <= ROUTED_CAP {
                Vec::new()
            } else {
                let mut by_age: Vec<(String, Instant)> =
                    map.iter().map(|(u, t)| (u.clone(), *t)).collect();
                by_age.sort_by_key(|(_, t)| *t);
                let over = by_age
                    .into_iter()
                    .take(map.len() - ROUTED_CAP)
                    .map(|(u, _)| u)
                    .collect::<Vec<_>>();
                for u in &over {
                    map.remove(u);
                }
                over
            }
        };
        for url in victims {
            let _ = self.client.remove_relay(&url).force().await;
        }
    }

    /// Session teardown: every routed relay goes home, so the next login
    /// (any account) starts a clean route graph.
    pub async fn clear_routed(&self) {
        let urls: Vec<String> = {
            let mut map = self.routed.lock().unwrap();
            map.drain().map(|(u, _)| u).collect()
        };
        for url in urls {
            let _ = self.client.remove_relay(&url).force().await;
        }
    }

    /// Deadline-not-completeness read (pool.ts 'page' mode).
    pub async fn get(&self, filter: Filter) -> Result<BTreeSet<Event>, SdkError> {
        self.client
            .fetch_events(filter)
            .timeout(READ_BUDGET)
            .await
            // Client-level fetch: no single relay to attribute to.
            .map(|events| consume_and_filter(events, ""))
    }

    /// The session's connected read set (indexers + the NIP-65 reads).
    pub fn read_relays(&self) -> Vec<String> {
        self.reads.lock().unwrap().iter().cloned().collect()
    }

    /// Own contact list: fresh from relays, cached into the store.
    pub async fn follows(&self, me: PublicKey) -> Result<Vec<PublicKey>, SdkError> {
        // Fresh from relays (the SDK persists what it receives), then the
        // store's cached copy is parsed.
        let _ = self
            .get(Filter::new().kind(Kind::ContactList).author(me).limit(1))
            .await?;
        let cached = self.store.latest_by_kind(me, Kind::ContactList).await?;
        Ok(cached.map(|ev| ev.tags.public_keys().collect()).unwrap_or_default())
    }

    /// Own NIP-65 relay list, split into (read, write) — the shared parser.
    pub async fn nip65(&self, me: PublicKey) -> Result<(Vec<String>, Vec<String>), SdkError> {
        // Fresh from relays (the SDK persists what it receives), then the
        // store's cached copy is parsed.
        let _ = self
            .get(Filter::new().kind(Kind::RelayList).author(me).limit(1))
            .await?;
        let cached = self.store.latest_by_kind(me, Kind::RelayList).await?;
        let Some(ev) = cached else {
            return Ok((Vec::new(), Vec::new()));
        };
        let list = outbox::parse_relay_list(&ev);
        Ok((list.read, list.write))
    }

    // --- full outbox model (nip65.ts routeAuthorsToRelays + feeds.ts routeFor) ---

    /// Relay lists for a set of authors: store-first (the client's database
    /// is this store, so everything ever seen is cached), missing ones
    /// fetched from the indexers in one deadline-bounded, author-chunked
    /// query per 200 and saved. Authors with no list anywhere stay absent —
    /// routing sends them to the fallback. A present-but-stale list is
    /// served as-is for now (no background refresher yet — that lands with
    /// the seen-on memory slice).
    pub async fn relay_lists(&self, authors: &[PublicKey]) -> HashMap<String, RelayList> {
        let mut out: HashMap<String, RelayList> = HashMap::new();
        let mut missing: Vec<PublicKey> = Vec::new();
        // Store-side lookups batched: one query per 200 authors (the
        // per-author cursor limit(1) IS the newest list), not one
        // sequential LMDB round trip per follow.
        if let Ok(events) = self.store.relay_lists(authors).await {
            for ev in &events {
                let list = Self::routed_list(ev);
                if !list.is_empty() {
                    out.insert(ev.pubkey.to_string(), list);
                }
            }
        }
        for pk in authors {
            if !out.contains_key(&pk.to_string()) {
                missing.push(*pk);
            }
        }
        for chunk in outbox::chunk(&missing, outbox::MAX_AUTHORS_PER_FILTER) {
            // Chunk is non-empty by construction: NIP-01, never send [].
            let filter = Filter::new()
                .kind(Kind::RelayList)
                .authors(chunk)
                .limit(3000);
            if let Ok(events) = self.get(filter).await {
                for ev in &events {
                    // (no explicit save: the SDK persists what it receives)
                    let list = Self::routed_list(ev);
                    if !list.is_empty() {
                        out.insert(ev.pubkey.to_string(), list);
                    }
                }
            }
        }
        out
    }

    /// A follow's parsed relay list, screened for ROUTED use
    /// (outbox::routable_relay): wss only, public IP literals only. A list
    /// left empty by the screen reads as "no list" — the author rides the
    /// indexers with the listless, never a dialed private host.
    fn routed_list(ev: &Event) -> RelayList {
        let mut list = outbox::parse_relay_list(ev);
        list.read.retain(|u| outbox::routable_relay(u));
        list.write.retain(|u| outbox::routable_relay(u));
        list
    }

    /// Fan a route out into per-relay, author-chunked deadline queries and
    /// merge (feeds.ts fetchRoutedPage: limit*2 per shard, read-dead relays
    /// skipped at query time, mergeNewest → the BTreeSet's newest-first
    /// ordering). Fetched events cache on arrival (client db = store).
    async fn fetch_route(
        &self,
        route: &Route,
        kinds: &[Kind],
        since: Option<Timestamp>,
        until: Option<Timestamp>,
        limit: usize,
    ) -> BTreeSet<Event> {
        let mut queries = Vec::new();
        // The client reference copies into every timed shard future.
        let client = &self.client;
        self.trim_routed().await;
        for (url, author_set) in route {
            // Bad relay = skip; read-scoped capability (add_relay is
            // idempotent — the pool rejects un-added urls at REQ time).
            // The route itself is already screened (relay_lists), this is
            // the belt to that suspenders.
            if !outbox::routable_relay(url.as_str()) {
                continue;
            }
            // The mid-session shard skip (feeds.ts fetchRoutedPage): a
            // relay we've LEARNED is read-dead gets none of this query's
            // budget.
            if relay_latency::is_read_dead(url.as_str()) {
                continue;
            }
            self.add_routed(url.as_str()).await;
            // Adaptive per-relay budget (relay-latency.ts relayBudget; the
            // knobs are pool.ts's caps): a profiled-empty relay bails fast
            // (floor), a rich-but-truncating one earns rope toward the
            // ceiling, unknown relays get the default.
            let budget = relay_latency::budget(url.as_str(), PAGE_BUDGET, READ_BUDGET, CEILING_BUDGET);
            let authors: Vec<String> = author_set.iter().cloned().collect();
            for shard in outbox::chunk(&authors, outbox::MAX_AUTHORS_PER_FILTER) {
                let pks: Vec<PublicKey> = shard
                    .iter()
                    .filter_map(|a| PublicKey::from_str(a).ok())
                    .collect();
                if pks.is_empty() {
                    continue;
                }
                let mut filter = Filter::new()
                    .kinds(kinds.to_vec())
                    .authors(pks)
                    .limit(limit * 2);
                if let Some(s) = since {
                    filter = filter.since(s);
                }
                if let Some(u) = until {
                    filter = filter.until(u);
                }
                // ONE relay per query, manually targeted — the fan-out's
                // whole point. fetch_events(filter) without the target is
                // a client-level req that went to EVERY read relay per
                // shard (the routing was silently undone); manual targets
                // also give per-shard attribution for the latency profile
                // and seen-on memory.
                let shard_url = url.as_str().to_string();
                queries.push(async move {
                    let started = std::time::Instant::now();
                    let res = client
                        .fetch_events(ReqTarget::manual(vec![(
                            shard_url.as_str(),
                            vec![filter],
                        )]))
                        .timeout(budget)
                        .into_future()
                        .await;
                    (shard_url, budget, started.elapsed(), res)
                });
            }
        }
        let results = futures_util::future::join_all(queries).await;
        let mut merged: BTreeSet<Event> = BTreeSet::new();
        for (url, budget, elapsed, res) in results {
            // `truncated` = rode to the hard cap while (evidently) still
            // delivering — TS's finish()-on-timer flag, read off the clock
            // (nostr-sdk merges internally; the EOSE-quiet tail is not
            // observable, so ms is time-to-complete, a slightly LOOSER
            // measure than pool.ts's time-to-last-event).
            let truncated = elapsed >= budget;
            let events = res.unwrap_or_default();
            relay_latency::record(&url, elapsed.as_millis() as u64, truncated, events.len());
            for ev in &events {
                seen::record(&ev.pubkey, &[url.as_str()]);
                // Author-keyed relay hints (WS1, RelayHintStore.kt):
                // provenance + e/p-tag relay urls, feeding the
                // no-kind-10002 routing fallback (get_routed /
                // subscribe_routed seed their route from these).
                hints::observe(ev, url.as_str());
            }
            merged.extend(consume_and_filter(events, url.as_str()));
        }
        merged
    }

    /// The `pool.get(urls, filter, maxWait)` port (feeds.ts resolveEvent /
    /// fetchEventsByIds): a targeted race against EXPLICITLY listed relays
    /// — the single-event fetch path. Each listed relay runs its own
    /// query with its own adaptive budget, so latency attribution and
    /// seen-on recording stay exact (the fan-out discipline, one relay
    /// per query); read-dead relays are dropped from the list before
    /// spending a round trip on them. Read-dead here covers learned
    /// denials/blasters only; an unprofiled relay races normally.
    pub async fn get_from(&self, urls: &[String], filter: &Filter) -> BTreeSet<Event> {
        let mut queries = Vec::new();
        let client = &self.client;
        for url in urls {
            // Same screen + read-scoped add as fetch_route (an un-added
            // url is rejected at REQ time).
            if !outbox::routable_relay(url) || relay_latency::is_read_dead(url) {
                continue;
            }
            self.add_routed(url).await;
            let budget = relay_latency::budget(url, PAGE_BUDGET, READ_BUDGET, CEILING_BUDGET);
            let shard_url = url.clone();
            let filter = filter.clone();
            queries.push(async move {
                let started = std::time::Instant::now();
                let res = client
                    .fetch_events(ReqTarget::manual(vec![(shard_url.as_str(), vec![filter])]))
                    .timeout(budget)
                    .into_future()
                    .await;
                (shard_url, budget, started.elapsed(), res)
            });
        }
        let results = futures_util::future::join_all(queries).await;
        let mut merged: BTreeSet<Event> = BTreeSet::new();
        for (url, budget, elapsed, res) in results {
            // `truncated` = rode to the hard cap while (evidently) still
            // delivering — TS's finish()-on-timer flag, read off the clock
            // (nostr-sdk merges internally; the EOSE-quiet tail is not
            // observable, so ms is time-to-complete, a slightly LOOSER
            // measure than pool.ts's time-to-last-event).
            let truncated = elapsed >= budget;
            let events = res.unwrap_or_default();
            // The latency profile measures DELIVERY (the raw count, the
            // tombstone/expiry filtering below is not the relay's fault).
            relay_latency::record(&url, elapsed.as_millis() as u64, truncated, events.len());
            for ev in &events {
                seen::record(&ev.pubkey, &[url.as_str()]);
                // Same hint feed as fetch_route (WS1).
                hints::observe(ev, url.as_str());
            }
            merged.extend(consume_and_filter(events, url.as_str()));
        }
        merged
    }

    /// One paged read over the OUTBOX: route authors to the relays THEY
    /// write to (set-cover at 70 relays, 2x redundancy per author, orphan
    /// recovery), then query each relay with its author shard.
    pub async fn get_routed(
        &self,
        kinds: Vec<Kind>,
        authors: &[PublicKey],
        since: Option<Timestamp>,
        until: Option<Timestamp>,
        limit: usize,
    ) -> BTreeSet<Event> {
        // NIP-01: an empty list can never match — and routing nobody is
        // nothing to do.
        if authors.is_empty() {
            return Default::default();
        }
        let keys: Vec<String> = authors.iter().map(|p| p.to_string()).collect();
        let lists = extended_cover_seeded(hint_seeded_lists(self.relay_lists(authors).await, authors), authors);
        let fallback: Vec<String> = INDEXERS.iter().map(|s| s.to_string()).collect();
        // relay_score = the learned quality profile (relay-latency.ts
        // relayQuality): known-empty relays deprioritized (0.15), never
        // picked over live ones, still there for orphans.
        let route = outbox::route(&lists, &keys, &fallback, relay_latency::quality);
        self.fetch_route(&route, &kinds, since, until, limit).await
    }

    /// Subscribe the live bell over the OUTBOX: the same routing as
    /// get_routed, one subscription id spanning every relay+shard pair.
    /// Events arrive through the client's shared notification stream,
    /// unchanged. The caller keeps using the main pool for its own
    /// me-scoped filters (mentions/deletions read from the inbox set).
    pub async fn subscribe_routed(
        &self,
        kinds: Vec<Kind>,
        authors: &[PublicKey],
        since: Option<Timestamp>,
    ) -> Result<Output<SubscriptionId>, SdkError> {
        if authors.is_empty() {
            return Err(SdkError::other("no authors to subscribe"));
        }
        let keys: Vec<String> = authors.iter().map(|p| p.to_string()).collect();
        let lists = extended_cover_seeded(hint_seeded_lists(self.relay_lists(authors).await, authors), authors);
        let fallback: Vec<String> = INDEXERS.iter().map(|s| s.to_string()).collect();
        // Same learned quality as get_routed.
        let route = outbox::route(&lists, &keys, &fallback, relay_latency::quality);
        let mut targets: Vec<(&str, Vec<Filter>)> = Vec::new();
        self.trim_routed().await;
        for (url, author_set) in &route {
            // Same screen as fetch_route (defense in depth); the
            // mid-session shard skip drops read-dead relays here too —
            // the live bell stops paying for dead sockets (feeds.ts).
            if !outbox::routable_relay(url.as_str()) || relay_latency::is_read_dead(url.as_str())
            {
                continue;
            }
            self.add_routed(url.as_str()).await;
            let authors: Vec<String> = author_set.iter().cloned().collect();
            for shard in outbox::chunk(&authors, outbox::MAX_AUTHORS_PER_FILTER) {
                let pks: Vec<PublicKey> = shard
                    .iter()
                    .filter_map(|a| PublicKey::from_str(a).ok())
                    .collect();
                if pks.is_empty() {
                    continue;
                }
                let mut filter = Filter::new().kinds(kinds.clone()).authors(pks);
                if let Some(s) = since {
                    filter = filter.since(s);
                }
                targets.push((url.as_str(), vec![filter]));
            }
        }
        self.client.subscribe(ReqTarget::manual(targets)).await
    }

    /// Subscribe the VIEWPORT engagement fan (WS2, viewport.rs): one
    /// subscription id spanning every `#e` filter shard, kinds fixed by
    /// viewport::ENGAGEMENT_KINDS. Engagement authors are ARBITRARY (anyone
    /// can react), so outbox author-routing doesn't apply — the filters ride
    /// the connected read set (the same targets the main bell's filters
    /// use). Events arrive through the client's shared notification stream;
    /// the manager's viewport task filters by the returned subscription id.
    /// Chunked at the D39 e-tag ceiling (viewport.rs chunks_for_ids).
    pub async fn subscribe_for_ids(
        &self,
        kinds: Vec<Kind>,
        ids: &[EventId],
        since: Option<Timestamp>,
    ) -> Result<Output<SubscriptionId>, SdkError> {
        if ids.is_empty() {
            return Err(SdkError::other("no ids to subscribe"));
        }
        let mut filters = Vec::new();
        for shard in crate::viewport::chunks_for_ids(ids) {
            let mut filter = Filter::new().kinds(kinds.clone()).events(shard);
            if let Some(s) = since {
                filter = filter.since(s);
            }
            filters.push(filter);
        }
        self.client.subscribe(filters).await
    }

    /// Publish to the write set (own write relays, fallback indexers) and
    /// report per-relay outcomes (D36): the SDK's per-relay Output is
    /// PRESERVED — the old `let _ = ...?; Ok(())` discarded it, which is
    /// how a total publish failure looked like success and notes died
    /// silently in the local store. Decision = ≥1 relay ACKed (OK true).
    pub async fn publish(&self, event: &Event, write_relays: &[String]) -> PublishReport {
        let targets: Vec<String> = if write_relays.is_empty() {
            INDEXERS.iter().map(|s| s.to_string()).collect()
        } else {
            write_relays.to_vec()
        };
        // D36: WRITE relays join at publish time — this was the documented
        // contract, but nothing registered them anymore and nostr-sdk 0.45
        // gates every send on per-relay capability ("write actions are
        // disabled", the silent killer that made every publish fail
        // after the Nov 3 re-lock). add_relay UPSELLS capabilities (merge,
        // not replace), so a relay that is also a read keeps both. Connect
        // only when something new joined; sends to already-connected
        // relays are unaffected.
        let new_targets: Vec<String> = {
            let reg = self.writes.lock().unwrap();
            targets
                .iter()
                .filter(|u| !reg.contains(*u))
                .cloned()
                .collect()
        };
        if !new_targets.is_empty() {
            for url in &new_targets {
                // Own write relays are user-chosen (NIP-65): dial direct.
                if let Ok(parsed) = url::Url::parse(url)
                    && let Some(host) = parsed.host_str() {
                        crate::net_guard::allow_direct_relay(host);
                }
                let _ = self
                    .client
                    .add_relay(url.clone())
                    .capabilities(RelayCapabilities::WRITE)
                    .await;
                self.writes.lock().unwrap().insert(url.clone());
            }
            self.client.connect().await;
        }
        let short = &event.id.to_string()[..8];
        let mut report = PublishReport::default();
        match self.client.send_event(event).to(targets.clone()).await {
            Ok(output) => {
                for (url, status) in output.success {
                    let u = url.to_string();
                    if matches!(status, EventSendStatus::Ack(_)) {
                        report.ok.push(u);
                    } else {
                        // `Sent` (no OK waited) never occurs under our
                        // default wait-for-OK; if it ever does, treat it
                        // as unaccepted.
                        report.failed.push((u, "sent, no OK".into()));
                    }
                }
                for (url, msg) in output.failed {
                    report.failed.push((url.to_string(), clean_reason(&msg)));
                }
            }
            // Top-level failure (no relay reported anything at all).
            Err(e) => {
                let reason = clean_reason(&e.to_string());
                for t in &targets {
                    report.failed.push((t.clone(), reason.clone()));
                }
            }
        }
        for r in &report.ok {
            eprintln!("[core] publish {short}: ok {r}");
        }
        for (r, m) in &report.failed {
            eprintln!("[core] publish {short}: fail {r} ({m})");
        }
        eprintln!(
            "[core] publish {short}: {} accepted, {} failed",
            report.ok.len(),
            report.failed.len()
        );
        report
    }
}

/// Per-relay publish report (D36): the SDK's `Output<EventId,
/// EventSendStatus, String>` preserved instead of discarded. `Ack` (the
/// relay's OK true) is the only acceptance signal; OK false, auth walls,
/// timeouts and dead sockets all land in `failed` with their reason.
#[derive(Debug, Clone, Default)]
pub struct PublishReport {
    /// Relays that returned OK true (EventSendStatus::Ack).
    pub ok: Vec<String>,
    /// (relay, reason) for every relay that did not accept. Reasons are
    /// relay-supplied hostile input: control chars stripped, length
    /// capped (clean_reason) before they reach our logs.
    pub failed: Vec<(String, String)>,
}

impl PublishReport {
    /// The publish decision: at least one relay accepted the event.
    pub fn accepted(&self) -> bool {
        !self.ok.is_empty()
    }
}

/// Relay-supplied text is hostile input: strip control chars (a message
/// carrying `\n` could forge log lines) and cap the length.
fn clean_reason(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).take(120).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Any 32-byte value; a throwaway test key, never an identity.
    const TEST_HEX: &str = "e1d4a5b33a9d2f0c8b7e6f5a4d3c2b1a0918273645f4e3d2c1b0a99887766554";

    fn auth() -> PoolAuthenticator {
        PoolAuthenticator(PoolIdentity::default())
    }

    /// With a session attached, a challenge yields a valid NIP-42 event:
    /// kind 22242, signed by the identity, relay + challenge tagged,
    /// empty content. Without one (and after clear), nothing is signed.
    #[tokio::test]
    async fn auth_event_follows_nip42_and_needs_an_identity() {
        let url: RelayUrl = "wss://relay.example".parse().unwrap();
        let a = auth();

        // No session: the challenge stays unanswered.
        assert!(a.make_auth_event(&url, "c1").await.is_err());

        let keys = crate::signer::parse_local_secret(TEST_HEX).unwrap();
        a.0.set(Signer::Local(keys.clone()));
        let ev = a.make_auth_event(&url, "c1").await.unwrap();
        assert_eq!(ev.kind, Kind::Authentication);
        assert_eq!(ev.pubkey, keys.public_key());
        assert_eq!(ev.content, "");
        let tags = ev.tags.clone().to_vec();
        let tag_val = |name: &str| {
            tags.iter()
                .find(|t| t.as_slice().first().map(String::as_str) == Some(name))
                .and_then(|t| t.as_slice().get(1).cloned())
        };
        assert_eq!(tag_val("relay").as_deref(), Some("wss://relay.example"));
        assert_eq!(tag_val("challenge").as_deref(), Some("c1"));

        // Logout: the identity is gone, challenges fail again.
        a.0.clear();
        assert!(a.make_auth_event(&url, "c2").await.is_err());
    }

    /// Live-network probe (run: cargo test -p satori-core -- --ignored --nocapture).
    /// Proves: indexers connect → kind:10002 discovery → store roundtrip →
    /// split parsing. The settings pane depends on exactly this chain.
    #[tokio::test]
    #[ignore = "network"]
    async fn nip65_discovery_end_to_end() {
        let pool = Pool::open().await.unwrap();
        pool.connect_reads(Vec::new()).await.ok();

        // Any relay list off the indexers proves discovery.
        let filter = Filter::new().kind(Kind::RelayList).limit(3);
        let events = pool.get(filter).await.expect("fetch");
        println!("discovered {} relay list(s)", events.len());
        assert!(!events.is_empty(), "indexers returned no kind:10002 events");

        let ev = events.iter().next().unwrap();
        let r_tags = ev
            .tags
            .clone()
            .to_vec()
            .iter()
            .filter(|t| t.as_slice().first().map(String::as_str) == Some("r"))
            .count();
        println!("author {} has {} r-tags", ev.pubkey, r_tags);
        assert!(r_tags > 0);

        // Store roundtrip: the exact query nip65() runs.
        pool.store.save(ev).await.unwrap();
        let cached = pool
            .store
            .latest_by_kind(ev.pubkey, Kind::RelayList)
            .await
            .unwrap();
        assert!(cached.is_some(), "latest_by_kind lost the stored relay list");

        let (read, write) = pool.nip65(ev.pubkey).await.unwrap();
        println!("nip65 split: {} read, {} write", read.len(), write.len());
        assert!(!read.is_empty() || !write.is_empty());
    }
}
