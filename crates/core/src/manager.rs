//! Core: owns the tokio runtime and the active session — the seam between the
//! GTK UI and all I/O. UI code submits commands here; results flow back over
//! executor-agnostic channels (`tokio::sync`) awaited from the GLib main
//! context (DESIGN.md §3.2). The web app's server-session machinery
//! (`src/session.ts`) collapses to this single-user handle.

use std::collections::{HashMap, HashSet, VecDeque};
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use nostr::prelude::*;
use nostr_connect::prelude::*;
use nostr_sdk::client::Output;
use tokio::sync::mpsc;

use crate::blocktime::Blocktime;
use crate::error::{LoginError, Result};
use crate::nip::nip78;
use crate::deletions;
use crate::hints;
use crate::nip40;
use crate::outbox;
use crate::pool::{Pool, INDEXERS};
use crate::relay_latency;
use crate::seen;
use crate::secrets;
use crate::session::{self, Session, SessionMode};
use crate::signer::{self, Signer};
use crate::wallet::{self, Wallet, WalletEvent};

/// How long to wait for the remote signer to approve a connect request.
const LOGIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// Feed page size; the bootstrap fetch keeps depth for "view older".
const PAGE: usize = 40;
/// How deep one older-page top-up reaches into the relays (the web app's
/// fetchRoutedPage asked limit*2 per author shard — same spirit: each round
/// trip should feed several pages before the next one).
const TOPUP_DEPTH: usize = 200;
const BOOTSTRAP_DEPTH: usize = 200;



/// Progress events streamed back to the login UI.
#[derive(Debug, Clone)]
pub enum ConnectEvent {
    /// Request sent; the user must approve in their bunker app.
    Waiting,
    /// An out-of-band auth_url approval (NIP-46); open it in a browser.
    AuthUrl(String),
    /// The nostrconnect:// URI to advertise (QR in the UI) — client-initiated
    /// NIP-46; the signer scans it and approves.
    Uri(String),
    Approved(PublicKey),
    Failed(String),
}

/// The channel login flows resolve through. Tokio's sync primitives are
/// executor-agnostic, so the GLib main context can await them directly.
pub type ConnectRx = mpsc::UnboundedReceiver<ConnectEvent>;

/// One zap's result stream: the events for the view that started (or
/// retried) the payment. The same events also flow on the wallet broadcast
/// (`subscribe_wallet`) — a view's channel dies with the view, the feed's
/// bolt glyphs must not.
pub type WalletResultRx = mpsc::UnboundedReceiver<WalletEvent>;

/// Zap-flow outcome: the error IS the event (a failed zap is a user-facing
/// message, not a crash).
type ZapFlow = std::result::Result<(), WalletEvent>;

/// Stream of feed/write results for the UI.
#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum FeedEvent {
    Loaded(FeedPage),
    /// Older page + has-more.
    Older(FeedPage, bool),
    Replies(Vec<Event>, Vec<Profile>),
    /// Notifications (replies + mentions; reactions stay off by default).
    Notifications(Vec<Event>, Vec<Profile>),
    /// Whether the bell should light (unread past high-water).
    NotifDot(bool),
    /// NIP-50 search results (notes).
    Search(Vec<Event>, Vec<Profile>),
    /// One event by id (repost target resolution), + author profile.
    One(Option<Event>, Option<Profile>),
    /// Resolved reply parents for the timeline's context whisper: parent
    /// event id → author + snippet. Misses resolve on a later ask.
    Parents(std::collections::HashMap<String, ParentNote>),
    /// Poll tallies: (option id, count) over each voter's latest ballot.
    PollVotes(Vec<(String, u32)>),
    /// Comments on a target, oldest first + profiles.
    Comments(Vec<Event>, Vec<Profile>),
    /// Reply-presence faces: (note id, up to 3 replier pubkeys).
    Faces(Vec<(EventId, Vec<PublicKey>)>),
    /// Profiles resolved reactively (cards patch themselves).
    Profiles(Vec<Profile>),
    /// A backup export payload (raw signed events JSON).
    BackupJson(String),
    /// Your kind:10063 Blossom media-server list (settings pane).
    MediaServers(Vec<String>),
    BootstrapDone,
    Failed(String),
}

pub type FeedRx = mpsc::UnboundedReceiver<FeedEvent>;

// --- Notification tier + receipts (issue #2 WS4) --------------------------------

/// One notification the WoT tier suppressed — a receipt, never a silent
/// void: the bell's "N hidden, see why" surface lists these with the
/// verdict and reason, and a per-item "show anyway" exemption.
/// Serializes for the D48 sidecar: receipts survive restarts (a receipt
/// that evaporated at every launch was a weak receipt).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SuppressedNotif {
    /// The suppressed event itself (the surface renders author + action).
    pub event: Event,
    /// The verdict that gated it ("outside your network").
    pub reason: String,
}

static SUPPRESSED: Mutex<Vec<SuppressedNotif>> = Mutex::new(Vec::new());

// --- Receipts persistence (D48): the suppressed ledger is the audit
// trail of the app's only auto-actions; it survives restarts. Two
// effects: the "N hidden" surface is populated from the first frame,
// and — the load-bearing part — `split_wot_tier` re-receipts any
// candidate already in the ledger, so a verdict that EXPIRED (the
// velocity window) while the event sat in the store doesn't resurrect
// old spam at boot. Same discipline as the other sidecars.

/// Newest receipts kept on disk (the bell's queries are 200-limited —
/// anything older can't re-candidate anyway).
const SUPPRESSED_CAP: usize = 200;
const SUPPRESSED_FLUSH_SECS: u64 = 10;
static SUPPRESSED_DIRTY: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
static SUPPRESSED_FLUSHER: std::sync::OnceLock<()> = std::sync::OnceLock::new();
static SUPPRESSED_LOADED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

fn suppressed_dirty() {
    SUPPRESSED_DIRTY.store(true, std::sync::atomic::Ordering::Relaxed);
    SUPPRESSED_FLUSHER.get_or_init(|| {
        std::thread::Builder::new()
            .name("suppressed-flush".into())
            .spawn(|| loop {
                std::thread::park_timeout(std::time::Duration::from_secs(
                    SUPPRESSED_FLUSH_SECS,
                ));
                if SUPPRESSED_DIRTY.swap(false, std::sync::atomic::Ordering::Relaxed) {
                    write_suppressed_disk();
                }
            })
            .ok();
    });
}

fn write_suppressed_disk() {
    let mut items = SUPPRESSED.lock().unwrap().clone();
    items.sort_by_key(|s| std::cmp::Reverse(s.event.created_at.as_secs()));
    items.truncate(SUPPRESSED_CAP);
    let arr: Vec<serde_json::Value> = items
        .iter()
        .map(|s| serde_json::json!({ "reason": s.reason, "event": s.event }))
        .collect();
    let path = crate::config::state_file(crate::config::files::SUPPRESSED);
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    let tmp = path.with_extension(format!("tmp-{}-{nanos}", std::process::id()));
    let body = serde_json::Value::Array(arr).to_string();
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

/// Merge the persisted receipts into the live store (bootstrap arm;
/// once per process — later runs REPLACE the store with their
/// re-derivation, and the receipted-gate keeps the merged ids in it).
fn load_suppressed_disk() {
    if SUPPRESSED_LOADED.swap(true, std::sync::atomic::Ordering::Relaxed) {
        return;
    }
    let Ok(raw) =
        std::fs::read_to_string(crate::config::state_file(crate::config::files::SUPPRESSED))
    else {
        return;
    };
    let Ok(arr) = serde_json::from_str::<serde_json::Value>(&raw) else {
        return;
    };
    let mut held = SUPPRESSED.lock().unwrap();
    for e in arr.as_array().unwrap_or(&Vec::new()) {
        let (Ok(event), Some(reason)) = (
            serde_json::from_value::<Event>(e.get("event").cloned().unwrap_or_default()),
            e.get("reason").and_then(|x| x.as_str()).map(String::from),
        ) else {
            continue;
        };
        if held.iter().any(|s| s.event.id == event.id) {
            continue;
        }
        held.push(SuppressedNotif { event, reason });
    }
    held.sort_by_key(|s| std::cmp::Reverse(s.event.created_at.as_secs()));
    held.truncate(SUPPRESSED_CAP);
}
/// One-session "show anyway" exemptions (pubkey hex): the user chose to
/// see an author's suppressed notifications — the tier stops gating them
/// until sign-out. NOT a pref (the posture: the exemption is a conscious
/// per-session act, visible in the receipts it empties).
static NOTIF_EXEMPT: std::sync::LazyLock<Mutex<HashSet<String>>> =
    std::sync::LazyLock::new(|| Mutex::new(HashSet::new()));

/// The notification tier's pref (`notif_wot_tier` in prefs.json, default
/// ON per the issue posture: the only auto-actions live in notifications,
/// and they leave receipts).
fn notif_tier_enabled() -> bool {
    crate::config::prefs()
        .and_then(|v| v.get("notif_wot_tier").and_then(|b| b.as_bool()))
        .unwrap_or(true)
}

/// Apply the tier to one page: reactions/reposts (kinds 6/7 — engagement
/// noise, not speech) AND kind-1 replies to the user's own notes (D43's
/// anti-bot amendment — bot replies are the cheapest notification attack)
/// from authors the graph KNOWS are NotInNetwork are pulled out as
/// receipts. Mentions/zaps pass; and the second D43 path: an Unknown
/// author whose replies hit the reply-velocity verdict (rate.rs) is
/// suppressed into the receipts too — 1–4 replies pass untouched, the
/// counter is fed only by DELIVERED replies, and exempted authors pass
/// everything (the exemption is a conscious per-session act).
///
/// `my_notes` is the user's recent note ids — what makes a kind-1 a REPLY
/// (an `e` tag at one of them) rather than a mention. `count_velocity`
/// feeds the rate counter: the final-union split sets it; the cached-phase
/// split leaves it false so overlapping phases don't double-count (the
/// cached phase still wears the flood GATE via `reply_flooded` — the
/// phase-equality rule).
fn split_wot_tier(
    notifs: Vec<Event>,
    my_notes: &HashSet<EventId>,
    count_velocity: bool,
) -> (Vec<Event>, Vec<SuppressedNotif>) {
    // Hoisted (audit fix): the pref read (one metadata syscall + Arc)
    // and the exempt-set lock were per EVENT — now per PAGE. The
    // receipted ledger snapshots too (D48): its ids re-suppress below.
    let tier_on = notif_tier_enabled();
    let exempt_set: HashSet<String> = NOTIF_EXEMPT.lock().unwrap().clone();
    let receipted: HashMap<String, String> = {
        let held = SUPPRESSED.lock().unwrap();
        held.iter()
            .map(|s| (s.event.id.to_string(), s.reason.clone()))
            .collect()
    };
    let mut kept = Vec::new();
    let mut suppressed = Vec::new();
    for ev in notifs {
        let kind = u16::from(ev.kind);
        let engagement = matches!(kind, 6 | 7);
        let reply = matches!(kind, 1 | 1111)
            && ev.tags.event_ids().any(|id| my_notes.contains(&id));
        // Show-anyway first: the conscious per-session act outranks
        // every auto-gate — including the dedup store door below
        // (otherwise the receipts strip's button lied for
        // duplicate-content receipts).
        if exempt_set.contains(&ev.pubkey.to_string()) {
            kept.push(ev);
            continue;
        }
        // The store door: the chokepoint stops a hidden spammer's
        // DELIVERIES, but the SDK already persisted their earlier
        // events — the cached phase reads those straight back. The
        // dedup ledger is the truth about who's hidden (D41's
        // "unreachable through any read path" made true here too).
        // Suppressed with a receipt, consistent with the tier.
        if crate::dedup::is_hidden(&ev.pubkey.to_string()) {
            suppressed.push(SuppressedNotif {
                reason: "duplicate-content filter".to_string(),
                event: ev,
            });
            continue;
        }
        if !(tier_on && (engagement || reply)) {
            kept.push(ev);
            continue;
        }
        // Receipt durability (D48): a verdict that expired (the
        // velocity window) while the event sat in the store must not
        // resurrect old spam on the first frame of a launch — once
        // receipted, still receipted. The show-anyway exemption above
        // is the per-session override; the tier switch below (`tier_on`)
        // is the feature-off state.
        if let Some(reason) = receipted.get(&ev.id.to_string()) {
            suppressed.push(SuppressedNotif {
                reason: reason.clone(),
                event: ev,
            });
            continue;
        }
        match crate::wot::verdict(&ev.pubkey) {
            // Known and outside: gated regardless of kind or velocity.
            crate::wot::Verdict::NotInNetwork => suppressed.push(SuppressedNotif {
                reason: "outside your network".to_string(),
                event: ev,
            }),
            // The D43 mule rule: Unknown + reply velocity. The check runs
            // on both phases; only the delivering phase feeds the counter.
            crate::wot::Verdict::Unknown if reply => {
                if crate::rate::reply_flooded(&ev.pubkey, ev.created_at.as_secs())
                    || (count_velocity
                        && !crate::rate::admit_reply(
                            &ev.pubkey,
                            ev.created_at.as_secs(),
                            &ev.id.to_string(),
                        ))
                {
                    suppressed.push(SuppressedNotif {
                        reason: crate::rate::flood_reason(),
                        event: ev,
                    });
                } else {
                    kept.push(ev);
                }
            }
            _ => kept.push(ev),
        }
    }
    (kept, suppressed)
}

/// What the write path reports back.
#[derive(Debug, Clone)]
pub enum PublishEvent {
    /// The signed event is held for the undo window; countdown starts.
    Held { token: u64, event: Event, hold_secs: u64 },
    /// The hold was undone; nothing was published.
    Undone { token: u64 },
    /// Published (or hold expired — the backstop committed).
    Committed { token: u64 },
    /// A Blossom upload finished (upload.rs): blob URL + the NIP-92 imeta tag.
    Uploaded { url: String, imeta: Vec<String> },
    /// A restore finished: n events re-signed + published.
    Restored(u32),
    Failed { token: u64, error: String },
}

pub type PublishRx = mpsc::UnboundedReceiver<PublishEvent>;

/// What the scheduling path reports back (schedule_note).
#[derive(Debug, Clone)]
pub enum ScheduleEvent {
    /// Held on disk; the sweep publishes it at `scheduled_at`.
    Scheduled { token: String, scheduled_at: u64 },
    /// Refused (cap reached, sign failure, logged out).
    Failed { error: String },
}

#[derive(Clone)]
struct Active {
    session: Session,
    signer: Signer,
    pool: Arc<Pool>,
    profiles: Arc<crate::profiles::ProfileService>,
    undo: crate::undo::UndoWindow,
    /// Own NIP-65 write relays.
    write_relays: Vec<String>,
    /// Own NIP-65 read relays (indexers are always on).
    read_relays: Vec<String>,
    follows: Vec<PublicKey>,
    /// Own pubkey, parsed once at session build. me() hands it out; it
    /// used to re-parse the session hex per call (26 call sites, some on
    /// hot paths) and expect-panicked if session.json held a corrupt
    /// pubkey — build_active now refuses the session instead.
    me: PublicKey,
}

impl Active {
    fn me(&self) -> PublicKey {
        self.me
    }
}

/// A rendered-ready feed page: notes plus resolved profiles.
#[derive(Debug, Clone)]
pub struct FeedPage {
    pub notes: Vec<Event>,
    pub profiles: Vec<Profile>,
}

/// A push signal off the live subscription (one persistent sub per session,
/// three filters). Live signaling, not the live timeline — nothing renders
/// until a view asks. Also carries a few out-of-band manager signals (the
/// NIP-78 login sync) that ride the same broadcast for want of a second one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Live {
    /// A reply or mention tagging me (#p) — light the bell.
    Mention,
    /// A fresh post from a follow — bump the timeline's new-notes pill.
    Post,
    /// NIP-78 app-data sync landed (login): remote prefs won — re-read.
    PrefsSynced,
    /// Engagement on a viewport note arrived live (WS2, viewport.rs): the
    /// event is already in the store (the SDK saves on receive) — the open
    /// feed re-reads its state and repaints.
    Engagement,
}

/// A reply's parent, for the timeline context whisper: author + a plain
/// one-liner from the parent's content.
#[derive(Debug, Clone)]
pub struct ParentNote {
    pub author: String,
    pub snippet: String,
}

/// Plain-text one-liner for previews: whitespace collapsed, `nostr:` refs
/// ellipsized, URLs dropped entirely (they never read as text — mangled
/// “https//…” tails in a whisper or quote preview were pure noise; links get
/// their own row/embed), capped at `cap` chars. Shared by the reply whisper
/// (load_parents) and quote embeds (content.rs embed_card).
pub fn plain_snippet(content: &str, cap: usize) -> String {
    let mut words: Vec<&str> = Vec::new();
    for w in content.split_whitespace() {
        if w.starts_with("nostr:") {
            words.push("…");
        } else if w.starts_with("https://") || w.starts_with("http://") {
            continue;
        } else {
            words.push(w);
        }
    }
    let mut s = words.join(" ");
    if s.chars().count() > cap {
        s = s.chars().take(cap).collect::<String>() + "…";
    }
    s
}

#[derive(Debug, Clone, Default)]
pub struct Profile {
    pub pubkey: String,
    pub name: String,
    pub picture: String,
    pub about: String,
    pub banner: String,
    /// NIP-05 address as self-asserted ("name@domain") — the profile page
    /// shows it, then verifies it out-of-band (verify_nip05).
    pub nip05: String,
    /// The lightning pointer, lud16 before lud06 (NIP-57's order) — the
    /// profile page's zap row (same field the zap request reads).
    pub lud: String,
    /// The banner's blurhash, from a kind-0 imeta tag whose url IS the
    /// banner (NIP-92, Oct 2026) — the header's placeholder while the
    /// bytes are in flight.
    pub banner_blurhash: Option<String>,
}

impl Profile {
    pub fn from_event(ev: &Event) -> Option<Self> {
        #[derive(serde::Deserialize)]
        struct RawMeta {
            name: Option<String>,
            display_name: Option<String>,
            picture: Option<String>,
            about: Option<String>,
            banner: Option<String>,
            nip05: Option<String>,
            lud16: Option<String>,
            lud06: Option<String>,
        }
        let raw: RawMeta = serde_json::from_str(&ev.content).ok()?;
        // NIP-92 (Oct 2026): a kind-0 MAY carry imeta describing its
        // picture and banner — a tag describes a field only when its url
        // matches exactly. We adopt the banner's blurhash (the header
        // placeholder); `dim` is moot under the cover-fit strip.
        let banner_blurhash = crate::nip::imeta::parse(ev)
            .into_iter()
            .find(|m| Some(m.url.as_str()) == raw.banner.as_deref())
            .and_then(|m| m.blurhash);
        Some(Self {
            pubkey: ev.pubkey.to_string(),
            name: raw.display_name.or(raw.name).unwrap_or_default(),
            picture: raw.picture.unwrap_or_default(),
            about: raw.about.unwrap_or_default(),
            banner: raw.banner.unwrap_or_default(),
            nip05: raw.nip05.unwrap_or_default(),
            lud: raw.lud16.or(raw.lud06).unwrap_or_default(),
            banner_blurhash,
        })
    }

    /// Display name fallback chain: name → short npub (render/util.ts style).
    pub fn display(&self) -> String {
        if self.name.is_empty() {
            let npub = self.pubkey.clone();
            format!("npub1…{}", &npub[npub.len().saturating_sub(6)..])
        } else {
            self.name.clone()
        }
    }
}

/// In-memory cap for the cross-session profile mirror (`profiles_mem`):
/// display data for mentions/search only — the durable copy is the
/// profile service's profiles.json (10k there). 5000 hydrated profiles
/// is far past anything a long session touches.
const PROFILES_MEM_CAP: usize = 5000;

/// The bounded profile mirror. A plain HashMap is insert-only, so every
/// unique pubkey seen (each feed page absorbs ~40) stayed for the process
/// lifetime — and it survived logout, too. Insertion-order eviction: the
/// oldest-absorbed profile goes first, which is exactly the stale half
/// of the cache.
struct ProfileMem {
    map: HashMap<String, Profile>,
    order: VecDeque<String>,
}

impl ProfileMem {
    fn new() -> Self {
        Self {
            map: HashMap::new(),
            order: VecDeque::new(),
        }
    }

    /// Absorb one profile. Overwrites don't re-push the order key (the
    /// entry keeps its place; re-pushing would turn the deque into a
    /// duplicate-riddled mess for zero benefit).
    fn insert(&mut self, p: Profile) {
        let key = p.pubkey.clone();
        if !self.map.contains_key(&key)
            && self.map.len() >= PROFILES_MEM_CAP
            && let Some(oldest) = self.order.pop_front()
        {
            self.map.remove(&oldest);
        }
        if !self.map.contains_key(&key) {
            self.order.push_back(key.clone());
        }
        self.map.insert(key, p);
    }

    fn get(&self, pk: &str) -> Option<&Profile> {
        self.map.get(pk)
    }

    fn values(&self) -> impl Iterator<Item = &Profile> {
        self.map.values()
    }

    fn clear(&mut self) {
        self.map.clear();
        self.order.clear();
    }
}

pub struct Core {
    rt: tokio::runtime::Runtime,
    /// Hold-state mirror (Held/Committed/Undone/Failed) for the shell's
    /// undo toast — the composer pops on Held, so the toast must outlive
    /// it. subscribe_hold().
    hold_tx: tokio::sync::broadcast::Sender<PublishEvent>,
    active: Mutex<Option<Active>>,
    pending: Mutex<Option<Arc<NostrConnect>>>,
    hold_seq: AtomicU64,
    /// Login epoch: bumped on every connect attempt and cancel; a
    /// handshake whose epoch has moved on drops itself instead of saving
    /// a session the UI (or a newer attempt) no longer expects — the
    /// core-side twin of the login view's generation guard.
    login_seq: AtomicU64,
    /// ONE pool for the process: the LMDB write lock must not survive a
    /// logout (a second env open on the same path deadlocks). The profile
    /// service's debouncer is session-scoped (Weak handle — it exits when
    /// the service drops), so each login builds its own.
    pool: Mutex<Option<Arc<Pool>>>,
    /// Own reactions: target event id (hex) → engaged.
    own_liked: Mutex<HashSet<String>>,
    /// Own reposts (NIP-18 kind 6/16) — same shape as own_liked.
    own_reposted: Mutex<HashSet<String>>,
    own_bookmarked: Mutex<HashSet<String>>,
    /// Synced composer drafts (D38): NIP-78 kind 30078 d="satori/drafts",
    /// the array nip44-encrypted — text + reply/quote context (ids; the
    /// full events live in the store) + the attachment imetas (v1.4; the
    /// blobs are on Blossom).
    own_drafts: Mutex<Vec<DraftEntry>>,
    /// Muted authors (pubkey hex) — NIP-51 kind:10000, content encrypted.
    muted: Mutex<HashSet<String>>,
    /// Own zaps: note id (hex) → zapped. The ledger (zaps.json) is the
    /// durable authority; this mirrors it for render, like own_liked.
    own_zapped: Mutex<HashSet<String>>,
    /// Tombstone hydration: the one-time store scan that seeds the
    /// deletions module with kind:5s that predate it (drop_deleted's
    /// doc). The module persists past this point; the flag just keeps
    /// the scan from repeating.
    tombstones_hydrated: std::sync::atomic::AtomicBool,
    /// The outbox drainer spawns once per process (D36), on the first
    /// bootstrap that has a write set; later logins are no-ops.
    outbox_started: std::sync::atomic::AtomicBool,
    /// The scheduled sweep spawns once per process (WS4), on the first
    /// bootstrap — same discipline as the outbox drainer.
    scheduled_started: std::sync::atomic::AtomicBool,
    /// The NIP-47 wallet handle (D20) — one per process, like the pool.
    wallet: Arc<Wallet>,
    /// Bitcoin timestamp→height service (blocktime, Phase 2 §4.4) — one
    /// per process; its table outlives sessions like the ledger.
    blocktime: Arc<Blocktime>,
    /// Resolved profiles (mentions/name display) — absorbed as they stream
    /// in. Bounded (`ProfileMem`): insert-only maps grow for the process
    /// lifetime otherwise, and this one survives logouts by design.
    profiles_mem: Mutex<ProfileMem>,
    /// Live undo holds: token → cancel signal.
    holds: Mutex<std::collections::HashMap<u64, tokio::sync::oneshot::Sender<()>>>,
    /// Push signals off the live subscription (shell bell, feed pills).
    live: tokio::sync::broadcast::Sender<Live>,
    /// The live sub starts once per process (bootstrap runs per surface).
    /// Whether the live subscription is armed (start_live). An Arc so the
    /// spawned task can re-arm it when the subscribe fails.
    live_on: Arc<std::sync::atomic::AtomicBool>,
    /// Identity epoch for the live sub: bumped on sign-out. A running
    /// live loop compares its captured epoch per event and tears down
    /// (unsubscribe + exit) on mismatch — the loop used to outlive its
    /// session, still filtering by the old account's pubkey and follows,
    /// while live_on true blocked the next login from arming its own.
    live_epoch: Arc<std::sync::atomic::AtomicU64>,
    /// Refresh single-flight (audit perf M4).
    refreshing: std::sync::atomic::AtomicBool,
    /// Viewport engagement ids (WS2, viewport.rs): the feed's settled
    /// visible window. The long-lived viewport task watches this channel,
    /// replacing ONE `#e` subscription as the window moves.
    viewport_ids: tokio::sync::watch::Sender<Vec<EventId>>,
    /// The viewport task spawns once per process (the outbox drainer's
    /// discipline).
    viewport_started: std::sync::atomic::AtomicBool,
    /// Bootstrap session-phase single-flight (audit perf M5).
    session_boot: tokio::sync::Mutex<()>,
}

impl Default for Core {
    fn default() -> Self {
        Self::new()
    }
}

impl Core {
    pub fn new() -> Self {
        // Keep the diagnostic mirror bounded (diag.rs) before anything logs.
        crate::diag::rotate();
        // The runtime is built first — the blocktime service needs its
        // handle for the single-flight spawns (Handle::current would panic
        // outside a runtime).
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("tokio runtime");
        // One-time media-cache migration: the pre-polish cache could hold
        // poisoned files (bytes written before decode validated them); the
        // versioned dir starts clean, the legacy dir goes (media.rs).
        rt.spawn(async { crate::media::purge_legacy_cache(); });
        let blocktime = Arc::new(Blocktime::new(rt.handle().clone()));
        // The viewport channel: the receiver half rides the viewport task
        // (subscribe() below); this seed receiver keeps send() honest
        // before the task arms.
        let (viewport_ids, _viewport_seed_rx) = tokio::sync::watch::channel(Vec::new());
        Self {
            rt,
            blocktime,
            active: Mutex::new(None),
            pending: Mutex::new(None),
            hold_seq: AtomicU64::new(1),
            outbox_started: std::sync::atomic::AtomicBool::new(false),
            scheduled_started: std::sync::atomic::AtomicBool::new(false),
            login_seq: AtomicU64::new(1),
            pool: Mutex::new(None),
            own_liked: Mutex::new(HashSet::new()),
            own_reposted: Mutex::new(HashSet::new()),
            own_bookmarked: Mutex::new(HashSet::new()),
        own_drafts: Mutex::new(Vec::new()),
            muted: Mutex::new(HashSet::new()),
            own_zapped: Mutex::new(HashSet::new()),
            tombstones_hydrated: std::sync::atomic::AtomicBool::new(false),
            wallet: Arc::new(Wallet::new()),
            profiles_mem: Mutex::new(ProfileMem::new()),
            holds: Mutex::new(std::collections::HashMap::new()),
            live: tokio::sync::broadcast::Sender::new(64),
            hold_tx: tokio::sync::broadcast::Sender::new(16),
            live_on: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            live_epoch: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            refreshing: std::sync::atomic::AtomicBool::new(false),
            viewport_ids,
            viewport_started: std::sync::atomic::AtomicBool::new(false),
            session_boot: tokio::sync::Mutex::new(()),
        }
    }

    /// Store retention (audit memory H-2): every event ever seen was kept
    /// forever - several MB/day, GB-class over a month of live saves. One
    /// prune pass shortly after launch (bootstraps settle first), then
    /// daily. The store is a cache; the relays are the archive. Call once,
    /// from main, on the Arc'd core.
    pub fn spawn_store_prune(self: &Arc<Self>) {
        let this = Arc::clone(self);
        self.rt.spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(90)).await;
                // Clone the pool out of the lock; no lock spans the awaits.
                let pool = this.pool.lock().unwrap().as_ref().map(Arc::clone);
                if let Some(p) = pool {
                    // The own bookmark set survives the sweep — the
                    // Bookmarks tab renders exactly these notes (v1.2).
                    let protect: std::collections::HashSet<EventId> = this
                        .own_bookmarked
                        .lock()
                        .unwrap()
                        .iter()
                        .filter_map(|h| EventId::from_hex(h).ok())
                        .collect();
                    match p.store.prune(&protect).await {
                        Ok(0) => {}
                        Ok(n) => eprintln!("[core] store prune: {n} event(s) past retention"),
                        Err(e) => eprintln!("[core] store prune failed: {e}"),
                    }
                }
                tokio::time::sleep(std::time::Duration::from_secs(24 * 3600)).await;
            }
        });
    }

    /// The follows' kind:10002 relay lists age out of the store, and
    /// routed reads go stale with them (pool.rs relay_lists: "no background
    /// refresher yet — that lands with the seen-on memory slice"). This is
    /// that refresher: hourly (first pass ~90s after launch, bootstraps
    /// settle first, like the prune), every follow whose cached list is
    /// older than 7 days - or missing - gets one TARGETED indexer query for
    /// a fresh list; the SDK persists what it receives, so the routed reads
    /// warm again on their own. Chunks of 200 (the store's per-query author
    /// cap). Desktop-only divergence from the TS (which cached per pubkey
    /// in memory and never refreshed): the daemon-sized process can afford
    /// the hourly sweep, and a long-lived session SHOULD heal its routing.
    /// Call once, from main, on the Arc'd core.
    pub fn spawn_list_refresher(self: &Arc<Self>) {
        let this = Arc::clone(self);
        self.rt.spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(90)).await;
                // Logged out = nothing to refresh (the watchdog's rule).
                let active = match this.active().await {
                    Ok(a) => a,
                    Err(_) => continue,
                };
                let pool = Arc::clone(&active.pool);
                let me = active.me();
                // The active account's follows (same store read the
                // bootstrap paints from).
                let follows: Vec<PublicKey> = pool
                    .store
                    .latest_by_kind(me, Kind::ContactList)
                    .await
                    .unwrap_or(None)
                    .map(|ev| ev.tags.public_keys().collect())
                    .unwrap_or_default();
                if follows.is_empty() {
                    continue;
                }
                // Stale = no cached list, or one older than the window.
                let have = pool.store.relay_lists(&follows).await.unwrap_or_default();
                let cutoff =
                    Timestamp::now() - std::time::Duration::from_secs(7 * 24 * 3600).as_secs();
                let stale: Vec<PublicKey> = follows
                    .iter()
                    .filter(|pk| {
                        have.iter()
                            .any(|ev| ev.pubkey == **pk && ev.created_at < cutoff)
                            || !have.iter().any(|ev| ev.pubkey == **pk)
                    })
                    .copied()
                    .collect();
                if stale.is_empty() {
                    continue;
                }
                eprintln!("[core] list refresher: {} stale list(s)", stale.len());
                let fallback: Vec<String> =
                    crate::pool::INDEXERS.iter().map(|s| s.to_string()).collect();
                for chunk in crate::outbox::chunk(
                    &stale.iter().map(|p| p.to_string()).collect::<Vec<_>>(),
                    200,
                ) {
                    let pks: Vec<PublicKey> = chunk
                        .iter()
                        .filter_map(|a| PublicKey::from_str(a).ok())
                        .collect();
                    if pks.is_empty() {
                        continue;
                    }
                    let n = pks.len();
                    let filter = Filter::new()
                        .kind(Kind::RelayList)
                        .authors(pks)
                        .limit(n);
                    // The SDK persists what it receives; the store's
                    // per-author newest-list read warms by itself.
                    let got = pool.get_from(&fallback, &filter).await;
                    eprintln!("[core] list refresher: {} fresh list(s)", got.len());
                }
                tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
            }
        });
    }

    /// Suspend watchdog (DESIGN.md §3.4): after sleep/hibernate every relay
    /// socket is dead. The SDK's 55s ping notices, but its adaptive backoff
    /// (10s doubling) can take minutes to reconnect — until then every read
    /// burns its whole budget against dead relays. A wall-clock jump far
    /// larger than the monotonic one means the machine slept: poke every
    /// relay (`connect()` is idempotent) so reads recover in seconds, not
    /// minutes. One probe per 30s for the process lifetime; skipped while
    /// logged out. Call once, from main, on the Arc'd core.
    pub fn spawn_suspend_watchdog(self: &Arc<Self>) {
        let this = Arc::clone(self);
        self.rt.spawn(async move {
            let mut last_wall = std::time::SystemTime::now();
            let mut last_mono = std::time::Instant::now();
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                let wall = std::time::SystemTime::now();
                let mono = std::time::Instant::now();
                let wall_d = wall.duration_since(last_wall).unwrap_or_default();
                let mono_d = mono.duration_since(last_mono);
                last_wall = wall;
                last_mono = mono;
                // CLOCK_MONOTONIC freezes in sleep; the wall clock doesn't.
                if wall_d.saturating_sub(mono_d) <= std::time::Duration::from_secs(90) {
                    continue;
                }
                // The pool() getter would BUILD a pool while logged out —
                // read the raw field and skip when there's nothing to poke.
                let Some(pool) = this.pool.lock().unwrap().clone() else {
                    continue;
                };
                crate::dlog!(
                    "watchdog: wall jumped {:?} vs monotonic {:?}, machine slept; reconnecting relays",
                    wall_d, mono_d
                );
                pool.client().connect().await;
            }
        });
    }

    // --- lifecycle -----------------------------------------------------------

    /// Resume a persisted session, if any. Returns the session plus the
    /// failure reason (shown on the login page — silent resume failures are
    /// how users get lost). The bunker signer is rebuilt from the transport
    /// secret without user interaction.
    /// Shared session teardown (sign_out + logout): shut the bunker
    /// transport down FIRST (zombie kind-24133 subscriptions = phantom
    /// approval prompts in the user's bunker app once the session is
    /// gone), drop the pool's NIP-42 identity (never answer AUTH as a
    /// stale account), close the NWC wallet (phantom subscriptions are the
    /// bunker bug's cousin; the LEDGER stays — history, not state), and
    /// clear the engagement/mute/profile mirrors so a different account
    /// never inherits them. sign_out used to skip all of this and bleed
    /// mirrors across accounts.
    fn teardown_session(&self) {
        let old = self.active.lock().unwrap().take();
        if let Some(a) = old
            && let Signer::Bunker(connect) = &a.signer {
                let connect = Arc::clone(connect);
                self.rt
                    .spawn(async move { Arc::unwrap_or_clone(connect).shutdown().await });
            }
        // The pool answered NIP-42 AUTH challenges as this session's
        // identity (pool.rs): drop it now, before the bunker transport
        // finishes dying and before session::clear drops the session
        // record.
        if let Some(p) = self.pool.lock().unwrap().as_ref() {
            p.clear_identity();
            // Routed relays belonged to this session's route graph: sweep
            // them so the next login (any account) starts clean. Nothing
            // removed a relay before — the set grew for the process
            // lifetime (audit Nov 2026).
            let p = Arc::clone(p);
            self.rt.spawn(async move { p.clear_routed().await });
        }
        let w = Arc::clone(&self.wallet);
        self.rt.spawn(async move { w.disconnect().await });
        self.own_liked.lock().unwrap().clear();
        self.own_reposted.lock().unwrap().clear();
        self.own_bookmarked.lock().unwrap().clear();
        self.own_drafts.lock().unwrap().clear();
        self.own_zapped.lock().unwrap().clear();
        self.muted.lock().unwrap().clear();
        // The WoT graph + dedup exemptions are per-session identity
        // state: disarm so verdicts read Unknown until the next login.
        // The bell's receipts + one-session exemptions go with them.
        crate::wot::clear_identity();
        crate::dedup::clear();
        // The reply-velocity counter is per-session identity state too
        // (D43): a different account never inherits a mule verdict.
        crate::rate::clear();
        SUPPRESSED.lock().unwrap().clear();
        NOTIF_EXEMPT.lock().unwrap().clear();
        // The profile mirror is display state for the logged-in session's
        // reading; a next login re-hydrates it from its own feed pages.
        self.profiles_mem.lock().unwrap().clear();
    }

    /// Sign out: run the full session teardown (transports, pool identity,
    /// mirrors) and forget the session file + both secret-store entries —
    /// the next login rebuilds everything exactly as a fresh process
    /// would.
    pub fn sign_out(&self) {
        self.teardown_session();
        session::clear();
        secrets::delete(secrets::NSEC);
        secrets::delete(secrets::BUNKER_CLIENT_SECRET);
        // The tombstone store outlives sessions (it is keyed by
        // deleter, not by follows) — nothing to clear at logout.
        // The live sub is armed per session: the epoch bump makes the old
        // loop tear down at its next event, and live_on false lets the
        // next login's bootstrap arm a fresh one with the new identity.
        self.live_epoch
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.live_on
            .store(false, std::sync::atomic::Ordering::SeqCst);
        // The viewport engagement sub closes with the session too (the
        // empty set plans a Drop; the pool it rides outlives the session).
        let _ = self.viewport_ids.send(Vec::new());
    }

    pub fn init(&self) -> (Option<Session>, Option<String>) {
        let Some(session) = session::load() else {
            return (None, None); // first run — not an error
        };
        match self.rt.block_on(self.build_active(&session)) {
            Ok(active) => {
                *self.active.lock().unwrap() = Some(active);
                self.resume_wallet();
                (Some(session), None)
            }
            Err(e) => {
                eprintln!("[core] resume failed: {e}");
                // The notice copy is human on purpose (the doors show it
                // verbatim); the technical detail is the stderr line above.
                match e {
                    // Definitive — retrying can never succeed: forget the
                    // session so the notice shows once, not every launch.
                    LoginError::CredentialGone(_) => {
                        session::clear();
                        (
                            None,
                            Some("Couldn't unlock your saved session, sign in again \
                                  below. Your keys stay with your signer."
                                .into()),
                        )
                    }
                    // Transient (relay down at launch, store timeout): keep
                    // the session — the next launch retries the resume.
                    _ => (
                        None,
                        Some("Couldn't reach your signer just now, Satori retries \
                              on next launch, or sign in below."
                            .into()),
                    ),
                }
            }
        }
    }

    pub fn pubkey(&self) -> Option<PublicKey> {
        self.active
            .lock()
            .unwrap()
            .as_ref()
            .and_then(|a| PublicKey::from_str(&a.session.pubkey).ok())
    }

    pub fn logout(&self) {
        // Full shared teardown: bunker transport first (zombie kind-24133
        // subscriptions = phantom approval prompts), then pool identity,
        // wallet, mirrors.
        self.teardown_session();
        session::clear();
        secrets::delete(secrets::BUNKER_CLIENT_SECRET);
        secrets::delete(secrets::NSEC);
        eprintln!("[core] logout");
    }

    /// Rebuild the two-hop WoT graph from the store's cached kind-3
    /// contact lists of the follows, then compute the extended-network
    /// relay cover from the qualified set's kind-10002s (issue #2 WS1;
    /// dark-wisp ExtendedNetworkRepository's qualification + greedy
    /// `computeRelaySetCover`). In-memory projection of the LMDB store
    /// — disposable, nothing persisted.
    async fn rebuild_wot_graph(&self, active: &Active, follows: &[PublicKey]) {
        let start = std::time::Instant::now();
        // The sidecar first (D45): the applied sources the SDK's one-shot
        // fetch never persisted. The store's cached kind-3s replay after
        // and win on newer (observe's newest-wins diff).
        let persisted = crate::wot::load_disk();
        for (pk, at, list) in &persisted {
            crate::wot::apply_persisted(pk, *at, list);
        }
        let sidecar: HashMap<String, u64> = persisted
            .iter()
            .map(|(pk, at, _)| (pk.clone(), *at))
            .collect();
        let sources = active
            .pool
            .store
            .contact_lists(follows)
            .await
            .unwrap_or_default();
        for ev in &sources {
            crate::wot::observe(ev);
        }
        let qualified = crate::wot::qualified();
        let cover = if qualified.is_empty() {
            Vec::new()
        } else {
            let lists = active
                .pool
                .store
                .relay_lists(&qualified)
                .await
                .unwrap_or_default();
            let mut parsed: HashMap<String, Vec<String>> = HashMap::new();
            for ev in lists {
                let urls: Vec<String> = crate::outbox::parse_relay_list(&ev)
                    .read
                    .into_iter()
                    .filter(|u| crate::outbox::routable_relay(u))
                    .collect();
                if !urls.is_empty() {
                    parsed.insert(ev.pubkey.to_string(), urls);
                }
            }
            let authors: Vec<String> =
                qualified.iter().map(|p| p.to_string()).collect();
            crate::wot::relay_cover(
                &parsed,
                &authors,
                crate::wot::MAX_EXTENDED_RELAYS,
                crate::wot::MAX_AUTHORS_PER_RELAY,
            )
        };
        crate::wot::set_cover(cover);
        crate::wot::note_rebuilt();
        eprintln!(
            "[core] wot: {} source list(s), {} qualified, {} cover relay(s) ({:?})",
            sources.len(),
            crate::wot::qualified().len(),
            crate::wot::extended_relays().len(),
            start.elapsed()
        );
        self.spawn_wot_source_fetch(active, follows, &sources, &sidecar)
            .await;
    }

    /// Bootstrap source fetch (issue #2): the graph rebuilds only from
    /// kind-3s the store HAPPENS to hold — without this pass a fresh
    /// install reads "253 follows · 0 qualified" forever, because nothing
    /// ever fetched the follows' contact lists. Select the follows whose
    /// cached list is missing or older than `wot::STALE_SECS`, cap at
    /// `wot::MAX_FETCH_TARGETS` (D24: two outbox shards of 200 authors),
    /// and fire ONE routed read-tier fetch per launch — no retry loop,
    /// the next bootstrap retries what this one missed. Fire-and-forget
    /// like the other bootstrap fetches: as results land, the pool
    /// chokepoint's `wot::observe` applies every kind-3 to the graph
    /// incrementally (diff-based, newest-wins), so authors re-qualify
    /// live — verdicts are computed from `scores` on demand, no second
    /// rebuild is needed.
    async fn spawn_wot_source_fetch(
        &self,
        active: &Active,
        follows: &[PublicKey],
        cached: &[Event],
        sidecar: &HashMap<String, u64>,
    ) {
        if crate::wot::status() == crate::wot::WotStatus::OverCap {
            return; // the graph shut off; fetching sources feeds nothing
        }
        let targets = crate::wot::fetch_targets(
            follows,
            cached,
            now_secs(),
            crate::wot::MAX_FETCH_TARGETS,
            sidecar,
        );
        if targets.is_empty() {
            return;
        }
        eprintln!(
            "[core] wot: fetching {} stale/missing contact list(s)",
            targets.len()
        );
        let pool = Arc::clone(&active.pool);
        let limit = targets.len();
        self.rt.spawn(async move {
            // The value is not read: the SDK persists what it receives,
            // and the chokepoint's wot::observe feeds the graph.
            let got = pool
                .get_routed(vec![Kind::ContactList], &targets, None, None, limit)
                .await;
            eprintln!(
                "[core] wot: source fetch returned {} list(s) for {} target(s)",
                got.len(),
                limit
            );
            {
                let (src, tgt, qual) = crate::wot::stats();
                eprintln!(
                    "[core] wot: graph now: {src} source list(s) applied, {tgt} scored target(s), {qual} qualified"
                );
            }
        });
    }

    /// Follow-state lookup for profile pages (from the cached contact list).
    pub fn is_following(&self, who: &PublicKey) -> bool {
        self.active
            .lock()
            .unwrap()
            .as_ref()
            .map(|a| a.follows.iter().any(|f| f == who))
            .unwrap_or(false)
    }

    /// Trust verdict for an author (issue #2 WS1): the shared
    /// vocabulary every gate consumes — see `wot::Verdict`. UNKNOWN
    /// means the graph can't say yet, never "outside".
    pub fn verdict(&self, who: &PublicKey) -> crate::wot::Verdict {
        crate::wot::verdict(who)
    }

    /// Shared-follows count for the trust badge ("N shared follows").
    pub fn shared_follows(&self, who: &PublicKey) -> usize {
        crate::wot::shared_follows(who)
    }

    /// The WoT graph's honest status for the settings surface (graph size,
    /// qualified set, last rebuild, staleness state).
    pub fn wot_status(&self) -> crate::wot::WotStatus {
        crate::wot::status()
    }

    /// The bell's receipts: notifications the WoT tier suppressed this
    /// session (the "N hidden, see why" surface). Empty when the tier is
    /// off or nothing was gated — never a silent void.
    pub fn suppressed_notifications(&self) -> Vec<SuppressedNotif> {
        SUPPRESSED.lock().unwrap().clone()
    }

    /// The receipts' per-item "show anyway": a ONE-SESSION exemption for
    /// this author — the tier stops gating them until sign-out (session
    /// teardown clears the set). The caller re-opens the notifications
    /// stream; the exempted items then pass the gate.
    pub fn show_suppressed_author(&self, pubkey_hex: &str) {
        NOTIF_EXEMPT
            .lock()
            .unwrap()
            .insert(pubkey_hex.to_string());
    }

    /// Caught spammers with per-relay attribution (issue #2 WS2
    /// receipts; the settings surface lands with the UI phase).
    pub fn spam_report(&self) -> Vec<crate::dedup::SpamRecord> {
        crate::dedup::snapshot()
    }

    /// The SpammingUsers surface's un-hide: clear one author's spammer
    /// record so their events store again (dedup::unhide — the threshold
    /// re-arms on a fresh duplicate streak).
    pub fn unhide_spammer(&self, pubkey_hex: &str) {
        crate::dedup::unhide(pubkey_hex);
    }

    pub fn is_muted(&self, who: &PublicKey) -> bool {
        self.muted.lock().unwrap().contains(&who.to_string())
    }

    /// Engagement lookups for card rendering (pure set membership, render is a
    /// projection — DESIGN.md §1.2).
    pub fn is_liked(&self, event_id: &EventId) -> bool {
        self.own_liked.lock().unwrap().contains(&event_id.to_string())
    }

    /// The engagement sets, for a view's session snapshot (feed.rs seeds its
    /// optimistic sets from these at construction — after a restart the
    /// glyphs still read engaged).
    pub fn liked_set(&self) -> HashSet<String> {
        self.own_liked.lock().unwrap().clone()
    }

    pub fn bookmarked_set(&self) -> HashSet<String> {
        self.own_bookmarked.lock().unwrap().clone()
    }

    pub fn reposted_set(&self) -> HashSet<String> {
        self.own_reposted.lock().unwrap().clone()
    }

    pub fn is_bookmarked(&self, event_id: &EventId) -> bool {
        self.own_bookmarked.lock().unwrap().contains(&event_id.to_string())
    }

    /// Fetch a JSON document (oEmbed previews) through the guarded pipeline.
    pub fn fetch_json(
        self: &Arc<Self>,
        url: String,
    ) -> mpsc::UnboundedReceiver<Option<serde_json::Value>> {
        let (tx, rx) = mpsc::unbounded_channel();
        self.rt.spawn(async move {
            let res = crate::media::fetch_json(&url).await.ok();
            let _ = tx.send(res);
        });
        rx
    }

    /// NIP-05 verification: does `domain`'s /.well-known/nostr.json vouch
    /// that `name` maps to this pubkey? One SSRF-guarded JSON fetch (the
    /// same path the zap invoice rides). `None` = unproven (fetch failed,
    /// malformed answer, mismatch beyond doubt is `Some(false)`); the UI
    /// treats None as "stay quiet", never red — verification is an
    /// affordance, not an accusation.
    pub fn verify_nip05(
        self: &Arc<Self>,
        nip05: String,
        pubkey: String,
    ) -> mpsc::UnboundedReceiver<Option<bool>> {
        let (tx, rx) = mpsc::unbounded_channel();
        self.rt.spawn(async move {
            let verdict = verify_nip05_inner(&nip05, &pubkey).await;
            let _ = tx.send(verdict);
        });
        rx
    }

    /// Fetch (and cache) an image — SSRF-guarded, sha256-keyed (media.rs).
    /// The outcome carries the failure KIND: Transient failures cool off and
    /// get another look in the UI; NotMedia is a verdict (the bytes arrived
    /// whole and are not an image).
    pub fn fetch_image(
        self: &Arc<Self>,
        url: String,
    ) -> mpsc::UnboundedReceiver<
        std::result::Result<crate::media::DecodedImage, crate::media::MediaError>,
    > {
        let (tx, rx) = mpsc::unbounded_channel();
        self.rt.spawn(async move {
            let res = crate::media::fetch_image(&url).await;
            let _ = tx.send(res);
        });
        rx
    }

    /// The poster job (D32): everything tokio-flavored stays on this
    /// runtime — the UI's executor has no tokio context, and awaiting
    /// these futures from it panicked thread 'main (the crash the day
    /// D32 shipped). The sniffer is injected by the UI (gstreamer lives
    /// there) and runs on this pool's blocking threads; the channel is
    /// fetch_image's exact seam.
    pub fn fetch_poster(
        self: &Arc<Self>,
        url: String,
        cap: usize,
        sniff: impl FnOnce(&[u8]) -> std::result::Result<(u32, u32, Vec<u8>), ()> + Send + 'static,
    ) -> mpsc::UnboundedReceiver<
        std::result::Result<crate::media::DecodedImage, crate::media::MediaError>,
    > {
        let (tx, rx) = mpsc::unbounded_channel();
        self.rt.spawn(async move {
            let res = crate::media::fetch_poster(url, cap, sniff).await;
            let _ = tx.send(res);
        });
        rx
    }

    // --- wallet / zaps (D20) ---------------------------------------------------

    /// The wallet handle (the settings pane reads status/balance directly).
    pub fn wallet(&self) -> Arc<Wallet> {
        Arc::clone(&self.wallet)
    }

    // --- blocktime (Phase 2 §4.4) ----------------------------------------------

    /// Resolve a timestamp to a Bitcoin block height (Feather's blocktime
    /// spec): hot answers immediately, otherwise one guarded single-flight
    /// fetch to mempool.space. The answer lands on every waiter.
    pub fn block_height(self: &Arc<Self>, ts: u64) -> crate::blocktime::BlockRx {
        self.blocktime.get(ts)
    }

    /// The display-ready answer: exact when known, interpolated from the
    /// nearest point otherwise. Pure read — per-frame safe, never fetches.
    pub fn block_height_cached(&self, ts: u64) -> Option<u64> {
        self.blocktime.cached(ts)
    }

    /// Is there an exact (fetched or recorded) height for this timestamp?
    /// The ensure path's skip test — interpolation doesn't count.
    pub fn block_height_known(&self, ts: u64) -> bool {
        self.blocktime.known(ts)
    }

    /// Wallet event stream: status changes, pay outcomes, verified
    /// receipts. The global pump every surface keeps.
    pub fn subscribe_wallet(&self) -> wallet::WalletRx {
        self.wallet.subscribe()
    }

    /// Connect a `nostr+walletconnect://` URI. Status streams on
    /// subscribe_wallet (Connecting → Ready | ConnectFailed).
    pub fn connect_wallet(&self, uri: String) {
        let w = Arc::clone(&self.wallet);
        self.rt.spawn(async move { w.connect(uri).await });
    }

    /// Disconnect and forget (wallet.json + the secret store entry).
    pub fn disconnect_wallet(&self) {
        let w = Arc::clone(&self.wallet);
        self.rt.spawn(async move { w.disconnect().await });
    }

    /// Reconnect a persisted wallet and seed the own-zapped mirror from
    /// the ledger. Best-effort: a dead wallet backend is a settings
    /// concern, never a login failure.
    fn resume_wallet(&self) {
        // Paid/Confirmed notes render settled without waiting on the
        // wallet; Pending/Uncertain still owe the wallet an answer.
        let mut zapped = self.own_zapped.lock().unwrap();
        for z in wallet::ledger_history() {
            if matches!(z.state, wallet::ZapState::Paid | wallet::ZapState::Confirmed) {
                zapped.insert(z.note);
            }
        }
        drop(zapped);
        let w = Arc::clone(&self.wallet);
        self.rt.spawn(async move { w.resume().await });
    }

    /// Zap-state lookup for render (the settled bolt).
    pub fn is_zapped(&self, note: &EventId) -> bool {
        self.own_zapped.lock().unwrap().contains(&note.to_string())
    }

    /// The whole own-zapped set (a view seeds its snapshot from this).
    pub fn zapped_set(&self) -> HashSet<String> {
        self.own_zapped.lock().unwrap().clone()
    }

    /// Zap a note: a PUBLIC NIP-57 zap through the connected NWC wallet
    /// (the tap = 21 sats default). Events stream on the returned channel
    /// AND on subscribe_wallet — see [`WalletResultRx`].
    pub fn zap(self: &Arc<Self>, note: Event, msat: u64) -> WalletResultRx {
        let (tx, rx) = mpsc::unbounded_channel();
        let this = Arc::clone(self);
        let w = Arc::clone(&self.wallet);
        self.rt.spawn(async move {
            if let Err(e) = this.zap_inner(&note, msat, &tx).await {
                // Early failures never reach pay_stored's own emit — the
                // feed's whisper still needs to hear them.
                w.emit(e.clone());
                let _ = tx.send(e);
            }
        });
        rx
    }

    /// Retry a stored zap (Pending/Uncertain only). The SAME signed request
    /// goes back out — same event id, no duplicate zap events; that is the
    /// ledger's whole reason for keeping the full signed 9734.
    pub fn retry_zap(self: &Arc<Self>, note: String) -> WalletResultRx {
        let (tx, rx) = mpsc::unbounded_channel();
        let this = Arc::clone(self);
        let w = Arc::clone(&self.wallet);
        self.rt.spawn(async move {
            if let Err(e) = this.retry_inner(note, &tx).await {
                w.emit(e.clone());
                let _ = tx.send(e);
            }
        });
        rx
    }

    async fn retry_inner(
        self: &Arc<Self>,
        note: String,
        tx: &mpsc::UnboundedSender<WalletEvent>,
    ) -> ZapFlow {
        let Some(record) = wallet::ledger_for_note(&note).filter(|z| {
            matches!(z.state, wallet::ZapState::Pending | wallet::ZapState::Uncertain)
        }) else {
            return Err(WalletEvent::ZapFailed {
                note,
                reason: "nothing to retry for this note".into(),
            });
        };
        // The stored request replays as-is — re-signing would mint a new
        // event id and risk a duplicate zap event (the Feather rule).
        let signed = serde_json::from_str::<Event>(&record.event).map_err(|_| {
            WalletEvent::ZapFailed {
                note: note.clone(),
                reason: "stored zap request is corrupt".into(),
            }
        })?;
        // One in-flight payment per note — the retry reclaims the slot.
        if !self.wallet.claim_flight(&note) {
            return Err(WalletEvent::ZapFailed {
                note,
                reason: "a zap on this note is already in flight".into(),
            });
        }
        let _guard = FlightGuard(&self.wallet, &note);
        self.pay_stored(&record, &signed, tx).await
    }

    async fn zap_inner(
        self: &Arc<Self>,
        note: &Event,
        msat: u64,
        tx: &mpsc::UnboundedSender<WalletEvent>,
    ) -> ZapFlow {
        let note_hex = note.id.to_string();
        // One in-flight payment per note — the Feather rule (the wallet
        // owns the set; fresh zaps and retries both come through it).
        if !self.wallet.claim_flight(&note_hex) {
            return Err(WalletEvent::ZapFailed {
                note: note_hex,
                reason: "a zap on this note is already in flight".into(),
            });
        }
        let _guard = FlightGuard(&self.wallet, &note_hex);

        if !self.wallet.is_ready() {
            return Err(WalletEvent::ZapFailed {
                note: note_hex.clone(),
                reason: "no wallet connected".into(),
            });
        }
        let active = self.active().await.map_err(|e| WalletEvent::ZapFailed {
            note: note_hex.clone(),
            reason: e.to_string(),
        })?;
        let me = active.me();
        let recipient = note.pubkey;

        // The recipient's lightning pointer (lud16 before lud06). No
        // address, no zap — an honest quiet failure, not a dialog.
        let lud = match active
            .pool
            .store
            .latest_by_kind(recipient, Kind::Metadata)
            .await
        {
            Ok(Some(meta)) => lightning_field(&meta.content),
            _ => None,
        }
        .ok_or_else(|| WalletEvent::ZapFailed {
            note: note_hex.clone(),
            reason: "this profile has no lightning address".into(),
        })?;
        let lnurl = wallet::lnurlp_url(&lud).map_err(|e| WalletEvent::ZapFailed {
            note: note_hex.clone(),
            reason: e,
        })?;

        // Sign FIRST (through the owner's signer — the bunker), STORE the
        // signed request, then pay. A crash between sign and pay leaves a
        // Pending record a retry can finish — same event id.
        let unsigned = wallet::zap_request(
            me,
            recipient,
            note.id,
            msat,
            &lnurl,
            active.write_relays.clone(),
        );
        let signed = active
            .signer
            .sign_event(unsigned)
            .await
            .map_err(|e| WalletEvent::ZapFailed {
                note: note_hex.clone(),
                reason: e.to_string(),
            })?;
        let record = wallet::ZapRecord {
            req: signed.id.to_string(),
            note: note_hex.clone(),
            recipient: recipient.to_string(),
            msat,
            state: wallet::ZapState::Pending,
            created_at: now_secs(),
            event: serde_json::to_string(&signed).unwrap_or_default(),
        };
        wallet::ledger_update(record.clone());

        self.pay_stored(&record, &signed, tx).await
    }

    /// The shared pay path for a STORED, signed request (fresh or retry):
    /// fetch the invoice from the recipient's LNURL-pay endpoint, hand the
    /// bolt11 to the NWC wallet, classify the answer per the Feather rule.
    async fn pay_stored(
        self: &Arc<Self>,
        record: &wallet::ZapRecord,
        signed: &Event,
        tx: &mpsc::UnboundedSender<WalletEvent>,
    ) -> ZapFlow {
        let note = record.note.clone();
        let req = record.req.clone();

        // The lnurl tag rides the signed request (bech32) — lnurlp_url
        // accepts it as-is (the lud06 branch). Reading it from the event
        // (not the caller) is what lets retries share this path.
        let lnurl_tag = signed
            .tags
            .iter()
            .find(|t| t.as_slice().first().map(String::as_str) == Some("lnurl"))
            .and_then(|t| t.as_slice().get(1).cloned())
            .ok_or_else(|| WalletEvent::ZapFailed {
                note: note.clone(),
                reason: "zap request has no lnurl tag".into(),
            })?;
        let endpoint =
            wallet::lnurlp_url(&lnurl_tag).map_err(|e| WalletEvent::ZapFailed {
                note: note.clone(),
                reason: e,
            })?;
        // No invoice yet → nothing CAN have been paid: a definite LNURL
        // error erases the record, the user just taps again.
        let callback = match wallet::fetch_lnurlp(&endpoint).await {
            Ok(cb) => cb,
            Err(e) => {
                wallet::ledger_remove(&req);
                return Err(WalletEvent::ZapFailed { note, reason: e });
            }
        };
        let bolt11 = match wallet::fetch_zap_invoice(&callback, record.msat, signed).await {
            Ok(pr) => pr,
            Err(e) => {
                wallet::ledger_remove(&req);
                return Err(WalletEvent::ZapFailed { note, reason: e });
            }
        };

        // The money moment. The wallet SPOKE and did not pay → retrying is
        // safe (erase + quiet error). Anything else → Uncertain, terminal
        // until the user (or a receipt) decides — never auto-retried.
        match self.wallet.pay(&bolt11).await {
            Ok(_preimage) => {
                wallet::ledger_set_state(&req, wallet::ZapState::Paid);
                let ev = WalletEvent::ZapPaid {
                    note: note.clone(),
                    req: req.clone(),
                    msat: record.msat,
                };
                self.wallet.emit(ev.clone());
                let _ = tx.send(ev);
                self.watch_receipt(&note, &req, tx);
                Ok(())
            }
            Err(wallet::PayError::Uncertain) => {
                wallet::ledger_set_state(&req, wallet::ZapState::Uncertain);
                let ev = WalletEvent::ZapUncertain {
                    note: note.clone(),
                    req: req.clone(),
                    msat: record.msat,
                };
                self.wallet.emit(ev.clone());
                let _ = tx.send(ev);
                Ok(())
            }
            Err(e) => {
                // Code(_) or NoWallet: the wallet never paid.
                wallet::ledger_remove(&req);
                let ev = WalletEvent::ZapFailed {
                    note,
                    reason: e.to_string(),
                };
                self.wallet.emit(ev.clone());
                let _ = tx.send(ev);
                Ok(())
            }
        }
    }

    /// Watch for the wallet service's kind-9735 receipt (it publishes to
    /// OUR relays — the request's relays tag) and reconcile the ledger to
    /// Confirmed when OUR verified zap lands. Best-effort: Paid is already
    /// truthful (the wallet returned a preimage); the receipt is the
    /// stronger proof and recovers nothing else.
    fn watch_receipt(
        self: &Arc<Self>,
        note_hex: &str,
        req: &str,
        tx: &mpsc::UnboundedSender<WalletEvent>,
    ) {
        let this = Arc::clone(self);
        let note = note_hex.to_string();
        let req = req.to_string();
        let tx = tx.clone(); // the spawned task outlives the borrow
        self.rt.spawn(async move {
            let Ok(active) = this.active().await else { return };
            let me = active.me();
            let Ok(note_id) = EventId::from_hex(&note) else { return };
            for _ in 0..6 {
                tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                let events = match active
                    .pool
                    .get(Filter::new().kind(Kind::Custom(9735)).event(note_id))
                    .await
                {
                    Ok(set) => set,
                    Err(_) => continue, // relay budget blown — look again
                };
                // parse_zap_receipt verifies the embedded 9734 (signature +
                // p/e/a tags); the sender being ME is the reconciliation.
                if events
                    .iter()
                    .any(|ev| crate::notifications::parse_zap_receipt(ev).sender == Some(me))
                {
                    wallet::ledger_set_state(&req, wallet::ZapState::Confirmed);
                    let ev = WalletEvent::ZapReceipt {
                        note: note.clone(),
                        req: req.clone(),
                    };
                    this.wallet.emit(ev.clone());
                    let _ = tx.send(ev);
                    return;
                }
            }
        });
    }

    // --- bunker login ---------------------------------------------------------

    /// Connect to a `bunker://` URI. Events stream on the returned channel:
    /// Waiting → (AuthUrl?) → Approved | Failed. Cancel with `cancel_login`.
    pub fn connect_bunker(self: &Arc<Self>, uri: String) -> ConnectRx {
        // This flow's epoch = the counter value after the bump; any later
        // bump (cancel, a newer attempt) invalidates it.
        let seq = self.login_seq.fetch_add(1, Ordering::SeqCst) + 1;
        let (tx, rx) = mpsc::unbounded_channel();
        let this = Arc::clone(self);
        self.rt.spawn(async move {
            let _ = tx.send(ConnectEvent::Waiting);
            crate::dlog!("bunker: flow started (seq {seq})");
            match this.connect_bunker_inner(&uri, seq).await {
                Ok(pk) => {
                    crate::dlog!("bunker: approved for {pk}");
                    let _ = tx.send(ConnectEvent::Approved(pk));
                }
                Err(e) => {
                    crate::dlog!("bunker: failed: {e}");
                    let _ = tx.send(ConnectEvent::Failed(e.to_string()));
                }
            }
        });
        rx
    }

    /// Abandon an in-flight bunker connect (best-effort shutdown).
    pub fn cancel_login(&self) {
        self.login_seq.fetch_add(1, Ordering::SeqCst);
        if let Some(pending) = self.pending.lock().unwrap().take() {
            self.rt
                .spawn(async move { Arc::unwrap_or_clone(pending).shutdown().await });
        }
    }

    async fn connect_bunker_inner(&self, uri: &str, seq: u64) -> Result<PublicKey> {
        let parsed = NostrConnectUri::parse(uri.trim())
            .map_err(|e| LoginError::InvalidBunkerUri(e.to_string()))?;

        // bunker://<remote>?relay=... (client:// initiation is out of scope).
        let remote = match &parsed {
            NostrConnectUri::Bunker { remote_signer_public_key, .. } => {
                remote_signer_public_key.to_string()
            }
            _ => return Err(LoginError::InvalidBunkerUri("expected bunker:// URI".into())),
        };
        crate::dlog!("bunker: parsed, remote signer {remote}");

        let client_keys = Keys::generate();
        let connect = Arc::new(
            NostrConnect::new(parsed, client_keys.clone(), LOGIN_TIMEOUT, None)
                .map_err(|e| LoginError::Connect(e.to_string()))?,
        );
        let relays: Vec<String> = connect.relays().iter().map(|r| r.to_string()).collect();
        crate::dlog!("bunker: client built over {} relay(s); awaiting approval", relays.len());
        *self.pending.lock().unwrap() = Some(Arc::clone(&connect));

        let pk = match connect.get_public_key_async().await {
            Ok(pk) => pk,
            Err(e) => {
                crate::dlog!("bunker: get_public_key failed: {e}");
                return Err(LoginError::Connect(e.to_string()));
            }
        };
        crate::dlog!("bunker: approval received from signer");

        if self.login_seq.load(Ordering::SeqCst) != seq {
            crate::dlog!("bunker: login superseded mid-handshake; dropping");
            return Err(LoginError::Connect("superseded".into()));
        }

        secrets::store(
            secrets::BUNKER_CLIENT_SECRET,
            &client_keys.secret_key().display_secret().to_string(),
        )
        .await?;
        let session = Session {
            pubkey: pk.to_string(),
            mode: SessionMode::Bunker { remote, relays },
        };
        session::save(&session)?;
        crate::dlog!("bunker: session saved");

        // Already on the runtime (spawned task): await, never block_on.
        let active = self.build_active(&session).await?;
        *self.active.lock().unwrap() = Some(active);
        // Clear pending only if it still points at THIS handshake — a newer
        // attempt may have replaced it.
        let mut pending = self.pending.lock().unwrap();
        if pending.as_ref().is_some_and(|p| Arc::ptr_eq(p, &connect)) {
            *pending = None;
        }
        drop(pending);
        crate::dlog!("bunker: active session built, login complete");
        Ok(pk)
    }

    /// nostrconnect login (NIP-46, client-initiated): generate a fresh
    /// transport keypair and advertise it as a QR'd nostrconnect:// URI on
    /// the shared NIP-46 relay — the signer scans and approves. The URI goes
    /// down the same stream first (ConnectEvent::Uri); from approval on,
    /// this is the bunker flow (transport key in BUNKER_CLIENT_SECRET,
    /// session mode Bunker — resume rebuilds a bunker:// URI).
    pub fn connect_nostrconnect(self: &Arc<Self>, relay: String) -> ConnectRx {
        let seq = self.login_seq.fetch_add(1, Ordering::SeqCst) + 1;
        let (tx, rx) = mpsc::unbounded_channel();
        let this = Arc::clone(self);
        self.rt.spawn(async move {
            let _ = tx.send(ConnectEvent::Waiting);
            crate::dlog!("nostrconnect: flow started (seq {seq}, relay {relay})");
            match this.connect_nostrconnect_inner(&relay, seq, &tx).await {
                Ok(pk) => {
                    crate::dlog!("nostrconnect: approved for {pk}");
                    let _ = tx.send(ConnectEvent::Approved(pk));
                }
                Err(e) => {
                    crate::dlog!("nostrconnect: first window failed: {e}");
                    // One automatic retry on the SDK's 60s timeout: a fast
                    // signer (kumaOS's built-in panel approves in ~1s) can
                    // publish its response before the SDK's subscribe is
                    // live, and kind-24133 filters don't replay. A fresh
                    // URI re-arms the handshake — the Uri event repaints
                    // the QR. Superseded or cancelled flows don't retry.
                    if !e.to_string().contains("timeout")
                        || this.login_seq.load(Ordering::SeqCst) != seq
                    {
                        let _ = tx.send(ConnectEvent::Failed(e.to_string()));
                        return;
                    }
                    // (No lock across the shutdown await — take first.)
                    let pending = this.pending.lock().unwrap().take();
                    if let Some(pending) = pending {
                        Arc::unwrap_or_clone(pending).shutdown().await;
                    }
                    crate::dlog!("nostrconnect: retrying with a fresh URI");
                    match this.connect_nostrconnect_inner(&relay, seq, &tx).await {
                        Ok(pk) => {
                            crate::dlog!("nostrconnect: approved for {pk} (retry)");
                            let _ = tx.send(ConnectEvent::Approved(pk));
                        }
                        Err(e2) => {
                            crate::dlog!("nostrconnect: retry failed: {e2}");
                            let _ = tx.send(ConnectEvent::Failed(e2.to_string()));
                        }
                    }
                }
            }
        });
        rx
    }

    async fn connect_nostrconnect_inner(
        &self,
        relay: &str,
        seq: u64,
        tx: &mpsc::UnboundedSender<ConnectEvent>,
    ) -> Result<PublicKey> {
        let client_keys = Keys::generate();
        // The metadata the signer shows at approval time. url/icons stay
        // unset until the app has hosted art — both optional per NIP-46.
        let mut uri = NostrConnectUri::client(
            client_keys.public_key(),
            [RelayUrl::parse(relay)
                .map_err(|e| LoginError::InvalidBunkerUri(e.to_string()))?],
            "Satori",
        );
        if let NostrConnectUri::Client { metadata, .. } = &mut uri {
            metadata.description = Some("A quiet Nostr reader.".to_string());
        }
        // The SDK emits the client identity as a metadata= JSON blob (the
        // pre-2025 NIP-46 draft); the current spec spells flat query params
        // (name/url/image). Append both — old signers read the blob, current
        // ones (kumaOS) the flat param. The handshake itself validates the
        // secret against the parsed URI, so the extras ride along inert.
        let mut uri_str = uri.to_string();
        uri_str.push_str("&name=Satori");
        crate::dlog!("nostrconnect: uri ready ({} chars)", uri_str.len());
        let _ = tx.send(ConnectEvent::Uri(uri_str));

        let connect = Arc::new(
            NostrConnect::new(uri, client_keys.clone(), LOGIN_TIMEOUT, None)
                .map_err(|e| LoginError::Connect(e.to_string()))?,
        );
        crate::dlog!("nostrconnect: client built, awaiting signer…");
        *self.pending.lock().unwrap() = Some(Arc::clone(&connect));

        // The probe: a bare diagnostic client riding the same relay,
        // subscribed to this key's response kind. The SDK's own pump skips
        // bad responses with a tracing::warn that vanishes (no subscriber),
        // and a fast approval can land before its subscribe — the probe
        // turns both into lines we can actually read. Stands down when the
        // handshake resolves.
        let (probe_done_tx, probe_done_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(Self::nostrconnect_probe(
            client_keys.clone(),
            relay.to_string(),
            probe_done_rx,
        ));

        let user_pk = match connect.get_public_key_async().await {
            Ok(pk) => pk,
            Err(e) => {
                let _ = probe_done_tx.send(());
                crate::dlog!("nostrconnect: get_public_key failed: {e}");
                return Err(LoginError::Connect(e.to_string()));
            }
        };
        let _ = probe_done_tx.send(());
        crate::dlog!("nostrconnect: approval received from signer");

        if self.login_seq.load(Ordering::SeqCst) != seq {
            crate::dlog!("nostrconnect: login superseded mid-handshake; dropping");
            return Err(LoginError::Connect("superseded".into()));
        }

        secrets::store(
            secrets::BUNKER_CLIENT_SECRET,
            &client_keys.secret_key().display_secret().to_string(),
        )
        .await?;
        let remote = match connect
            .bunker_uri()
            .await
            .map_err(|e| LoginError::Connect(e.to_string()))?
        {
            NostrConnectUri::Bunker { remote_signer_public_key, .. } => {
                remote_signer_public_key.to_string()
            }
            _ => unreachable!("bunker_uri returns the Bunker variant"),
        };
        let relays: Vec<String> = connect.relays().iter().map(|r| r.to_string()).collect();

        let session = Session {
            pubkey: user_pk.to_string(),
            mode: SessionMode::Bunker { remote, relays },
        };
        session::save(&session)?;
        crate::dlog!("nostrconnect: session saved");

        let active = self.build_active(&session).await?;
        *self.active.lock().unwrap() = Some(active);
        // Clear pending only if it still points at THIS handshake — a newer
        // attempt may have replaced it.
        let mut pending = self.pending.lock().unwrap();
        if pending.as_ref().is_some_and(|p| Arc::ptr_eq(p, &connect)) {
            *pending = None;
        }
        drop(pending);
        crate::dlog!("nostrconnect: active session built, login complete");
        Ok(user_pk)
    }

    /// The nostrconnect diagnostic sub (see connect_nostrconnect_inner):
    /// one bare client on the same relay, subscribed to the transport
    /// key's response kind. Every signer response it sees is logged with
    /// its decrypt outcome — "the relay delivered it and the SDK pump
    /// missed it" becomes provable from the log instead of a guess.
    async fn nostrconnect_probe(client_keys: Keys, relay: String, done: tokio::sync::oneshot::Receiver<()>) {
        use futures_util::StreamExt as _;
        // The login relay is user-supplied (typed/QR'd seconds ago):
        // user-chosen class, dials direct like the rest of the
        // exemptions (M5 WP2's policy boundary).
        if let Ok(parsed) = url::Url::parse(&relay)
            && let Some(host) = parsed.host_str() {
                crate::net_guard::allow_direct_relay(host);
        }
        let probe = nostr_sdk::client::ClientBuilder::new().build();
        if let Err(e) = probe.add_relay(&relay).await {
            crate::dlog!("nostrconnect probe: relay add failed: {e}");
            return;
        }
        probe.connect().await;
        crate::dlog!("nostrconnect probe: relay connected");
        let filter = Filter::new()
            .pubkey(client_keys.public_key())
            .kind(Kind::NostrConnect)
            .limit(0);
        let Ok(output) = probe.subscribe(vec![filter]).await else {
            crate::dlog!("nostrconnect probe: subscribe failed");
            return;
        };
        crate::dlog!("nostrconnect probe: subscribed for responses");
        let mut done = done;
        let mut notifications = probe.notifications();
        loop {
            tokio::select! {
                _ = &mut done => {
                    crate::dlog!("nostrconnect probe: handshake resolved, standing down");
                    let _ = probe.shutdown().await;
                    return;
                }
                n = notifications.next() => {
                    let Some(n) = n else {
                        crate::dlog!("nostrconnect probe: notification stream ended");
                        return;
                    };
                    match n {
                        nostr_sdk::client::ClientNotification::Event { subscription_id, event, .. }
                            if output.id() == &subscription_id =>
                        {
                            let event = *event;
                            crate::dlog!(
                                "nostrconnect probe: response event from {}, the relay DID deliver",
                                event.pubkey
                            );
                            match nostr::nips::nip44::decrypt(
                                client_keys.secret_key(),
                                &event.pubkey,
                                &event.content,
                            ) {
                                Ok(json) => {
                                    match serde_json::from_str::<serde_json::Value>(&json) {
                                        Ok(v) => crate::dlog!(
                                            "nostrconnect probe: response type={:?} result={:?} error={:?}",
                                            v.get("type"),
                                            v.get("result"),
                                            v.get("error"),
                                        ),
                                        Err(_) => crate::dlog!(
                                            "nostrconnect probe: undecodable response: {}…",
                                            json.chars().take(120).collect::<String>()
                                        ),
                                    }
                                }
                                Err(e) => {
                                    crate::dlog!("nostrconnect probe: decrypt failed: {e}");
                                }
                            }
                        }
                        nostr_sdk::client::ClientNotification::Shutdown => {
                            crate::dlog!("nostrconnect probe: client shutdown");
                            return;
                        }
                        _ => continue,
                    }
                }
            }
        }
    }



    // --- resume machinery ------------------------------------------------------

    async fn build_signer(&self, session: &Session) -> Result<Signer> {
        match &session.mode {
            SessionMode::Bunker { remote, relays } => {
                let secret = secrets::load(secrets::BUNKER_CLIENT_SECRET)
                    .await?
                    .ok_or(LoginError::CredentialGone("transport secret"))?;
                let client_keys = signer::client_keys_from_secret(&secret)?;
                // Repeated relays join with & (query params, not extra ?s).
                let mut uri = format!("bunker://{remote}");
                if !relays.is_empty() {
                    uri.push_str("?relay=");
                    uri.push_str(&relays.join("&relay="));
                }
                let parsed = NostrConnectUri::parse(&uri)
                    .map_err(|e| LoginError::Resume(e.to_string()))?;
                let connect = NostrConnect::new(parsed, client_keys, LOGIN_TIMEOUT, None)
                    .map_err(|e| LoginError::Resume(e.to_string()))?;
                Ok(Signer::Bunker(Arc::new(connect)))
            }
            SessionMode::Local => {
                let secret = secrets::load(secrets::NSEC)
                    .await?
                    .ok_or(LoginError::CredentialGone("local key"))?;
                Ok(Signer::Local(signer::parse_local_secret(&secret)?))
            }
        }
    }

    /// The process pool (create-or-get).
    async fn pool(&self) -> Result<Arc<Pool>> {
        if let Some(p) = self.pool.lock().unwrap().as_ref() {
            return Ok(Arc::clone(p));
        }
        let p = Arc::new(Pool::open().await.map_err(|e| LoginError::Resume(e.to_string()))?);
        *self.pool.lock().unwrap() = Some(Arc::clone(&p));
        Ok(p)
    }

    async fn build_active(&self, session: &Session) -> Result<Active> {
        // The session pubkey, parsed once. A corrupt session.json fails
        // the login here, with a message on the login pane, instead of
        // panicking at the first me() call somewhere deep in a feed task.
        let me = PublicKey::from_str(&session.pubkey)
            .map_err(|e| LoginError::Resume(format!("session pubkey: {e}")))?;
        let signer = self.build_signer(session).await?;
        let pool = self.pool().await?;
        // The pool's NIP-42 authenticator now answers challenges AS this
        // account (pool.rs): strict relays serve kinds 78/30078 only to
        // the authenticated owner (NIP-78, Sep 2026).
        pool.set_identity(signer.clone());
        let profiles = crate::profiles::ProfileService::new(Arc::clone(&pool));
        // Undo-window prefs live in prefs.json (theme.ts semantics); core
        // reads its slice at session build — TODO(M1): cleaner pref split.
        let mut undo = crate::undo::UndoWindow::default();
        if let Ok(raw) = std::fs::read_to_string(crate::config::state_file(
            crate::config::files::PREFS,
        ))
            && let Ok(v) = serde_json::from_str::<serde_json::Value>(&raw) {
                if let Some(b) = v.get("undo_enabled").and_then(|b| b.as_bool()) {
                    undo.enabled = b;
                }
                if let Some(sec) = v.get("undo_seconds").and_then(|s| s.as_u64()) {
                    undo.set_seconds(sec as u32);
                }
            }
        // NIP-78 app-data sync (Phase 2 §4.1): our kind-30078 slots →
        // prefs.json. Remote wins at login (Feather's semantics): every
        // local change publishes forward, so only offline edits lose.
        // PrefsSynced wakes the shell to re-read what it renders live.
        {
            let pool = Arc::clone(&pool);
            let signer = signer.clone();
            let live = self.live.clone();
            self.rt.spawn(async move {
                sync_app_data(&pool, &me, &signer, &live).await;
            });
        }
        Ok(Active {
            session: session.clone(),
            signer,
            pool,
            profiles,
            undo,
            write_relays: Vec::new(),
            read_relays: Vec::new(),
            follows: Vec::new(),
            me,
        })
    }

    /// Live undo-window update (settings): active state + prefs.json,
    /// then NIP-78 sync of both undo keys (Phase 2 §4.1).
    pub fn set_undo(self: &Arc<Self>, enabled: bool, seconds: u32) {
        {
            let mut a = self.active.lock().unwrap();
            if let Some(a) = a.as_mut() {
                a.undo.enabled = enabled;
                a.undo.set_seconds(seconds);
            }
        }
        write_prefs_overlay(&[
            ("undo_enabled".to_string(), enabled.into()),
            ("undo_seconds".to_string(), seconds.into()),
        ]);
        // Fire and forget — sync needs no feedback surface.
        self.publish_app_data("undo_enabled", serde_json::Value::Bool(enabled));
        self.publish_app_data("undo_seconds", serde_json::Value::from(seconds));
    }

    /// NIP-78 app-data publish (Phase 2 §4.1): one kind-30078 per prefs
    /// key, `d` = prefs.json key verbatim, content NIP-44-encrypted to
    /// self — the same private-by-default semantics as the NIP-51 lists.
    pub fn publish_app_data(self: &Arc<Self>, key: &str, value: serde_json::Value) -> PublishRx {
        let (tx, rx) = mpsc::unbounded_channel();
        let this = Arc::clone(self);
        let key = key.to_string();
        self.rt.spawn(async move {
            let res: Result<()> = async {
                let active = this.active().await?;
                let me = active.me();
                let content = active.signer.nip44_encrypt_self(&me, &value.to_string()).await?;
                let unsigned = UnsignedEvent::new(
                    me,
                    Timestamp::now(),
                    Kind::Custom(nip78::KIND),
                    [Tag::custom("d", [key.as_str()])],
                    content,
                );
                let signed = active.signer.sign_event(unsigned).await?;
                Self::commit(&active, &signed, &tx).await?;
                Ok(())
            }
            .await;
            if let Err(e) = res {
                let _ = tx.send(PublishEvent::Failed { token: 0, error: e.to_string() });
            } else {
                let _ = tx.send(PublishEvent::Committed { token: 0 });
            }
        });
        rx
    }

    // --- feed ------------------------------------------------------------------

    /// Bootstrap: NIP-65 relay lists, follows, connect reads, first page
    /// (deep fetch for older pagination), own engagement sets, profiles.
    /// Bootstrap the given surface: `visible_kinds()` for the timeline, a
    /// single kind for a narrow one (articles).
    pub fn bootstrap(self: &Arc<Self>, kinds: Vec<Kind>) -> FeedRx {
        let (tx, rx) = mpsc::unbounded_channel();
        let this = Arc::clone(self);
        self.rt.spawn(async move {
            // D36: the outbox drainer arms on the first bootstrap —
            // crash leftovers and queued failures come due here.
            this.spawn_outbox_drain();
            // WS4: the scheduled-posts sweep arms alongside it — restart
            // catch-up is just its first tick finding due entries on disk.
            this.spawn_scheduled_sweep();
            if let Err(e) = this.bootstrap_inner(&tx, kinds).await {
                let _ = tx.send(FeedEvent::Failed(e.to_string()));
            }
        });
        rx
    }

    async fn bootstrap_inner(
        &self,
        tx: &mpsc::UnboundedSender<FeedEvent>,
        kinds: Vec<Kind>,
    ) -> Result<()> {
        let mut active = self.active().await?;
        let me = active.me();

        // 1. PAINT FIRST: whatever the store already holds (instant — the
        // LMDB cache persists across runs). Cached follows drive the filter.
        let cached_follows: Vec<PublicKey> = active
            .pool
            .store
            .latest_by_kind(me, Kind::ContactList)
            .await
            .unwrap_or(None)
            .map(|ev| ev.tags.public_keys().collect())
            .unwrap_or_default();
        if !cached_follows.is_empty() {
            active.follows = cached_follows.clone();
            let page = self.page_from_store(&active, None, &kinds).await?;
            let _ = tx.send(FeedEvent::Loaded(page));
        }
        let _ = tx.send(FeedEvent::BootstrapDone);

        // 2. The network phase — everything independent, IN PARALLEL. The
        // UI re-renders when the fresh page lands (the reactive profile
        // patching fills names/avatars as they arrive).
        // Session-phase single-flight (audit perf M5): surfaces opened in
        // quick succession re-ran the nip65/follows phase CONCURRENTLY
        // against the same relays. The first surface runs it; the rest
        // wait, then read the (now warm) store. Keyed per account —
        // read_state persists across logouts — TTL 1h, armed only when a
        // phase actually found follows.
        let phase_key = format!("session-phase-{me}");
        {
            let _guard = self.session_boot.lock().await;
            let ran = crate::read_state::load()
                .warm_at
                .get(&phase_key)
                .is_some_and(|t| *t > now_secs().saturating_sub(3600));
            if !ran {
                active.pool.connect_reads(Vec::new()).await.ok();
                let (read, write) = active
                    .pool
                    .nip65(me)
                    .await
                    .unwrap_or_else(|_| {
                        eprintln!("[core] nip65 fetch failed or timed out");
                        (Vec::new(), Vec::new())
                    });
                eprintln!(
                    "[core] bootstrap: {} read relay(s), {} write relay(s)",
                    read.len(),
                    write.len()
                );
                active.read_relays = read.clone();
                active.write_relays = write.clone();
                if let Some(a) = self.active.lock().unwrap().as_mut() {
                    a.read_relays = read.clone();
                    a.write_relays = write;
                }
                let n = crate::outbox_queue::len();
                if n > 0 {
                    eprintln!("[core] outbox: {n} item(s) pending, drain armed");
                }
                active.pool.connect_reads(read.clone()).await.ok();
                self.spawn_relay_info(&read);
                // D48: the anti-spam ledgers reload before anything can
                // paint — dedup's caught-spammer records + recent keys,
                // the velocity stamps + counted ids, the receipted
                // suppressions. Boot gates from last session's knowledge
                // instead of re-learning it from relays (a minute of
                // spam on the first frame). Guards make re-arms no-ops.
                crate::dedup::load_disk();
                crate::rate::load_disk();
                load_suppressed_disk();
                // Arm the trust vocabulary from LOCAL state first (D45):
                // the fresh contact-list fetch below is a relay round-trip,
                // and until the graph is armed every verdict reads Unknown,
                // which lets the notification tier pass everything — spam
                // painted first and got cleaned up a minute later. The
                // store's cached own list + the wot sidecar are local
                // reads; gating must be correct from the FIRST paint.
                // The fresh fetch below re-arms with a newer list (all
                // rebuilds are idempotent and ms-cheap; observe is
                // newest-wins).
                if let Ok(Some(own)) = active
                    .pool
                    .store
                    .latest_by_kind(me, Kind::ContactList)
                    .await
                {
                    let local_follows: Vec<PublicKey> =
                        own.tags.public_keys().collect();
                    crate::wot::set_identity(me, &local_follows);
                    crate::wot::set_muted(self.muted.lock().unwrap().clone());
                    crate::dedup::set_exemptions(me, &local_follows);
                    self.rebuild_wot_graph(&active, &local_follows).await;
                }
                let follows = active.pool.follows(me).await.unwrap_or_default();
                active.follows = follows.clone();
                if let Some(a) = self.active.lock().unwrap().as_mut() {
                    a.follows = follows.clone();
                }
                if !follows.is_empty() {
                    crate::read_state::advance(|st| {
                        st.warm_at.insert(phase_key.clone(), now_secs());
                    });
                }
            } else {
                // The phase ran recently (this or a previous launch): no
                // relay round trips for nip65/follows. But the pool is
                // PER PROCESS — the session's reads must still join it,
                // from the store's copy of the own kind:10002 (no
                // network). Without this the main live sub armed with
                // zero relays and "subscribe failed; re-arming" every
                // surface (live loop, stderr8).
                let (read, write): (Vec<String>, Vec<String>) = active
                    .pool
                    .store
                    .latest_by_kind(me, Kind::RelayList)
                    .await
                    .ok()
                    .flatten()
                    .map(|ev| {
                        let lists = outbox::parse_relay_list(&ev);
                        (lists.read.into_iter().collect(), lists.write.into_iter().collect())
                    })
                    .unwrap_or_default();
                if !read.is_empty() {
                    active.read_relays = read.clone();
                    if let Some(a) = self.active.lock().unwrap().as_mut() {
                        a.read_relays = read.clone();
                    }
                    active.pool.connect_reads(read.clone()).await.ok();
                    self.spawn_relay_info(&read);
                } else {
                    // No cached list at all: indexers only, still connect.
                    active.pool.connect_reads(Vec::new()).await.ok();
                    self.spawn_relay_info(&[]);
                }
                // D36: the WRITE half too. A warm start previously left
                // the write set empty (only `.read` was hydrated), so
                // every publish — commit or outbox drain — fell back to
                // the indexer fan-out instead of the user's declared
                // write relays until the next full phase ran (the
                // three recovered notes went out via indexers for
                // exactly this reason). Same staleness contract as the
                // read half: the store copy until a full phase refreshes.
                if !write.is_empty() {
                    eprintln!("[core] bootstrap: write set from store: {} relay(s)", write.len());
                    active.write_relays = write.clone();
                    if let Some(a) = self.active.lock().unwrap().as_mut() {
                        a.write_relays = write;
                    }
                }
                // The phase already landed the fresh contact list; pick it
                // up (a store read).
                if let Ok(Some(ev)) =
                    active.pool.store.latest_by_kind(me, Kind::ContactList).await
                {
                    let follows: Vec<PublicKey> = ev.tags.public_keys().collect();
                    active.follows = follows.clone();
                    if let Some(a) = self.active.lock().unwrap().as_mut() {
                        a.follows = follows;
                    }
                }
            }
        }
        // The phase (or its store pickup) left active.follows authoritative.
        let follows = active.follows.clone();
        // Trust graph (issue #2 WS1): arm the WoT vocabulary + dedup
        // exemptions for this session, then rebuild the two-hop graph
        // from the store's cached kind-3s (an in-memory projection —
        // new kind-3s apply incrementally at the chokepoint/live bell).
        crate::wot::set_identity(me, &follows);
        crate::wot::set_muted(self.muted.lock().unwrap().clone());
        crate::dedup::set_exemptions(me, &follows);
        self.rebuild_wot_graph(&active, &follows).await;
        self.start_live(kinds.clone()).await;

        // Profiles + engagement + deep fetch: parallel, none block paint.
        let mut warm_set = follows.clone();
        warm_set.push(me);
        active.profiles.warm(warm_set);

        // The warm skip is per surface (keyed by kind set) — a timeline
        // deep-filled five minutes ago says nothing about the articles
        // shelf's store depth.
        let warm_key: String = {
            let mut ks: Vec<u16> = kinds.iter().map(|k| u16::from(*k)).collect();
            ks.sort();
            ks.dedup();
            ks.iter().map(|k| k.to_string()).collect::<Vec<_>>().join(",")
        };
        let warm = crate::read_state::load()
            .warm_at
            .get(&warm_key)
            .is_some_and(|t| *t > now_secs().saturating_sub(600));
        // Only a deep fetch that actually RAN earns the stamp — stamping a
        // skipped bootstrap would let a surface opened every few minutes
        // defer its fill forever.
        let ran_deep = !follows.is_empty() && !warm;
        // The fetches' values are not read: their effect is the SDK's
        // save-on-receive; the page projects from the store below.
        let (engagement, fetched, _dels) = tokio::join!(
            async {
                let mine = Filter::new()
                    .author(me)
                    .kinds([
                        Kind::Reaction,
                        Kind::Repost,
                        Kind::Custom(16),
                        Kind::Custom(10003),
                        // D38 v1.1: the own surfaces the store never had a
                        // fetch for — the public bookmarks list (30001),
                        // the NIP-51 named lists (30000, one per d) and the
                        // web app's NIP-37 draft wraps (31234, retired
                        // format, imported into the 30078 stash).
                        Kind::Custom(30000),
                        Kind::Custom(30001),
                        Kind::Custom(31234),
                    ])
                    .limit(2000);
                active.pool.get(mine).await.unwrap_or_default()
            },
            async {
                if !follows.is_empty() && !warm {
                    let filter = Filter::new()
                        .kinds(kinds.clone())
                        .authors(follows.clone())
                        .limit(BOOTSTRAP_DEPTH);
                    active.pool.get(filter).await.unwrap_or_default()
                } else {
                    eprintln!(
                        "[core] deep fetch skipped: follows_empty={} warm={}",
                        follows.is_empty(),
                        warm
                    );
                    Default::default()
                }
            },
            // Deletions ride along (NIP-09): rare, follows-scoped, needed
            // before the render filter can drop what they cover. The
            // chokepoint consumes the kind:5s (records them, filters them
            // from the set), so the arm's value is the tombstones it
            // seeds plus the ordering — the projection waits on it.
            async {
                if !follows.is_empty() && !warm {
                    let filter = Filter::new()
                        .kind(Kind::EventDeletion)
                        .authors(follows.clone())
                        .limit(500);
                    let _ = active.pool.get(filter).await;
                }
                0usize
            }
        );
        eprintln!(
            "[core] deep fetch: {} events",
            engagement.len() + fetched.len()
        );
        // No explicit saves: the SDK persists every relay-received event
        // before notifying (relay/inner.rs), so these loops re-saved what
        // was already on disk (audit perf M2). The page projects from the
        // store below.
        self.load_own_sets(&active).await;

        if ran_deep {
            crate::read_state::advance(|st| {
                st.warm_at.insert(warm_key, now_secs());
            });
        }
        let page = self.page_from_store(&active, None, &kinds).await?;
        eprintln!("[core] bootstrap page: {} notes", page.notes.len());
        let _ = tx.send(FeedEvent::Loaded(page));
        Ok(())
    }



    async fn load_own_sets(&self, active: &Active) {
        let me = active.me();
        if let Ok(reactions) = active.pool.store.own_reactions(me).await {
            let mut liked = self.own_liked.lock().unwrap();
            for ev in reactions {
                if let Some(target) = ev.tags.clone().event_ids().next() {
                    liked.insert(target.to_string());
                }
            }
        }

        // Own reposts (kind 6 and its generic cousin 16): the e-tag IS the
        // target.
        if let Ok(reposts) = active.pool.store.own_reposts(me).await {
            let mut rp = self.own_reposted.lock().unwrap();
            for ev in reposts {
                if let Some(target) = ev.tags.clone().event_ids().next() {
                    rp.insert(target.to_string());
                }
            }
        }

        // Private lists (NIP-51, content = nip44-encrypted tag JSON — the web
        // app's private-by-default semantics): bookmarks 10003, mutes 10000.
        if let Ok(Some(ev)) = active
            .pool
            .store
            .latest_by_kind(me, Kind::Custom(10003))
            .await
        {
            if !ev.content.is_empty()
                && let Ok(plain) = active.signer.nip44_decrypt_self(&me, ev.content.as_str()).await {
                    let mut b = self.own_bookmarked.lock().unwrap();
                    for id in parse_list_event(&plain) {
                        b.insert(id);
                    }
                }
            // Public tags still count (merge public+private — list semantics).
            let mut b = self.own_bookmarked.lock().unwrap();
            for id in ev.tags.clone().event_ids() {
                b.insert(id.to_string());
            }
        }

        // The public bookmarks list (D38: NIP-51 kind 30001 d="bookmarks")
        // merges into the same display set — the star fills for either,
        // unbookmarking clears both.
        if let Ok(Some(ev)) = active
            .pool
            .store
            .latest_by_kind_d(me, Kind::Custom(30001), "bookmarks")
            .await
        {
            let mut b = self.own_bookmarked.lock().unwrap();
            for id in ev.tags.clone().event_ids() {
                b.insert(id.to_string());
            }
        }

        // The web app's synced drafts (NIP-37 kind 31234 wraps — retired
        // with the web app): content = nip44-to-self of the inner draft
        // event, d = the draft id, empty content = deleted. They migrate
        // into the same array as id-marked entries (deduped by id across
        // logins); the Library shows them and opening/deleting one
        // republishes the wrap empty (NIP-37's delete) — the moment the
        // text becomes a Satori slot draft.
        if let Ok(wraps) = active
            .pool
            .store
            .all_by_kind(me, Kind::Custom(31234))
            .await
        {
            // Parameterized replaceable: the newest wrap per d wins.
            let mut newest: HashMap<String, Event> = HashMap::new();
            for wrap in wraps {
                let Some(d) = wrap
                    .tags
                    .clone()
                    .to_vec()
                    .iter()
                    .find(|t| t.kind() == "d")
                    .and_then(|t| t.content().map(str::to_string))
                else {
                    continue;
                };
                match newest.get(&d) {
                    Some(old) if old.created_at >= wrap.created_at => {}
                    _ => {
                        newest.insert(d, wrap);
                    }
                }
            }
            let mut drafts = self.own_drafts.lock().unwrap().clone();
            for (d, wrap) in newest {
                if wrap.content.trim().is_empty() || nip40::is_expired(&wrap) {
                    continue;
                }
                if drafts.iter().any(|e| e.id.as_deref() == Some(d.as_str())) {
                    continue;
                }
                let Ok(plain) = active
                    .signer
                    .nip44_decrypt_self(&me, wrap.content.as_str())
                    .await
                else {
                    continue;
                };
                // The inner event: {kind, created_at, tags, content} — our
                // own data, but stay crash-proof (the TS parse's posture).
                let Ok(inner) = serde_json::from_str::<serde_json::Value>(&plain) else {
                    continue;
                };
                let kind = inner.get("kind").and_then(|k| k.as_u64()).unwrap_or(0);
                let content = inner
                    .get("content")
                    .and_then(|c| c.as_str())
                    .unwrap_or("")
                    .to_string();
                let title = inner.get("tags").and_then(|t| t.as_array()).and_then(|tags| {
                    tags.iter().find_map(|t| {
                        let arr = t.as_array()?;
                        if arr.first()?.as_str()? == "title" {
                            arr.get(1)?.as_str().map(str::to_string)
                        } else {
                            None
                        }
                    })
                });
                // A note draft keeps its text; an article's body rides its
                // title; a poll's question is the text.
                let text = match kind {
                    30023 => match (&title, content.is_empty()) {
                        (Some(t), false) => format!("{t}\n\n{content}"),
                        (Some(t), true) => t.clone(),
                        _ => content,
                    },
                    _ => content,
                };
                if text.trim().is_empty() {
                    continue;
                }
                drafts.push(DraftEntry {
                    text,
                    reply_to: None,
                    quote: None,
                    id: Some(d),
                    attachments: Vec::new(),
                    photo_post: false,
                    at: wrap.created_at.as_secs(),
                });
            }
            *self.own_drafts.lock().unwrap() = drafts;
        }

        // Synced drafts (D38): NIP-78 kind 30078 d="satori/drafts" — one
        // replaceable event, the draft array nip44-encrypted (self).
        if let Ok(Some(ev)) = active
            .pool
            .store
            .latest_by_kind_d(me, Kind::Custom(30078), "satori/drafts")
            .await
            && !ev.content.is_empty()
            && let Ok(plain) = active
                .signer
                .nip44_decrypt_self(&me, ev.content.as_str())
                .await
            && let Ok(entries) = serde_json::from_str::<Vec<DraftEntry>>(&plain)
        {
            *self.own_drafts.lock().unwrap() = entries;
        }

        if let Ok(Some(ev)) = active
            .pool
            .store
            .latest_by_kind(me, Kind::Custom(10000))
            .await
        {
            let decrypted: Vec<String> = if ev.content.is_empty() {
                Vec::new()
            } else {
                active
                    .signer
                    .nip44_decrypt_self(&me, ev.content.as_str())
                    .await
                    .map(|plain| parse_list_event(&plain))
                    .unwrap_or_default()
            };
            let mut m = self.muted.lock().unwrap();
            for pk in decrypted {
                m.insert(pk);
            }
            for pk in ev.tags.clone().public_keys() {
                m.insert(pk.to_string());
            }
            drop(m);
            // The WoT graph consults mutes at qualification time
            // (dark-wisp filters muted/blocked out) — push the set.
            crate::wot::set_muted(self.muted.lock().unwrap().clone());
        }
    }

    /// Newest page (home button): relay fetch since the newest known note.
    pub fn refresh(self: &Arc<Self>, kinds: Vec<Kind>) -> FeedRx {
        let (tx, rx) = mpsc::unbounded_channel();
        // Single-flight (audit perf M4): overlapping refreshes stacked
        // full routed fan-outs. A click while one runs drops the new tx —
        // the caller's pump sees the closed channel and exits quietly;
        // the running refresh lands its Loaded anyway.
        if self.refreshing.swap(true, std::sync::atomic::Ordering::SeqCst) {
            return rx;
        }
        let this = Arc::clone(self);
        self.rt.spawn(async move {
            if let Err(e) = this.refresh_inner(&tx, kinds).await {
                let _ = tx.send(FeedEvent::Failed(e.to_string()));
            }
            this.refreshing
                .store(false, std::sync::atomic::Ordering::SeqCst);
        });
        rx
    }

    async fn refresh_inner(
        &self,
        tx: &mpsc::UnboundedSender<FeedEvent>,
        kinds: Vec<Kind>,
    ) -> Result<()> {
        let active = self.active().await?;
        let follows = active.follows.clone();
        if follows.is_empty() {
            return self.bootstrap_inner(tx, kinds).await;
        }
        // The 'since' probe: newest known kind-1 (newest_created_at docs:
        // the all-kinds page materialized one event per author-kind pair,
        // ~7,000 for 500 follows, on every refresh). A kind-1-only newest
        // underestimates, which just widens the refetch window.
        let since = active
            .pool
            .store
            .newest_created_at(&follows)
            .await
            .map_err(|e| LoginError::Resume(e.to_string()))?
            .unwrap_or(0);
        // The full outbox model (nip65.ts routeAuthorsToRelays): each follow
        // is read from the relays THEY write to — set-cover-bounded, 2x
        // redundancy, orphans recovered to their own relays. The guard
        // upstream already sent no-follow accounts to the bootstrap; the
        // call's own guard makes the empty case a no-op regardless.
        let fetched = active
            .pool
            .get_routed(kinds.clone(), &follows, Some(Timestamp::from(since)), None, 100)
            .await;
        if fetched.is_empty() {
            // Relays unreachable (post-suspend, offline): this used to end
            // the refresh as NothingNew — which the feed swallows — so a
            // new-notes chip click no-oped until the relays recovered. The
            // live sub saves pushed notes to the store even while relays
            // are down, so project from the store regardless: the missed
            // notes appear with zero relay round-trips.
            crate::dlog!("refresh: relay fetch empty; projecting the store");
            let page = self.page_from_store(&active, None, &kinds).await?;
            let _ = tx.send(FeedEvent::Loaded(page));
            return Ok(());
        }
        // The SDK saves what it receives; the store projection follows.
        if !follows.is_empty() {
            let del_filter = Filter::new()
                .kind(Kind::EventDeletion)
                .authors(follows.clone())
                .since(Timestamp::from(since.saturating_sub(86400)));
            let _ = active.pool.get(del_filter).await;
        }
        let page = self.page_from_store(&active, None, &kinds).await?;
        eprintln!("[core] bootstrap page: {} notes", page.notes.len());
        let _ = tx.send(FeedEvent::Loaded(page));
        Ok(())
    }

    /// Older page: project the store; when it runs dry, top up from the
    /// relays — strictly older than `until` (the oldest note currently
    /// shown), all visible kinds — and project again. The store stays the
    /// chokepoint; the relays are the reservoir.
    pub fn older(self: &Arc<Self>, until: u64, kinds: Vec<Kind>) -> FeedRx {
        let (tx, rx) = mpsc::unbounded_channel();
        let this = Arc::clone(self);
        self.rt.spawn(async move {
            let res: Result<FeedEvent> = async {
                let active = this.active().await?;
                let mut notes = this.project_page(&active, Some(until), &kinds).await?;
                // NIP-01: an empty list can never match — with no follows
                // there is nothing to top up from the relays.
                if notes.len() <= PAGE && !active.follows.is_empty() {
                    // Outbox routing: strictly older than the page bottom,
                    // from each follow's own write relays. The value is not
                    // read - the SDK saves what it receives.
                    let _ = active
                        .pool
                        .get_routed(
                            kinds.clone(),
                            &active.follows,
                            None,
                            Some(Timestamp::from(until)),
                            TOPUP_DEPTH,
                        )
                        .await;
                    // (no explicit save: the SDK persists what it receives;
                    // commit() saves own events)
                    // Deletions ride along (NIP-09).
                    let del_filter = Filter::new()
                        .kind(Kind::EventDeletion)
                        .authors(active.follows.clone())
                        .until(Timestamp::from(until))
                        .limit(500);
                    let _ = active.pool.get(del_filter).await;
                    notes = this.project_page(&active, Some(until), &kinds).await?;
                }
                let has_more = notes.len() > PAGE;
                notes.truncate(PAGE);
                let profiles = Self::profiles_for(&active, &notes).await;
                Ok(FeedEvent::Older(FeedPage { notes, profiles }, has_more))
            }
            .await;
            match res {
                Ok(ev) => {
                    let _ = tx.send(ev);
                }
                Err(e) => {
                    let _ = tx.send(FeedEvent::Failed(e.to_string()));
                }
            }
        });
        rx
    }

    fn absorb_profiles(&self, profiles: &[Profile]) {
        let mut m = self.profiles_mem.lock().unwrap();
        for p in profiles {
            m.insert(p.clone());
        }
    }

    /// Resolve profiles reactively: cards call this with whatever pks they
    /// need; the service coalesces + fetches, the UI patches on arrival.
    pub fn ensure_profiles(self: &Arc<Self>, pks: Vec<PublicKey>) -> FeedRx {
        let (tx, rx) = mpsc::unbounded_channel();
        match &*self.active.lock().unwrap() {
            Some(active) => {
                let service = Arc::clone(&active.profiles);
                let service2 = Arc::clone(&active.profiles);
                self.rt.spawn(async move {
                    let mut inner = service.ensure_many(pks);
                    while let Some(profs) = inner.recv().await {
                        let _ = tx.send(FeedEvent::Profiles(profs));
                    }
                    let _ = service2;
                });
            }
            None => {
                let _ = tx.send(FeedEvent::Profiles(Vec::new()));
            }
        }
        rx
    }

    /// Display resolution for inline mentions (content.ts: @names from the
    /// profile cache; misses render as short npubs).
    pub fn profile_of(&self, pk: &PublicKey) -> Option<Profile> {
        self.profiles_mem.lock().unwrap().get(&pk.to_string()).cloned()
    }

    /// @-mention candidates for the composer: the people you follow whose
    /// cached name (or pubkey hex) matches the typed handle. Profiles not
    /// yet in the cache match only by hex — the profiles service fills the
    /// rest as the feed loads them. One lock, eight hits max: this runs
    /// per keystroke.
    pub fn mention_candidates(&self, query: &str) -> Vec<Profile> {
        let (follows, me): (Vec<PublicKey>, String) = {
            let held = self.active.lock().unwrap();
            let me = held
                .as_ref()
                .map(|a| a.session.pubkey.clone())
                .unwrap_or_default();
            let follows = held.as_ref().map(|a| a.follows.clone()).unwrap_or_default();
            (follows, me)
        };
        let q = query.to_lowercase();
        let m = self.profiles_mem.lock().unwrap();
        let mut out: Vec<Profile> = Vec::new();
        for pk in &follows {
            if pk.to_string() == me {
                continue;
            }
            let Some(p) = m.get(&pk.to_string()) else {
                continue;
            };
            if q.is_empty()
                || p.name.to_lowercase().contains(&q)
                || p.pubkey.to_lowercase().contains(&q)
            {
                out.push(p.clone());
                if out.len() == 8 {
                    break;
                }
            }
        }
        out
    }

    /// People results for the search pane: a substring scan of the hydrated
    /// profile cache (name, NIP-05, pubkey hex), any author — mention
    /// candidates without the follow gate. Cache-local by design: kind-0
    /// search is thin relay-side, and the cache hydrates as the session
    /// reads. Sorted by name so the rows hold still run to run.
    pub fn search_people(&self, query: &str) -> Vec<Profile> {
        let q = query.trim().to_lowercase();
        if q.is_empty() {
            return vec![];
        }
        let m = self.profiles_mem.lock().unwrap();
        let mut hits: Vec<Profile> = m
            .values()
            .filter(|p| {
                p.name.to_lowercase().contains(&q)
                    || p.nip05.to_lowercase().contains(&q)
                    || p.pubkey.to_lowercase().contains(&q)
            })
            .cloned()
            .collect();
        hits.sort_by_key(|p| p.name.to_lowercase());
        // The search pane's People tab is a proper results page now (not a
        // sidebar strip) — room for a real page.
        hits.truncate(20);
        hits
    }

    fn active_pubkey(&self) -> String {        self.active
            .lock()
            .unwrap()
            .as_ref()
            .map(|a| a.session.pubkey.clone())
            .unwrap_or_default()
    }

    /// The active account's pubkey, when logged in — scheduled_list /
    /// scheduled_cancel gate on it (only the author touches their posts).
    fn active_pubkey_opt(&self) -> Option<PublicKey> {
        PublicKey::from_str(&self.active_pubkey()).ok()
    }

    /// One page projection: store query (a PAGE+1 window so "has more" is
    /// knowable), then the mutes gate at the chokepoint.
    /// NIP-09/NIP-40 render filter: drop events their own author deleted
    /// (deletions.rs tombstone lookups — O(1), persisted, fed by the pool
    /// chokepoint) and events whose NIP-40 expiration has passed (the SDK
    /// persists expired copies; they must not paint). A stranger's
    /// kind:5 can't delete your notes, so the author must match — the
    /// tombstone store enforces that structurally.
    fn drop_deleted(&self, notes: Vec<Event>) -> Vec<Event> {
        // One-time hydration: tombstones that entered the store BEFORE
        // the deletions module shipped would otherwise resurrect (the
        // module's own file starts empty). Idempotent — record keeps the
        // newest per key.
        if !self
            .tombstones_hydrated
            .swap(true, std::sync::atomic::Ordering::SeqCst)
        {
            let pool = self.pool.lock().unwrap().as_ref().map(Arc::clone);
            if let Some(pool) = pool {
                self.rt.spawn(async move {
                    if let Ok(tombs) = pool.store.tombstones().await {
                        for t in &tombs {
                            crate::deletions::record(t, false);
                        }
                        eprintln!("[core] tombstones hydrated: {}", tombs.len());
                    }
                });
            }
        }
        notes
            .into_iter()
            .filter(|ev| !crate::nip40::is_expired(ev) && !crate::deletions::is_deleted(ev))
            .collect()
    }

    async fn project_page(
        &self,
        active: &Active,
        until: Option<u64>,
        kinds: &[Kind],
    ) -> Result<Vec<Event>> {
        let mut notes = active
            .pool
            .store
            .feed_page_kinds(&active.follows, until, PAGE + 1, kinds.to_vec())
            .await
            .map_err(|e| LoginError::Resume(e.to_string()))?;
        {
            let muted = self.muted.lock().unwrap();
            notes.retain(|ev| !muted.contains(&ev.pubkey.to_string()));
        }
        Ok(self.drop_deleted(notes))
    }

    async fn page_from_store(
        &self,
        active: &Active,
        until: Option<u64>,
        kinds: &[Kind],
    ) -> Result<FeedPage> {
        let follows = active.follows.clone();
        let mut notes = active
            .pool
            .store
            .feed_page_kinds(&follows, until, PAGE, kinds.to_vec())
            .await
            .map_err(|e| LoginError::Resume(e.to_string()))?;
        // Mutes + deletions gate here — every feed page passes this
        // chokepoint (pool.ts: NIP-09/NIP-40 consume-at-the-chokepoint role).
        {
            let muted = self.muted.lock().unwrap();
            notes.retain(|ev| !muted.contains(&ev.pubkey.to_string()));
        }
        notes = self.drop_deleted(notes);
        let profiles = Self::profiles_for(active, &notes).await;
        self.absorb_profiles(&profiles);
        for p in &profiles {
            active.profiles.absorb(p.clone());
        }
        Ok(FeedPage { notes, profiles })
    }

    async fn profiles_for(active: &Active, notes: &[Event]) -> Vec<Profile> {
        let authors: Vec<PublicKey> = notes.iter().map(|e| e.pubkey).collect();
        let cached = active
            .pool
            .store
            .profiles(&authors)
            .await
            .unwrap_or_default();
        let mut profiles: Vec<Profile> = cached
            .iter()
            .filter_map(Profile::from_event)
            .collect();
        // Fresh metadata for authors missing from the cache.
        let mut seen = std::collections::HashSet::new();
        let missing: Vec<PublicKey> = authors
            .iter()
            .filter(|a| !profiles.iter().any(|p| p.pubkey == a.to_string()))
            .filter(|a| seen.insert(a.to_string()))
            .cloned()
            .collect();
        if !missing.is_empty() {
            let filter = Filter::new().kind(Kind::Metadata).authors(missing.clone()).limit(500);
            // The SDK saves what it receives; `fresh` reads the store.
            let _ = active.pool.get(filter).await;
            let fresh = active
                .pool
                .store
                .profiles(&missing)
                .await
                .unwrap_or_default();
            for p in fresh.iter().filter_map(Profile::from_event) {
                if !profiles.iter().any(|q| q.pubkey == p.pubkey) {
                    profiles.push(p);
                }
            }
        }
        profiles
    }

    // --- notifications ------------------------------------------------------------

    /// The notification stream (port of `src/data/notifications.ts`, slice 1):
    /// replies to my notes + mentions (#p=me), newest first, own events
    /// dropped, reactions/poll-votes/zap classes land with their milestones.
    pub fn notifications(self: &Arc<Self>) -> FeedRx {
        let (tx, rx) = mpsc::unbounded_channel();
        let this = Arc::clone(self);
        self.rt.spawn(async move {
            let res: Result<(Vec<Event>, Vec<Profile>, bool)> = async {
                let active = this.active().await?;
                let me = active.me();

                // Cached candidates paint instantly; the relay phase runs in
                // parallel below and the response re-renders.
                let my_notes = active
                    .pool
                    .store
                    // 500, not 100: bots hunt OLDER notes (a reply to
                    // anything past the window isn't a "reply" and would
                    // ring the bell ungated). 500 own ids is still one
                    // small HashSet (D24: bounded, named).
                    .feed_page(&[me], None, 500)
                    .await
                    .unwrap_or_default();
                let ids: Vec<EventId> = my_notes.iter().map(|e| e.id).collect();

                // Instant paint: the store's cached candidates (kind-1
                // replies, NIP-22 comments — the Amethyst migration
                // made 1111 the carrier for non-kind-1 replies — and the
                // engagement kinds: reactions/zaps/votes by `e` tag).
                // Three batched index passes for the whole id set: this
                // used to run one query per category PER NOTE — up to 300
                // sequential LMDB transactions for a 100-note window.
                let reaction_notifs = this.reaction_notifs();
                let mut cached: Vec<Event> = Vec::new();
                cached.extend(
                    active
                        .pool
                        .store
                        .replies_of(ids.clone())
                        .await
                        .unwrap_or_default(),
                );
                cached.extend(
                    active
                        .pool
                        .store
                        .comments_of(ids.clone())
                        .await
                        .unwrap_or_default(),
                );
                cached.extend(
                    active
                        .pool
                        .store
                        .engagement_of(ids.clone())
                        .await
                        .unwrap_or_default(),
                );
                cached.retain(|ev| ev.pubkey != me);
                // The relay phase filters these too — the cached phase
                // must wear the same gates (a cold start previously showed
                // a stranger's thumbs-down the relay phase would have
                // dropped, and reactions when the pref was off).
                cached.retain(|ev| {
                    !(u16::from(ev.kind) == 7
                        && (!reaction_notifs || ev.content.trim() == "-"))
                });
                // The chokepoint gates too: the union keeps cached rows in
                // the final page, so a deleted (NIP-09) or expired
                // (NIP-40) cached copy must not paint here either.
                cached.retain(|ev| !nip40::is_expired(ev) && !deletions::is_deleted(ev));
                {
                    let muted = this.muted.lock().unwrap();
                    cached.retain(|ev| !muted.contains(&ev.pubkey.to_string()));
                }
                // The WoT tier (WS4): out-of-network reactions/reposts come
                // out as receipts — the cached phase's list rides the same
                // gates the relay phase wears (the phase-equality rule
                // above). The final union re-splits; the receipts store
                // holds the union.
                let my_note_ids: HashSet<EventId> = ids.iter().copied().collect();
                let (kept, mut cached_suppressed) =
                    split_wot_tier(cached, &my_note_ids, false);
                cached = kept;
                {
                    let authors: Vec<PublicKey> = cached.iter().map(|e| e.pubkey).collect();
                    let profiles = active
                        .pool
                        .store
                        .profiles(&authors)
                        .await
                        .unwrap_or_default()
                        .iter()
                        .filter_map(Profile::from_event)
                        .collect();
                    // A clone rides the instant paint; `cached` stays here
                    // for the final union (below) — the second emit must be
                    // a SUPERSET of the first, never a replacement.
                    let _ = tx.send(FeedEvent::Notifications(cached.clone(), profiles));
                }

                let since = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0)
                    .saturating_sub(7 * 86400);

                // Mentions (#p=me) and replies (#e=my notes): PARALLEL.
                // (The pref was already read for the cached phase — no
                // second disk read here.)
                let mut mention_kinds = vec![Kind::TextNote, Kind::Custom(1111), Kind::Custom(9735)];
                if reaction_notifs {
                    mention_kinds.push(Kind::Reaction);
                }
                let mention_q = Box::pin(active.pool.get(
                    Filter::new()
                        .kinds(mention_kinds)
                        .pubkeys([me])
                        .since(Timestamp::from(since))
                        .limit(200),
                ));
                let reply_q = if ids.is_empty() {
                    None
                } else {
                    Some(Box::pin(active.pool.get(
                        Filter::new()
                            .kinds([Kind::TextNote, Kind::Custom(1111)])
                            .events(ids)
                            .since(Timestamp::from(since))
                            .limit(200),
                    )))
                };
                let poll_ids: Vec<EventId> = my_notes
                    .iter()
                    .filter(|e| u16::from(e.kind) == 1068)
                    .map(|e| e.id)
                    .collect();
                let vote_q = Box::pin(async {
                    if poll_ids.is_empty() {
                        return Default::default();
                    }
                    let mut f = Filter::new()
                        .kind(Kind::Custom(1018))
                        .since(Timestamp::from(since))
                        .limit(200);
                    for id in poll_ids {
                        f = f.event(id);
                    }
                    active.pool.get(f).await.unwrap_or_default()
                });
                let (mentions_res, replies_res, votes_res) = tokio::join!(mention_q, async {
                    match reply_q {
                        Some(q) => q.await.unwrap_or_default(),
                        None => Default::default(),
                    }
                }, vote_q);
                let mine_events: Vec<Event> = mentions_res
                    .into_iter()
                    .flat_map(|set| set.into_iter())
                    .chain(replies_res)
                    .chain(votes_res)
                    .collect();
                // (no explicit save: the SDK persists what it receives)

                // Dedup + drop own + sort desc — as a UNION with the
                // cached paint, not a replacement. The two phases have
                // different memberships (the cached paint is
                // replies/comments/engagement on my recent notes, any age;
                // the relay phase is mentions/replies/votes within the
                // 7-day window), so emitting the relay set ALONE made the
                // list visibly reload on every open: old rows vanished
                // while the window's new ones appeared. The union keeps
                // both: the page paints instantly, then only GROWS as the
                // fresh rows land on top.
                let mut seen = std::collections::HashSet::new();
                let muted = this.muted.lock().unwrap().clone();
                let mut notifs: Vec<Event> = mine_events
                    .into_iter()
                    .chain(cached)
                    .filter(|ev| {
                        ev.pubkey != me
                            && seen.insert(ev.id)
                            && !muted.contains(&ev.pubkey.to_string())
                            // A stranger's thumbs-down is pure agitation
                            // (notifications.ts): never shown. +/emoji stay.
                            && !(u16::from(ev.kind) == 7 && ev.content.trim() == "-")
                    })
                    .collect();
                notifs.sort_by_key(|e| std::cmp::Reverse(e.created_at.as_secs()));

                // The tier on the final union, then the receipts store
                // becomes the union of both phases' pulls (deduped by id) —
                // the bell's "N hidden" reads exactly this.
                // `count_velocity = true`: this is the delivering split —
                // the receipts store is written from it, so only its
                // admitted replies feed the velocity counter (a suppressed
                // reply must never count toward the flood verdict; the
                // cached-phase pass above checked the gate without
                // counting).
                let (kept, mut suppressed) = split_wot_tier(notifs, &my_note_ids, true);
                cached_suppressed.append(&mut suppressed);
                let mut seen_sup = HashSet::new();
                cached_suppressed.retain(|s| seen_sup.insert(s.event.id));
                *SUPPRESSED.lock().unwrap() = cached_suppressed;
                suppressed_dirty(); // the receipts ledger persists (D48)
                let notifs = kept;

                let authors: Vec<PublicKey> = notifs.iter().map(|e| e.pubkey).collect();
                let cached = active
                    .pool
                    .store
                    .profiles(&authors)
                    .await
                    .unwrap_or_default();
                let profiles: Vec<Profile> =
                    cached.iter().filter_map(Profile::from_event).collect();

                // Dot state: anything newer than the high-water?
                let high_water = crate::read_state::load().notif;
                let unread = notifs
                    .first()
                    .map(|e| e.created_at.as_secs() > high_water)
                    .unwrap_or(false);

                Ok((notifs, profiles, unread))
            }
            .await;
            match res {
                Ok((notifs, profiles, unread)) => {
                    let _ = tx.send(FeedEvent::Notifications(notifs, profiles));
                    let _ = tx.send(FeedEvent::NotifDot(unread));
                }
                Err(e) => {
                    let _ = tx.send(FeedEvent::Failed(e.to_string()));
                }
            }
        });
        rx
    }

    /// The "Show reactions in notifications" pref (prefs.json
    /// reactionNotifs, default off — render/settings.ts PREF_LABELS).
    fn reaction_notifs(&self) -> bool {
        crate::config::prefs()
            .and_then(|v| v.get("reactionNotifs").and_then(|b| b.as_bool()))
            .unwrap_or(false)
    }

    /// Opening the notifications page advances the high-water (monotonic).
    pub fn mark_notifications_seen(self: &Arc<Self>) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        crate::read_state::advance(|s| s.notif = s.notif.max(now));
    }

    /// Reply-presence: per note, who replied (up to 3, earliest first) —
    /// the web app's "faces" hydration (routes/feed.ts getFaces).
    pub fn reply_faces(self: &Arc<Self>, ids: Vec<EventId>) -> FeedRx {
        let (tx, rx) = mpsc::unbounded_channel();
        let this = Arc::clone(self);
        self.rt.spawn(async move {
            let res: Result<Vec<(EventId, Vec<PublicKey>)>> = async {
                let active = this.active().await?;
                let filter = Filter::new()
                    .kind(Kind::TextNote)
                    .events(ids.clone())
                    .limit(600);
                let mut out: Vec<(EventId, Vec<PublicKey>)> = Vec::new();
                let mut per_note: std::collections::HashMap<EventId, Vec<PublicKey>> =
                    std::collections::HashMap::new();
                let id_set: std::collections::HashSet<EventId> = ids.iter().copied().collect();
                let mut replies: Vec<Event> = active
                    .pool
                    .get(filter)
                    .await
                    .unwrap_or_default()
                    .into_iter()
                    .collect();
                replies.sort_by_key(|e| e.created_at.as_secs());
                for r in replies {
                    // Parent = last e tag within the requested set.
                    if let Some(pid) = r
                        .tags
                        .clone()
                        .event_ids()
                        .last()
                        .filter(|pid| id_set.contains(pid))
                    {
                        let names = per_note.entry(pid).or_default();
                        if names.len() < 3 && !names.contains(&r.pubkey) {
                            names.push(r.pubkey);
                        }
                    }
                }
                for (id, names) in per_note {
                    out.push((id, names));
                }
                Ok(out)
            }
            .await;
            match res {
                Ok(faces) => {
                    let _ = tx.send(FeedEvent::Faces(faces));
                }
                Err(e) => {
                    let _ = tx.send(FeedEvent::Failed(e.to_string()));
                }
            }
        });
        rx
    }

    /// Does the following feed hold notes newer than the last home view?
    /// (Quiet-dot poll — the store answers, no relays.)
    pub fn feed_dot(self: &Arc<Self>) -> FeedRx {
        let (tx, rx) = mpsc::unbounded_channel();
        let this = Arc::clone(self);
        self.rt.spawn(async move {
            let res: Result<bool> = async {
                let active = this.active().await?;
                // Same probe as refresh (newest_created_at docs): the
                // all-kinds page materialized one event per author-kind
                // pair per poll.
                let newest = active
                    .pool
                    .store
                    .newest_created_at(&active.follows)
                    .await
                    .map_err(|e| LoginError::Resume(e.to_string()))?;
                Ok(newest
                    .map(|t| t > crate::read_state::load().feed_seen)
                    .unwrap_or(false))
            }
            .await;
            match res {
                Ok(dot) => {
                    let _ = tx.send(FeedEvent::NotifDot(dot));
                }
                Err(e) => {
                    let _ = tx.send(FeedEvent::Failed(e.to_string()));
                }
            }
        });
        rx
    }

    /// Home opened: the feed is seen up to now (monotonic).
    pub fn mark_feed_seen(self: &Arc<Self>) {
        crate::read_state::advance(|s| s.feed_seen = s.feed_seen.max(now_secs()));
    }

    /// Export the user's list events (kinds 3/10000/10002/10003) as raw
    /// signed JSON — the list-backup.ts export.
    pub fn export_lists(self: &Arc<Self>) -> FeedRx {
        let (tx, rx) = mpsc::unbounded_channel();
        let this = Arc::clone(self);
        self.rt.spawn(async move {
            let res: Result<String> = async {
                let active = this.active().await?;
                let me = active.me();
                let filter = Filter::new().author(me).kinds([
                    Kind::ContactList,
                    Kind::Custom(10000),
                    Kind::Custom(10002),
                    Kind::Custom(10003),
                ]);
                let raw = active.pool.get(filter).await.unwrap_or_default();
                // Keep the newest per kind.
                let mut by_kind: std::collections::HashMap<u16, Event> =
                    std::collections::HashMap::new();
                for ev in raw {
                    by_kind.insert(u16::from(ev.kind), ev);
                }
                let events: Vec<&Event> = by_kind.values().collect();
                serde_json::to_string_pretty(&events)
                    .map_err(|e| LoginError::Resume(e.to_string()))
            }
            .await;
            match res {
                Ok(json) => {
                    let _ = tx.send(FeedEvent::BackupJson(json));
                }
                Err(e) => {
                    let _ = tx.send(FeedEvent::Failed(e.to_string()));
                }
            }
        });
        rx
    }

    /// Restore from a backup: re-sign each event fresh (list-backup.ts:
    /// replace = same tags/content, new created_at) and publish.
    pub fn import_lists(self: &Arc<Self>, json: String) -> PublishRx {
        let (tx, rx) = mpsc::unbounded_channel();
        let this = Arc::clone(self);
        self.rt.spawn(async move {
            let res: Result<u32> = async {
                let active = this.active().await?;
                let me = active.me();
                let events: Vec<Event> = serde_json::from_str(&json)
                    .map_err(|e| LoginError::Resume(format!("bad backup: {e}")))?;
                let mut n = 0;
                for ev in events {
                    if ev.pubkey != me {
                        continue; // only restore own lists
                    }
                    let unsigned = UnsignedEvent::new(
                        me,
                        Timestamp::now(),
                        ev.kind,
                        ev.tags.clone().to_vec(),
                        ev.content.clone(),
                    );
                    let signed = active.signer.sign_event(unsigned).await?;
                    Self::commit(&active, &signed, &tx).await?;
                    n += 1;
                }
                Ok(n)
            }
            .await;
            match res {
                Ok(n) => {
                    let _ = tx.send(PublishEvent::Restored(n));
                }
                Err(e) => {
                    let _ = tx.send(PublishEvent::Failed { token: 0, error: e.to_string() });
                }
            }
        });
        rx
    }

    /// Comments on a target (NIP-22 kind:1111), oldest first.
    pub fn comments(self: &Arc<Self>, target: crate::nip::comment::CommentTarget) -> FeedRx {
        let (tx, rx) = mpsc::unbounded_channel();
        let this = Arc::clone(self);
        self.rt.spawn(async move {
            let res: Result<(Vec<Event>, Vec<Profile>)> = async {
                let active = this.active().await?;
                let mut comments: Vec<Event> = Vec::new();
                for filter in target.fetch_filters() {
                    for ev in active.pool.get(filter).await.unwrap_or_default() {
                        comments.push(ev);
                    }
                }
                // (no explicit save: the SDK persists what it receives)
                // Dedup + oldest first.
                let mut seen = std::collections::HashSet::new();
                comments.retain(|ev| seen.insert(ev.id));
                comments.sort_by_key(|e| e.created_at.as_secs());
                let _authors: Vec<PublicKey> = comments.iter().map(|e| e.pubkey).collect();
                let profiles = Self::profiles_for(&active, &comments).await;
                this.absorb_profiles(&profiles);
                // Include target-author profile (fetch may be empty).

                Ok((comments, profiles))
            }
            .await;
            match res {
                Ok((comments, profiles)) => {
                    let _ = tx.send(FeedEvent::Comments(comments, profiles));
                }
                Err(e) => {
                    let _ = tx.send(FeedEvent::Failed(e.to_string()));
                }
            }
        });
        rx
    }

    /// Publish a comment (top-level when `parent` is None, else a reply).
    /// `imetas` (the uploaded NIP-92 arrays) ride the kind-1111 when the
    /// comment carries media — NIP-92 is event-kind agnostic, and dropping
    /// them here would silently lose an attachment on every reply to a
    /// non-kind-1 root (issue #3 WS1).
    pub fn comment(
        self: &Arc<Self>,
        content: String,
        target: crate::nip::comment::CommentTarget,
        parent: Option<Event>,
        mentions: Vec<PublicKey>,
        imetas: Vec<Vec<String>>,
    ) -> PublishRx {
        let (tx, rx) = mpsc::unbounded_channel();
        let this = Arc::clone(self);
        self.rt.spawn(async move {
            let res: Result<()> = async {
                let active = this.active().await?;
                let mut tags = match &parent {
                    Some(p) => crate::nip::comment::reply_tags(p, &target),
                    None => target.root_tags(),
                };
                let mut seen_p: Vec<String> = tags
                    .iter()
                    .filter(|t| t.as_slice().first().map(String::as_str) == Some("p"))
                    .filter_map(|t| t.as_slice().get(1).cloned())
                    .collect();
                for who in mentions {
                    let hex = who.to_string();
                    if hex != active.me().to_string() && !seen_p.contains(&hex) {
                        seen_p.push(hex.clone());
                        tags.push(Tag::public_key(who));
                    }
                }
                for m in &imetas {
                    if m.len() >= 2 && m[0] == "imeta" {
                        tags.push(Tag::custom("imeta", m[1..].iter()));
                    }
                }
                tags.push(Tag::custom("client", ["satori-desktop"]));
                let unsigned =
                    UnsignedEvent::new(active.me(), Timestamp::now(), Kind::Custom(1111), tags, content);
                let signed = active.signer.sign_event(unsigned).await?;
                // Same undo window as notes (the reply toast is the note
                // toast — one seam, hold_and_commit).
                match active.undo.hold_duration() {
                    Some(hold) => {
                        let token = this.hold_seq.fetch_add(1, Ordering::SeqCst);
                        let _ = tx.send(PublishEvent::Held {
                            token,
                            event: signed.clone(),
                            hold_secs: hold.as_secs(),
                        });
                        this.hold_and_commit(
                            Arc::new(active.clone()),
                            token,
                            signed,
                            hold,
                            tx.clone(),
                        )
                        .await;
                    }
                    None => {
                        Self::commit(&active, &signed, &tx).await?;
                    }
                }
                Ok(())
            }
            .await;
            if let Err(e) = res {
                let _ = tx.send(PublishEvent::Failed { token: 0, error: e.to_string() });
            } else {
                let _ = tx.send(PublishEvent::Committed { token: 0 });
            }
        });
        rx
    }

    /// Tallies for a poll: kind:1018 ballots #e=poll id.
    pub fn poll_votes(self: &Arc<Self>, poll_id: EventId) -> FeedRx {
        let (tx, rx) = mpsc::unbounded_channel();
        let this = Arc::clone(self);
        self.rt.spawn(async move {
            let res: Result<Vec<(String, u32)>> = async {
                let active = this.active().await?;
                let filter = Filter::new()
                    .kind(Kind::Custom(1018))
                    .event(poll_id)
                    .limit(1000);
                let mut votes: Vec<Event> = Vec::new();
                for ev in active.pool.get(filter).await.unwrap_or_default() {
                    votes.push(ev);
                }
                // (no explicit save: the SDK persists what it receives)
                Ok(crate::nip::poll::tally(&votes))
            }
            .await;
            match res {
                Ok(t) => {
                    let _ = tx.send(FeedEvent::PollVotes(t));
                }
                Err(e) => {
                    let _ = tx.send(FeedEvent::Failed(e.to_string()));
                }
            }
        });
        rx
    }

    /// Vote in a poll (NIP-88 kind:1018; re-voting replaces your ballot).
    pub fn poll_vote(self: &Arc<Self>, poll: &Event, option_ids: Vec<String>) -> PublishRx {
        let (tx, rx) = mpsc::unbounded_channel();
        let this = Arc::clone(self);
        let poll = poll.clone();
        self.rt.spawn(async move {
            let res: Result<()> = async {
                let active = this.active().await?;
                // The vote's e tag hints the poll author's most-recent
                // seen relay (actions.ts:118) so clients that never saw
                // the poll can still ask where it lives.
                let mut tags =
                    vec![seen::hint_tag(poll.id, &poll.pubkey), Tag::public_key(poll.pubkey)];
                for opt in option_ids {
                    tags.push(Tag::custom("response", [opt]));
                }
                let unsigned =
                    UnsignedEvent::new(active.me(), Timestamp::now(), Kind::Custom(1018), tags, "");
                let signed = active.signer.sign_event(unsigned).await?;
                Self::commit(&active, &signed, &tx).await?;
                Ok(())
            }
            .await;
            if let Err(e) = res {
                let _ = tx.send(PublishEvent::Failed { token: 0, error: e.to_string() });
            } else {
                let _ = tx.send(PublishEvent::Committed { token: 0 });
            }
        });
        rx
    }

    /// RSVP to a calendar event (NIP-52 kind:31925).
    pub fn rsvp(self: &Arc<Self>, calendar: &Event, status: &str) -> PublishRx {
        let (tx, rx) = mpsc::unbounded_channel();
        let this = Arc::clone(self);
        let calendar = calendar.clone();
        let status = status.to_string();
        self.rt.spawn(async move {
            let res: Result<()> = async {
                let active = this.active().await?;
                let data = crate::nip::calendar::parse(&calendar)
                    .ok_or_else(|| LoginError::Resume("bad calendar event".into()))?;
                let a = crate::nip::calendar::a_tag(&data, &calendar.pubkey);
                let unsigned = UnsignedEvent::new(
                    active.me(),
                    Timestamp::now(),
                    Kind::Custom(31925),
                    [
                        Tag::custom("a", [a]),
                        Tag::event(calendar.id),
                        Tag::public_key(calendar.pubkey),
                        Tag::custom("status", [status]),
                    ],
                    "",
                );
                let signed = active.signer.sign_event(unsigned).await?;
                Self::commit(&active, &signed, &tx).await?;
                Ok(())
            }
            .await;
            if let Err(e) = res {
                let _ = tx.send(PublishEvent::Failed { token: 0, error: e.to_string() });
            } else {
                let _ = tx.send(PublishEvent::Committed { token: 0 });
            }
        });
        rx
    }

    /// Repost (NIP-18): kind 6 for notes, kind 16 + a `k` tag for anything
    /// else — and the same undo window as every publish (hold_and_commit;
    /// the shell's toast carries the countdown and the Undo).
    pub fn repost(self: &Arc<Self>, target: &Event) -> PublishRx {
        let (tx, rx) = mpsc::unbounded_channel();
        let this = Arc::clone(self);
        let target = target.clone();
        self.rt.spawn(async move {
            let res: Result<()> = async {
                let active = this.active().await?;
                let note = u16::from(target.kind) == 1;
                let mut tags = vec![
                    seen::hint_tag(target.id, &target.pubkey),
                    Tag::public_key(target.pubkey),
                ];
                if !note {
                    tags.push(Tag::custom("k", [u16::from(target.kind).to_string()]));
                }
                let unsigned = UnsignedEvent::new(
                    active.me(),
                    Timestamp::now(),
                    if note { Kind::Repost } else { Kind::Custom(16) },
                    tags,
                    format!("nostr:{}", target.id.to_bech32().unwrap_or_default()),
                );
                let signed = active.signer.sign_event(unsigned).await?;
                match active.undo.hold_duration() {
                    Some(hold) => {
                        let token = this.hold_seq.fetch_add(1, Ordering::SeqCst);
                        let _ = tx.send(PublishEvent::Held {
                            token,
                            event: signed.clone(),
                            hold_secs: hold.as_secs(),
                        });
                        this.hold_and_commit(
                            Arc::new(active.clone()),
                            token,
                            signed,
                            hold,
                            tx.clone(),
                        )
                        .await;
                    }
                    None => {
                        Self::commit(&active, &signed, &tx).await?;
                        let _ = tx.send(PublishEvent::Committed { token: 0 });
                    }
                }
                Ok(())
            }
            .await;
            if let Err(e) = res {
                let _ = tx.send(PublishEvent::Failed { token: 0, error: e.to_string() });
            }
        });
        rx
    }

    /// Resolve a note/nevent bech32 to its event (embed/quote previews).
    pub fn event_by_id_dech32(self: &Arc<Self>, bech32: &str) -> FeedRx {
        use nostr::prelude::*;
        match Nip19::from_bech32(bech32) {
            // The nevent carries author + relay hints when the publisher
            // was polite (NIP-01 recommends both) — resolveEvent uses
            // them to skip the indexer fallback entirely.
            Ok(Nip19::Event(e)) => self.event_by_id(
                e.event_id,
                e.relays.iter().map(|r| r.to_string()).collect(),
                e.author,
            ),
            Ok(Nip19::EventId(id)) => self.event_by_id(id, Vec::new(), None),
            _ => {
                let (tx, rx) = mpsc::unbounded_channel();
                let _ = tx.send(FeedEvent::One(None, None));
                rx
            }
        }
    }

    /// Resolve one event by id (repost targets); None if unknown everywhere.
    /// Batch-resolve reply parents (the timeline's context whisper): store
    /// first, then one by-id relay round trip for the misses. Emits
    /// FeedEvent::Parents with whatever resolved — misses (deleted parents,
    /// relay gaps) just don't resolve, and the whisper degrades.
    /// The signed-in identity's pubkey hex, if any — views use it to
    /// phrase "your note" vs "{name}'s note" (the notifications whisper).
    pub fn me(&self) -> Option<String> {
        self.active
            .lock()
            .unwrap()
            .as_ref()
            .map(|a| a.session.pubkey.clone())
    }

    pub fn load_parents(self: &Arc<Self>, ids: Vec<String>) -> FeedRx {
        let (tx, rx) = mpsc::unbounded_channel();
        let this = Arc::clone(self);
        self.rt.spawn(async move {
            let mut resolved: std::collections::HashMap<String, ParentNote> =
                std::collections::HashMap::new();
            let _: Result<()> = async {
                let active = this.active().await?;
                let want: Vec<EventId> = ids
                    .iter()
                    .filter_map(|h| EventId::from_hex(h).ok())
                    .collect();
                if want.is_empty() {
                    return Ok(());
                }
                let mut events: Vec<Event> = Vec::new();
                for id in &want {
                    // The store hit path wears the same gates as the
                    // network one (the chokepoint): expired or
                    // author-deleted parents don't resolve — the whisper
                    // degrades, which is the point.
                    if let Some(ev) = active.pool.store.event_by_id(*id).await.ok().flatten()
                        && !nip40::is_expired(&ev)
                        && !deletions::is_deleted(&ev)
                    {
                        events.push(ev);
                    }
                }
                let have: HashSet<EventId> = events.iter().map(|e| e.id).collect();
                let missing: Vec<EventId> =
                    want.iter().filter(|id| !have.contains(id)).cloned().collect();
                if !missing.is_empty() {
                    // feeds.ts fetchEventsByIds: a TARGETED query on the
                    // indexers (parents' authors are unknown until they
                    // resolve, so seen-on can't narrow this one). Split at
                    // the REQ ceiling (WS1: OutboxRouter.kt
                    // MAX_ETAGS_PER_FILTER — big relays reject oversized
                    // filters).
                    let fallback: Vec<String> =
                        INDEXERS.iter().map(|s| s.to_string()).collect();
                    for id_shard in outbox::chunk(&missing, outbox::MAX_ETAGS_PER_FILTER) {
                        let n = id_shard.len();
                        let filter = Filter::new().ids(id_shard).limit(n);
                        let fetched: Vec<Event> = active
                            .pool
                            .get_from(&fallback, &filter)
                            .await
                            .into_iter()
                            .collect();
                        // (no explicit save: the SDK persists what it receives)
                        events.extend(fetched);
                    }
                }
                for ev in events {
                    let snippet = plain_snippet(&ev.content, 140);
                    resolved.insert(
                        ev.id.to_string(),
                        ParentNote { author: ev.pubkey.to_string(), snippet },
                    );
                }
                Ok(())
            }
            .await;
            if !resolved.is_empty() {
                let _ = tx.send(FeedEvent::Parents(resolved));
            }
        });
        rx
    }

    pub fn event_by_id(
        self: &Arc<Self>,
        id: EventId,
        hints: Vec<String>,
        author: Option<PublicKey>,
    ) -> FeedRx {
        let (tx, rx) = mpsc::unbounded_channel();
        let this = Arc::clone(self);
        self.rt.spawn(async move {
            let res: Result<(Option<Event>, Option<Profile>)> = async {
                let active = this.active().await?;
                let cached = active.pool.store.event_by_id(id).await.ok().flatten();
                let ev = match cached {
                    Some(ev) => Some(ev),
                    None => {
                        // feeds.ts resolveEvent: with a known author, race
                        // their DECLARED write relays + the relays we've
                        // empirically SEEN them on (+ nevent hints) first —
                        // read-dead relays dropped, a get against one just
                        // burns its share of the race. The big indexers are
                        // the fallback (an aggregator that can miss), not
                        // the primary.
                        let filter = Filter::new().id(id).limit(1);
                        let mut primary = hints.clone();
                        if let Some(pk) = author {
                            let lists = active.pool.relay_lists(&[pk]).await;
                            if let Some(list) = lists.get(&pk.to_string()) {
                                primary.extend(list.write.iter().cloned());
                            }
                            primary.extend(seen::for_pubkey(&pk));
                        }
                        primary.retain(|u| !relay_latency::is_read_dead(u));
                        primary.sort();
                        primary.dedup();
                        let mut ev = if primary.is_empty() {
                            None
                        } else {
                            active
                                .pool
                                .get_from(&primary, &filter)
                                .await
                                .into_iter()
                                .next()
                        };
                        if ev.is_none() {
                            let mut fallback = hints;
                            fallback.extend(INDEXERS.iter().map(|s| s.to_string()));
                            fallback.sort();
                            fallback.dedup();
                            ev = active
                                .pool
                                .get_from(&fallback, &filter)
                                .await
                                .into_iter()
                                .next();
                        }
                        // NIP-40 + NIP-09 re-check on the resolution (the
                        // pool chokepoint covers the network paths; the
                        // STORE hit needs this gate — a long-lived cache
                        // can serve an event that expired mid-retention
                        // or was deleted after it landed). A deleted
                        // event also earns one background sweep: ask the
                        // relays for its tombstone (at most once per TTL
                        // per id — deletions.ts checkDeletions) so the
                        // NEXT open reflects it.
                        let ev = ev.filter(|e| !nip40::is_expired(e) && !deletions::is_deleted(e));
                        if let Some(resolved) = &ev
                            && deletions::should_check(&resolved.id.to_string())
                        {
                            let pool = Arc::clone(&active.pool);
                            let sweep = Filter::new()
                                .kind(Kind::EventDeletion)
                                .event(resolved.id)
                                .limit(50);
                            this.rt.spawn(async move {
                                // The chokepoint inside get() records
                                // whatever comes back; nothing else to do
                                // with the (filtered) result.
                                let _ = pool.get(sweep).await;
                            });
                        }
                        ev
                    }
                };
                let profile = match &ev {
                    Some(ev) => {
                        let authors = [ev.pubkey];
                        let cached = active.pool.store.profiles(&authors).await.unwrap_or_default();
                        let mut p: Option<Profile> =
                            cached.iter().filter_map(Profile::from_event).next();
                        if p.is_none() {
                            let filter = Filter::new()
                                .kind(Kind::Metadata)
                                .author(ev.pubkey)
                                .limit(1);
                            for meta in active.pool.get(filter).await.unwrap_or_default() {
                                if p.is_none() {
                                    p = Profile::from_event(&meta);
                                }
                            }
                        }
                        p
                    }
                    None => None,
                };
                Ok((ev, profile))
            }
            .await;
            match res {
                Ok((ev, profile)) => {
                    let _ = tx.send(FeedEvent::One(ev, profile));
                }
                Err(e) => {
                    let _ = tx.send(FeedEvent::Failed(e.to_string()));
                }
            }
        });
        rx
    }

    /// One addressable event by (kind, author, d) — naddr resolution.
    pub fn event_by_address(
        self: &Arc<Self>,
        kind: u16,
        author: PublicKey,
        identifier: String,
    ) -> FeedRx {
        let (tx, rx) = mpsc::unbounded_channel();
        let this = Arc::clone(self);
        self.rt.spawn(async move {
            let res: Result<(Option<Event>, Option<Profile>)> = async {
                let active = this.active().await?;
                let filter = Filter::new()
                    .author(author)
                    .kind(Kind::from_u16(kind))
                    .identifier(&identifier)
                    .limit(1);
                let ev = active.pool.get(filter).await.unwrap_or_default();
                // Addressable events: newest replaces (NIP-01); take the
                // greatest (id-ordered BTreeSet ≈ latest seen).
                let ev = ev.into_iter().next_back();
                // (no explicit save: the SDK persists what it receives)
                let profile = match &ev {
                    Some(ev) => {
                        let authors = [ev.pubkey];
                        let cached = active
                            .pool
                            .store
                            .profiles(&authors)
                            .await
                            .unwrap_or_default();
                        let mut p: Option<Profile> =
                            cached.iter().filter_map(Profile::from_event).next();
                        if p.is_none() {
                            let f = Filter::new()
                                .kind(Kind::Metadata)
                                .author(ev.pubkey)
                                .limit(1);
                            for meta in active.pool.get(f).await.unwrap_or_default() {
                                if p.is_none() {
                                    p = Profile::from_event(&meta);
                                }
                            }
                        }
                        p
                    }
                    None => None,
                };
                if let Some(p) = &profile {
                    this.absorb_profiles(std::slice::from_ref(p));
                }
                Ok((ev, profile))
            }
            .await;
            match res {
                Ok((ev, profile)) => {
                    let _ = tx.send(FeedEvent::One(ev, profile));
                }
                Err(e) => {
                    let _ = tx.send(FeedEvent::Failed(e.to_string()));
                }
            }
        });
        rx
    }

    // --- search (NIP-50) ----------------------------------------------------------

    /// Note search across the read set, gated by NIP-11 capability
    /// (relay-info.ts:126's nip50Capable): relays KNOWN to lack NIP-50
    /// search are never asked (they can't answer a search filter);
    /// unknown relays stay (absence of evidence isn't refusal); never
    /// empty — all-known-incapable asks everyone, search degrades
    /// instead of breaking.
    pub fn search(self: &Arc<Self>, query: String) -> FeedRx {
        let (tx, rx) = mpsc::unbounded_channel();
        let this = Arc::clone(self);
        self.rt.spawn(async move {
            let res: Result<FeedPage> = async {
                let active = this.active().await?;
                let filter = Filter::new()
                    .kind(Kind::TextNote)
                    .search(&query)
                    .limit(50);
                let mut relays: Vec<String> = active
                    .pool
                    .read_relays()
                    .into_iter()
                    .filter(|url| crate::nip11::search(url) != Some(false))
                    .collect();
                if relays.is_empty() {
                    relays = active.pool.read_relays();
                }
                // The fan-out path (get_from): per-relay queries with
                // latency attribution — and the gate above decides WHICH
                // relays hear the query at all.
                let mut results: Vec<Event> =
                    active.pool.get_from(&relays, &filter).await.into_iter().collect();
                // (no explicit save: the SDK persists what it receives)
                results.sort_by_key(|e| std::cmp::Reverse(e.created_at.as_secs()));
                let profiles = Self::profiles_for(&active, &results).await;
                Ok(FeedPage { notes: results, profiles })
            }
            .await;
            match res {
                Ok(page) => {
                    let _ = tx.send(FeedEvent::Search(page.notes, page.profiles));
                }
                Err(e) => {
                    let _ = tx.send(FeedEvent::Failed(e.to_string()));
                }
            }
        });
        rx
    }

    // --- profiles ---------------------------------------------------------------

    /// A hashtag timeline (Phase 2 §4.2): the `#t` filter across the
    /// visible catalog, any author — the profile() shape with a tag filter
    /// instead of an author set. Relay fetch into the store, then project
    /// straight off the fetch (the store's matcher isn't trusted for tags);
    /// mutes and deletions gate like every feed page.
    pub fn hashtag(self: &Arc<Self>, tag: String) -> FeedRx {
        let (tx, rx) = mpsc::unbounded_channel();
        let this = Arc::clone(self);
        self.rt.spawn(async move {
            let res: Result<FeedPage> = async {
                let active = this.active().await?;
                // t tags are conventionally lowercase (NIP-24); the tap
                // keeps its raw case for display, the filter normalizes.
                let filter = Filter::new()
                    .kinds(crate::store::visible_kinds())
                    .custom_tag(SingleLetterTag::LOWERCASE_T, tag.to_lowercase())
                    .limit(PAGE + 1);
                let mut notes: Vec<Event> =
                    active.pool.get(filter).await.unwrap_or_default().into_iter().collect();
                // (no explicit save: the SDK persists what it receives)
                {
                    let muted = this.muted.lock().unwrap();
                    notes.retain(|ev| !muted.contains(&ev.pubkey.to_string()));
                }
                let mut notes = this.drop_deleted(notes);
                notes.sort_by_key(|e| std::cmp::Reverse(e.created_at.as_secs()));
                let profiles = Self::profiles_for(&active, &notes).await;
                Ok(FeedPage { notes, profiles })
            }
            .await;
            match res {
                Ok(page) => {
                    let _ = tx.send(FeedEvent::Loaded(page));
                }
                Err(e) => {
                    let _ = tx.send(FeedEvent::Failed(e.to_string()));
                }
            }
        });
        rx
    }

    /// The hashtag timeline's older page — the home feed's scroll
    /// pagination (older()), with the tag filter standing in for the
    /// follow set. A full page keeps `has_more` lit; the next probe
    /// refetches around the oldest shown.
    pub fn hashtag_older(self: &Arc<Self>, tag: String, until: u64) -> FeedRx {
        let (tx, rx) = mpsc::unbounded_channel();
        let this = Arc::clone(self);
        self.rt.spawn(async move {
            let res: Result<FeedEvent> = async {
                let active = this.active().await?;
                let filter = Filter::new()
                    .kinds(crate::store::visible_kinds())
                    .custom_tag(SingleLetterTag::LOWERCASE_T, tag.to_lowercase())
                    .until(Timestamp::from(until))
                    .limit(PAGE + 1);
                let mut notes: Vec<Event> =
                    active.pool.get(filter).await.unwrap_or_default().into_iter().collect();
                // (no explicit save: the SDK persists what it receives)
                {
                    let muted = this.muted.lock().unwrap();
                    notes.retain(|ev| !muted.contains(&ev.pubkey.to_string()));
                }
                let mut notes = this.drop_deleted(notes);
                notes.sort_by_key(|e| std::cmp::Reverse(e.created_at.as_secs()));
                let has_more = notes.len() > PAGE;
                notes.truncate(PAGE);
                let profiles = Self::profiles_for(&active, &notes).await;
                Ok(FeedEvent::Older(FeedPage { notes, profiles }, has_more))
            }
            .await;
            match res {
                Ok(ev) => {
                    let _ = tx.send(ev);
                }
                Err(e) => {
                    let _ = tx.send(FeedEvent::Failed(e.to_string()));
                }
            }
        });
        rx
    }

    /// A profile page's projection: their recent notes + their metadata.
    pub fn profile(self: &Arc<Self>, who: PublicKey) -> FeedRx {
        let (tx, rx) = mpsc::unbounded_channel();
        let this = Arc::clone(self);
        self.rt.spawn(async move {
            let res: Result<FeedPage> = async {
                let active = this.active().await?;
                // Their notes: relay fetch into the store, then project.
                let filter = Filter::new()
                    .kinds(crate::store::visible_kinds())
                    .author(who)
                    .limit(50);
                // (no explicit save: the SDK persists what it receives)
                let _ = active.pool.get(filter).await;
                let notes = active
                    .pool
                    .store
                    .feed_page(&[who], None, PAGE)
                    .await
                    .unwrap_or_default();
                let profiles = Self::profiles_for(&active, &notes).await;
                Ok(FeedPage { notes, profiles })
            }
            .await;
            match res {
                Ok(page) => {
                    let _ = tx.send(FeedEvent::Loaded(page));
                }
                Err(e) => {
                    let _ = tx.send(FeedEvent::Failed(e.to_string()));
                }
            }
        });
        rx
    }

    /// The profile's next older page (endless scroll): author-scoped mirror
    /// of `older` — the store page behind the anchor, then a relay top-up
    /// for the author only (deletions ride along), then re-project.
    pub fn profile_older(self: &Arc<Self>, who: PublicKey, until: u64) -> FeedRx {
        let (tx, rx) = mpsc::unbounded_channel();
        let this = Arc::clone(self);
        self.rt.spawn(async move {
            let res: Result<FeedEvent> = async {
                let active = this.active().await?;
                let mut notes = active
                    .pool
                    .store
                    .feed_page(&[who], Some(until), PAGE)
                    .await
                    .unwrap_or_default();
                if notes.len() <= PAGE {
                    let filter = Filter::new()
                        .kinds(crate::store::visible_kinds())
                        .author(who)
                        .until(Timestamp::from(until))
                        .limit(TOPUP_DEPTH);
                    // (no explicit save: the SDK persists what it receives)
                    let _ = active.pool.get(filter).await.unwrap_or_default();
                    let del_filter = Filter::new()
                        .kind(Kind::EventDeletion)
                        .author(who)
                        .until(Timestamp::from(until))
                        .limit(500);
                    let _ = active.pool.get(del_filter).await;
                    notes = active
                        .pool
                        .store
                        .feed_page(&[who], Some(until), PAGE)
                        .await
                        .unwrap_or_default();
                }
                let has_more = notes.len() > PAGE;
                notes.truncate(PAGE);
                let profiles = Self::profiles_for(&active, &notes).await;
                Ok(FeedEvent::Older(FeedPage { notes, profiles }, has_more))
            }
            .await;
            match res {
                Ok(ev) => {
                    let _ = tx.send(ev);
                }
                Err(e) => {
                    let _ = tx.send(FeedEvent::Failed(e.to_string()));
                }
            }
        });
        rx
    }

    // --- threads ----------------------------------------------------------------

    /// Replies to a note (store first, relay top-up).
    pub fn thread(self: &Arc<Self>, id: EventId) -> FeedRx {
        let (tx, rx) = mpsc::unbounded_channel();
        let this = Arc::clone(self);
        self.rt.spawn(async move {
            let res: Result<FeedEvent> = async {
                let active = this.active().await?;
                // Relay top-up for kind-1 replies (the SDK saves what it
                // receives); the store holds the threaded set.
                let filter = Filter::new().kind(Kind::TextNote).event(id).limit(200);
                let _ = active.pool.get(filter).await;
                let mut replies = active
                    .pool
                    .store
                    .replies(id)
                    .await
                    .map_err(|e| LoginError::Resume(e.to_string()))?;
                // NIP-22 comments addressing the note (Amethyst replies to
                // non-kind-1 roots as 1111; comments-on-comments nest under
                // their parents through the same `e` tag). Store first, then
                // a relay top-up, then merge into one threaded set.
                for ev in active.pool.store.comments(id).await.unwrap_or_default() {
                    replies.push(ev);
                }
                let comment_filter = Filter::new().kind(Kind::Custom(1111)).event(id).limit(200);
                for ev in active.pool.get(comment_filter).await.unwrap_or_default() {
                    replies.push(ev);
                }
                // Deletions (NIP-09), targeted by id — replies come from
                // beyond the follows, so the sync can't cover them. The
                // chokepoint consumes the kind:5s it fetches (records
                // them; the returned set is empty by design), so the gate
                // is the module lookup — which enforces the deleter ==
                // author MUST structurally. (Audit: the old local HashSet
                // read the get() results the chokepoint now consumes.)
                let reply_ids: Vec<EventId> = replies.iter().map(|e| e.id).collect();
                if !reply_ids.is_empty() {
                    let mut del_filter = Filter::new().kind(Kind::EventDeletion).limit(200);
                    for id in reply_ids {
                        del_filter = del_filter.event(id);
                    }
                    // (no explicit save: the SDK persists what it receives)
                    let _ = active.pool.get(del_filter).await;
                    replies.retain(|e| !deletions::is_deleted(e));
                }
                let mut seen: HashSet<EventId> = HashSet::new();
                replies.retain(|e| seen.insert(e.id));
                replies.sort_by_key(|e| e.created_at.as_secs());
                let authors: Vec<PublicKey> = replies.iter().map(|e| e.pubkey).collect();
                let cached = active
                    .pool
                    .store
                    .profiles(&authors)
                    .await
                    .unwrap_or_default();
                let profiles: Vec<Profile> =
                    cached.iter().filter_map(Profile::from_event).collect();
                Ok(FeedEvent::Replies(replies, profiles))
            }
            .await;
            match res {
                Ok(ev) => {
                    let _ = tx.send(ev);
                }
                Err(e) => {
                    let _ = tx.send(FeedEvent::Failed(e.to_string()));
                }
            }
        });
        rx
    }

    // --- write path ---------------------------------------------------------------

    /// Post a note — a NIP-10 reply, a NIP-18 quote, or plain. Signed, then
    /// held for the undo window with a backstop commit; events stream on
    /// the channel.
    pub fn post_note(
        self: &Arc<Self>,
        content: String,
        reply_to: Option<Event>,
        mentions: Vec<PublicKey>,
        quote: Option<Event>,
        imetas: Vec<Vec<String>>,
    ) -> PublishRx {
        let (tx, rx) = mpsc::unbounded_channel();
        let this = Arc::clone(self);
        self.rt.spawn(async move {
            let res = this
                .post_note_inner(&tx, content, reply_to, mentions, quote, imetas)
                .await;
            if let Err(e) = res {
                let _ = tx.send(PublishEvent::Failed { token: 0, error: e.to_string() });
            }
        });
        rx
    }

    /// Tag + content building for a note — shared by the immediate path
    /// (post_note) and the scheduled path (schedule_note), so a scheduled
    /// note's tags are byte-identical to an instant one. `imetas` (the
    /// uploaded NIP-92 tag arrays from upload.rs, element 0 = "imeta")
    /// ride the kind-1 as plain imeta tags — publish.ts signNote's
    /// `for (const m of imeta) tags.push(m)`; an attached image or video
    /// is media IN a note, not a picture event (issue #3 WS1).
    /// (pub(crate)-crossing: the composer's preview builds its synthetic
    /// event from the SAME builder — the preview shows what publish signs.)
    pub fn note_tags(
        content: String,
        reply_to: Option<Event>,
        mentions: Vec<PublicKey>,
        quote: Option<Event>,
        imetas: &[Vec<String>],
        me: PublicKey,
    ) -> (String, Vec<Tag>) {
        let mut tags: Vec<Tag> = Vec::new();
        // NIP-92 media metadata rides right after content-warning's slot
        // in the TS (signNote pushes it before the quote/reference tags).
        for m in imetas {
            if m.len() >= 2 && m[0] == "imeta" {
                tags.push(Tag::custom("imeta", m[1..].iter()));
            }
        }
        // The NIP-18 quote rides FIRST: a q tag (id, relay hint, author) and
        // the nostr: reference folded into the text the reader sees.
        let content = if let Some(q) = &quote {
            // The relay hint rides the author's most-recent seen relay
            // (actions.ts:118); empty when we've never seen them (NIP-18:
            // the hint is optional).
            tags.push(Tag::custom(
                "q",
                [
                    q.id.to_string(),
                    seen::first(&q.pubkey).unwrap_or_default(),
                    q.pubkey.to_string(),
                ],
            ));
            format!("{}\n\nnostr:{}", content, q.id.to_bech32().unwrap_or_default())
        } else {
            content
        };
        if let Some(parent) = &reply_to {
            // NIP-10 marked tags; root = parent's root if marked, else parent itself.
            let mut root_id: Option<EventId> = None;
            for tag in parent.tags.clone().to_vec() {
                let parts = tag.as_slice();
                if parts.len() >= 2 && parts[0] == "e" {
                    if parts.len() >= 4 && parts[3] == "root" {
                        root_id = Some(EventId::from_str(&parts[1]).ok()).flatten();
                    }
                    break;
                }
            }
            let root = root_id.unwrap_or(parent.id);
            let empty = "";
            tags.push(Tag::custom(
                "e",
                [root.to_string(), empty.to_string(), "root".to_string()],
            ));
            tags.push(Tag::custom(
                "e",
                [parent.id.to_string(), empty.to_string(), "reply".to_string()],
            ));
            tags.push(Tag::public_key(parent.pubkey));
            if root != parent.id {
                // Root author belongs in p too when different (NIP-10).
                tags.push(Tag::custom("p", [root.to_string()]));
            }
        }
        // @-mentions (NIP-10 p tags — what fires notifications). The
        // parent's own p's (root/parent authors) take precedence.
        let mut seen_p: Vec<String> = tags
            .iter()
            .filter(|t| t.as_slice().first().map(String::as_str) == Some("p"))
            .filter_map(|t| t.as_slice().get(1).cloned())
            .collect();
        for who in mentions {
            let hex = who.to_string();
            if hex != me.to_string() && !seen_p.contains(&hex) {
                seen_p.push(hex.clone());
                tags.push(Tag::public_key(who));
            }
        }
        (content, tags)
    }

    async fn post_note_inner(
        self: &Arc<Self>,
        tx: &mpsc::UnboundedSender<PublishEvent>,
        content: String,
        reply_to: Option<Event>,
        mentions: Vec<PublicKey>,
        quote: Option<Event>,
        imetas: Vec<Vec<String>>,
    ) -> Result<()> {
        let active = self.active().await?;
        let me = active.me();
        let (content, tags) =
            Self::note_tags(content, reply_to, mentions, quote, &imetas, me);
        let unsigned = UnsignedEvent::new(
            me,
            Timestamp::now(),
            Kind::TextNote,
            tags,
            content,
        );
        let signed = active.signer.sign_event(unsigned).await?;

        match active.undo.hold_duration() {
            Some(hold) => {
                let token = self.hold_seq.fetch_add(1, Ordering::SeqCst);
                let _ = tx.send(PublishEvent::Held {
                    token,
                    event: signed.clone(),
                    hold_secs: hold.as_secs(),
                });
                self.hold_and_commit(Arc::new(active.clone()), token, signed, hold, tx.clone()).await;
            }
            None => Self::commit(&active, &signed, tx).await?,
        }
        Ok(())
    }

    /// Schedule a note for later broadcast (scheduled.ts holdScheduled):
    /// signed AT COMPOSE with `created_at` == the scheduled time — it
    /// reads as ≈now when the sweep fires it, and relays don't reject
    /// future-dating. Held in scheduled.json (0600, synchronous flush),
    /// published by the 30s sweep through the SAME funnel as an instant
    /// post (store → outbox write-ahead → publish → dequeue). No undo
    /// window on the schedule itself — undoing IS cancelling
    /// (scheduled_cancel). Reports on ScheduleEvent.
    #[allow(clippy::too_many_arguments)]
    pub fn schedule_note(
        self: &Arc<Self>,
        title: String,
        content: String,
        reply_to: Option<Event>,
        mentions: Vec<PublicKey>,
        quote: Option<Event>,
        imetas: Vec<Vec<String>>,
        photo_post: bool,
        scheduled_at: u64,
    ) -> mpsc::UnboundedReceiver<ScheduleEvent> {
        let (tx, rx) = mpsc::unbounded_channel();
        let this = Arc::clone(self);
        self.rt.spawn(async move {
            let res: Result<String> = async {
                let active = this.active().await?;
                let me = active.me();
                // The composer's tab decides: a photo post schedules as the
                // SAME kind-20 picture event an instant post makes
                // (picture_tags' build — the composer's title rides, blank
                // derives from the caption like the instant path); a note
                // with attachments schedules as kind 1 + imeta (note_tags'
                // build), matching the instant path's routing (issue #3
                // WS1).
                let (kind, content, tags) = if !imetas.is_empty() && photo_post {
                    let tags = Self::picture_tags(&title, &content, &imetas, None);
                    (Kind::Custom(20), content, tags)
                } else {
                    let (content, tags) =
                        Self::note_tags(content, reply_to, mentions, quote, &imetas, me);
                    (Kind::TextNote, content, tags)
                };
                let unsigned = UnsignedEvent::new(
                    me,
                    Timestamp::from_secs(scheduled_at),
                    kind,
                    tags,
                    content,
                );
                let signed = active.signer.sign_event(unsigned).await?;
                crate::scheduled::hold(&me, signed, scheduled_at).ok_or_else(|| {
                    LoginError::Connect(format!(
                        "you have reached the maximum of {} scheduled posts; cancel some to schedule more",
                        crate::scheduled::MAX_PER_USER
                    ))
                })
            }
            .await;
            match res {
                Ok(token) => {
                    let _ = tx.send(ScheduleEvent::Scheduled { token, scheduled_at });
                }
                Err(e) => {
                    let _ = tx.send(ScheduleEvent::Failed { error: e.to_string() });
                }
            }
        });
        rx
    }

    /// The active account's pending scheduled posts, soonest first (the
    /// composer's schedule list). Empty when logged out.
    pub fn scheduled_list(&self) -> Vec<crate::scheduled::ScheduledPost> {
        self.active_pubkey_opt()
            .map(|me| crate::scheduled::list(&me))
            .unwrap_or_default()
    }

    /// Schedule an article (schedule_note's discipline, NIP-23-shaped):
    /// signed AT COMPOSE with `created_at` == the scheduled time, held in
    /// scheduled.json, published by the 30s sweep through the same funnel.
    pub fn schedule_article(
        self: &Arc<Self>,
        draft: crate::nip::article::ArticleDraft,
        scheduled_at: u64,
    ) -> mpsc::UnboundedReceiver<ScheduleEvent> {
        let (tx, rx) = mpsc::unbounded_channel();
        let this = Arc::clone(self);
        self.rt.spawn(async move {
            let res: Result<String> = async {
                if draft.title.trim().is_empty() || draft.body.trim().is_empty() {
                    return Err(LoginError::Other("an article needs a title and a body".into()));
                }
                let active = this.active().await?;
                let me = active.me();
                let unsigned = UnsignedEvent::new(
                    me,
                    Timestamp::from_secs(scheduled_at),
                    Kind::Custom(30023),
                    draft.tags(scheduled_at),
                    draft.body.clone(),
                );
                let signed = active.signer.sign_event(unsigned).await?;
                crate::scheduled::hold(&me, signed, scheduled_at).ok_or_else(|| {
                    LoginError::Connect(format!(
                        "you have reached the maximum of {} scheduled posts; cancel some to schedule more",
                        crate::scheduled::MAX_PER_USER
                    ))
                })
            }
            .await;
            match res {
                Ok(token) => {
                    let _ = tx.send(ScheduleEvent::Scheduled { token, scheduled_at });
                }
                Err(e) => {
                    let _ = tx.send(ScheduleEvent::Failed { error: e.to_string() });
                }
            }
        });
        rx
    }

    /// Cancel a scheduled post before its time (scheduled.ts
    /// cancelScheduled): only the author's own token goes, synchronously
    /// flushed so a confirmed cancel can't resurrect after a restart.
    pub fn scheduled_cancel(&self, token: &str) -> bool {
        let Some(me) = self.active_pubkey_opt() else { return false };
        crate::scheduled::cancel(&me, token)
    }

    /// The scheduled sweep (scheduled.ts startScheduledSweep, 30s): ONE
    /// task per process, armed on the first bootstrap next to the outbox
    /// drainer. Its first tick catches anything already due at boot — the
    /// restart catch-up: the store is the only state, there are no
    /// per-post timers. Due entries publish through the same funnel as
    /// instant posting (Self::commit's order: store save → outbox
    /// write-ahead → publish → dequeue on acceptance) and are removed only
    /// on acceptance — PUBLISH-BEFORE-MARK, see the scheduled.rs module
    /// doc. A session-less stretch just sleeps; entries persist on disk.
    fn spawn_scheduled_sweep(self: &Arc<Self>) {
        if self.scheduled_started.swap(true, Ordering::SeqCst) {
            return;
        }
        eprintln!("[core] scheduled: sweep armed");
        let weak = Arc::downgrade(self);
        self.rt.spawn(async move {
            loop {
                let Some(core) = weak.upgrade() else { break }; // app closing
                let now = crate::scheduled::now_secs();
                let Some(due) = crate::scheduled::take_due(now) else {
                    drop(core);
                    tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                    continue;
                };
                let mut settled: Vec<String> = Vec::new();
                if let Ok(active) = core.active().await {
                    for p in due {
                        // Same funnel as Self::commit (the publish-before-
                        // mark discipline: acceptance is the durability
                        // decision; removal rides the debounced flusher).
                        let _ = active.pool.store.save(&p.event).await;
                        crate::outbox_queue::enqueue(&p.event);
                        let targets = crate::outbox_queue::targets(&active.write_relays);
                        let report = active.pool.publish(&p.event, &targets).await;
                        for r in &report.ok {
                            crate::relay_latency::record_write_result(r, true);
                        }
                        for (r, _m) in &report.failed {
                            crate::relay_latency::record_write_result(r, false);
                        }
                        if report.accepted() {
                            crate::outbox_queue::remove(&p.event);
                            settled.push(p.token);
                        } else if crate::scheduled::give_up(now, p.scheduled_at) {
                            eprintln!("[core] scheduled: giving up on {}", p.token);
                            settled.push(p.token);
                        }
                        // else: kept; the next tick retries (relay may be down)
                    }
                }
                // Logged out: nothing settles, nothing drops — the sweep
                // just spins quietly until a session returns.
                crate::scheduled::finish_sweep(&settled);
                drop(core);
                tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            }
        });
    }

    /// A random 9-char option id (nip88.ts generateOptionId): xorshift off
    /// the clock and the option index — no rand dep for nine chars.
    fn poll_option_id(n: usize) -> String {
        const ID_CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
        let mut seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos() as u64)
            .unwrap_or(0)
            ^ (n as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15);
        let mut id = String::new();
        for _ in 0..9 {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            id.push(ID_CHARS[(seed % ID_CHARS.len() as u64) as usize] as char);
        }
        id
    }

    /// Publish a NIP-88 poll (kind:1068): question in content, `option`
    /// tags with random 9-char ids, polltype, optional endsAt (seconds
    /// from now) + relay hints. nip88.ts buildPollTags shape. Same undo
    /// hold as notes.
    pub fn post_poll(
        self: &Arc<Self>,
        question: String,
        options: Vec<String>,
        multi: bool,
        ends_in_secs: Option<u64>,
    ) -> PublishRx {
        let (tx, rx) = mpsc::unbounded_channel();
        let this = Arc::clone(self);
        self.rt.spawn(async move {
            let res: Result<()> = async {
                let active = this.active().await?;
                const ID_CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
                let mut tag_list: Vec<Tag> = Vec::new();
                for (n, label) in options.iter().enumerate() {
                    tag_list.push(Tag::custom(
                        "option",
                        [Self::poll_option_id(n), label.as_str().to_string()],
                    ));
                }
                tag_list.push(Tag::custom(
                    "polltype",
                    [if multi { "multiplechoice" } else { "singlechoice" }],
                ));
                if let Some(secs) = ends_in_secs {
                    let ends_at = Timestamp::now().as_secs() + secs;
                    tag_list.push(Tag::custom("endsAt", [ends_at.to_string()]));
                }
                for url in &active.read_relays {
                    tag_list.push(Tag::custom("relay", [url.as_str()]));
                }
                let unsigned = UnsignedEvent::new(
                    active.me(),
                    Timestamp::now(),
                    Kind::Custom(1068),
                    tag_list,
                    question,
                );
                let signed = active.signer.sign_event(unsigned).await?;
                match active.undo.hold_duration() {
                    Some(hold) => {
                        let token = this.hold_seq.fetch_add(1, Ordering::SeqCst);
                        let _ = tx.send(PublishEvent::Held {
                            token,
                            event: signed.clone(),
                            hold_secs: hold.as_secs(),
                        });
                        this.hold_and_commit(Arc::new(active.clone()), token, signed, hold, tx.clone())
                            .await;
                    }
                    None => Self::commit(&active, &signed, &tx).await?,
                }
                Ok(())
            }
            .await;
            if let Err(e) = res {
                let _ = tx.send(PublishEvent::Failed { token: 0, error: e.to_string() });
            } else {
                let _ = tx.send(PublishEvent::Committed { token: 0 });
            }
        });
        rx
    }

    /// Post a NIP-68 picture (kind:20). `imeta` carries one or more full NIP-92
    /// imeta tags (from `upload::blossom_upload_all`) — a picture needs at least
    /// one. Same undo window as notes. Port of `publish.ts signPicture`.
    pub fn post_picture(
        self: &Arc<Self>,
        title: String,
        content: String,
        imeta: Vec<Vec<String>>,
        content_warning: Option<String>,
    ) -> PublishRx {
        let (tx, rx) = mpsc::unbounded_channel();
        let this = Arc::clone(self);
        self.rt.spawn(async move {
            let res = this.post_picture_inner(&tx, title, content, imeta, content_warning).await;
            if let Err(e) = res {
                let _ = tx.send(PublishEvent::Failed { token: 0, error: e.to_string() });
            }
        });
        rx
    }

    /// The NIP-68 kind-20 tag build, shared by the instant path
    /// (post_picture_inner) and the scheduled path (schedule_note) so a
    /// scheduled picture's tags are byte-identical to an instant one.
    /// (pub: the composer's preview uses the same builder.)
    pub fn picture_tags(
        title: &str,
        content: &str,
        imetas: &[Vec<String>],
        content_warning: Option<&str>,
    ) -> Vec<Tag> {
        // NIP-68: a picture event carries a `title` tag (structural). A blank
        // composer title derives one from the caption's first non-empty line.
        let mut tags: Vec<Tag> = vec![Tag::custom(
            "title",
            [if title.trim().is_empty() {
                first_caption_line(content)
            } else {
                title.trim().to_string()
            }],
        )];
        if let Some(cw) = content_warning {
            tags.push(Tag::custom("content-warning", [cw]));
        }
        for m in imetas {
            if m.len() >= 2 && m[0] == "imeta" {
                tags.push(Tag::custom("imeta", m[1..].iter()));
            }
        }
        // NIP-68 also surfaces each image's hash (`x`) + mime (`m`) as TOP-LEVEL
        // tags (relay/client filtering), deduped across the imetas.
        let mut xs: Vec<String> = Vec::new();
        let mut mimes: Vec<String> = Vec::new();
        for m in imetas {
            for v in m.iter().skip(1) {
                if let Some(x) = v.strip_prefix("x ")
                    && !xs.contains(&x.to_string())
                {
                    xs.push(x.to_string());
                }
                if let Some(mm) = v.strip_prefix("m ")
                    && !mimes.contains(&mm.to_string())
                {
                    mimes.push(mm.to_string());
                }
            }
        }
        for x in &xs {
            tags.push(Tag::custom("x", [x.as_str()]));
        }
        for m in &mimes {
            tags.push(Tag::custom("m", [m.as_str()]));
        }
        tags
    }

    async fn post_picture_inner(
        self: &Arc<Self>,
        tx: &mpsc::UnboundedSender<PublishEvent>,
        title: String,
        content: String,
        imeta: Vec<Vec<String>>,
        content_warning: Option<String>,
    ) -> Result<()> {
        if imeta.is_empty() {
            return Err(LoginError::Other("a picture needs at least one image".into()));
        }
        let active = self.active().await?;
        let me = active.me();
        let tags = Self::picture_tags(&title, &content, &imeta, content_warning.as_deref());
        // TODO(port): src/nostr/content.ts mention tokenization → p tags (the
        // note path carries the same deferral).
        let unsigned = UnsignedEvent::new(me, Timestamp::now(), Kind::Custom(20), tags, content);
        let signed = active.signer.sign_event(unsigned).await?;

        match active.undo.hold_duration() {
            Some(hold) => {
                let token = self.hold_seq.fetch_add(1, Ordering::SeqCst);
                let _ = tx.send(PublishEvent::Held {
                    token,
                    event: signed.clone(),
                    hold_secs: hold.as_secs(),
                });
                self.hold_and_commit(Arc::new(active.clone()), token, signed, hold, tx.clone()).await;
            }
            None => Self::commit(&active, &signed, tx).await?,
        }
        Ok(())
    }

    /// Post a NIP-23 article (kind:30023) — port of `signArticle` +
    /// the article route's publish (article.ts). Top-level only (no
    /// reply/quote; the reader's comments are NIP-22 kind-1111s). The
    /// `d` identifier is random when the draft doesn't carry one. Same
    /// undo window as notes/pictures.
    pub fn post_article(
        self: &Arc<Self>,
        draft: crate::nip::article::ArticleDraft,
    ) -> PublishRx {
        let (tx, rx) = mpsc::unbounded_channel();
        let this = Arc::clone(self);
        self.rt.spawn(async move {
            let res: Result<()> = async {
                if draft.title.trim().is_empty() {
                    return Err(LoginError::Other("an article needs a title".into()));
                }
                if draft.body.trim().is_empty() {
                    return Err(LoginError::Other("an article needs a body".into()));
                }
                let active = this.active().await?;
                let me = active.me();
                let now = Timestamp::now().as_secs();
                let unsigned = UnsignedEvent::new(
                    me,
                    Timestamp::from_secs(now),
                    Kind::Custom(30023),
                    draft.tags(now),
                    draft.body.clone(),
                );
                let signed = active.signer.sign_event(unsigned).await?;
                // Same undo window as notes/pictures (hold_and_commit).
                match active.undo.hold_duration() {
                    Some(hold) => {
                        let token = this.hold_seq.fetch_add(1, Ordering::SeqCst);
                        let _ = tx.send(PublishEvent::Held {
                            token,
                            event: signed.clone(),
                            hold_secs: hold.as_secs(),
                        });
                        this.hold_and_commit(Arc::new(active.clone()), token, signed, hold, tx.clone())
                            .await;
                    }
                    None => Self::commit(&active, &signed, &tx).await?,
                }
                Ok(())
            }
            .await;
            if let Err(e) = res {
                let _ = tx.send(PublishEvent::Failed { token: 0, error: e.to_string() });
            } else {
                let _ = tx.send(PublishEvent::Committed { token: 0 });
            }
        });
        rx
    }

    /// Upload a blob to your Blossom servers (upload.ts). Emits
    /// `PublishEvent::Uploaded` with the blob URL + NIP-92 imeta tag; feed that
    /// imeta to `post_picture`.
    pub fn blossom_upload(self: &Arc<Self>, bytes: Vec<u8>, content_type: String) -> PublishRx {
        let (tx, rx) = mpsc::unbounded_channel();
        let this = Arc::clone(self);
        self.rt.spawn(async move {
            let res: std::result::Result<(), String> = async {
                if bytes.len() as u64 > crate::upload::MAX_BYTES {
                    return Err(format!(
                        "that file is too large (max {} MB)",
                        crate::upload::MAX_BYTES / (1024 * 1024)
                    ));
                }
                let active = this.active().await.map_err(|e| e.to_string())?;
                let me = active.me();
                // Your kind:10063 media-server list, newest wins (upload.ts
                // fetchBlossomServers); out-of-box default when unset.
                let filter = Filter::new()
                    .author(me)
                    .kind(Kind::Custom(crate::upload::KIND_BLOSSOM_LIST))
                    .limit(1);
                let server = active
                    .pool
                    .get(filter)
                    .await
                    .ok()
                    .and_then(|events| {
                        events
                            .into_iter()
                            .max_by_key(|ev| ev.created_at.as_secs())
                            .and_then(|ev| {
                                ev.tags
                                    .iter()
                                    .find(|t| t.as_slice().first().map(String::as_str) == Some("server"))
                                    .and_then(|t| t.as_slice().get(1).cloned())
                            })
                    })
                    .unwrap_or_else(|| crate::upload::DEFAULT_BLOSSOM_SERVER.to_string());
                let servers: Vec<String> = vec![server];
                let hash = crate::upload::sha256_hex(&bytes);
                let unsigned = crate::upload::blossom_auth_template(me, &hash);
                let signed = active
                    .signer
                    .sign_event(unsigned)
                    .await
                    .map_err(|e| e.to_string())?;                let up = crate::upload::blossom_upload_all(
                    &servers,
                    bytes,
                    &content_type,
                    &hash,
                    &signed,
                )
                .await?;
                let _ = tx.send(PublishEvent::Uploaded { url: up.url, imeta: up.imeta });
                Ok(())
            }
            .await;
            if let Err(e) = res {
                let _ = tx.send(PublishEvent::Failed { token: 0, error: e });
            }
        });
        rx
    }

    /// Fetch your kind:10063 media-server list for the settings pane. Emits
    /// `FeedEvent::MediaServers` (empty list = the out-of-box default applies).
    pub fn fetch_media_servers(self: &Arc<Self>) -> FeedRx {
        let (tx, rx) = mpsc::unbounded_channel();
        let this = Arc::clone(self);
        self.rt.spawn(async move {
            let res: Result<Vec<String>> = async {
                let active = this.active().await?;
                let me = active.me();
                let filter = Filter::new()
                    .author(me)
                    .kind(Kind::Custom(crate::upload::KIND_BLOSSOM_LIST))
                    .limit(1);
                let list = active
                    .pool
                    .get(filter)
                    .await
                    .ok()
                    .and_then(|events| {
                        events
                            .into_iter()
                            .max_by_key(|ev| ev.created_at.as_secs())
                    })
                    .map(|ev| server_tags(&ev))
                    .unwrap_or_default();
                Ok(list)
            }
            .await;
            match res {
                Ok(list) => {
                    let _ = tx.send(FeedEvent::MediaServers(list));
                }
                Err(e) => {
                    let _ = tx.send(FeedEvent::Failed(e.to_string()));
                }
            }
        });
        rx
    }

    /// Publish the media-server list (kind:10063, BUD-03) to your write
    /// relays — routes/settings.ts postMedia + upload.ts serverListTemplate.
    pub fn set_media_servers(self: &Arc<Self>, servers: Vec<String>) -> PublishRx {
        let (tx, rx) = mpsc::unbounded_channel();
        let this = Arc::clone(self);
        self.rt.spawn(async move {
            let res: Result<()> = async {
                let active = this.active().await?;
                let me = active.me();
                let tags: Vec<Tag> = servers
                    .iter()
                    .map(|s| Tag::custom("server", [s.trim_end_matches('/').to_string()]))
                    .collect();
                let unsigned = UnsignedEvent::new(
                    me,
                    Timestamp::now(),
                    Kind::Custom(crate::upload::KIND_BLOSSOM_LIST),
                    tags,
                    "",
                );
                let signed = active.signer.sign_event(unsigned).await?;
                Self::commit(&active, &signed, &tx).await?;
                Ok(())
            }
            .await;
            if let Err(e) = res {
                let _ = tx.send(PublishEvent::Failed { token: 0, error: e.to_string() });
            } else {
                let _ = tx.send(PublishEvent::Committed { token: 0 });
            }
        });
        rx
    }

    /// The undo window: sleep-or-cancel, then the backstop commit (ports
    /// undo.ts semantics; disk-persistence of holds lands in M1).
    async fn hold_and_commit(
        self: &Arc<Self>,
        active: Arc<Active>,
        token: u64,
        event: Event,
        hold: std::time::Duration,
        tx: mpsc::UnboundedSender<PublishEvent>,
    ) {
        let (cancel_tx, cancel_rx) = tokio::sync::oneshot::channel::<()>();
        self.holds.lock().unwrap().insert(token, cancel_tx);
        self.mirror_hold(&PublishEvent::Held { token, event: event.clone(), hold_secs: hold.as_secs() });
        tokio::spawn({
            let core = Arc::clone(self);
            async move {
                tokio::select! {
                    _ = tokio::time::sleep(hold + crate::undo::BACKSTOP_GRACE) => {
                        if let Err(e) = Self::commit(&active, &event, &tx).await {
                            core.mirror_hold(&PublishEvent::Failed { token, error: e.to_string() });
                            let _ = tx.send(PublishEvent::Failed { token, error: e.to_string() });
                        } else {
                            core.mirror_hold(&PublishEvent::Committed { token });
                            let _ = tx.send(PublishEvent::Committed { token });
                        }
                    }
                    _ = cancel_rx => {
                        core.mirror_hold(&PublishEvent::Undone { token });
                        let _ = tx.send(PublishEvent::Undone { token });
                    }
                }
                core.holds.lock().unwrap().remove(&token);
            }
        });
    }

    /// Cancel a held publish.
    pub fn undo(&self, token: u64) {
        if let Some(cancel) = self.holds.lock().unwrap().remove(&token) {
            let _ = cancel.send(());
        }
    }

    /// THE publish funnel (D36 full outbox): every outgoing event —
    /// notes, reactions, deletions, relay lists, restores — comes through
    /// here. The order IS the contract:
    /// 1. save to the store FIRST (local-first: the event exists even
    ///    fully offline),
    /// 2. enqueue in the outbox (write-ahead, synchronously persisted)
    ///    so a crash mid-publish still retries later,
    /// 3. publish to the current write set (slash-normalized, write-dead
    ///    filtered), learning per-relay outcomes for the fan-out,
    /// 4. ≥1 relay ACK → dequeue + Ok (the UI gets Committed); zero →
    ///    the item STAYS queued and Err flows to the UI as Failed. The
    ///    composer shows Committed only on first acceptance; a later
    ///    outbox success is logged, not re-toasted (D36).
    async fn commit(active: &Active, event: &Event, _tx: &mpsc::UnboundedSender<PublishEvent>) -> Result<()> {
        let _ = active.pool.store.save(event).await;
        crate::outbox_queue::enqueue(event);
        let targets = crate::outbox_queue::targets(&active.write_relays);
        let report = active.pool.publish(event, &targets).await;
        for r in &report.ok {
            crate::relay_latency::record_write_result(r, true);
        }
        for (r, _m) in &report.failed {
            crate::relay_latency::record_write_result(r, false);
        }
        if report.accepted() {
            crate::outbox_queue::remove(event);
            Ok(())
        } else {
            let n = report.failed.len();
            Err(LoginError::Connect(format!(
                "no relay accepted the event ({n} tried); queued for retry"
            )))
        }
    }

    /// The outbox drainer (D36): ONE task owns every retry, spawned once
    /// per process on the first bootstrap with a session. Serialized
    /// publishes mean a login drain can never double-fire against an
    /// in-flight backoff attempt (per-item loops could). Items survive
    /// restarts (the queue file loads on first touch), so drain-on-login
    /// is simply the drainer finding due items; logged-out stretches
    /// just push each item's next try out 60s at a time.
    fn spawn_outbox_drain(self: &Arc<Self>) {
        if self.outbox_started.swap(true, Ordering::SeqCst) {
            return;
        }
        eprintln!("[core] outbox: drainer armed");
        let weak = Arc::downgrade(self);
        self.rt.spawn(async move {
            loop {
                let Some(core) = weak.upgrade() else { break }; // app closing
                let Some(item) = crate::outbox_queue::next_due(crate::outbox_queue::now_secs()) else {
                    drop(core);
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                    continue;
                };
                let Ok(active) = core.active().await else {
                    crate::outbox_queue::reschedule(
                        &item.event,
                        crate::outbox_queue::now_secs() + 60,
                    );
                    continue;
                };
                let targets = crate::outbox_queue::targets(&active.write_relays);
                let report = active.pool.publish(&item.event, &targets).await;
                for r in &report.ok {
                    crate::relay_latency::record_write_result(r, true);
                }
                for (r, _m) in &report.failed {
                    crate::relay_latency::record_write_result(r, false);
                }
                if report.accepted() {
                    crate::outbox_queue::remove(&item.event);
                    let short = &item.event.id.to_string()[..8];
                    eprintln!(
                        "[core] outbox: {short} delivered after {} queued attempt(s)",
                        item.attempts
                    );
                } else {
                    crate::outbox_queue::mark_attempt(&item.event);
                }
            }
        });
    }

    /// Like (NIP-25). No undo window on reactions.
    pub fn react(self: &Arc<Self>, target: &Event) -> PublishRx {
        let (tx, rx) = mpsc::unbounded_channel();
        let this = Arc::clone(self);
        let target = target.clone();
        self.rt.spawn(async move {
            let res: Result<()> = async {
                let active = this.active().await?;
                let unsigned = UnsignedEvent::new(
                    active.me(),
                    Timestamp::now(),
                    Kind::Reaction,
                    [seen::hint_tag(target.id, &target.pubkey), Tag::public_key(target.pubkey)],
                    "+",
                );
                let signed = active.signer.sign_event(unsigned).await?;
                Self::commit(&active, &signed, &tx).await?;
                this.own_liked.lock().unwrap().insert(target.id.to_string());
                Ok(())
            }
            .await;
            if let Err(e) = res {
                let _ = tx.send(PublishEvent::Failed { token: 0, error: e.to_string() });
            } else {
                let _ = tx.send(PublishEvent::Committed { token: 0 });
            }
        });
        rx
    }

    /// Bookmark (NIP-51). Private by default: kind 10003 with the id in a
    /// nip44-encrypted tag list — the web app's private-default semantics.
    /// Public scope (D38): kind 30001 d="bookmarks", the id as a plain e-tag
    /// — which list the star writes is the settings pref's job.
    pub fn bookmark(self: &Arc<Self>, target: &Event, public: bool) -> PublishRx {
        let (tx, rx) = mpsc::unbounded_channel();
        let this = Arc::clone(self);
        let target = target.clone();
        self.rt.spawn(async move {
            let res: Result<()> = async {
                let active = this.active().await?;
                let me = active.me();
                if !public {
                    // Private: the content array is the list (nip44); the
                    // stored event's other tags ride along (a plain e-tag
                    // the user's other client wrote must survive the RMW).
                    let stored = active
                        .pool
                        .store
                        .latest_by_kind(me, Kind::Custom(10003))
                        .await
                        .ok()
                        .flatten();
                    let mut ids: Vec<String> =
                        this.own_bookmarked.lock().unwrap().clone().into_iter().collect();
                    ids.push(target.id.to_string());
                    let plain = list_json(&ids, "e");
                    let content = active.signer.nip44_encrypt_self(&me, &plain).await?;
                    let unsigned = UnsignedEvent::new(
                        me,
                        Timestamp::now(),
                        Kind::Custom(10003),
                        stored.map(|ev| ev.tags.clone().to_vec()).unwrap_or_default(),
                        content,
                    );
                    let signed = active.signer.sign_event(unsigned).await?;
                    Self::commit(&active, &signed, &tx).await?;
                } else {
                    // Public: NIP-51 kind 30001 d="bookmarks" — the e-tags
                    // ARE the list (my event only — others' 30001s are
                    // different lists). The d and any other markers ride
                    // along; the push dedupes.
                    let stored = active
                        .pool
                        .store
                        .latest_by_kind_d(me, Kind::Custom(30001), "bookmarks")
                        .await
                        .ok()
                        .flatten();
                    let mut raw: Vec<Tag> = stored.map(|ev| ev.tags.clone().to_vec()).unwrap_or_default();
                    let hex = target.id.to_string();
                    let present = raw
                        .iter()
                        .any(|t| t.kind() == "e" && t.content() == Some(hex.as_str()));
                    if !present {
                        raw.push(Tag::event(target.id));
                    }
                    let unsigned =
                        UnsignedEvent::new(me, Timestamp::now(), Kind::Custom(30001), raw, "");
                    let signed = active.signer.sign_event(unsigned).await?;
                    Self::commit(&active, &signed, &tx).await?;
                }
                this.own_bookmarked.lock().unwrap().insert(target.id.to_string());
                Ok(())
            }
            .await;
            if let Err(e) = res {
                let _ = tx.send(PublishEvent::Failed { token: 0, error: e.to_string() });
            } else {
                let _ = tx.send(PublishEvent::Committed { token: 0 });
            }
        });
        rx
    }

    /// Un-bookmark (D38): RMW BOTH lists — the private 10003 (content array
    /// plus any plain e-tags it carries) and the public 30001
    /// d="bookmarks" — publishing only a list that actually held the id.
    pub fn unbookmark(self: &Arc<Self>, id: EventId) -> PublishRx {
        let (tx, rx) = mpsc::unbounded_channel();
        let this = Arc::clone(self);
        self.rt.spawn(async move {
            let res: Result<()> = async {
                let active = this.active().await?;
                let me = active.me();
                let hex = id.to_string();
                // Private list: decrypt, drop the id, re-encrypt — only if
                // it was there (content array OR a plain e-tag).
                let stored = active
                    .pool
                    .store
                    .latest_by_kind(me, Kind::Custom(10003))
                    .await
                    .ok()
                    .flatten();
                if let Some(ev) = stored {
                    let ids: Vec<String> = if ev.content.is_empty() {
                        Vec::new()
                    } else {
                        active
                            .signer
                            .nip44_decrypt_self(&me, ev.content.as_str())
                            .await
                            .map(|plain| parse_list_event(&plain))
                            .unwrap_or_default()
                    };
                    let in_content = ids.iter().any(|s| s == &hex);
                    let in_tags = ev
                        .tags
                        .clone()
                        .to_vec()
                        .iter()
                        .any(|t| t.kind() == "e" && t.content() == Some(hex.as_str()));
                    if in_content || in_tags {
                        let ids: Vec<String> =
                            ids.into_iter().filter(|s| s != &hex).collect();
                        let plain = list_json(&ids, "e");
                        let content = active.signer.nip44_encrypt_self(&me, &plain).await?;
                        // The stored event's non-removed tags ride along
                        // (plain e-tags from another client, client marks).
                        let mut raw: Vec<Tag> = ev.tags.clone().to_vec();
                        raw.retain(|t| !(t.kind() == "e" && t.content() == Some(hex.as_str())));
                        let unsigned = UnsignedEvent::new(
                            me,
                            Timestamp::now(),
                            Kind::Custom(10003),
                            raw,
                            content,
                        );
                        let signed = active.signer.sign_event(unsigned).await?;
                        Self::commit(&active, &signed, &tx).await?;
                    }
                }
                // Public list: rebuild the stored tags without the id's
                // e-tag (the d rides along) — only if it was there.
                let stored = active
                    .pool
                    .store
                    .latest_by_kind_d(me, Kind::Custom(30001), "bookmarks")
                    .await
                    .ok()
                    .flatten();
                if let Some(ev) = stored {
                    let mut raw: Vec<Tag> = ev.tags.clone().to_vec();
                    let before = raw.len();
                    raw.retain(|t| !(t.kind() == "e" && t.content() == Some(hex.as_str())));
                    if raw.len() < before {
                        let unsigned = UnsignedEvent::new(
                            me,
                            Timestamp::now(),
                            Kind::Custom(30001),
                            raw,
                            "",
                        );
                        let signed = active.signer.sign_event(unsigned).await?;
                        Self::commit(&active, &signed, &tx).await?;
                    }
                }
                this.own_bookmarked.lock().unwrap().remove(&hex);
                Ok(())
            }
            .await;
            if let Err(e) = res {
                let _ = tx.send(PublishEvent::Failed { token: 0, error: e.to_string() });
            } else {
                let _ = tx.send(PublishEvent::Committed { token: 0 });
            }
        });
        rx
    }

    /// The own bookmarks hydrated (D38): the merged id set (private 10003 +
    /// public 30001) resolved from the store — expired (NIP-40) and deleted
    /// (NIP-09) dropped at the same gates the whisper uses — with missing
    /// ids fetched from the indexers by a targeted ids query. One shot: the
    /// list is finite, so the page carries has_more = false (the feed never
    /// orders an Older round for this mode).
    pub fn bookmarked_notes(self: &Arc<Self>) -> FeedRx {
        let (tx, rx) = mpsc::unbounded_channel();
        let this = Arc::clone(self);
        self.rt.spawn(async move {
            let res: Result<FeedEvent> = async {
                let active = this.active().await?;
                let want: Vec<EventId> = this
                    .own_bookmarked
                    .lock()
                    .unwrap()
                    .iter()
                    .filter_map(|h| EventId::from_hex(h).ok())
                    .collect();
                let mut events: Vec<Event> = Vec::new();
                for id in &want {
                    if let Some(ev) = active.pool.store.event_by_id(*id).await.ok().flatten()
                        && !nip40::is_expired(&ev)
                        && !deletions::is_deleted(&ev)
                    {
                        events.push(ev);
                    }
                }
                let have: HashSet<EventId> = events.iter().map(|e| e.id).collect();
                let missing: Vec<EventId> =
                    want.iter().filter(|id| !have.contains(id)).cloned().collect();
                if !missing.is_empty() {
                    // feeds.ts fetchEventsByIds: a TARGETED query on the
                    // indexers (a bookmarked note's author may be outside
                    // the follows — seen-on can't narrow this one). Split
                    // at the REQ ceiling (WS1: OutboxRouter.kt
                    // MAX_ETAGS_PER_FILTER).
                    let fallback: Vec<String> =
                        INDEXERS.iter().map(|s| s.to_string()).collect();
                    for id_shard in outbox::chunk(&missing, outbox::MAX_ETAGS_PER_FILTER) {
                        let n = id_shard.len();
                        let filter = Filter::new().ids(id_shard).limit(n);
                        let fetched: Vec<Event> = active
                            .pool
                            .get_from(&fallback, &filter)
                            .await
                            .into_iter()
                            .collect();
                        // Explicit saves (v1.2): the SDK's saves are async and
                        // once raced a reader — a fetched bookmark should BE
                        // in the store before this task ends.
                        for ev in &fetched {
                            let _ = active.pool.store.save(ev).await;
                        }
                        events
                            .extend(fetched.into_iter().filter(|ev| !deletions::is_deleted(ev)));
                    }
                }
                events.sort_by_key(|e| std::cmp::Reverse(e.created_at));
                let profiles = Self::profiles_for(&active, &events).await;
                Ok(FeedEvent::Loaded(FeedPage { notes: events, profiles }))
            }
            .await;
            match res {
                Ok(ev) => {
                    let _ = tx.send(ev);
                }
                Err(e) => {
                    let _ = tx.send(FeedEvent::Failed(e.to_string()));
                }
            }
        });
        rx
    }

    /// Save a composer draft (D38): replace-or-insert by slot — the
    /// (reply, quote) pair; an empty text DELETES the slot (closing a
    /// compose empty clears a stale draft, the session stash's semantics).
    /// `attachments` (v1.4) ride the entry: the uploaded imeta arrays,
    /// verbatim — the blobs are already on Blossom (upload-at-attach).
    /// `photo_post` (issue #3 WS1) rides too: the composer tab the draft
    /// was written in decides the publish kind on restore.
    /// The whole array re-encrypts into the one NIP-78 event and rides
    /// commit() (30078 is coordinate-keyed, the outbox retries it).
    /// Optimistic (v1.1): the in-memory array spends immediately so the
    /// composer/Library never wait on the relay round; a failed publish
    /// restores what was spent.
    pub fn save_draft(
        self: &Arc<Self>,
        reply_to: Option<EventId>,
        quote: Option<EventId>,
        text: String,
        attachments: Vec<Vec<String>>,
        photo_post: bool,
    ) -> PublishRx {
        let (tx, rx) = mpsc::unbounded_channel();
        let this = Arc::clone(self);
        // Optimistic (v1.1): the in-memory array updates NOW — the
        // composer open and the Library rows react instantly — and the
        // publish rides behind; a failed publish RESTORES the spent
        // entries (D38's "failed save leaves the slot intact", just
        // without the wait).
        let key = (reply_to.map(|e| e.to_string()), quote.map(|e| e.to_string()));
        let (plain, spent) = {
            let mut drafts = this.own_drafts.lock().unwrap().clone();
            // Satori's own slot entries replace by (reply, quote);
            // imported (id-marked) entries only ever leave through
            // drop_draft (their wrap is a separate event).
            let mut spent: Vec<DraftEntry> = drafts
                .iter()
                .filter(|d| d.id.is_none() && d.matches(key.0.as_deref(), key.1.as_deref()))
                .cloned()
                .collect();
            drafts.retain(|d| d.id.is_some() || !d.matches(key.0.as_deref(), key.1.as_deref()));
            if !text.trim().is_empty() {
                let entry = DraftEntry {
                    text,
                    reply_to: key.0,
                    quote: key.1,
                    id: None,
                    attachments,
                    photo_post,
                    at: Timestamp::now().as_secs(),
                };
                spent.push(entry.clone());
                drafts.push(entry);
            }
            let plain = serde_json::to_string(&drafts).unwrap_or_default();
            *this.own_drafts.lock().unwrap() = drafts;
            (plain, spent)
        };
        self.rt.spawn(async move {            let res: Result<()> = async {
                let active = this.active().await?;
                let me = active.me();
                let content = active.signer.nip44_encrypt_self(&me, &plain).await?;
                let unsigned = UnsignedEvent::new(
                    me,
                    Timestamp::now(),
                    Kind::Custom(30078),
                    [Tag::custom("d", ["satori/drafts"])],
                    content,
                );
                let signed = active.signer.sign_event(unsigned).await?;
                Self::commit(&active, &signed, &tx).await?;
                Ok(())
            }
            .await;
            if let Err(e) = res {
                // Restore: the spent entries come back unless a newer
                // save already re-filled the slot.
                let mut drafts = this.own_drafts.lock().unwrap().clone();
                for d in spent {
                    if !drafts.contains(&d) {
                        drafts.push(d);
                    }
                }
                *this.own_drafts.lock().unwrap() = drafts;
                let _ = tx.send(PublishEvent::Failed { token: 0, error: e.to_string() });
            } else {
                let _ = tx.send(PublishEvent::Committed { token: 0 });
            }
        });
        rx
    }

    /// Drop a draft entry (D38 v1.1): remove it from the array and
    /// republish the stash; an imported entry's kind 31234 wrap is ALSO
    /// republished with empty content — NIP-37's delete (the empty shell
    /// sits on the relays until its NIP-40 expiry purges it).
    pub fn drop_draft(self: &Arc<Self>, id: String) -> PublishRx {
        let (tx, rx) = mpsc::unbounded_channel();
        let this = Arc::clone(self);
        // Optimistic (v1.1): the entry leaves the in-memory array NOW —
        // the row vanishes the moment the tap lands — and the publishes
        // (the 30078 stash, then the wrap's NIP-37 empty-content delete)
        // ride behind; a failed publish restores the entry.
        let (plain, spent) = {
            let mut drafts = this.own_drafts.lock().unwrap().clone();
            let spent: Vec<DraftEntry> = drafts
                .iter()
                .filter(|d| d.id.as_deref() == Some(id.as_str()))
                .cloned()
                .collect();
            drafts.retain(|d| d.id.as_deref() != Some(id.as_str()));
            let plain = serde_json::to_string(&drafts).unwrap_or_default();
            *this.own_drafts.lock().unwrap() = drafts;
            (plain, spent)
        };
        self.rt.spawn(async move {
            let res: Result<()> = async {
                let active = this.active().await?;
                let me = active.me();
                let content = active.signer.nip44_encrypt_self(&me, &plain).await?;
                let unsigned = UnsignedEvent::new(
                    me,
                    Timestamp::now(),
                    Kind::Custom(30078),
                    [Tag::custom("d", ["satori/drafts"])],
                    content,
                );
                let signed = active.signer.sign_event(unsigned).await?;
                Self::commit(&active, &signed, &tx).await?;
                // The wrap itself: NIP-37's delete — republish with empty
                // content (relays keep the empty shell until NIP-40 expiry).
                if let Ok(Some(wrap)) = active
                    .pool
                    .store
                    .latest_by_kind_d(me, Kind::Custom(31234), &id)
                    .await
                {
                    let unsigned = UnsignedEvent::new(
                        me,
                        Timestamp::now(),
                        Kind::Custom(31234),
                        wrap.tags.clone().to_vec(),
                        "",
                    );
                    let signed = active.signer.sign_event(unsigned).await?;
                    Self::commit(&active, &signed, &tx).await?;
                }
                Ok(())
            }
            .await;
            if let Err(e) = res {
                let mut drafts = this.own_drafts.lock().unwrap().clone();
                for d in spent {
                    if !drafts.contains(&d) {
                        drafts.push(d);
                    }
                }
                *this.own_drafts.lock().unwrap() = drafts;
                let _ = tx.send(PublishEvent::Failed { token: 0, error: e.to_string() });
            } else {
                let _ = tx.send(PublishEvent::Committed { token: 0 });
            }
        });
        rx
    }

    /// The synced drafts, snapshot (the Library's Drafts tab reads it at
    /// render — pane switches notify on every path that changes it).
    pub fn own_draft_list(&self) -> Vec<DraftEntry> {
        self.own_drafts.lock().unwrap().clone()
    }

    /// One note by id (D38: the Drafts tab restores a draft's reply/quote
    /// context): the store first, then a targeted ids query on the
    /// indexers — the ParentNote resolution's pattern, with the same
    /// NIP-40/NIP-09 gates. None when nowhere.
    pub fn note_by_id(self: &Arc<Self>, id: EventId) -> tokio::sync::mpsc::UnboundedReceiver<Option<Event>> {
        let (tx, rx) = mpsc::unbounded_channel();
        let this = Arc::clone(self);
        self.rt.spawn(async move {
            let ev = async {
                let active = this.active().await?;
                let stored = active.pool.store.event_by_id(id).await.ok().flatten();
                let ev = match stored {
                    Some(ev)
                        if !nip40::is_expired(&ev) && !deletions::is_deleted(&ev) =>
                    {
                        Some(ev)
                    }
                    _ => {
                        let filter = Filter::new().ids(vec![id]).limit(1);
                        let fallback: Vec<String> =
                            INDEXERS.iter().map(|s| s.to_string()).collect();
                        active
                            .pool
                            .get_from(&fallback, &filter)
                            .await
                            .into_iter()
                            .find(|ev| !deletions::is_deleted(ev))
                    }
                };
                Ok::<Option<Event>, LoginError>(ev)
            }
            .await;
            let _ = tx.send(ev.unwrap_or(None));
        });
        rx
    }

    /// Current NIP-65 relay split (settings pane projection).
    pub fn current_relays(&self) -> (Vec<String>, Vec<String>) {
        self.active
            .lock()
            .unwrap()
            .as_ref()
            .map(|a| (a.read_relays.clone(), a.write_relays.clone()))
            .unwrap_or_default()
    }

    /// The learned per-relay health (D33/D36: latency EWMA, read-dead,
    /// write-dead) for the settings relay-health pane. A free function on
    /// the type — the data is a process-wide sidecar, not per-account.
    pub fn relay_health() -> Vec<crate::relay_latency::RelayHealth> {
        crate::relay_latency::snapshot()
    }

    /// Pool connectivity for the shell rail's live dot (0.2-design-spec
    /// §4.4), read off the D33/D36 latency machinery — the SDK's socket
    /// states are not surfaced per relay, so "connected" means the only
    /// thing we can honestly claim: some relay DELIVERED an event or ACKed
    /// a publish inside the recent window. False = no recent proof of life
    /// (startup, all relays dead, offline).
    pub fn pool_connected() -> bool {
        crate::relay_latency::connected()
    }

    /// Remembered NIP-11 capabilities (nip11.rs): what each relay
    /// ADVERTISES it can do, for honest degradation whispers. A relay we
    /// never fetched is absent or `search: None` — unknown, not refused.
    pub fn relay_capabilities() -> Vec<crate::nip11::RelayCaps> {
        crate::nip11::snapshot()
    }

    /// NIP-11 capability sweep for the read set (nip11.rs refresh_stale):
    /// TTL-gated (7d), background, fire-and-forget — capabilities are
    /// whispers, not routing. Spawned wherever the read set joins the pool.
    fn spawn_relay_info(&self, reads: &[String]) {
        let mut urls: Vec<String> = crate::pool::INDEXERS.iter().map(|s| s.to_string()).collect();
        urls.extend(reads.iter().cloned());
        urls.sort();
        urls.dedup();
        self.rt.spawn(async move {
            crate::nip11::refresh_stale(&urls).await;
        });
    }

    /// Pending outbox items (D36): notes signed and saved but not yet ACKed
    /// by any relay. The shell's "queued for delivery" honesty state.
    pub fn outbox_pending() -> usize {
        crate::outbox_queue::len()
    }

    /// Publish the NIP-65 relay list (kind:10002 RMW) and swap it in live:
    /// new reads join the pool, removed writes stop receiving publishes.
    pub fn set_relays(self: &Arc<Self>, read: Vec<String>, write: Vec<String>) -> PublishRx {
        let (tx, rx) = mpsc::unbounded_channel();
        let this = Arc::clone(self);
        self.rt.spawn(async move {
            let res: Result<()> = async {
                let active = this.active().await?;
                let me = active.me();
                let mut tags: Vec<Tag> = Vec::new();
                for url in &read {
                    let marker = if write.contains(url) { None } else { Some("read") };
                    tags.push(relay_tag(url, marker));
                }
                for url in &write {
                    if read.contains(url) {
                        continue; // both-capability tags carry no marker
                    }
                    tags.push(relay_tag(url, Some("write")));
                }
                let unsigned =
                    UnsignedEvent::new(me, Timestamp::now(), Kind::RelayList, tags, "");
                let signed = active.signer.sign_event(unsigned).await?;
                Self::commit(&active, &signed, &tx).await?;
                {
                    let mut a = this.active.lock().unwrap();
                    if let Some(a) = a.as_mut() {
                        a.read_relays = read.clone();
                        a.write_relays = write.clone();
                    }
                }
                // New reads join the pool; reads the user dropped are
                // retired live (they used to drain only on restart).
                active.pool.set_reads(&read).await;
                this.spawn_relay_info(&read);
                Ok(())
            }
            .await;
            if let Err(e) = res {
                let _ = tx.send(PublishEvent::Failed { token: 0, error: e.to_string() });
            } else {
                let _ = tx.send(PublishEvent::Committed { token: 0 });
            }
        });
        rx
    }

    /// Follow / unfollow (NIP-02 kind:3 read-modify-write).
    pub fn set_following(self: &Arc<Self>, who: PublicKey, follow: bool) -> PublishRx {
        let (tx, rx) = mpsc::unbounded_channel();
        let this = Arc::clone(self);
        self.rt.spawn(async move {
            let res: Result<()> = async {
                let active = this.active().await?;
                let me = active.me();
                let mut follows = active.follows.clone();
                if follow {
                    if !follows.contains(&who) {
                        follows.push(who);
                    }
                } else {
                    follows.retain(|f| f != &who);
                }
                let tags: Vec<Tag> = follows.iter().map(|pk| Tag::public_key(*pk)).collect();
                let unsigned = UnsignedEvent::new(me, Timestamp::now(), Kind::ContactList, tags, "");
                let signed = active.signer.sign_event(unsigned).await?;
                Self::commit(&active, &signed, &tx).await?;
                {
                    let mut a = this.active.lock().unwrap();
                    if let Some(a) = a.as_mut() {
                        a.follows = follows;
                    }
                }
                Ok(())
            }
            .await;
            if let Err(e) = res {
                let _ = tx.send(PublishEvent::Failed { token: 0, error: e.to_string() });
            } else {
                let _ = tx.send(PublishEvent::Committed { token: 0 });
            }
        });
        rx
    }

    /// Mute / unmute (NIP-51 kind:10000, content encrypted to self).
    pub fn set_muted(self: &Arc<Self>, who: PublicKey, mute: bool) -> PublishRx {
        let (tx, rx) = mpsc::unbounded_channel();
        let this = Arc::clone(self);
        self.rt.spawn(async move {
            let res: Result<()> = async {
                let active = this.active().await?;
                let me = active.me();
                let mut mutes = this.muted.lock().unwrap().clone();
                let hex = who.to_string();
                if mute {
                    mutes.insert(hex.clone());
                } else {
                    mutes.remove(&hex);
                }
                let plain = list_json(&mutes.into_iter().collect::<Vec<_>>(), "p");
                let content = active.signer.nip44_encrypt_self(&me, &plain).await?;
                let unsigned = UnsignedEvent::new(me, Timestamp::now(), Kind::Custom(10000), [], content);
                let signed = active.signer.sign_event(unsigned).await?;
                Self::commit(&active, &signed, &tx).await?;
                // Keep the WoT qualification's mute screen in step.
                crate::wot::set_muted(this.muted.lock().unwrap().clone());
                Ok(())
            }
            .await;
            if let Err(e) = res {
                let _ = tx.send(PublishEvent::Failed { token: 0, error: e.to_string() });
            } else {
                let _ = tx.send(PublishEvent::Committed { token: 0 });
            }
        });
        rx
    }

    /// The own kind:0 content string, RAW (D38: the edit form prefills
    /// from it — the parsed Profile drops display_name/website, and a form
    /// save writes every displayed field, so a missing prefill would
    /// silently clobber them). Empty string when none (fresh account).
    pub fn own_metadata(self: &Arc<Self>) -> tokio::sync::mpsc::UnboundedReceiver<String> {
        let (tx, rx) = mpsc::unbounded_channel();
        let this = Arc::clone(self);
        self.rt.spawn(async move {
            let content = async {
                let active = this.active().await?;
                let me = active.me();
                let raw = active
                    .pool
                    .store
                    .latest_by_kind(me, Kind::Metadata)
                    .await
                    .ok()
                    .flatten()
                    .map(|e| e.content)
                    .unwrap_or_default();
                Ok::<String, LoginError>(raw)
            }
            .await;
            let _ = tx.send(content.unwrap_or_default());
        });
        rx
    }

    /// The own parsed Profile, from the store's freshest kind:0 (D38: the
    /// edit form's save lands a new kind 0 — the shell refreshes the rail's
    /// copy and the profile pane underneath with it; the profiles service's
    /// cache holds a 12h TTL, far too long to lean on). None when none is
    /// stored.
    pub fn own_profile(self: &Arc<Self>) -> tokio::sync::mpsc::UnboundedReceiver<Option<Profile>> {
        let (tx, rx) = mpsc::unbounded_channel();
        let this = Arc::clone(self);
        self.rt.spawn(async move {
            let p = async {
                let active = this.active().await?;
                let me = active.me();
                Ok::<Option<Profile>, LoginError>(active
                    .pool
                    .store
                    .latest_by_kind(me, Kind::Metadata)
                    .await
                    .ok()
                    .flatten()
                    .and_then(|e| Profile::from_event(&e)))
            }
            .await;
            let _ = tx.send(p.unwrap_or(None));
        });
        rx
    }

    /// Edit profile (NIP-01 kind:0 read-modify-write): the patch's Some
    /// fields overwrite, Some("") clears, None leaves the stored value;
    /// fields the app doesn't edit (lud06/lud16 and friends) ride along
    /// untouched. Published through commit() — the outbox retries it
    /// (kind 0 is coordinate-keyed, D36).
    pub fn set_profile(self: &Arc<Self>, patch: ProfileEdit) -> PublishRx {
        let (tx, rx) = mpsc::unbounded_channel();
        let this = Arc::clone(self);
        self.rt.spawn(async move {
            let res: Result<()> = async {
                let active = this.active().await?;
                let me = active.me();
                let stored = active
                    .pool
                    .store
                    .latest_by_kind(me, Kind::Metadata)
                    .await
                    .ok()
                    .flatten();
                let content = apply_profile_patch(
                    stored.as_ref().map(|e| e.content.as_str()).unwrap_or(""),
                    &patch,
                );
                let unsigned = UnsignedEvent::new(me, Timestamp::now(), Kind::Metadata, [], content);
                let signed = active.signer.sign_event(unsigned).await?;
                Self::commit(&active, &signed, &tx).await?;
                Ok(())
            }
            .await;
            if let Err(e) = res {
                let _ = tx.send(PublishEvent::Failed { token: 0, error: e.to_string() });
            } else {
                let _ = tx.send(PublishEvent::Committed { token: 0 });
            }
        });
        rx
    }

    /// Delete own post (NIP-09 kind:5) + local tombstone.
    pub fn delete(self: &Arc<Self>, target: &Event) -> PublishRx {
        let (tx, rx) = mpsc::unbounded_channel();
        let this = Arc::clone(self);
        let target = target.clone();
        self.rt.spawn(async move {
            let res: Result<()> = async {
                let active = this.active().await?;
                let unsigned = UnsignedEvent::new(
                    active.me(),
                    Timestamp::now(),
                    Kind::EventDeletion,
                    [seen::hint_tag(target.id, &target.pubkey)],
                    "",
                );
                let signed = active.signer.sign_event(unsigned).await?;
                Self::commit(&active, &signed, &tx).await?;
                // Own deletion accepted: PIN the tombstone (deletions.ts
                // recordDeletion(ev, pin=true)) — immune to relay-fed
                // eviction, so the deleted note can't resurrect through
                // embeds, re-fetches, or a stranger's tag-spam churn.
                // (Audit: this was never wired; the pinned maps were dead.)
                deletions::record(&signed, true);
                let _ = active.pool.store.delete_event(target.id).await;
                Ok(())
            }
            .await;
            if let Err(e) = res {
                let _ = tx.send(PublishEvent::Failed { token: 0, error: e.to_string() });
            } else {
                let _ = tx.send(PublishEvent::Committed { token: 0 });
            }
        });
        rx
    }

    /// Listen for push signals (bell dot, new-notes pill). Broadcast —
    /// every open pane keeps its own receiver.
    pub fn subscribe_live(&self) -> tokio::sync::broadcast::Receiver<Live> {
        self.live.subscribe()
    }

    // --- viewport engagement (WS2, viewport.rs) ---------------------------------

    /// The feed's settled visible window: the ids whose engagement should
    /// arrive LIVE. One subscription, closed/replaced as the window moves
    /// (no-op when the id set is unchanged). An empty vec drops the sub.
    pub fn set_viewport(self: &Arc<Self>, ids: Vec<EventId>) {
        // Unchanged sets don't mark the watch — no churn on no-op calls.
        let _ = self.viewport_ids.send(ids);
        self.start_viewport();
    }

    /// ONE task per process owns the viewport subscription's lifecycle
    /// (the live bell's discipline, minus the session scoping — the pool
    /// is per-process): watch the id channel; on change, plan → close the
    /// current sub → arm the next; deliver matching events into the store
    /// (the SDK saves on receive) and signal `Live::Engagement`.
    fn start_viewport(self: &Arc<Self>) {
        if self
            .viewport_started
            .swap(true, std::sync::atomic::Ordering::SeqCst)
        {
            return;
        }
        let this = Arc::clone(self);
        self.rt.spawn(async move {
            use futures_util::StreamExt as _;
            // The pool is built before any session paints a feed; a task
            // that raced it simply re-arms on the next set_viewport.
            let Some(pool) = this.pool.lock().unwrap().clone() else {
                this.viewport_started
                    .store(false, std::sync::atomic::Ordering::SeqCst);
                return;
            };
            let mut rx_ids = this.viewport_ids.subscribe();
            let mut tracker = crate::viewport::ViewportTracker::default();
            let mut current: Option<Output<SubscriptionId>> = None;
            let kinds: Vec<Kind> = crate::viewport::ENGAGEMENT_KINDS
                .iter()
                .map(|k| Kind::from_u16(*k))
                .collect();
            let mut notifs = pool.client().notifications();
            loop {
                tokio::select! {
                    res = rx_ids.changed() => {
                        if res.is_err() {
                            // All senders gone (process teardown).
                            return;
                        }
                        let ids = rx_ids.borrow().clone();
                        match tracker.plan(&ids) {
                            crate::viewport::Plan::Keep => {}
                            crate::viewport::Plan::Drop => {
                                // The viewport went away (pane closed, no
                                // rows): the sub MUST close with it.
                                if let Some(o) = current.take() {
                                    let _ = pool.client().unsubscribe(o.id()).await;
                                }
                                tracker.commit(Vec::new());
                            }
                            crate::viewport::Plan::Replace(shards) => {
                                // Close before arming — never two live
                                // viewport subs (D24: no churn pileup).
                                if let Some(o) = current.take() {
                                    let _ = pool.client().unsubscribe(o.id()).await;
                                }
                                match pool
                                    .subscribe_for_ids(
                                        kinds.clone(),
                                        &shards.iter().flatten().copied().collect::<Vec<_>>(),
                                        Some(Timestamp::now()),
                                    )
                                    .await
                                {
                                    Ok(o) => {
                                        tracker
                                            .commit(shards.iter().flatten().copied().collect());
                                        current = Some(o);
                                    }
                                    Err(e) => {
                                        eprintln!(
                                            "[core] viewport: subscribe failed ({e})"
                                        );
                                        // Bookkeeping matches the relay's
                                        // view so the next change re-arms.
                                        tracker.commit(Vec::new());
                                        current = None;
                                    }
                                }
                            }
                        }
                    }
                    Some(n) = notifs.next() => {
                        // Only OUR subscription's events; the bell's own
                        // loop consumes its own ids from the same stream.
                        let Some(o) = &current else { continue };
                        match n {
                            nostr_sdk::client::ClientNotification::Event {
                                relay_url,
                                subscription_id,
                                event,
                                ..
                            } if o.id() == &subscription_id => {
                                // Same ingestion discipline as the bell:
                                // seen-on + author hints, the chokepoint
                                // gates, then the signal. The SDK has
                                // already saved the event.
                                seen::record(&event.pubkey, &[relay_url.as_str()]);
                                hints::observe(&event, relay_url.as_str());
                                // Proof of life for the rail's live dot
                                // (relay_latency::connected): an event
                                // arrived over this relay's socket.
                                crate::relay_latency::mark_delivery(relay_url.as_str());
                                if u16::from(event.kind) == 5 {
                                    deletions::record(&event, false);
                                    continue;
                                }
                                if nip40::is_expired(&event) || deletions::is_deleted(&event) {
                                    continue;
                                }
                                // Own engagement arriving from the relays
                                // (another device/client): the mirrors are
                                // the render state — flip them live.
                                if Some(event.pubkey) == this.pubkey() {
                                    let target = event
                                        .tags
                                        .clone()
                                        .event_ids()
                                        .next()
                                        .map(|t| t.to_string());
                                    if let Some(target) = target {
                                        match u16::from(event.kind) {
                                            7 => {
                                                this.own_liked
                                                    .lock()
                                                    .unwrap()
                                                    .insert(target);
                                            }
                                            6 | 16 => {
                                                this.own_reposted
                                                    .lock()
                                                    .unwrap()
                                                    .insert(target);
                                            }
                                            _ => {}
                                        }
                                    }
                                }
                                let _ = this.live.send(Live::Engagement);
                            }
                            _ => {}
                        }
                    }
                }
            }
        });
    }

    /// The hold-state mirror for the shell's undo toast (Held → countdown,
    /// Committed/Undone/Failed → clear). The composer pops on Held, so the
    /// toast outlives it — subscribe once at shell creation.
    pub fn subscribe_hold(&self) -> tokio::sync::broadcast::Receiver<PublishEvent> {
        self.hold_tx.subscribe()
    }

    fn mirror_hold(&self, ev: &PublishEvent) {
        let _ = self.hold_tx.send(ev.clone());
    }

    /// ONE persistent subscription per session, three filters: fresh posts
    /// from follows (timeline pill), #p me (bell — every NIP-10/NIP-22 reply
    /// tags the parent author), kind-5 deletions (render filter). First-seen
    /// events route to broadcast signals; everything saves to the store.
    /// Follows are snapshotted at start — a mid-session follow change rides
    /// the next refresh's fetches until the next session.
    async fn start_live(&self, kinds: Vec<Kind>) {
        use futures_util::StreamExt as _;
        // Resolve the session BEFORE arming the flag: a failed resolve must
        // not wedge live_on true (it used to — the sub could never re-arm).
        let Ok(active) = self.active().await else { return };
        if self.live_on.swap(true, std::sync::atomic::Ordering::SeqCst) {
            return;
        }
        let pool = active.pool.clone();
        let live = self.live.clone();
        let live_on = self.live_on.clone();
        let live_epoch = Arc::clone(&self.live_epoch);
        // Captured at arm time; a mismatch at loop time means this session
        // was signed out and the loop tears its sub down below.
        let my_epoch = live_epoch.load(std::sync::atomic::Ordering::SeqCst);
        let me = active.me();
        let follows = active.follows.clone();
        self.rt.spawn(async move {
            let now = Timestamp::now();
            // NIP-01: an empty list can never match — the follows-scoped
            // filters join only when there are follows to scope by.
            let mut filters = vec![Filter::new()
                .kinds([Kind::TextNote, Kind::Custom(1111), Kind::Custom(9735)])
                .pubkey(me)
                .since(now)];
            if !follows.is_empty() {
                filters.push(
                    Filter::new()
                        .kind(Kind::EventDeletion)
                        .authors(follows.clone())
                        .since(now),
                );
            }
            let output = match pool.client().subscribe(filters).await {
                Ok(o) => o,
                Err(e) => {
                    eprintln!("[core] live: subscribe failed ({e}); re-arming");
                    live_on.store(false, std::sync::atomic::Ordering::SeqCst);
                    return;
                }
            };
            // The follows' notes ride the OUTBOX (each author from the
            // relays they write to — routed live fan-out, feeds.ts): a
            // second subscription, merged into the same notification
            // stream. Failure degrades to the main read set (indexers +
            // own inbox relays), not to a dead bell.
            let routed = if follows.is_empty() {
                None
            } else {
                match pool
                    .subscribe_routed(kinds.clone(), &follows, Some(now))
                    .await
                {
                    Ok(o) => Some(o),
                    Err(e) => {
                        eprintln!("[core] live: outbox fan-out failed ({e}); indexers only");
                        None
                    }
                }
            };
            let mut notifications = pool.client().notifications();
            while let Some(n) = notifications.next().await {
                // Session changed (sign-out, or a different account): drop
                // the stale identity's subscription. The check runs before
                // anything touches the store or the bell. live_on is left
                // alone here — sign-out already reset it, and storing
                // again could clobber a NEWER session's armed flag.
                if live_epoch.load(std::sync::atomic::Ordering::SeqCst) != my_epoch {
                    eprintln!("[core] live: session changed; unsubscribing");
                    let _ = pool.client().unsubscribe(output.id()).await;
                    if let Some(r) = &routed {
                        let _ = pool.client().unsubscribe(r.id()).await;
                    }
                    return;
                }
                let event = match n {
                    nostr_sdk::client::ClientNotification::Event {
                        relay_url,
                        subscription_id,
                        event,
                        ..
                    }
                        if output.id() == &subscription_id
                            || routed
                                .as_ref()
                                .map(|r| r.id() == &subscription_id)
                                .unwrap_or(false) =>
                    {
                        (relay_url, *event)
                    }
                    nostr_sdk::client::ClientNotification::Message { relay_url, message }
                        if matches!(
                            &*message,
                            nostr::message::RelayMessage::Closed { message, .. }
                                if relay_latency::is_read_denial(message)
                        ) =>
                    {
                        // An explicit REQ refusal (write-only blaster,
                        // auth wall we won't sign for, paywall) — the
                        // read-dead signal (pool.ts onclose →
                        // recordReadDenial; the broadcast stream delivers
                        // every relay's CLOSED here).
                        relay_latency::record_read_denial(relay_url.as_str());
                        eprintln!("[core] live: read denial from {relay_url}");
                        continue;
                    }
                    nostr_sdk::client::ClientNotification::Shutdown => break,
                    _ => continue,
                };
                let (relay_url, event) = event;
                // Seen-on memory (seen-relays.ts recordSeenOn): which
                // relays we ACTUALLY receive each author from — the live
                // bell is the same drain the TS wrapped around its
                // subscription's onevent. The author-keyed hint store
                // (WS1, RelayHintStore.kt) feeds off the same drain.
                seen::record(&event.pubkey, &[relay_url.as_str()]);
                hints::observe(&event, relay_url.as_str());
                // Same proof-of-life mark (the live dot, §4.4).
                crate::relay_latency::mark_delivery(relay_url.as_str());
                // The chokepoint lives here too (pool.ts onevent):
                // kind:5s are recorded as tombstones; expired copies
                // (NIP-40) and author-deleted content (NIP-09) never
                // ping the bell. The SDK has already persisted the
                // event either way — the tombstone store is how it
                // stops rendering.
                if u16::from(event.kind) == 5 {
                    deletions::record(&event, false);
                    continue;
                }
                if nip40::is_expired(&event) || deletions::is_deleted(&event) {
                    continue;
                }
                // WoT graph feed (issue #2 WS1): live contact lists
                // apply to the two-hop graph incrementally.
                if u16::from(event.kind) == 3 {
                    crate::wot::observe(&event);
                }
                // Duplicate-content gate (issue #2 WS2, AntiSpamFilter
                // .kt): a hidden spammer's events never ping the bell
                // (the SDK has already persisted them — the gate keeps
                // them out of every view; the record rides with it).
                if crate::dedup::observe(&event, relay_url.as_str()) {
                    continue;
                }
                let sig = if event.tags.clone().public_keys().any(|pk| pk == me) {
                    Some(Live::Mention)
                } else {
                    Some(Live::Post)
                };
                if let Some(sig) = sig {
                    let _ = live.send(sig);
                }
            }
            // The stream ended without a Shutdown (client teardown): the
            // bell used to stay armed-dead until the next login (audit
            // perf L1) — drop the flag so a later bootstrap re-arms, but
            // only if no newer arm took over (that one owns the flag).
            if live_epoch.load(std::sync::atomic::Ordering::SeqCst) == my_epoch {
                live_on.store(false, std::sync::atomic::Ordering::SeqCst);
            }
            eprintln!("[core] live stream ended (relay disconnects resume via fetches)");
        });
    }

    async fn active(&self) -> Result<Active> {
        let held = self.active.lock().unwrap().clone();
        held.ok_or_else(|| {
            eprintln!("[core] ERROR: something asked for the session while logged out");
            eprintln!("{}", std::backtrace::Backtrace::force_capture());
            LoginError::Resume("no active session".into())
        })
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Releases the one-per-note flight slot on every exit path (success,
/// failure, early return) — the manager's arm of the Feather rule.
struct FlightGuard<'a>(&'a Wallet, &'a str);
impl Drop for FlightGuard<'_> {
    fn drop(&mut self) {
        self.0.release_flight(self.1);
    }
}

/// A profile's lightning pointer: lud16 before lud06 (NIP-57's order).
/// `None` = the profile has no zap address.
fn lightning_field(content: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(content).ok()?;
    let field = |k: &str| {
        v.get(k)
            .and_then(|x| x.as_str())
            .filter(|s| !s.is_empty())
            .map(String::from)
    };
    field("lud16").or_else(|| field("lud06"))
}

/// NIP-05's wire check: `https://<domain>/.well-known/nostr.json?name=<name>`
/// maps `"names": { "<name>": "<hex pubkey>" }`. The local part is
/// spec-lowercased alphanumerics/`-`/`_` (`_` = the domain root), so it is
/// URL-safe as-is. Hostile/malformed answers read as unproven, not `false`.
async fn verify_nip05_inner(nip05: &str, pubkey: &str) -> Option<bool> {
    let nip05 = nip05.trim().to_lowercase();
    let (name, domain) = nip05.rsplit_once('@')?;
    if name.is_empty() || domain.is_empty() {
        return None;
    }
    let url = format!("https://{domain}/.well-known/nostr.json?name={name}");
    let v = crate::media::fetch_json(&url).await.ok()?;
    v.get("names")?.get(name)?.as_str()
        .map(|mapped| mapped.eq_ignore_ascii_case(pubkey))
}

/// The caption's first non-empty line, capped at 120 chars — nip68.ts
/// `firstCaptionLine`, the ONE definition the blank-picture-title derive uses.
fn first_caption_line(content: &str) -> String {
    content
        .lines()
        .map(|l| l.trim())
        .find(|l| !l.is_empty())
        .unwrap_or("")
        .chars()
        .take(120)
        .collect()
}

/// The `server` tag values of a kind:10063 list (BUD-03).
fn server_tags(ev: &Event) -> Vec<String> {
    ev.tags
        .iter()
        .filter(|t| t.as_slice().first().map(String::as_str) == Some("server"))
        .filter_map(|t| t.as_slice().get(1).cloned())
        .filter(|s| !s.is_empty())
        .collect()
}

/// NIP-65 `r` tag with optional read/write marker.
fn relay_tag(url: &str, marker: Option<&str>) -> Tag {
    match marker {
        Some(m) => Tag::custom("r", [url.to_string(), m.to_string()]),
        None => Tag::custom("r", [url.to_string()]),
    }
}

/// NIP-51 encrypted list content: [["p", hex], ...] / [["e", hex], ...].
fn list_json(items: &[String], letter: &str) -> String {
    let arr: Vec<[String; 2]> = items.iter().map(|i| [letter.to_string(), i.clone()]).collect();
    serde_json::to_string(&arr).unwrap_or_default()
}

/// Parse an encrypted list's plaintext back into item ids.
fn parse_list_event(plain: &str) -> Vec<String> {
    let arr: Vec<[String; 2]> = serde_json::from_str(plain).unwrap_or_default();
    arr.into_iter().filter_map(|pair| pair.get(1).cloned()).collect()
}

/// Read-modify-write prefs.json (0600): overlay `pairs` onto the existing
/// object, preserving app-owned keys. Core's single prefs write path —
/// set_undo and the NIP-78 sync both land here.
fn write_prefs_overlay(pairs: &[(String, serde_json::Value)]) {
    let path = crate::config::state_file(crate::config::files::PREFS);
    let mut value = std::fs::read_to_string(&path)
        .ok()
        .and_then(|raw| serde_json::from_str::<serde_json::Value>(&raw).ok())
        .unwrap_or_else(|| serde_json::Value::Object(serde_json::Map::new()));
    if let Some(obj) = value.as_object_mut() {
        for (k, v) in pairs {
            obj.insert(k.clone(), v.clone());
        }
    }
    if let Ok(body) = serde_json::to_string_pretty(&value) {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let _ = std::fs::create_dir_all(crate::config::data_dir());
        let _ = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&path)
            .and_then(|mut f| f.write_all(body.as_bytes()));
    }
}

/// NIP-78 login sync (Phase 2 §4.1): fetch our own kind-30078 slots, keep
/// the newest per d tag, decrypt, and overlay the Satori keys into
/// prefs.json. Best-effort — relay misses, foreign d tags and undecryptable
/// slots are skipped. PrefsSynced lets the shell re-read what it renders.
async fn sync_app_data(
    pool: &Arc<Pool>,
    me: &PublicKey,
    signer: &Signer,
    live: &tokio::sync::broadcast::Sender<Live>,
) {
    let filter = Filter::new().kind(Kind::Custom(nip78::KIND)).author(*me);
    let events = match pool.get(filter).await {
        Ok(set) => set.into_iter().collect::<Vec<_>>(),
        Err(_) => return,
    };
    let mut pairs: Vec<(String, serde_json::Value)> = Vec::new();
    for slot in nip78::group_latest(&events) {
        if !nip78::synced_key(&slot.key) || slot.content.is_empty() {
            continue;
        }
        let Ok(plain) = signer.nip44_decrypt_self(me, slot.content.as_str()).await
        else {
            continue;
        };
        let Some(value) = nip78::parse_payload(&plain) else { continue };
        pairs.push((slot.key, value));
    }
    if pairs.is_empty() {
        return;
    }
    write_prefs_overlay(&pairs);
    let _ = live.send(Live::PrefsSynced);
}

/// One synced composer draft (D38): the buffer text plus its context —
/// reply parent / quoted note as IDS (the full events live in the store).
/// The array rides NIP-78 kind 30078 d="satori/drafts", nip44-encrypted;
/// the (reply, quote) pair is the composer slot (top-level = both None).
///
/// Entries imported from the web app's NIP-37 kind 31234 wraps (v1.1)
/// carry `id` (the wrap's d) — Satori's own slot entries have none, and
/// a close-sync never clobbers an id-marked entry; opening or deleting
/// one converts it (the empty-content wrap republish, NIP-37's delete).
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct DraftEntry {
    pub text: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reply_to: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quote: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Uploaded attachment imetas (v1.4): the blobs are on Blossom before
    /// the draft saves (upload happens at ATTACH time), so the entry
    /// carries the NIP-92 tag arrays verbatim — a restore republishes
    /// them unchanged. No bytes ride the draft; the composer tile shows
    /// the CDN copy through the media cache.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attachments: Vec<Vec<String>>,
    /// The composer tab the draft was written in (issue #3 WS1): true =
    /// Photo tab, publishes kind 20; false = Note tab, attachments ride
    /// kind 1 + imeta. Defaults false so legacy entries (and web-app
    /// imports) restore as notes — the only thing they could ever be.
    #[serde(default, skip_serializing_if = "is_false")]
    pub photo_post: bool,
    /// Last touch (wrap created_at / save time) — the tab sorts by it,
    /// the composer's restore takes the newest top-level.
    #[serde(default)]
    pub at: u64,
}

/// serde skip predicate: omit `photo_post` when false (the legacy shape).
fn is_false(b: &bool) -> bool {
    !*b
}

impl DraftEntry {
    /// Which composer slot this draft belongs to.
    pub fn matches(&self, reply_to: Option<&str>, quote: Option<&str>) -> bool {
        self.reply_to.as_deref() == reply_to && self.quote.as_deref() == quote
    }
}

/// One NIP-51 named list (kind 30000, D38's Lists tab): the d tag IS the
/// list's identifier (its name unless a title tag rides along); the p tags
/// are the members. People lists only in v1 — e/a members are skipped at
/// parse. Read-only surface: lists are MADE in other clients today; Satori
/// shows the user's own.
#[derive(Debug, Clone, PartialEq)]
pub struct NostrList {
    pub d: String,
    pub title: Option<String>,
    pub members: Vec<PublicKey>,
    /// The source event (v1.2): a private list's members live encrypted
    /// in its content — the detail view decrypts them LAZILY (per open),
    /// the rows never wait on crypto.
    pub event: Event,
}

/// Minimal percent-decoding (%XX hex pairs) for display: list ds
/// percent-encode path separators; malformed escapes pass through.
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let hex = |b: u8| (b as char).to_digit(16);
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let (Some(h), Some(l)) = (hex(bytes[i + 1]), hex(bytes[i + 2]))
        {
            out.push((h * 16 + l) as u8);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

impl NostrList {
    /// The display name: a title tag beats the d identifier; percent
    /// escapes decode (Bloom's folder ds encode `/` as %2F — the raw
    /// identifier is wire format, the row shows the path).
    pub fn display(&self) -> String {
        match &self.title {
            Some(t) if !t.trim().is_empty() => t.clone(),
            _ => percent_decode(&self.d),
        }
    }

    /// Parse one kind 30000 event: the d, an optional title, the p-tag
    /// pubkeys (malformed ones skipped).
    pub fn from_event(ev: &Event) -> Option<Self> {
        let mut d = String::new();
        let mut title = None;
        let mut members = Vec::new();
        for tag in ev.tags.clone().to_vec() {
            match tag.kind() {
                "d" => d = tag.content().unwrap_or_default().to_string(),
                "title" => title = Some(tag.content().unwrap_or_default().to_string()),
                "p" => {
                    if let Some(pk) = tag.content().and_then(|c| c.parse::<PublicKey>().ok()) {
                        members.push(pk);
                    }
                }
                _ => {}
            }
        }
        // NIP-51: a named list MUST carry a d; dedupe members preserving
        // order (a list event can repeat a p tag across edits — not always
        // adjacent).
        if d.is_empty() {
            return None;
        }
        let mut seen = std::collections::HashSet::new();
        members.retain(|pk| seen.insert(pk.to_string()));
        Some(Self {
            d,
            title,
            members,
            event: ev.clone(),
        })
    }
}

impl Core {
    /// The own NIP-51 lists (D38's Lists tab): kind 30000 (follow sets)
    /// plus kind 30001 (categorized people/bookmark sets — Primal's
    /// "custom sets" live there), EXCEPT the 30001 d="bookmark" — that
    /// one IS the public bookmarks list and shows in the Bookmarks tab.
    /// TWO deliveries: a store-only snapshot first (the tab paints
    /// instantly — the relay round never gates the rows), then the
    /// merged fresh one. The relay round saves every fetched event
    /// EXPLICITLY before the read: the one-shot fetch's SDK-side saves
    /// are async and can still be landing when the read runs (v1.2's
    /// empty-tab race). Newest event per (kind, d) wins (parameterized
    /// replaceable); a private list's members (encrypted tag-JSON
    /// content, Bloom's folders) decrypt to-self. Sorted by display
    /// name.
    pub fn own_lists(self: &Arc<Self>) -> tokio::sync::mpsc::UnboundedReceiver<Vec<NostrList>> {
        let (tx, rx) = mpsc::unbounded_channel();
        let this = Arc::clone(self);
        self.rt.spawn(async move {
            // Snapshot 1: whatever the store holds right now.
            if let Ok(active) = this.active().await {
                let me = active.me();
                let snapshot = Self::lists_from_store(&active, me).await;
                eprintln!("[core] own_lists: store snapshot: {} list(s)", snapshot.len());
                let _ = tx.send(snapshot);
            }
            // Snapshot 2: after the relay round + explicit saves.
            let lists = async {
                let active = this.active().await?;
                let me = active.me();
                for kind in [30000u16, 30001] {
                    let filter = Filter::new()
                        .author(me)
                        .kind(Kind::Custom(kind))
                        .limit(200);
                    let fetched = active.pool.get(filter).await.unwrap_or_default();
                    eprintln!(
                        "[core] own_lists: kind {kind}: {} event(s) fetched",
                        fetched.len()
                    );
                    for ev in &fetched {
                        let _ = active.pool.store.save(ev).await;
                    }
                }
                let merged = Self::lists_from_store(&active, me).await;
                eprintln!("[core] own_lists: merged: {} list(s)", merged.len());
                Ok::<Vec<NostrList>, LoginError>(merged)
            }
            .await;
            // Send ONLY on Ok (v1.2): an error's empty-default must never
            // overwrite the snapshot the tab already painted.
            match lists {
                Ok(merged) => {
                    let _ = tx.send(merged);
                }
                Err(e) => eprintln!("[core] own_lists: merge failed ({e}), snapshot stands"),
            }
        });
        rx
    }

    /// The store's own list events, collapsed to newest per (kind, d),
    /// display-sorted (own_lists' read side). Members stay undecrypted —
    /// the detail view decrypts them lazily (v1.3).
    async fn lists_from_store(active: &Active, me: PublicKey) -> Vec<NostrList> {
        // (kind, d) is the replaceable coordinate; a plain d key would
        // collide 30000 and 30001 sets.
        let mut newest: HashMap<(u16, String), Event> = HashMap::new();
        for kind in [30000u16, 30001] {
            for ev in active
                .pool
                .store
                .all_by_kind(me, Kind::Custom(kind))
                .await
                .unwrap_or_default()
            {
                let Some(d) = ev
                    .tags
                    .clone()
                    .to_vec()
                    .iter()
                    .find(|t| t.kind() == "d")
                    .and_then(|t| t.content().map(str::to_string))
                else {
                    continue;
                };
                if kind == 30001 && d == "bookmark" {
                    continue;
                }
                match newest.get(&(kind, d.clone())) {
                    Some(old) if old.created_at >= ev.created_at => {}
                    _ => {
                        newest.insert((kind, d), ev);
                    }
                }
            }
        }
        let mut lists: Vec<NostrList> = Vec::new();
        for ev in newest.values() {
            // No decryption here (v1.2): rows paint from plain tags only;
            // a private list's members decrypt lazily in the detail view
            // (decrypt_list_members) — 78 serial decrypts blocked the
            // snapshot and the tab crawled.
            if let Some(l) = NostrList::from_event(ev) {
                lists.push(l);
            }
        }
        lists.sort_by_key(|l| l.display().to_lowercase());
        lists
    }

    /// A private list's members (NIP-51: the content is nip44-to-self of
    /// the tag array). The detail view's lazy path — called per open, so
    /// the Library rows never wait on crypto. Empty when the content is
    /// empty or undecryptable.
    pub fn decrypt_list_members(
        self: &Arc<Self>,
        ev: Event,
    ) -> tokio::sync::mpsc::UnboundedReceiver<Vec<PublicKey>> {
        let (tx, rx) = mpsc::unbounded_channel();
        let this = Arc::clone(self);
        self.rt.spawn(async move {
            let members = async {
                if ev.content.is_empty() {
                    return Ok(Vec::new());
                }
                let active = this.active().await?;
                let me = active.me();
                let plain = active
                    .signer
                    .nip44_decrypt_self(&me, ev.content.as_str())
                    .await?;
                let mut members = Vec::new();
                if let Ok(tags) = serde_json::from_str::<Vec<Vec<String>>>(&plain) {
                    for tag in tags {
                        if tag.first().map(String::as_str) == Some("p")
                            && let Some(pk) =
                                tag.get(1).and_then(|c| c.parse::<PublicKey>().ok())
                        {
                            members.push(pk);
                        }
                    }
                }
                Ok::<Vec<PublicKey>, LoginError>(members)
            }
            .await;
            let _ = tx.send(members.unwrap_or_default());
        });
        rx
    }
}

/// A profile edit (D38): each field maps to a kind:0 content key. None =
/// leave the stored value; Some("") = clear the key; Some(s) = set it.
/// Ported from the TS reference's edit form (routes/profile.ts — git
/// a4b09e8), whose header states the invariant this merge keeps: "fields
/// the app doesn't show … survive a save".
#[derive(Debug, Clone, Default)]
pub struct ProfileEdit {
    pub name: Option<String>,
    pub display_name: Option<String>,
    pub about: Option<String>,
    pub picture: Option<String>,
    pub banner: Option<String>,
    pub website: Option<String>,
    pub nip05: Option<String>,
}

/// Merge a ProfileEdit into a kind:0 content string (set_profile's pure
/// half — unit-tested): unknown keys survive, Some overwrites, Some("")
/// removes, a non-object or unparseable store body starts fresh.
pub fn apply_profile_patch(stored: &str, patch: &ProfileEdit) -> String {
    let mut obj = serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(stored)
        .unwrap_or_default();
    for (key, value) in [
        ("name", &patch.name),
        ("display_name", &patch.display_name),
        ("about", &patch.about),
        ("picture", &patch.picture),
        ("banner", &patch.banner),
        ("website", &patch.website),
        ("nip05", &patch.nip05),
    ] {
        match value {
            None => {}
            Some(s) if s.is_empty() => {
                obj.remove(key);
            }
            Some(s) => {
                obj.insert(key.to_string(), serde_json::Value::String(s.clone()));
            }
        }
    }
    serde_json::to_string(&obj).unwrap_or_default()
}

#[cfg(test)]
/// Test-only local-key login — the user-facing nsec door is gone (D17: the
/// app never handles the master key), but the logout/re-login flow tests
/// still need a way in.
#[cfg(test)]
impl Core {
    async fn login_nsec_inner(&self, secret: &str) -> Result<PublicKey> {
        let keys = signer::parse_local_secret(secret)?;
        let pk = keys.public_key();

        secrets::store(secrets::NSEC, &keys.secret_key().display_secret().to_string()).await?;
        let session = Session { pubkey: pk.to_string(), mode: SessionMode::Local };
        session::save(&session)?;

        let active = self.build_active(&session).await?;
        *self.active.lock().unwrap() = Some(active);
        Ok(pk)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    /// The synced draft round-trip (D38 v1.4): attachment imetas survive
    /// the serde pass verbatim, and a legacy entry (no attachments key)
    /// deserializes to an empty vec — old events stay readable.
    #[test]
    fn draft_entry_attachments_round_trip() {
        let imeta = vec![
            "imeta".to_string(),
            "url https://cdn.example.com/abc.png".to_string(),
            "m image/png".to_string(),
            "x deadbeef".to_string(),
        ];
        let entry = DraftEntry {
            text: "with a picture".into(),
            reply_to: None,
            quote: None,
            id: None,
            attachments: vec![imeta.clone()],
            photo_post: false,
            at: 42,
        };
        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("attachments"), "non-empty must serialize");
        let back: DraftEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(back.attachments, vec![imeta]);

        // Legacy shape: the key is absent entirely.
        let legacy: DraftEntry = serde_json::from_str(
            r#"{"text":"old","at":7}"#,
        )
        .unwrap();
        assert!(legacy.attachments.is_empty());
        assert!(!legacy.photo_post, "absent = a note draft");
        assert!(legacy.matches(None, None));

        // The photo_post flag (issue #3 WS1): false is omitted (the legacy
        // shape stays byte-stable), true round-trips.
        let note_draft = DraftEntry {
            photo_post: false,
            ..back
        };
        let note_json = serde_json::to_string(&note_draft).unwrap();
        assert!(!note_json.contains("photo_post"), "false must be skipped");
        let photo_draft = DraftEntry {
            photo_post: true,
            ..note_draft
        };
        let photo_json = serde_json::to_string(&photo_draft).unwrap();
        let back: DraftEntry = serde_json::from_str(&photo_json).unwrap();
        assert!(back.photo_post, "true must round-trip");
    }

    /// A note with attachments is a NOTE (issue #3 WS1): note_tags carries
    /// the NIP-92 imeta arrays as kind-1 tags (signNote's
    /// `for (const m of imeta) tags.push(m)`), alongside the reply tags —
    /// the reply-with-attachment case keeps its thread context.
    #[test]
    fn note_tags_carry_imeta() {
        let imeta = vec![
            "imeta".to_string(),
            "url https://cdn.example.com/abc.png".to_string(),
            "m image/png".to_string(),
            "x deadbeef".to_string(),
        ];
        let me = Keys::generate().public_key();
        let (content, tags) = Core::note_tags(
            "look at this".into(),
            None,
            Vec::new(),
            None,
            &[imeta.clone()],
            me,
        );
        assert_eq!(content, "look at this");
        let imeta_tags: Vec<&Tag> = tags.iter().filter(|t| t.kind() == "imeta").collect();
        assert_eq!(imeta_tags.len(), 1, "one imeta tag rides the kind-1");
        let parts = imeta_tags[0].as_slice();
        assert!(parts.contains(&"url https://cdn.example.com/abc.png".to_string()));
        assert!(parts.contains(&"x deadbeef".to_string()));

        // A malformed imeta (missing the leading "imeta" marker) is
        // dropped, not injected as garbage tags.
        let bad = vec!["url https://cdn.example.com/x.png".to_string()];
        let (_, tags) = Core::note_tags("x".into(), None, Vec::new(), None, &[bad], me);
        assert!(tags.iter().all(|t| t.kind() != "imeta"));
    }

    /// NIP-92 kind-0 adoption: the banner's blurhash arrives only from an
    /// The profile patch (D38): Some overwrites, Some("") clears, None
    /// keeps, unknown keys (lud16 and friends) ride along, garbage input
    /// starts fresh.
    #[test]
    fn profile_patch_merges_and_preserves() {
        let base = r#"{"name":"luna","about":"hi","lud16":"luna@zap.me"}"#;
        let patch = ProfileEdit {
            name: Some("luna2".into()),
            about: Some(String::new()), // clear
            nip05: Some("luna@example.com".into()),
            ..Default::default()
        };
        let out = apply_profile_patch(base, &patch);
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["name"], "luna2");
        assert_eq!(v["nip05"], "luna@example.com");
        assert!(v.get("about").is_none(), "Some(\"\") clears the key");
        assert_eq!(v["lud16"], "luna@zap.me", "unknown keys ride along");
        // None leaves everything; garbage starts a fresh object.
        let untouched = apply_profile_patch(base, &ProfileEdit::default());
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&untouched).unwrap()["about"],
            "hi"
        );
        let fresh = apply_profile_patch("not json at all", &patch);
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&fresh).unwrap()["name"],
            "luna2"
        );
    }

    /// imeta tag whose url matches the banner field exactly (Oct 2026 spec
    /// section; the TS reference predates it).
    #[test]
    fn profile_banner_blurhash_needs_an_exact_url_match() {
        use nostr::prelude::*;
        let banner = "https://b/banner.webp";
        let content = format!(
            "{{\"name\":\"luna\",\"banner\":\"{banner}\"}}"
        );
        let build = |imeta: &[&str]| {
            let keys = Keys::generate();
            let mut tags = Tags::new();
            tags.push(Tag::custom("imeta", imeta.iter().copied()));
            let unsigned = UnsignedEvent::new(
                keys.public_key(),
                Timestamp::from_secs(1),
                Kind::Metadata,
                tags,
                content.clone(),
            );
            keys.sign_event(unsigned).unwrap()
        };
        let hit = Profile::from_event(&build(&[
            "url https://b/banner.webp",
            "m image/webp",
            "blurhash LEHV6nWB2yk8pyo0adR*.7kCMdnj",
        ]))
        .unwrap();
        assert_eq!(
            hit.banner_blurhash.as_deref(),
            Some("LEHV6nWB2yk8pyo0adR*.7kCMdnj")
        );
        // A tag describing the PICTURE (or any other url) says nothing
        // about the banner.
        let miss = Profile::from_event(&build(&[
            "url https://b/picture.jpg",
            "blurhash LEHV6nWB2yk8pyo0adR*.7kCMdnj",
        ]))
        .unwrap();
        assert_eq!(miss.banner_blurhash, None);
    }


    /// The D32 crash seam: the poster job must run on THIS runtime no
    /// matter which thread summons it — the first cut let the UI poll the
    /// futures on gpui's executor, where `spawn_blocking` has no tokio
    /// context, and thread 'main panicked the app. A plain thread calling
    /// the wrapper (no runtime anywhere on it) must still get its verdict.
    /// The unsafe URL returns before any network or sniff work.
    #[test]
    fn poster_job_runs_on_the_core_runtime() {
        // Core::new() rotates the diag mirror into the data dir: keep
        // that off the real $HOME (the guard isolates it, lock held).
        let _env = crate::test_env::EnvGuard::new("poster");
        let core = Arc::new(Core::new());
        let mut rx = core.fetch_poster("not a url".into(), 16, |_| Err(()));
        let verdict =
            std::thread::spawn(move || rx.blocking_recv()).join().unwrap();
        assert!(matches!(
            verdict,
            Some(Err(crate::media::MediaError::NotMedia))
        ));
    }

    /// Logout → login → notifications must NOT fail with "no active
    /// session" (the user-report). Runs headless; network errors are fine,
    /// session-state errors are not. Login runs via block_on: the
    /// spawned-task variant hangs in this container; the host does not.
    #[test]
    fn login_then_notifications_has_session() {
        let env = crate::test_env::EnvGuard::new("login");
        let core = Arc::new(Core::new());
        core.logout(); // start clean
        // The nsec lands inside the guard's isolated dir (never a shared
        // temp path a parallel run could race).
        let secret_path = env.dir().join("test-nsec");
        let secret =
            "e1d4a5b33a9d2f0c8b7e6f5a4d3c2b1a0918273645f4e3d2c1b0a99887766554";
        let _ = std::fs::write(&secret_path, secret);

        core.rt
            .block_on(core.login_nsec_inner(secret))
            .expect("login");
        assert!(core.pubkey().is_some(), "no pubkey after login");

        // The bug: notifications must not report "no active session".
        let mut rx = core.notifications();
        let mut got = None;
        for _ in 0..500 {
            if let Ok(ev) = rx.try_recv() {
                got = Some(ev);
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        match got {
            Some(FeedEvent::Failed(msg)) => {
                assert!(!msg.contains("no active session"), "session lost: {msg}");
                eprintln!("network failure (acceptable headless): {msg}");
            }
            Some(_) => {}
            None => panic!("notifications never resolved"),
        }

        // THE USER'S FLOW: logout → re-login → notifications.
        core.logout();
        assert!(core.pubkey().is_none(), "pubkey survived logout");
        core.rt
            .block_on(core.login_nsec_inner(secret))
            .expect("re-login");
        assert!(core.pubkey().is_some(), "no pubkey after re-login");

        let mut rx = core.notifications();
        let mut got = None;
        for _ in 0..500 {
            if let Ok(ev) = rx.try_recv() {
                got = Some(ev);
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        match got {
            Some(FeedEvent::Failed(msg)) => {
                assert!(!msg.contains("no active session"), "session lost after re-login: {msg}");
                eprintln!("network failure after re-login (acceptable headless): {msg}");
            }
            Some(_) => {}
            None => panic!("notifications never resolved after re-login"),
        }
    }

    // --- notification tier + reply velocity (D41/D43) -----------------------

    use crate::test_env::EnvGuard as TierEnv;

    fn note(k: &Keys, kind: Kind, tags: Tags, content: &str, at: u64) -> Event {
        let unsigned = UnsignedEvent::new(
            k.public_key(),
            Timestamp::from_secs(at),
            kind,
            tags,
            content.to_string(),
        );
        k.sign_event(unsigned).unwrap()
    }

    /// A graph where `outsider` is known NotInNetwork (one fresh follow's
    /// list vouches for them, sub-threshold) — the rule-1 fixture.
    fn tier_session() -> (EventId, Keys, Keys, Keys) {
        crate::wot::clear_identity();
        crate::rate::clear();
        let me = Keys::generate();
        let follow = Keys::generate();
        let outsider = Keys::generate();
        crate::wot::set_identity(me.public_key(), &[follow.public_key()]);
        // kind3(follow → outsider): seen, sub-threshold → NotInNetwork.
        // Fresh list (now_secs): stale lists contribute nothing (D41b).
        let mut tags = Tags::new();
        tags.push(Tag::public_key(outsider.public_key()));
        crate::wot::observe(&note(
            &follow,
            Kind::ContactList,
            tags,
            "",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
        ));
        let my_note = EventId::from_byte_array([7u8; 32]);
        (my_note, me, follow, outsider)
    }

    fn reply(k: &Keys, parent: EventId, at: u64) -> Event {
        let mut tags = Tags::new();
        tags.push(Tag::event(parent));
        note(k, Kind::TextNote, tags, "gm", at)
    }

    #[test]
    fn tier_gates_not_in_network_replies_and_engagement() {
        let _env = TierEnv::new("tier-nin");
        let (my_note, _me, _f, outsider) = tier_session();
        let my_notes: HashSet<EventId> = [my_note].into();
        let at = 1000;
        // Replies: the amendment's target — gated.
        let (kept, sup) = split_wot_tier(vec![reply(&outsider, my_note, at)], &my_notes, false);
        assert!(kept.is_empty());
        assert_eq!(sup.len(), 1);
        assert_eq!(sup[0].reason, "outside your network");
        // Reactions were already gated (D41).
        let mut tags = Tags::new();
        tags.push(Tag::event(my_note));
        let (kept, sup) = split_wot_tier(
            vec![note(&outsider, Kind::Reaction, tags, "+", at)],
            &my_notes,
            false,
        );
        assert!(kept.is_empty() && sup.len() == 1 && sup[0].reason == "outside your network");
        // Mentions and zaps stay passing — direct attention that is NOT a
        // reply to your note.
        let mut mention = Tags::new();
        mention.push(Tag::public_key(_me.public_key()));
        let (kept, sup) = split_wot_tier(
            vec![note(&outsider, Kind::TextNote, mention, "hi", at)],
            &my_notes,
            false,
        );
        assert_eq!(kept.len(), 1, "mention passes");
        assert!(sup.is_empty());
        let (kept, sup) = split_wot_tier(
            vec![note(&outsider, Kind::Custom(9735), Tags::new(), "", at)],
            &my_notes,
            false,
        );
        assert_eq!(kept.len(), 1, "zap passes");
        assert!(sup.is_empty());
        crate::wot::clear_identity();
        crate::rate::clear();
    }

    #[test]
    fn unknown_single_reply_passes() {
        let _env = TierEnv::new("tier-unknown");
        let (my_note, _me, _f, _outsider) = tier_session();
        let my_notes: HashSet<EventId> = [my_note].into();
        // `unseen` was observed by nobody → Unknown. One reply: passes,
        // and the delivering pass feeds the counter (1 in window).
        let unseen = Keys::generate();
        let (kept, sup) =
            split_wot_tier(vec![reply(&unseen, my_note, 1000)], &my_notes, true);
        assert_eq!(kept.len(), 1, "Unknown ≠ outside; one reply passes");
        assert!(sup.is_empty());
        assert!(!crate::rate::reply_flooded(&unseen.public_key(), 1000));
        crate::wot::clear_identity();
        crate::rate::clear();
    }

    #[test]
    fn velocity_flood_trips_with_receipt_reason() {
        let _env = TierEnv::new("tier-velocity");
        let (my_note, _me, _f, _outsider) = tier_session();
        let my_notes: HashSet<EventId> = [my_note].into();
        let mule = Keys::generate();
        let at = 1000;
        let notifs: Vec<Event> = (0..7u64).map(|i| reply(&mule, my_note, at + i)).collect();
        let (kept, sup) = split_wot_tier(notifs, &my_notes, true);
        // 4 pass untouched; the 5th is the trip and every later reply in
        // the window joins it — each with the named reason.
        assert_eq!(kept.len(), 4);
        assert_eq!(sup.len(), 3);
        let want = crate::rate::flood_reason();
        assert_eq!(want, "5 replies in 30 min");
        assert!(sup.iter().all(|s| s.reason == want));
        // The counter was fed only by the 4 DELIVERED replies — the
        // suppressed ones never joined (suppression is not self-justifying:
        // the ring still trips, it did not grow past it).
        assert!(crate::rate::reply_flooded(&mule.public_key(), at + 100));
        // Window reset: silence past the window and the author passes.
        assert!(!crate::rate::reply_flooded(&mule.public_key(), at + crate::rate::REPLY_WINDOW_SECS + 1));
        crate::wot::clear_identity();
        crate::rate::clear();
    }

    #[test]
    fn velocity_clears_at_session_boundary() {
        let _env = TierEnv::new("tier-clear");
        let (my_note, _me, _f, _outsider) = tier_session();
        let my_notes: HashSet<EventId> = [my_note].into();
        let mule = Keys::generate();
        for i in 0..4u64 {
            split_wot_tier(vec![reply(&mule, my_note, 1000 + i)], &my_notes, true);
        }
        // teardown_session's rule: the counter is per-session identity
        // state (rate::clear(); the graph clear is asserted in wot.rs).
        crate::rate::clear();
        assert!(!crate::rate::reply_flooded(&mule.public_key(), 1000));
        crate::wot::clear_identity();
    }
}
