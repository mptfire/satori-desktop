//! The home feed, GPUI-rendered.
//!
//! TODO(port): crates/app/src/feed.rs + note_card.rs (and src/feed.js) — P0.
//! Read-only following feed with optimistic like; the receiver-pumping seam is
//! the GPUI twin of `bridge.rs`'s `drain`. Rich cards for the manifest
//! registry kinds render via cards.rs (P3).

use std::{
    collections::{HashMap, HashSet, VecDeque},
    sync::Arc,
};

use gpui::{
    Context, Div, Entity, EventEmitter, FontWeight, ListAlignment, ListOffset, ListScrollEvent,
    ListState, Render, SharedString, Window, div, list, prelude::*, px, relative, rgb,
};
use nostr::prelude::*;
use satori_core::manager::{Core, FeedEvent, FeedRx, Live, ParentNote, Profile, PublishEvent};
use satori_core::nip::nip10;

use super::{actions, cards, content, engagement, nav, nav::Nav, quotes, states};
use crate::{icons, media, theme};

/// Which surface a feed pane carries: the timeline (the visible catalog),
/// the articles shelf (kind 30023 from the same follows), or a hashtag
/// timeline (Phase 2 §4.2 — the `#t` filter, any author).
#[derive(Clone, PartialEq)]
pub(crate) enum FeedMode {
    Timeline,
    Articles,
    Hashtag(String),
    /// One author's notes — the profile page's Notes tab (an embedded Feed
    /// entity; the profile view only renders the header + media strips).
    Profile(PublicKey),
    /// The Library pane's Bookmarks tab (D38): the own bookmark set
    /// (private 10003 + public 30001 merged), no paging.
    Bookmarks,
}

/// The reply-parent whisper cache's bound (#31 latent): a long session's
/// `parents`/`parents_asked` maps used to grow for the process lifetime.
/// 512 tracked parents is far past one sitting's scrolling.
const PARENTS_CAP: usize = 512;

/// Dry rounds before the end-cap seal is believed: the relays genuinely
/// remember nothing older (five straight pages deepened nothing). Impl
/// level, not maybe_older-local — the seal-reopen chain condition (the
/// audit's duplication lens) reads it too, and a literal `5` there
/// drifted from this cap the moment it was inlined.
const DRY_CAP: usize = 5;
/// Cool-off between dry retries: the reader at the end cap fires
/// wheel ticks, not pages — each dry round costs a relay trip.
const DRY_COOLDOWN: std::time::Duration = std::time::Duration::from_secs(4);

/// The comment-count maps' bound — same discipline as PARENTS_CAP.
const COUNTS_CAP: usize = 512;
impl FeedMode {
    pub(crate) fn kinds(&self) -> Vec<Kind> {
        match self {
            // Never dispatched on for Hashtag/Profile — those fetches switch
            // on the mode (the tag/author filter is the query; there's no
            // follow set). The kinds themselves honor the content prefs.
            FeedMode::Timeline
            | FeedMode::Hashtag(_)
            | FeedMode::Profile(_)
            | FeedMode::Bookmarks => satori_core::store::visible_kinds(),
            FeedMode::Articles => vec![Kind::Custom(30023)],
        }
    }
}

pub struct Feed {
    mode: FeedMode,
    core: Arc<Core>,
    notes: Vec<Event>,
    profiles: HashMap<String, Profile>,
    /// Reply parents (nip10) resolved for the context whisper: parent id →
    /// author + snippet. `parents_asked` keeps misses from re-requesting.
    /// Both are eviction-capped (#31 latent): a long session's maps used
    /// to grow for the process lifetime. Past the cap the OLDEST key
    /// (insertion order — the scroll origin's side) drops; a re-scroll
    /// back re-asks and re-hydrates it. ASKED ids enter the order queue
    /// too (a miss — deleted parent, relay gap — would otherwise evade
    /// eviction forever): the queue tracks asks, landings only refresh.
    parents: HashMap<String, ParentNote>,
    parents_asked: HashSet<String>,
    /// Insertion order for the parents cap's eviction (front = oldest).
    parents_order: VecDeque<String>,
    /// Comment counts for the bubbles (CommentCounts landings), and the
    /// asked-set that keeps a paging feed from re-asking per page. Capped
    /// on the same insertion-order discipline as the parents maps —
    /// `counts_asked` grew per unique note for the session otherwise.
    counts: HashMap<String, usize>,
    counts_asked: HashSet<String>,
    counts_order: VecDeque<String>,
    /// Push signals since the last load (the live subscription): the
    /// new-notes pill's count. Nothing moves until the reader clicks.
    /// The new-notes pill's count (Live::Post bumps), zeroed by a click.
    live_new: usize,
    /// The pill's click promise: between the click and the first Loaded —
    /// which since the paint-first refresh is the STORE page, near
    /// instant — the chip reads "Loading new notes…" instead of a count
    /// that was just zeroed.
    loading_new: bool,
    /// The optimistic engagement mirrors (engagement.rs): the action row's
    /// glyph state, seeded from core's persisted sets, mutated optimistically.
    engagement: engagement::Engagement,
    quotes: content::Quotes,
    // Rich-card interaction state (cards.rs): poll tallies + ballots, and
    // my RSVP per calendar event.
    poll_tallies: HashMap<EventId, Vec<(String, u32)>>,
    poll_sel: HashMap<EventId, Vec<String>>,
    voted: HashSet<EventId>,
    rsvped: HashMap<EventId, String>,
    /// NIP-36 warnings revealed this session (veil_card taps Show).
    revealed: HashSet<EventId>,
    /// NIP-75 zap goals' raised totals in msat (goal id → sum).
    goal_msat: HashMap<EventId, u64>,
    status: String,
    /// §4.3: the pane's kinded error — the strip replaces the old raw
    /// `format!("… {e}")` status-line dump (deficiency 8).
    error: Option<states::PaneError>,
    /// Endless scroll: the relays may have more; a round trip is in flight.
    has_more: bool,
    paging: bool,
    /// Consecutive dry rounds (pages that came back with no more): the
    /// seal is the LAST round's verdict, not the timeline's — a slow relay
    /// round (the wot graph mid-load, a cold pool) used to seal the reader
    /// out of history that exists. The seal reopens on continued scroll
    /// until DRY_CAP rounds come back dry in a row.
    dry_rounds: usize,
    last_dry: Option<std::time::Instant>,
    /// The paging anchor: the oldest note timestamp EVER absorbed — not the
    /// window's last row. The RAM window (trim_window) drops the tail, and
    /// `older()` must continue from where the STREAM ended, not where the
    /// Vec ends, or the next page would re-fetch the rows just dropped.
    oldest_ts: Option<u64>,
    /// Render snapshot (D13's snapshot rule, made cheap): the render item
    /// closure used to clone the whole notes vec + profile map on every
    /// frame — and `cx.notify()` fires for every profile resolution, image
    /// arrival, poll tally and publish event. The snapshot rebuilds only
    /// when the data changed (or the media cache's epoch moved).
    snap: Option<FeedSnap>,
    snap_dirty: bool,
    /// Mirror of `notes` ids — dedupe was an O(n) scan per incoming note
    /// (O(n·m) per bootstrap batch); now a hash lookup.
    note_ids: HashSet<EventId>,
    /// The scroll stream's last visible end — remembered so a page landing
    /// while the reader idles at the end cap can chain the next one (the
    /// scroll handler only fires on wheel ticks, which stop at the cap).
    last_visible_end: usize,
    /// Deep-scroll state, emitted to the shell (Nav::PaneDeep); the shell
    /// re-reads this field for the ACTIVE pane at render, so it must be
    /// visible across views' modules.
    pub(crate) deep: bool,
    /// j/k's row cursor (key_nav); the scroll handler re-anchors it.
    cursor: usize,
    /// WS2 viewport debounce: bumps on every scroll/nav/landing; the
    /// spawned push only fires if the pulse_id is still current (fast
    /// scrolling coalesces into ONE core.set_viewport per settle).
    viewport_gen: usize,
    list: ListState,
}

/// Everything the render's item closure reads, rebuilt (one deep copy) only
/// when the data changed instead of every frame; the Arcs make the per-frame
/// clone a refcount bump.
struct FeedSnap {
    notes: std::sync::Arc<Vec<Event>>,
    profiles: std::sync::Arc<HashMap<String, Profile>>,
    parents: std::sync::Arc<HashMap<String, ParentNote>>,
    /// Note id → comment count (the bubbles).
    counts: std::sync::Arc<HashMap<String, usize>>,
    engagement: std::sync::Arc<engagement::Engagement>,
    quotes: std::sync::Arc<content::Quotes>,
    cards: std::sync::Arc<cards::CardState>,
}

impl EventEmitter<Nav> for Feed {}

impl Feed {
    pub fn new(core: Arc<Core>, cx: &mut Context<Self>) -> Self {
        crate::theme::watch(cx); // repaint on theme change
        crate::timefmt::watch(cx); // repaint on mode/height change
        crate::video::watch(cx); // repaint on player open/toggle/close
        Self::with_mode(core, FeedMode::Timeline, cx)
    }

    /// The articles shelf: same follows, same paging, kind 30023 only.
    pub fn articles(core: Arc<Core>, cx: &mut Context<Self>) -> Self {
        Self::with_mode(core, FeedMode::Articles, cx)
    }

    /// The hashtag timeline (Phase 2 §4.2): the `#t` filter, any author —
    /// opened by tapping a #tag in a note body.
    pub fn hashtag(core: Arc<Core>, tag: String, cx: &mut Context<Self>) -> Self {
        Self::with_mode(core, FeedMode::Hashtag(tag), cx)
    }

    /// The hashtag feed's tag (the columns workspace pins it — the drill
    /// title row's + Column affordance reads it). None on other modes.
    pub fn tag(&self) -> Option<String> {
        match &self.mode {
            FeedMode::Hashtag(tag) => Some(tag.clone()),
            _ => None,
        }
    }

    /// One author's notes: the profile page's Notes tab embeds a full Feed,
    /// so its rows ARE the timeline's rows (avatar, media, reactions) with
    /// the same endless scroll — scoped to the author's pubkey.
    pub fn author(core: Arc<Core>, who: PublicKey, cx: &mut Context<Self>) -> Self {
        Self::with_mode(core, FeedMode::Profile(who), cx)
    }

    /// The Library pane's Bookmarks tab (D38): the merged own bookmark set
    /// as timeline rows. One shot — the list is finite, no Older rounds.
    pub fn bookmarks(core: Arc<Core>, cx: &mut Context<Self>) -> Self {
        Self::with_mode(core, FeedMode::Bookmarks, cx)
    }

    fn with_mode(core: Arc<Core>, mode: FeedMode, cx: &mut Context<Self>) -> Self {
        let feed = Self {
            engagement: engagement::Engagement::new(&core),
            core,
            notes: vec![],
            profiles: HashMap::new(),
            parents: HashMap::new(),
            parents_asked: HashSet::new(),
            parents_order: VecDeque::new(),
            counts: HashMap::new(),
            counts_asked: HashSet::new(),
            counts_order: VecDeque::new(),
            live_new: 0,
            loading_new: false,
            quotes: HashMap::new(),
            poll_tallies: HashMap::new(),
            poll_sel: HashMap::new(),
            voted: HashSet::new(),
            rsvped: HashMap::new(),
            revealed: HashSet::new(),
            goal_msat: HashMap::new(),
            status: "connecting to the relays…".into(),
            error: None,
            has_more: true,
            paging: false,
            dry_rounds: 0,
            last_dry: None,
            oldest_ts: None,
            snap: None,
            snap_dirty: true,
            mode,
            note_ids: HashSet::new(),
            last_visible_end: 0,
            // j/k's row cursor (feed.rs key_nav) — re-anchored by every
            // scroll event, so mouse and keys never disagree for long.
            cursor: 0,
            viewport_gen: 0,
            deep: false,
            list: ListState::new(0, ListAlignment::Top, px(400.)),
        };
        // Endless scroll: the list's own scroll stream orders the next page
        // (the GTK app prefetched at 70% scroll — same idea). The handler
        // runs on &mut App; WeakEntity::update accepts that.
        let this = cx.entity().downgrade();
        feed.list
            .set_scroll_handler(move |ev: &ListScrollEvent, _w, cx| {
                let _ = this.update(cx, |feed, cx| {
                    feed.last_visible_end = ev.visible_range.end;
                    // j/k's cursor rides the scroll stream: keys move it one
                    // row, the wheel re-anchors it to the top visible row.
                    feed.cursor = ev.visible_range.start;
                    // Deep-scroll whisper: the shell floats a back-to-top button
                    // once the reader is a few items down — a dozen was too
                    // deep (the owner kept scrolling before thinking "where is
                    // it"). Emit on change only.
                    let deep = ev.visible_range.start >= nav::PANE_DEEP_AT;
                    if feed.deep != deep {
                        feed.deep = deep;
                        cx.emit(Nav::PaneDeep);
                    }
                    feed.maybe_older(feed.last_visible_end, cx);
                    // The trim can only fire once the reader is back above the
                    // trim line — the scroll stream is where that happens.
                    feed.trim_window(cx);
                    // WS2: the visible window moved — re-scope the engagement
                    // subscription (debounced in viewport_pulse).
                    feed.viewport_pulse(cx);
                    // The window moved: pin its media, release the old
                    // window's (the idle-pane flash fix).
                    feed.pin_window(cx);
                });
            });
        // Live push: fresh follow posts bump the new-notes pill (the list
        // itself never moves on its own — the reader clicks when ready).
        let this = cx.entity().downgrade();
        let mut live_rx = feed.core.subscribe_live();
        cx.spawn(async move |_, cx| {
            loop {
                match live_rx.recv().await {
                    Ok(Live::Post) => {
                        // A dead pane (popped) must not leave the pump
                        // looping forever: update() failing IS the exit
                        // (audit memory: detached pumps used to ignore it
                        // and tick every broadcast for the process's life).
                        if this
                            .update(cx, |feed, cx| {
                                // A follow's fresh post needn't carry this
                                // hashtag — no new-notes pill on hashtag feeds.
                                // Author feeds likewise: the pill would sit
                                // under the profile's own header, noise. The
                                // Library's bookmarks (D38) too: a follow's
                                // post is not a new bookmark. And ARTICLES:
                                // in multicolumn view the reader watches both
                                // timelines; a follow's fresh long-form lit
                                // both pills — the notes timeline is where
                                // "new" is announced (the articles column
                                // catches up on its own refresh).
                                if matches!(
                                    feed.mode,
                                    FeedMode::Hashtag(_)
                                        | FeedMode::Profile(_)
                                        | FeedMode::Bookmarks
                                        | FeedMode::Articles
                                ) {
                                    return;
                                }
                                feed.live_new += 1;
                                cx.notify();
                            })
                            .is_err()
                        {
                            break;
                        }
                    }
                    // WS2: engagement on a viewport note arrived live —
                    // the event is in the store (the SDK saves on
                    // receive); re-seed the own-engagement mirrors and
                    // repaint. No new rendering path: this is the same
                    // snapshot invalidation every data change rides.
                    Ok(Live::Engagement) => {
                        if this.update(cx, |feed, cx| feed.on_engagement(cx)).is_err() {
                            break;
                        }
                    }
                    Ok(_) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                    Err(_) => continue, // lagged: still true that there's news
                }
            }
        })
        .detach();
        // The wallet broadcast (D20): bolt glyphs follow every zap —
        // theirs or the sheet's — wherever it started.
        engagement::pump_wallet(&feed.core, &cx.entity(), cx);
        // Hashtag feeds have no follow set to deep-fetch — the tag filter
        // IS the query (profile()-shaped); the rest bootstrap as usual.
        let boot = match &feed.mode {
            FeedMode::Hashtag(tag) => feed.core.hashtag(tag.clone()),
            FeedMode::Profile(who) => feed.core.profile(*who),
            FeedMode::Bookmarks => feed.core.bookmarked_notes(),
            _ => feed.core.bootstrap(feed.mode.kinds()),
        };
        feed.pump(boot, cx);
        feed
    }

    /// The shell header's title — the raw-cased tag on hashtag panes.
    pub fn header(&self) -> String {
        match &self.mode {
            FeedMode::Hashtag(tag) => format!("#{tag}"),
            FeedMode::Timeline => "Feed".into(),
            FeedMode::Articles => "Articles".into(),
            FeedMode::Bookmarks => "Bookmarks".into(),
            // Author feeds nest inside the profile pane, which carries its
            // own header — this title never renders.
            FeedMode::Profile(_) => "Profile".into(),
        }
    }

    /// The list's item count: one row per note + the end cap.
    fn list_len(&self) -> usize {
        self.notes.len() + 1
    }

    /// Back to the top (rail re-click, ensō click, the floating whisper):
    /// home is item zero. The remembered scroll end resets too, or the next
    /// landing page would chain a prefetch for a reader sitting at the top.
    pub fn scroll_top(&mut self) {
        self.last_visible_end = 0;
        self.deep = false;
        self.cursor = 0;
        self.list.scroll_to(ListOffset {
            item_ix: 0,
            offset_in_item: px(0.),
        });
    }

    /// WS2: j/k moves the cursor within the buffer — the window is
    /// unchanged unless the anchor scrolls, and scroll_to fires the scroll
    /// stream (which pulses) whenever it does.
    pub fn key_nav(&mut self, delta: isize) {
        let len = self.notes.len();
        if len == 0 {
            return;
        }
        let next = (self.cursor as isize + delta).clamp(0, len as isize - 1) as usize;
        self.cursor = next;
        self.list.scroll_to(ListOffset {
            item_ix: next,
            offset_in_item: px(0.),
        });
    }

    /// ←/→ (shell.rs key handler): step the cursor row's multi-image
    /// carousel — the same selection the ‹ › arrows move (content.rs
    /// carousel_key_step re-derives the carousel's seg id). False = the
    /// row has no carousel; the shell treats the key as unhandled.
    pub fn carousel_nav(&mut self, delta: isize, cx: &mut Context<Self>) -> bool {
        let Some(ev) = self.notes.get(self.cursor) else {
            return false;
        };
        let media = media::Snapshot::new(cx);
        let stepped = content::carousel_key_step(ev, &media, delta as i64);
        if stepped {
            cx.notify();
        }
        stepped
    }

    /// Near the bottom, order the next older page. The scroll handler calls
    /// this on every wheel tick — `paging` keeps it one round trip at a time.
    /// The lookahead is generous (a third of a page): the order goes out
    /// while the reader is still several screens away, so the relay round
    /// trip (up to READ_BUDGET) overlaps reading instead of parking the
    /// reader at the end cap.
    fn maybe_older(&mut self, visible_end: usize, cx: &mut Context<Self>) {
        const LOOKAHEAD: usize = 12;
        if self.paging || self.notes.is_empty() {
            return;
        }
        // The bookmark list is finite (D38) — the one-shot load never pages.
        if matches!(self.mode, FeedMode::Bookmarks) {
            self.has_more = false;
            return;
        }
        if visible_end + LOOKAHEAD < self.notes.len() {
            return;
        }
        if !self.has_more {
            // A dry seal reopens on the reader's continued scroll: the
            // failed round may have raced the wot graph's load or a cold
            // relay pool, and every retry deepens the store even when it
            // lands nothing. DRY_CAP straight dry rounds is the real end.
            if self.dry_rounds >= DRY_CAP {
                return;
            }
            if self.last_dry.is_some_and(|t| t.elapsed() < DRY_COOLDOWN) {
                return;
            }
        }
        self.paging = true;
        // The anchor, not the window's last row: the RAM window may have
        // trimmed the tail since this page was ordered.
        let oldest = self.oldest_ts.unwrap_or(0);
        let rx = match &self.mode {
            FeedMode::Hashtag(tag) => self.core.hashtag_older(tag.clone(), oldest),
            FeedMode::Profile(who) => self.core.profile_older(*who, oldest),
            _ => self.core.older(oldest, self.mode.kinds()),
        };
        self.pump(rx, cx);
        cx.notify();
    }

    /// The feed's RAM window. Notes are KB-scale events and the timeline
    /// only ever grows (`absorb` never clears — dedup makes reloads
    /// idempotent), so a long reading session used to hold every note ever
    /// fetched — and `FeedSnap` deep-clones the Vec on every data change,
    /// so unbounded `notes` also unbounded the per-frame rebuild cost.
    /// Past the ceiling the OLDEST tail is dropped, but only when the
    /// reader sits well above the trim line: splice preserves heights (and
    /// the scroll anchor) for rows above the removed range, and the paging
    /// anchor (`oldest_ts`) keeps `older()` streaming from where the stream
    /// ended, not where the Vec ends. `note_ids` keeps the dropped ids —
    /// a reload overlapping the trimmed range must dedup (a re-added note
    /// would land at the bottom, out of order).
    fn trim_window(&mut self, cx: &mut Context<Self>) {
        let Some(to) = trim_target(self.notes.len(), self.last_visible_end) else {
            return;
        };
        let old_len = self.list_len();
        // Shed the trimmed notes' dedup entries too (audit perf L2): the
        // window may hold 1000 while the visible target is 400 - every
        // scrolled-away note carried its id in note_ids for the session.
        // A trimmed note re-delivered by the live bell re-enters as fresh
        // content, which is correct: nothing of it is on screen.
        for note in self.notes.drain(to..) {
            self.note_ids.remove(&note.id);
        }
        // The end cap replaces the dropped tail: range to..old_len becomes
        // one row. Rows above `to` (the reader's anchor) keep their heights.
        self.list.splice(to..old_len, 1);
        self.touch();
        cx.notify();
    }

    /// The GPUI twin of app/bridge.rs `drain`: core returns receivers, the UI
    /// pumps them. tokio's receiver is executor-agnostic, so gpui's executor
    /// awaits it directly — no tokio context anywhere in the UI.
    fn pump(&self, mut rx: FeedRx, cx: &mut Context<Self>) {
        cx.spawn(async move |this, cx| {
            while let Some(ev) = rx.recv().await {
                let _ = this.update(cx, |this, cx| this.on_event(ev, cx));
            }
        })
        .detach();
    }

    /// Any state mutation goes through here so the render snapshot knows to
    /// rebuild. (on_event covers the event-driven arms wholesale.)
    fn touch(&mut self) {
        self.snap_dirty = true;
    }

    /// NIP-36: reveal a warned row (veil_card's Show seal). Stays for the
    /// session — a re-render never re-veils what was revealed.
    pub(crate) fn reveal(&mut self, id: EventId) {
        self.revealed.insert(id);
        self.touch();
    }

    /// §4.3 Retry: re-ask what this pane asks on open, per mode. The strip's
    /// Retry action only re-runs a relay round trip — it never pages.
    fn retry_load(&mut self, cx: &mut Context<Self>) {
        self.error = None;
        let rx = match &self.mode {
            FeedMode::Hashtag(tag) => self.core.hashtag(tag.clone()),
            FeedMode::Profile(who) => self.core.profile(*who),
            FeedMode::Bookmarks => self.core.bookmarked_notes(),
            _ => self.core.refresh(self.mode.kinds()),
        };
        self.pump(rx, cx);
        cx.notify();
    }

    fn on_event(&mut self, ev: FeedEvent, cx: &mut Context<Self>) {
        self.touch();
        enum Reflow {
            Reset,
            Append(usize),
            None,
        }
        let mut reflow = Reflow::Reset;
        let before = self.list_len();
        match ev {
            FeedEvent::Loaded(page) => {
                self.absorb(page.notes, page.profiles, cx);
                self.want_parents(cx);
                self.want_counts(cx);
                self.status.clear();
                self.error = None;
                // The badge click's promise is kept: the notes are in place.
                self.loading_new = false;
                // The bookmark list is finite (D38) — never page it.
                self.has_more = !matches!(self.mode, FeedMode::Bookmarks);
                self.dry_rounds = 0;
            }
            FeedEvent::Older(page, more) => {
                if more {
                    self.has_more = true;
                    self.dry_rounds = 0;
                } else {
                    self.has_more = false;
                    self.dry_rounds += 1;
                    self.last_dry = Some(std::time::Instant::now());
                }
                self.paging = false;
                let old = self.notes.len();
                self.absorb(page.notes, page.profiles, cx);
                self.want_parents(cx);
                self.want_counts(cx);
                if self.notes.len() > old {
                    // Appends keep the reader's place: reset() clears the
                    // scroll anchor and would yank the pane to the top,
                    // while splice() leaves logical_scroll_top alone (the
                    // anchor survives a non-overlapping splice).
                    reflow = Reflow::Append(old);
                } else {
                    reflow = Reflow::None;
                }
                // Chain: if the reader is (still) at the end cap — the scroll
                // handler fired its last wheel tick before this page existed —
                // order the next page now instead of waiting for a tick
                // that may never come. Pages served from the store are
                // near-instant, so a dry-spell relay trip deepens the store
                // once and the chain runs free afterwards. A dry round
                // chains too (the cool-off in maybe_older spaces the
                // retries): a slow relay round must not park the reader.
                if self.has_more || self.dry_rounds < DRY_CAP {
                    self.maybe_older(self.last_visible_end, cx);
                }
            }
            FeedEvent::Profiles(profiles) => self.absorb_profiles(profiles, cx),
            FeedEvent::CommentCounts(counts) => {
                // The bubble count: same-height patch (a digit appears in
                // an existing row slot) — no reflow, the anchor survives.
                // Re-landed ids re-enter the order queue (a re-ask after a
                // cap eviction refreshes recency, mirroring the parents
                // landing).
                for (id, n) in counts {
                    let key = id.to_string();
                    self.counts_order.retain(|o| o != &key);
                    self.counts_order.push_back(key.clone());
                    self.counts.insert(key, n as usize);
                }
                self.trim_counts();
                cx.notify();
            }
            FeedEvent::Parents(p) => {
                // Height-changing patches (the whisper appears) — the list
                // re-measures; no reset, the anchor survives small shifts.
                // The whisper's NAME resolves through the same profile map
                // as the header — but only note authors and mentions were
                // ever asked for, so every reply whisper fell back to raw
                // hex forever. Ask for the parent authors we can't name.
                let mut seen = HashSet::new();
                let missing: Vec<PublicKey> = p
                    .values()
                    .map(|pn| pn.author.clone())
                    .filter(|a| !self.profiles.contains_key(a) && seen.insert(a.clone()))
                    .filter_map(|a| PublicKey::from_hex(&a).ok())
                    .collect();
                for (k, v) in p {
                    self.parents.insert(k.clone(), v);
                    self.parents_order.retain(|o| o != &k);
                    self.parents_order.push_back(k);
                }
                self.trim_parents();
                if !missing.is_empty() {
                    let rx = self.core.ensure_profiles(missing);
                    self.pump(rx, cx);
                }
                cx.notify();
            }
            FeedEvent::Failed(e) => {
                // §4.3: the kinded strip, not a raw "… {e}" status dump —
                // the leading ellipsis collided with the loading convention.
                self.error = Some(states::PaneError::transient("The feed", &e));
                // A failed round trip must not wedge the end cap.
                self.paging = false;
                // ...nor the pill's loading state.
                self.loading_new = false;
            }
            _ => {}
        }
        // Reset only when the item count changed: gpui's List drops every
        // scroll event while a reset is pending, so resetting on profile
        // resolutions (constant during a busy feed) ate wheel input mid-scroll
        // and wedged the pane blank. Appends go through splice() instead (the
        // list learns the new count without losing the anchor); same-height
        // patches need neither (list.rs: "elements outside the scrolled area
        // do not change their height").
        match reflow {
            Reflow::Reset if self.list_len() != before => self.list.reset(self.list_len()),
            Reflow::Append(old) => {
                // splice inserts `count` items at `old`, keeping the suffix:
                // total = old + count + (state_total − old). The state was in
                // sync (state_total = before), so count is the DELTA — the
                // new-total-shaped call double-counted (the state grew by a
                // full list length per append; probed against gpui 0.2.2).
                let added = self.list_len() - before;
                self.list.splice(old..old, added);
            }
            _ => {}
        }
        // A landing can cross the ceiling on its own (a big bootstrap); the
        // reader is above the trim line in that case almost by definition.
        self.trim_window(cx);
        // WS2: a landing changed which notes sit under the viewport.
        self.viewport_pulse(cx);
        cx.notify();
    }

    fn absorb(&mut self, notes: Vec<Event>, profiles: Vec<Profile>, cx: &mut Context<Self>) {
        self.absorb_profiles(profiles, cx);
        // Mention candidates from the notes actually INSERTED (the loop
        // dedups): re-scanning the whole window re-classified every token
        // of every note on every landing (audit perf M6).
        let mut mention_candidates: Vec<PublicKey> = Vec::new();
        for note in notes {
            // The paging anchor advances on EVERY incoming note — even a
            // deduped repeat or a filtered kind marks where the stream has
            // reached; the window may already have trimmed the tail this
            // note belongs to.
            let ts = note.created_at.as_secs();
            self.oldest_ts = Some(self.oldest_ts.map_or(ts, |o: u64| o.min(ts)));
            // The unknown-kind policy (#52, the generic card): everything
            // lands — a kind Satori hasn't heard of renders the muted
            // "unrendered kind N" card (or NIP-31's alt line). Nothing
            // arrives invisible. The never-feed exceptions are structural,
            // not curational: engagement noise (reactions, zap requests —
            // a reaction with an alt tag is still a reaction, and alt is
            // attacker-writable; reposts ride their own guard below) and
            // NIP-22 comments (kind 1111 is a REPLY by definition — it
            // lives in threads and the bell, never in a roots feed).
            let kind_num = u16::from(note.kind);
            let noise = (satori_core::viewport::ENGAGEMENT_KINDS.contains(&kind_num)
                && kind_num != 6)
                || kind_num == 1111;
            if note.kind != Kind::TextNote && !cards::is_feed_kind(note.kind) && noise {
                continue;
            }
            // Amethyst's repost guard: a repost is not content of its own —
            // if the boosted kind has no card here, the row never renders
            // (a kind-6 payload is the original event's JSON; raw text
            // would leak it).
            if u16::from(note.kind) == 6 && content::repost_inner_cached(&note).is_none() {
                continue;
            }
            if self.note_ids.contains(&note.id) {
                continue;
            }
            self.want_images(&note, cx);
            quotes::want_quotes(self, &note, cx);
            if u16::from(note.kind) == 1068 {
                self.want_poll(&note, cx);
            }
            if u16::from(note.kind) == 9041 {
                self.want_goal(&note, cx);
            }
            mention_candidates.push(note.pubkey);
            mention_candidates.extend(content::mention_pks(&note.content));
            self.note_ids.insert(note.id);
            self.notes.push(note);
        }
        self.notes.sort_by_key(|n| std::cmp::Reverse(n.created_at));
        // Ask core for any authors we still can't name — the note's author
        // plus mentioned pubkeys, so a mention renders @name instead of
        // @npub1… (TODO(port): content.ts mentionPubkeys — hydrate before
        // render).
        let missing: Vec<PublicKey> = {
            let mut seen = HashSet::new();
            mention_candidates
                .into_iter()
                .filter(|pk| {
                    !self.profiles.contains_key(&pk.to_string()) && seen.insert(pk.to_string())
                })
                .collect()
        };
        if !missing.is_empty() {
            let rx = self.core.ensure_profiles(missing);
            self.pump(rx, cx);
        }
        // Fresh data: pin the visible window's media (the reader may be
        // idle-staring at it for minutes; the grace window cannot cover
        // an idle pane — only renders touch).
        self.pin_window(cx);
    }

    /// Pin the visible window's media urls, release the previous
    /// window's. Called when the window moves (the list's scroll stream)
    /// and when data lands (absorb) — the two moments the on-screen set
    /// can change. The set is EVERYTHING the visible cards paint
    /// (card_media_urls: avatars, body pictures, repost inners) — an
    /// idle feed stops rendering, and only renders touch, so a missing
    /// avatar here was the timeline's disappearing-image report.
    fn pin_window(&mut self, cx: &mut Context<Self>) {
        let start = self.cursor.min(self.notes.len());
        // Before the first scroll event the end is still 0: pin the top
        // rows (the list reports the true range once the wheel moves).
        let end = self.last_visible_end.max(start + 8).min(self.notes.len());
        let mut urls: Vec<String> = Vec::new();
        for note in &self.notes[start..end] {
            urls.extend(card_media_urls(note, &self.profiles));
        }
        media::repin(cx.entity_id(), urls, cx);
    }

    /// The bubbles' comment counts (one batched round per page of notes).
    fn want_counts(&mut self, cx: &mut Context<Self>) {
        let mut targets: Vec<(EventId, satori_core::nip::comment::CommentTarget)> = Vec::new();
        for note in &self.notes {
            let id = note.id.to_string();
            if self.counts_asked.contains(&id) {
                continue;
            }
            self.counts_asked.insert(id.clone());
            self.counts_order.push_back(id);
            // Mixed targets (#52): a parameterized picture/video hangs its
            // comment thread off the a-tag ADDRESS, a note off its id —
            // core counts each by its own grammar, keyed by note id.
            targets.push((
                note.id,
                satori_core::nip::comment::CommentTarget::for_event(note),
            ));
        }
        if targets.is_empty() {
            return;
        }
        self.trim_counts();
        let rx = self.core.comment_counts(targets);
        self.pump(rx, cx);
    }

    /// Collect the page's unresolved reply parents and ask core for them
    /// (store first, one by-id relay trip for the misses). Capped per ask.
    /// The parents cap (#31 latent): a long session's whisper maps used
    /// to grow for the process lifetime. Past the cap the OLDEST key
    /// (insertion order — the scroll origin's side) drops, asked-set
    /// included, so a re-scroll back re-asks and re-hydrates it. The
    /// order queue tracks ASKS (not just landings) — a miss would
    /// otherwise sit in `parents_asked` forever.
    fn trim_parents(&mut self) {
        content::fifo_trim(&mut self.parents, &mut self.parents_order, PARENTS_CAP);
        self.parents_asked.retain(|k| self.parents.contains_key(k));
    }

    /// The comment-count cap: `trim_parents`' discipline for the
    /// bubbles' maps.
    fn trim_counts(&mut self) {
        content::fifo_trim(&mut self.counts, &mut self.counts_order, COUNTS_CAP);
        self.counts_asked.retain(|k| self.counts.contains_key(k));
    }

    fn want_parents(&mut self, cx: &mut Context<Self>) {
        let mut ids: Vec<String> = Vec::new();
        for note in &self.notes {
            if let Some((id, _relays)) = nip10::reply_parent(note) {
                if self.parents.contains_key(&id) || self.parents_asked.contains(&id) {
                    continue;
                }
                self.parents_asked.insert(id.clone());
                self.parents_order.push_back(id.clone());
                ids.push(id);
                if ids.len() >= 60 {
                    break;
                }
            }
        }
        if ids.is_empty() {
            return;
        }
        self.trim_parents();
        let rx = self.core.load_parents(ids);
        let mut rx = rx;
        cx.spawn(async move |this, cx| {
            while let Some(ev) = rx.recv().await {
                let live = this
                    .update(cx, |f, cx| {
                        f.on_event(ev, cx);
                        true // keep draining until the channel closes
                    })
                    .unwrap_or(false);
                if !live {
                    break;
                }
            }
        })
        .detach();
    }

    fn absorb_profiles(&mut self, profiles: Vec<Profile>, cx: &mut Context<Self>) {
        for p in profiles {
            self.want_avatar(&p, cx);
            self.profiles.insert(p.pubkey.clone(), p);
        }
        // A landing can change a visible row's avatar URL (the picture
        // arrived after the note): re-pin so the new URL rides the
        // pinned set, not just this render's fetch.
        self.pin_window(cx);
    }

    /// Queue core fetches for every media URL we haven't got yet. Results
    /// land in the shared media cache (media.rs) — a `cx.notify()` re-render
    /// picks them up via the snapshot. The og: keys are NOT queued here:
    /// this sweep runs at note ARRIVAL (absorb) — previewing every link a
    /// relay pushes at us before the reader ever scrolls to it turned the
    /// facade rule's worst case up (third-party contacts keyed to what
    /// relays send, not what the user sees). The visible list factory
    /// requests the og: key when the row actually renders — the same
    /// discipline every avatar and picture rides (audit system-usage #1).
    fn want_images(&mut self, note: &Event, cx: &mut Context<Self>) {
        for url in content::media_urls_cached(note).iter().cloned() {
            if url.starts_with("og:") {
                continue;
            }
            media::fetch(&self.core, url, cx.entity_id(), cx);
        }
    }

    /// Tallies for a poll card (cards.rs poll_card): core drains the kind
    /// 1018 votes; the id rides the pump closure (PollVotes carries none).
    fn want_poll(&mut self, note: &Event, cx: &mut Context<Self>) {
        if self.poll_tallies.contains_key(&note.id) {
            return;
        }
        // Reserve so re-renders don't re-request while loading.
        self.poll_tallies.insert(note.id, vec![]);
        let id = note.id;
        let mut rx = self.core.poll_votes(id);
        cx.spawn(async move |this, cx| {
            while let Some(ev) = rx.recv().await {
                if let FeedEvent::PollVotes(t) = ev {
                    let _ = this.update(cx, |this, cx| {
                        this.poll_tallies.insert(id, t);
                        cx.notify();
                    });
                }
            }
        })
        .detach();
        cx.notify();
    }

    /// Progress for a goal card (cards.rs goal_card): core sums the zap
    /// receipts naming the goal; the id rides the pump closure (GoalMsat
    /// carries the id, but re-requests stay reserved like want_poll).
    fn want_goal(&mut self, note: &Event, cx: &mut Context<Self>) {
        if self.goal_msat.contains_key(&note.id) {
            return;
        }
        // Reserve so re-renders don't re-request while loading.
        self.goal_msat.insert(note.id, 0);
        let mut rx = self.core.goal_progress(note);
        cx.spawn(async move |this, cx| {
            while let Some(ev) = rx.recv().await {
                if let FeedEvent::GoalMsat(gid, msat) = ev {
                    let _ = this.update(cx, |this, cx| {
                        this.goal_msat.insert(gid, msat);
                        cx.notify();
                    });
                }
            }
        })
        .detach();
        cx.notify();
    }

    /// Ballot selection (cards.rs poll_card): replace for single-choice,
    /// toggle for multiple.
    pub(crate) fn toggle_poll_sel(
        &mut self,
        ev: &Event,
        opt: String,
        multiple: bool,
        cx: &mut Context<Self>,
    ) {
        self.touch();
        let sel = self.poll_sel.entry(ev.id).or_default();
        if sel.contains(&opt) {
            sel.retain(|o| *o != opt);
        } else if multiple {
            sel.push(opt);
        } else {
            *sel = vec![opt];
        }
        cx.notify();
    }

    /// Cast the ballot: publish the vote (kind 1018), mark voted on commit,
    /// re-drain the tallies.
    pub(crate) fn cast_vote(&mut self, ev: &Event, cx: &mut Context<Self>) {
        let Some(opts) = self.poll_sel.get(&ev.id).cloned() else {
            return;
        };
        if opts.is_empty() {
            return;
        }
        let id = ev.id;
        let mut rx = self.core.poll_vote(ev, opts);
        cx.spawn(async move |this, cx| {
            while let Some(pv) = rx.recv().await {
                if let PublishEvent::Committed { .. } = pv {
                    let _ = this.update(cx, |this, cx| {
                        this.voted.insert(id);
                        this.touch();
                        // Fresh tally including our own vote.
                        let mut rx = this.core.poll_votes(id);
                        cx.spawn(async move |this, cx| {
                            while let Some(ev) = rx.recv().await {
                                if let FeedEvent::PollVotes(t) = ev {
                                    let _ = this.update(cx, |this, cx| {
                                        this.poll_tallies.insert(id, t);
                                        this.touch();
                                        cx.notify();
                                    });
                                }
                            }
                        })
                        .detach();
                        cx.notify();
                    });
                    break;
                }
            }
        })
        .detach();
        cx.notify();
    }

    /// RSVP to a calendar event (NIP-52 kind 31925) — engaged on commit.
    pub(crate) fn send_rsvp(&mut self, ev: &Event, status: &'static str, cx: &mut Context<Self>) {
        let id = ev.id;
        let mut rx = self.core.rsvp(ev, status);
        cx.spawn(async move |this, cx| {
            while let Some(pv) = rx.recv().await {
                if let PublishEvent::Committed { .. } = pv {
                    let _ = this.update(cx, |this, cx| {
                        this.rsvped.insert(id, status.into());
                        this.touch();
                        cx.notify();
                    });
                    break;
                }
            }
        })
        .detach();
        cx.notify();
    }

    /// Queue the profile picture fetch (core's guarded, disk-cached path).
    fn want_avatar(&mut self, profile: &Profile, cx: &mut Context<Self>) {
        let url = profile.picture.clone();
        if url.is_empty() {
            return;
        }
        media::fetch(&self.core, url, cx.entity_id(), cx);
    }

    /// WS2 (viewport.rs): the settled viewport pulse. The scroll stream
    /// calls this on every wheel tick and every landing; only the LAST
    /// pulse inside the settle window reaches core (the generation guard
    /// drops superseded timers) — fast scrolling coalesces into one
    /// `set_viewport`, no subscription churn (D24).
    fn viewport_pulse(&mut self, cx: &mut Context<Self>) {
        self.viewport_gen += 1;
        let pulse_id = self.viewport_gen;
        cx.spawn(async move |this, cx| {
            cx.background_executor()
                .timer(std::time::Duration::from_millis(
                    satori_core::viewport::SETTLE_MS,
                ))
                .await;
            let _ = this.update(cx, |feed, cx| {
                if feed.viewport_gen != pulse_id {
                    return; // a newer scroll superseded this pulse
                }
                feed.push_viewport(cx);
            });
        })
        .detach();
    }

    /// The settled window → core: the visible range (+ buffer, capped)
    /// becomes the live engagement id set. The per-paint/store loads stay
    /// as the fallback for distant rows — this only ADDS liveness.
    fn push_viewport(&mut self, _cx: &mut Context<Self>) {
        if self.notes.is_empty() {
            self.core.set_viewport(Vec::new());
            return;
        }
        let end = self.last_visible_end.max(self.cursor);
        let (start, stop) = satori_core::viewport::window(
            self.notes.len(),
            self.cursor,
            end,
            satori_core::viewport::VIEWPORT_BUFFER,
            satori_core::viewport::MAX_LIVE_IDS,
        );
        let ids = satori_core::viewport::ids_in_window(&self.notes, start, stop);
        self.core.set_viewport(ids);
    }

    /// A viewport engagement event landed in the store (WS2): re-seed the
    /// own-engagement mirrors (they are the glyphs' render state) and
    /// repaint. The same snapshot invalidation every data change rides —
    /// no new rendering path.
    fn on_engagement(&mut self, cx: &mut Context<Self>) {
        engagement::reseed(self);
        cx.notify();
    }
}

impl Drop for Feed {
    fn drop(&mut self) {
        // WS2 (viewport.rs): the pane is gone — its viewport ids go with
        // it. The manager's task plans a Drop and closes the subscription;
        // nothing keeps a REQ alive for a feed nobody renders.
        self.core.set_viewport(Vec::new());
    }
}

/// The row's toggles land here (actions.rs): Feed's optimistic mirrors ARE
/// the implementation the timeline has always had — the trait just names
/// it. The behavior itself lives in engagement.rs (the extracted engine);
/// Feed's Host impl carries its two deltas: touch() invalidation and the
/// Bookmarks row-drop.
impl engagement::Host for Feed {
    fn engagement(&mut self) -> &mut engagement::Engagement {
        &mut self.engagement
    }
    fn core(&self) -> &Arc<Core> {
        &self.core
    }
    fn whisper(&mut self, msg: String) {
        self.status = msg;
    }
    fn touched(&mut self) {
        self.touch();
    }
    fn unbookmark_committed(&mut self, ev_id: EventId, cx: &mut Context<Self>) {
        if matches!(self.mode, FeedMode::Bookmarks) {
            self.notes.retain(|n| n.id != ev_id);
            self.note_ids.remove(&ev_id);
            self.list.reset(self.list_len());
            self.touch();
            cx.notify();
        }
    }
}

// The quote engine rides the default no-op `touched`: a quote landing
// must not churn the feed list (the old pump_quote's routing comment).
impl quotes::Host for Feed {
    fn quotes(&mut self) -> &mut content::Quotes {
        &mut self.quotes
    }
    fn core(&self) -> &Arc<Core> {
        &self.core
    }
    fn profiles(&self) -> &HashMap<String, Profile> {
        &self.profiles
    }
}

impl actions::ActionHost for Feed {
    fn toggle_like(&mut self, ev: &Event, cx: &mut Context<Self>) {
        engagement::toggle_like(self, ev, cx)
    }
    fn toggle_reaction_picker(&mut self, id: &str, cx: &mut Context<Self>) {
        engagement::toggle_reaction_picker(self, id, cx)
    }
    fn react_with(&mut self, ev: &Event, content: &str, cx: &mut Context<Self>) {
        engagement::react_with(self, ev, content, cx)
    }
    fn toggle_repost(&mut self, ev: &Event, cx: &mut Context<Self>) {
        engagement::toggle_repost(self, ev, cx)
    }
    fn toggle_bookmark(&mut self, ev: &Event, cx: &mut Context<Self>) {
        engagement::toggle_bookmark(self, ev, cx)
    }
    fn zap_tap(&mut self, ev: &Event, cx: &mut Context<Self>) {
        engagement::zap_tap(self, ev, cx)
    }
}

/// The chip's label — the count, capped at 99+ (a four-digit count would
/// set the chip's width, and nobody reads the tail of a stampede). What
/// the click does is the tooltip's job, not the label's.
fn new_notes_label(n: usize) -> String {
    if n == 1 {
        "1 new note".to_string()
    } else if n > 99 {
        "99+ new notes".to_string()
    } else {
        format!("{n} new notes")
    }
}

/// Where a row's click opens (both open sites — the note row and the
/// repost's inner card — route through this). Articles open the reader;
/// parameterized media (NIP-68/71 with a d tag) threads by ADDRESS
/// (`CommentTarget::for_event`'s rule — the a-tag coordinate survives
/// edits, and the comment thread hangs off it); everything else threads
/// at the conversation's ROOT when the note is a reply (the reference
/// never links the parent).
fn thread_nav(ev: &Event) -> Nav {
    let kind = u16::from(ev.kind);
    if kind == 30023 {
        return Nav::OpenArticle(ev.clone());
    }
    // for_event's Address arm also covers every other addressable kind,
    // but those anchored fine by id before this door existed — only the
    // parameterized media switch (their threads are unreachable by id).
    if matches!(kind, 20..=22)
        && let satori_core::nip::comment::CommentTarget::Address { kind, author, d } =
            satori_core::nip::comment::CommentTarget::for_event(ev)
    {
        return Nav::OpenThreadAddr(kind, author, d);
    }
    let root = satori_core::nip::nip10::reply_root(ev)
        .and_then(|(id, _)| EventId::from_hex(&id).ok())
        .unwrap_or(ev.id);
    Nav::OpenThread(root)
}

// The card takes the full render-time snapshot — one struct would hide the
// shape, and GPUI's no-entity-reads-during-render rule makes them explicit.
#[allow(clippy::too_many_arguments)]
fn note_card(
    idx: usize,
    ev: &Event,
    profiles: &HashMap<String, Profile>,
    parents: &HashMap<String, ParentNote>,
    eng: &engagement::Engagement,
    reduced_motion: bool,
    media: &media::Snapshot,
    quotes: &content::Quotes,
    cards: &cards::CardState,
    // The display timestamp under the current timefmt mode (the item
    // closure computes it — this fn has no cx to read the mode with).
    time: String,
    // The row's comment count (the bubble), from the Feed's counts map.
    replies: usize,
    handle: Entity<Feed>,
) -> impl IntoElement {
    // TODO(port): note_card.rs layout — P0 minimal card; name fallback chain
    // matches Profile::display (render/util.ts style).
    // One owned Arc up front: the eight action closures below each need the
    // event, and cloning the whole Event per closure was eight deep copies
    // of every visible row, every frame — Arc bumps now. (The list hands
    // out &Event; the single clone here is the row's only deep copy.)
    let ev = std::sync::Arc::new(ev.clone());
    let id = ev.id.to_string();
    let key = ev.pubkey.to_string();
    let profile = profiles.get(&key);
    let name = content::display_name(profile, &key);
    let picture = profile.map(|p| p.picture.clone()).unwrap_or_default();
    let engaged = eng.liked.contains(&id);
    let saved = eng.bookmarked.contains(&id);
    let shared = eng.reposted.contains(&id);
    let zapped = eng.zapped.contains(&id);
    let zapping = eng.zap_pending.contains(&id);
    let ev_for_open = ev.clone();
    let handle_open = handle.clone();

    // No card box: posts sit directly on the washi, separated by whitespace
    // alone (sumi-e — the empty space carries the composition).
    // §2.1 anatomy: py S4 (12px/side, not 16), and the head→body gap (S2,
    // 4px) is TIGHTER than body→actions (S3, 8px) — hierarchy via one
    // exception here, not per-call nudges.
    div()
        .w_full()
        .flex()
        .flex_col()
        .gap_1()
        .px_4()
        .py(px(theme::S4))
        .child(content::actor_header(
            None,
            media,
            &picture,
            name,
            None,
            time,
            format!("note-{idx}"),
            Some(ev.pubkey),
            Some(satori_core::nip::nip19::uri(&ev)),
            handle.clone(),
        ))
        // The reply context (nip10.ts replyContext, option B): the parent's
        // author + a snippet, fetched by id once and cached in the feed.
        // A whisper, not a box — one muted line with the elbow glyph; click
        // opens the parent's thread (the thread pane anchors by id, so this
        // works even before the parent resolves).
        .children(reply_whisper(idx, &ev, parents, profiles, &handle))
        .child(
            // Clicking the note body opens its thread (nav via the shell).
            div()
                .id(SharedString::from(format!("open-{idx}")))
                .cursor_pointer()
                .on_click(move |_, _, cx| {
                    let ev = ev_for_open.clone();
                    handle_open.update(cx, |_feed, cx| {
                        // The row's door (thread_nav): reader for articles,
                        // address-thread for parameterized media, root
                        // thread otherwise.
                        cx.emit(thread_nav(&ev));
                    });
                })
                .child(cards::row_body(
                    &ev,
                    &content::Body {
                        media,
                        quotes,
                        profiles,
                        emoji: content::body_parse(&ev).emoji.clone(),
                    },
                    &handle,
                    cards,
                )),
        )
        .child(actions::action_row(
            &id,
            &ev,
            actions::ActionState {
                liked: engaged,
                reposted: shared,
                bookmarked: saved,
                zapped,
                zapping,
                wallet_ready: eng.wallet_ready,
                picker_open: eng.reaction_picker.as_deref() == Some(&id),
                replies,
                reduced_motion,
            },
            handle,
        ))
}

impl Render for Feed {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let handle = cx.entity();
        let status = self.status.clone();
        // Rebuild the render snapshot only when the DATA changed (any
        // mutation sets snap_dirty). Media is NOT in the snapshot: render
        // takes the memoized cache snapshot fresh each frame (same epoch =
        // refcount bump), so a landed image repaints its card without
        // deep-copying a thousand events.
        // The pending bolt's breathing honors the desktop's motion pref
        // (desktop.rs: the portal's prefers-reduced-motion).
        let reduced_motion = crate::desktop::Desktop::get(cx).reduced_motion;
        if self.snap_dirty || self.snap.is_none() {
            self.snap = Some(FeedSnap {
                notes: std::sync::Arc::new(self.notes.clone()),
                profiles: std::sync::Arc::new(self.profiles.clone()),
                parents: std::sync::Arc::new(self.parents.clone()),
                counts: std::sync::Arc::new(self.counts.clone()),
                engagement: std::sync::Arc::new(self.engagement.clone()),
                quotes: std::sync::Arc::new(self.quotes.clone()),
                cards: std::sync::Arc::new(cards::CardState {
                    poll_tallies: self.poll_tallies.clone(),
                    poll_sel: self.poll_sel.clone(),
                    voted: self.voted.clone(),
                    rsvped: self.rsvped.clone(),
                    revealed: self.revealed.clone(),
                    goal_msat: self.goal_msat.clone(),
                }),
            });
            self.snap_dirty = false;
        }
        let media = media::Snapshot::new(cx);
        let snap = self.snap.as_ref().unwrap();
        let empty = snap.notes.is_empty();

        div()
            .flex_1()
            .min_h_0()
            .overflow_hidden()
            // (The 16px top band lives in the shell's content column —
            // every page wears the same padding.)
            .bg(rgb(theme::washi()))
            .text_color(rgb(theme::ink()))
            .font_family(theme::SANS)
            .flex()
            .flex_col()
            // Relay status line — the shell header carries the title now, so
            // this only speaks when there's something to say (loading; the
            // errors have their own strip below, §4.3).
            .when(!status.is_empty(), {
                let status = status.clone();
                move |d| {
                    d.child(
                        div()
                            .px_4()
                            .py_2()
                            .text_size(px(theme::T_SMALL))
                            .text_color(rgb(theme::muted()))
                            .border_b_1()
                            .border_color(rgb(theme::hairline()))
                            .child(status),
                    )
                }
            })
            // The kinded error strip (§4.3): dismissible, retryable.
            .when_some(self.error.clone(), |d, err| {
                let retry = handle.clone();
                let dismiss = handle.clone();
                d.child(states::error_strip(
                    &err,
                    // Retry: re-ask, per mode (retry_load).
                    move |_, _, cx| {
                        retry.update(cx, |feed, cx| feed.retry_load(cx));
                    },
                    // Dismiss: quiet, no reload.
                    move |_, _, cx| {
                        dismiss.update(cx, |feed, cx| {
                            feed.error = None;
                            cx.notify();
                        });
                    },
                ))
            })
            // The new-notes pill (the live subscription's push signal):
            // a small centered chip on the washi — content-sized, not a
            // pane-wide bar. Nothing else moves; the reader decides when
            // the list turns over.
            .when(self.live_new > 0 && !empty, |d| {
                let n = self.live_new;
                let handle = handle.clone();
                d.child(
                    div().w_full().flex().justify_center().child(
                        div()
                            .id("new-posts-pill")
                            .cursor_pointer()
                            .flex_none()
                            .mb_1()
                            .px_4()
                            .py_1p5()
                            .rounded_full()
                            .border_1()
                            .border_color(rgb(theme::hairline()))
                            .text_size(px(theme::T_SMALL))
                            .text_color(rgb(theme::vermilion()))
                            .hover(|s| {
                                s.border_color(rgb(theme::vermilion()))
                                    .text_color(rgb(theme::ink()))
                            })
                            .tooltip(super::shell::tip("Load new notes"))
                            .on_click(move |_, _, cx| {
                                handle.update(cx, |feed, cx| {
                                    feed.live_new = 0;
                                    // The chip keeps its promise visibly:
                                    // "Loading new notes…" until the first
                                    // Loaded — the paint-first refresh makes
                                    // that the store page, near instant.
                                    feed.loading_new = true;
                                    feed.scroll_top();
                                    let rx = feed.core.refresh(feed.mode.kinds());
                                    feed.pump(rx, cx);
                                    cx.notify();
                                });
                            })
                            .child(if self.loading_new {
                                "Loading new notes…".to_string()
                            } else {
                                new_notes_label(n)
                            }),
                    ),
                )
            })
            .child(
                // The centered timeline column (the web app's reading width).
                div()
                    .flex_1()
                    .min_h_0()
                    .flex()
                    .justify_center()
                    .child(if empty {
                        // §4.1: "the relays are still answering" was wrong for
                        // a persistently empty feed — it never resolves. Split:
                        // first load pending → the loading line; loaded, zero
                        // events → the honest quiet.
                        if !status.is_empty() {
                            states::empty(&status, None)
                        } else {
                            states::empty(
                                "Quiet here.",
                                Some("The relays remember nothing from this view."),
                            )
                        }
                    } else {
                        // GPUI rule (D13): an entity can't be read while it renders,
                        // so snapshot the data into the item closure; only the click
                        // handlers touch the entity, later, legally. Arc clones.
                        let notes = snap.notes.clone();
                        let profiles = snap.profiles.clone();
                        let parents = snap.parents.clone();
                        let counts = snap.counts.clone();
                        let eng = snap.engagement.clone();
                        let quotes = snap.quotes.clone();
                        let cards = snap.cards.clone();
                        let media = media.clone();
                        let paging = self.paging;
                        let has_more = self.has_more;
                        let core = self.core.clone();
                        list(self.list.clone(), move |idx, _w, cx| {
                            // Re-request what this VISIBLE card paints but
                            // the cache dropped — eviction is the RAM
                            // budget working, and this is what brings an
                            // evicted avatar back the moment its card
                            // scrolls into view. Ready/not-media are silent
                            // no-ops; only a landing notifies, so this
                            // can't loop a render.
                            if let Some(ev) = notes.get(idx) {
                                for url in card_media_urls(ev, &profiles) {
                                    media::fetch(&core, url, handle.entity_id(), cx);
                                }
                            }
                            match notes.get(idx) {
                                Some(ev) if u16::from(ev.kind) == 6 => {
                                    // The stamp reads the current mode +
                                    // blocktime cache per frame; ensure
                                    // refines Block mode from the bridge.
                                    let secs = ev.created_at.as_secs();
                                    let time = crate::timefmt::stamp(secs, cx);
                                    crate::timefmt::ensure(secs, cx);
                                    repost_card(
                                        ev,
                                        &profiles,
                                        &eng,
                                        &counts,
                                        reduced_motion,
                                        &media,
                                        &quotes,
                                        &cards,
                                        time,
                                        handle.clone(),
                                    )
                                    .into_any_element()
                                }
                                Some(ev) => {
                                    let secs = ev.created_at.as_secs();
                                    let time = crate::timefmt::stamp(secs, cx);
                                    crate::timefmt::ensure(secs, cx);
                                    let eng = eng.clone();
                                    let replies =
                                        counts.get(&ev.id.to_string()).copied().unwrap_or(0);
                                    note_card(
                                        idx,
                                        ev,
                                        &profiles,
                                        &parents,
                                        &eng,
                                        reduced_motion,
                                        &media,
                                        &quotes,
                                        &cards,
                                        time,
                                        replies,
                                        handle.clone(),
                                    )
                                    .into_any_element()
                                }
                                None => end_cap(paging, has_more).into_any_element(),
                            }
                        })
                        // list() has no intrinsic height — it must be told to fill
                        // its container or it lays out at 0px and paints nothing.
                        .w_full()
                        .max_w(px(content::COL_W))
                        .h_full()
                        .into_any_element()
                    }),
            )
    }
}

/// Every media URL one card paints: the author's avatar, the body's
/// pictures, and for a repost both the booster's line and the boosted
/// card (which paints ITS author too). The lazy list renders only the
/// visible window, so this doubles as the visible re-request set —
/// evicted entries come back exactly when their card is seen.
fn card_media_urls(ev: &Event, profiles: &HashMap<String, Profile>) -> Vec<String> {
    fn one(note: &Event, profiles: &HashMap<String, Profile>, urls: &mut Vec<String>) {
        if let Some(p) = profiles.get(&note.pubkey.to_string()) {
            urls.push(p.picture.clone());
        }
        urls.extend(content::media_urls_cached(note).iter().cloned());
        // The landed og:image rides the sweep: the card paints it, so an
        // eviction must come back (and pin) like every other picture.
        urls.extend(content::og_image_urls(note));
    }
    let mut urls: Vec<String> = Vec::new();
    if u16::from(ev.kind) == 6 {
        one(ev, profiles, &mut urls);
        if let Some(inner) = content::repost_inner_cached(ev) {
            one(&inner, profiles, &mut urls);
        }
    } else {
        one(ev, profiles, &mut urls);
    }
    urls
}

/// A repost row (NIP-18 kind 6): the reposter in the header slot, the
/// boosted note's card as the body, and the BOOSTED note's action row
/// beneath it — a repost is a delivery envelope, not a different kind
/// of content; its engagement belongs to the note inside (user report:
/// the envelope-only row read as a broken card). Clicking the body
/// opens the note (thread, or reader for articles).
#[allow(clippy::too_many_arguments)]
fn repost_card(
    ev: &Event,
    profiles: &HashMap<String, Profile>,
    eng: &engagement::Engagement,
    counts: &HashMap<String, usize>,
    reduced_motion: bool,
    media: &media::Snapshot,
    quotes: &content::Quotes,
    cards: &cards::CardState,
    time: String,
    handle: Entity<Feed>,
) -> impl IntoElement {
    let key = ev.pubkey.to_string();
    let name = content::display_name(profiles.get(&key), &key);
    let picture = profiles
        .get(&key)
        .map(|p| p.picture.clone())
        .unwrap_or_default();
    let inner = content::repost_inner_cached(ev);
    let open = inner.clone();
    let open_handle = handle.clone();
    inner.map_or_else(
        || {
            // The absorb guard keeps these out of the list; a defensive
            // quiet line in case one slips through a race.
            div()
                .w_full()
                .px_4()
                .py_3()
                .text_size(px(theme::T_SMALL))
                .text_color(rgb(theme::muted()))
                .child(format!("{name} boosted"))
        },
        |note| {
            // The action row speaks for the BOOSTED note: mirrors, picker
            // and counts keyed by its id, the same keys the toggles write.
            // Arc bump — the deep-clone discipline note_card keeps.
            let inner_ev = note.clone();
            let inner_id = inner_ev.id.to_string();
            let engaged = eng.liked.contains(&inner_id);
            let saved = eng.bookmarked.contains(&inner_id);
            let shared = eng.reposted.contains(&inner_id);
            let zapped = eng.zapped.contains(&inner_id);
            let zapping = eng.zap_pending.contains(&inner_id);
            let replies = counts.get(&inner_id).copied().unwrap_or(0);
            div()
                .w_full()
                .flex()
                .flex_col()
                .gap_2()
                .px_4()
                .py_4()
                .child(content::actor_header(
                    // The same glyph slot the notification rows wear: the
                    // boost announces itself before the words.
                    Some(icons::repost_icon(theme::muted()).into_any_element()),
                    media,
                    &picture,
                    name.clone(),
                    Some(
                        div()
                            .text_size(px(theme::T_UI))
                            .text_color(rgb(theme::muted()))
                            .child("boosted")
                            .into_any_element(),
                    ),
                    time,
                    format!("boost-{}", ev.id),
                    None,
                    // The seal copies the boosted note (the note on screen),
                    // not the kind-6 envelope.
                    Some(satori_core::nip::nip19::uri(&note)),
                    handle.clone(),
                ))
                .child(
                    div()
                        .id(SharedString::from(format!("repost-{}", ev.id)))
                        .cursor_pointer()
                        .on_click(move |_, _, cx| {
                            let note = open.clone().expect("inner held");
                            open_handle.update(cx, |_feed, cx| {
                                cx.emit(thread_nav(&note));
                            });
                        })
                        .child(cards::row_body(
                            &note,
                            &content::Body {
                                media,
                                quotes,
                                profiles,
                                emoji: content::body_parse(&note).emoji.clone(),
                            },
                            &handle,
                            cards,
                        )),
                )
                .child(actions::action_row(
                    &inner_id,
                    &inner_ev,
                    actions::ActionState {
                        liked: engaged,
                        reposted: shared,
                        bookmarked: saved,
                        zapped,
                        zapping,
                        wallet_ready: eng.wallet_ready,
                        picker_open: eng.reaction_picker.as_deref() == Some(&inner_id),
                        replies,
                        reduced_motion,
                    },
                    handle,
                ))
        },
    )
}

/// The reply-context whisper: `↳ replying to Name — snippet…`, clickable to
/// the parent's thread. None for non-replies (nip10: quotes/mentions don't
/// count). The name resolves through the same profile map as the header.
fn reply_whisper(
    idx: usize,
    ev: &Event,
    parents: &HashMap<String, ParentNote>,
    profiles: &HashMap<String, Profile>,
    handle: &Entity<Feed>,
) -> Option<gpui::AnyElement> {
    // Replies are a kind-1 concern; articles/highlights carry their own
    // context headers and comment parents are NIP-22 (not on this feed).
    if u16::from(ev.kind) != 1 {
        return None;
    }
    let (parent_id, _relays) = nip10::reply_parent(ev)?;
    let parent = parents.get(&parent_id);
    // The name waits for the parent author's profile (the Parents event
    // hydrates it — see on_event); while it's away the whisper stays
    // quiet "↳ reply" — raw hex was never text anyone reads.
    let name = parent
        .as_ref()
        .and_then(|p| profiles.get(&p.author))
        .map(|pr| pr.display());
    let snippet = parent.and_then(|p| (!p.snippet.is_empty()).then(|| p.snippet.clone()));
    let parent_for_open = parent_id.clone();
    let handle = handle.clone();
    Some(
        div()
            // NOT "reply-{idx}": the action row's reply button owns that id
            // one sibling away, and two elements sharing an id path clobber
            // each other's interaction state — the owner's reply clicks
            // died exactly here (only reply cards have a whisper).
            .id(SharedString::from(format!("parent-{idx}")))
            .cursor_pointer()
            .pl(px(36.0)) // under the note's avatar column
            .flex()
            .flex_col()
            .gap_0p5()
            .on_click(move |_, _, cx| {
                let id = parent_for_open.clone();
                handle.update(cx, |_feed, cx| {
                    if let Ok(event_id) = EventId::from_hex(&id) {
                        cx.emit(Nav::OpenThread(event_id));
                    }
                });
            })
            // Two voices, no box: the addressed name in ink, the parent's
            // words in serif italic beneath — the quoted speaker gets their
            // own texture (sumi-e: whitespace and weight, not rules).
            .children({
                let mut rows: Vec<gpui::AnyElement> = Vec::new();
                match &name {
                    Some(name) => rows.push(
                        div()
                            .text_size(px(theme::T_SMALL))
                            .font_weight(FontWeight::SEMIBOLD)
                            .text_color(rgb(theme::ink()))
                            .child(format!("↳ replying to {name}"))
                            .into_any_element(),
                    ),
                    None => rows.push(
                        div()
                            .text_size(px(theme::T_SMALL))
                            .text_color(rgb(theme::muted()))
                            .child("↳ reply")
                            .into_any_element(),
                    ),
                }
                if let Some(snippet) = snippet {
                    // Even before the name lands, the parent's own words
                    // are worth their line.
                    rows.push(
                        div()
                            .font_family(theme::SERIF)
                            .italic()
                            .text_size(px(theme::T_UI))
                            .text_color(rgb(theme::muted()))
                            .child(snippet.clone())
                            .into_any_element(),
                    );
                }
                rows
            })
            .into_any_element(),
    )
}

/// The list's last row: the round-trip note while paging, the caught-up seal
/// when the relays remember nothing older (the GTK app's caught_up box), and
/// nothing visible while more pages wait quietly. The seal wears a short
/// hairline — the boundary is felt, not announced.
fn end_cap(paging: bool, more: bool) -> Div {
    let words = if paging {
        "… fetching older posts"
    } else if more {
        ""
    } else {
        "Caught up."
    };
    let mut cap = div()
        .w_full()
        .py_4()
        .flex()
        .flex_col()
        .items_center()
        .gap_2();
    if !words.is_empty() {
        cap = cap
            .child(
                div()
                    .w(px(48.))
                    .border_t_1()
                    .border_color(rgb(theme::hairline())),
            )
            .child(
                div()
                    .font_family(theme::SERIF)
                    .text_size(px(theme::T_UI))
                    .line_height(relative(1.2))
                    .text_color(rgb(theme::muted()))
                    .child(words.to_string()),
            );
    }
    cap
}

/// The window decision, pure for the tests: the index to truncate the
/// timeline to, or None while it's under the ceiling — or while the reader
/// sits too close to the trim line (their anchor row must stay above the
/// removed range, or the splice would yank them).
///
/// CEIL/KEEP: the window oscillates 1000 → 400 notes (~KB each; the snap
/// rebuild clones it). MARGIN: a wheel tick past the trigger can't shrink
/// the visible range retroactively — 80 rows of headroom is generous.
fn trim_target(len: usize, visible_end: usize) -> Option<usize> {
    const CEIL: usize = 1000;
    const KEEP: usize = 400;
    const MARGIN: usize = 80;
    if len <= CEIL {
        return None;
    }
    let to = len - KEEP;
    (visible_end + MARGIN <= to).then_some(to)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::og;
    use satori_core::media::LinkPreview;

    fn ev_with(content: &str) -> Event {
        use nostr::prelude::*;
        let keys = Keys::generate();
        let unsigned = UnsignedEvent::new(
            keys.public_key(),
            Timestamp::from_secs(1),
            Kind::TextNote,
            [],
            content.to_string(),
        );
        keys.sign_event(unsigned).unwrap()
    }

    /// The disappearing-image regression (owner, Nov 2026): the og card
    /// paints `preview.image`, a URL NO view's re-request sweep knew — so
    /// once the RAM cache evicted the bytes, nothing ever asked again and
    /// the card's thumbnail went dark for the session. The invariant: a
    /// landed preview's image rides the same sweep every other painted
    /// picture rides (card_media_urls feeds both the feed's item-closure
    /// re-request and pin_window's pin set).
    #[test]
    fn landed_og_image_rides_the_sweep_set() {
        let ev = ev_with("read this\n\nhttps://ex.example/page");
        let image = "https://img.example/thumb.png";
        og::seed_test_preview(
            "https://ex.example/page",
            LinkPreview {
                site: "ex.example".into(),
                title: "A page".into(),
                description: None,
                image: Some(image.to_string()),
            },
        );
        let urls = card_media_urls(&ev, &HashMap::new());
        assert!(
            urls.iter().any(|u| u == image),
            "the landed og:image must ride the visible sweep: {urls:?}"
        );
    }

    #[test]
    fn window_stays_while_under_the_ceiling() {
        assert_eq!(trim_target(0, 0), None);
        assert_eq!(trim_target(999, 998), None);
        assert_eq!(trim_target(1000, 999), None);
    }

    #[test]
    fn window_trims_only_when_the_reader_is_clear_of_the_line() {
        // At the top (or anywhere below row 720): 1200 - 400 = 800.
        assert_eq!(trim_target(1200, 0), Some(800));
        // Exactly at the margin's edge (720 + 80 = 800): still clear.
        assert_eq!(trim_target(1200, 720), Some(800));
        // Deep reader — no trim, or the anchor would cross the range.
        assert_eq!(trim_target(1200, 721), None);
        assert_eq!(trim_target(1200, 1199), None);
    }
}
