//! Notifications — port of crates/app/src/notifications.rs (and
//! src/routes/notifications.ts): replies + mentions newest-first as compact
//! cards, mark-seen on open, the New/Earlier split at the pre-visit
//! high-water, "Nothing new. Sit quietly." when empty. The header bell dot
//! polls every 90s from the shell (shell.rs poll_notif).

use std::{collections::HashMap, sync::Arc};

use std::collections::HashSet;

use super::content::fifo_trim;

use gpui::{
    Context, Entity, EventEmitter, FontWeight, ListAlignment, ListOffset, ListScrollEvent,
    ListState, Render, SharedString, Window, div, img, list, prelude::*, px, rgb,
};
use nostr::prelude::*;
use satori_core::manager::{Core, FeedEvent, ParentNote, Profile};
use satori_core::nip::{comment, nip10};
use satori_core::notifications::parse_zap_receipt;

use super::{actions, content, engagement, nav, nav::Nav, quotes, states};
use crate::{icons, media, theme};

/// What the event did to you (notifications.ts `add`): a comment is always
/// a reply; kind 1 splits by whether it carries an `e` tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NotifType {
    Reply,
    Mention,
    Reaction,
    Repost,
    Quote,
    PollVote,
    Zap,
}

impl NotifType {
    /// Chip order (the strip's left-to-right): conversational first,
    /// money last.
    const ALL: [NotifType; 7] = [
        Self::Reply,
        Self::Mention,
        Self::Reaction,
        Self::Repost,
        Self::Quote,
        Self::PollVote,
        Self::Zap,
    ];
}

fn notif_type(ev: &Event) -> NotifType {
    match u16::from(ev.kind) {
        9735 => NotifType::Zap,
        7 => NotifType::Reaction,
        6 | 16 => NotifType::Repost,
        1018 => NotifType::PollVote,
        _ => {
            // NIP-18: a `q` tag quotes a note without replying into its
            // thread — a quote repost of one of mine. `e` stays the reply
            // marker: a note that both replies and quotes is a reply.
            let has = |tag: &str| {
                ev.tags
                    .iter()
                    .any(|t| t.as_slice().first().map(String::as_str) == Some(tag))
            };
            if has("e") {
                NotifType::Reply
            } else if has("q") {
                NotifType::Quote
            } else {
                NotifType::Mention
            }
        }
    }
}

/// The strip's timeframe dropdown: chips AND rows scope to it, so a
/// chip's count and its tap's row list agree by construction (client
/// counts over the same classified rows — relay COUNT can't see the
/// gates: WoT tier, mutes, the per-class caps, quote classification).
/// The choice persists in prefs.json — local chrome, not NIP-78 sync.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NotifWindow {
    Hours24,
    Days7,
    Days30,
}

impl NotifWindow {
    const ALL: [NotifWindow; 3] = [Self::Hours24, Self::Days7, Self::Days30];

    fn label(self) -> &'static str {
        match self {
            Self::Hours24 => "24h",
            Self::Days7 => "7d",
            Self::Days30 => "30d",
        }
    }

    fn secs(self) -> u64 {
        match self {
            Self::Hours24 => 86400,
            Self::Days7 => 7 * 86400,
            Self::Days30 => 30 * 86400,
        }
    }

    fn from_label(s: &str) -> Self {
        match s {
            "24h" => Self::Hours24,
            "30d" => Self::Days30,
            _ => Self::Days7,
        }
    }
}

fn chip_label(t: NotifType) -> &'static str {
    match t {
        NotifType::Reply => "Replies",
        NotifType::Mention => "Mentions",
        NotifType::Reaction => "Reactions",
        NotifType::Repost => "Reposts",
        NotifType::Quote => "Quotes",
        NotifType::PollVote => "Polls",
        NotifType::Zap => "Zaps",
    }
}

/// The verb and, for zaps, the emphasized tail: the amount IS the news
/// (it rides the header line set in ink, next to the actor's name).
///
/// Memoized per event (audit perf: the Zap arm runs a full NIP-44
/// signature verify inside parse_zap_receipt — a pure function of the
/// event, but the item closure used to sweep it per visible row per
/// frame, a millisecond of cryptography on the UI thread for a page of
/// zap receipts). Bounded, oldest-dropped at 4096 events. The verb for
/// everything else is a constant.
fn action_parts(t: NotifType, ev: &Event) -> (&'static str, Option<String>) {
    const CAP: usize = 4096;
    struct PartsMemo {
        map: HashMap<String, (&'static str, Option<String>)>,
        order: std::collections::VecDeque<String>,
    }
    static MEMO: std::sync::OnceLock<std::sync::Mutex<PartsMemo>> = std::sync::OnceLock::new();
    let memo = MEMO.get_or_init(|| {
        std::sync::Mutex::new(PartsMemo {
            map: HashMap::new(),
            order: std::collections::VecDeque::new(),
        })
    });
    let key = ev.id.to_string();
    let mut memo = memo.lock().unwrap();
    if let Some(parts) = memo.map.get(&key) {
        return parts.clone();
    }
    let parts = match t {
        NotifType::Reply => ("replied", None),
        NotifType::Mention => ("mentioned you", None),
        NotifType::Reaction => ("reacted", None),
        NotifType::Repost => ("reposted", None),
        NotifType::Quote => ("quoted your note", None),
        NotifType::PollVote => ("voted in your poll", None),
        NotifType::Zap => {
            let info = parse_zap_receipt(ev);
            if info.sats == 0 {
                ("zapped", None)
            } else {
                ("zapped", Some(format!("{} sats", info.sats)))
            }
        }
    };
    let memo = &mut *memo;
    fifo_trim(&mut memo.map, &mut memo.order, CAP);
    memo.order.push_back(key.clone());
    memo.map.insert(key, parts.clone());
    parts
}

/// One list row: a section label (New / Earlier) or a notification card.
#[derive(Clone)]
enum Row {
    Label(&'static str),
    Note(Event, NotifType),
}

pub struct NotificationsView {
    core: Arc<Core>,
    rows: Vec<Row>,
    /// The chip the reader tapped (tap again to clear): the strip
    /// filters the rows client-side. Counts are client-side too —
    /// computed from the same classified rows the list renders, so a
    /// chip and its tap always agree.
    class_filter: Option<NotifType>,
    /// The strip's timeframe (the dropdown's choice; persists in
    /// prefs.json). Scopes the chips AND the rows.
    window: NotifWindow,
    /// The dropdown open?
    window_open: bool,
    profiles: HashMap<String, Profile>,
    quotes: content::Quotes,
    /// What each notification answers (feed.rs's same resolver): id →
    /// author + snippet. `parents_asked` keeps misses from re-requesting.
    parents: HashMap<String, ParentNote>,
    parents_asked: HashSet<String>,
    me: String,
    status: String,
    /// §4.3: the kinded error strip (replaces "Could not load …: {e}").
    error: Option<states::PaneError>,
    /// The pre-visit high-water this pane was opened with — Retry re-asks
    /// with the same one (the New/Earlier split must not shift on a retry).
    prev: u64,
    /// Deep-scroll state, emitted to the shell (Nav::PaneDeep) so the
    /// floating back-to-top whisper covers this pane too — same shape as
    /// the feed's (feed.rs deep).
    pub(crate) deep: bool,
    /// WS4 receipts: the bell's audit trail open? (the "N hidden, see
    /// why" strip at the pane's bottom, a silent void is a bug).
    receipts_open: bool,
    /// The action-row mirrors (engagement.rs): optimistic glyph states,
    /// reconciled by the wallet broadcast and the publish pumps. The rows
    /// ARE notes (replies + mentions) — #16's one-row rule: the
    /// notifications page carries the timeline's affordances.
    engagement: engagement::Engagement,
    list: ListState,
    /// The scroll stream's visible window: the fetch/pin sweep covers only
    /// these rows (the feed's window discipline — a full-page sweep queued
    /// every row's media through the six-slot gate).
    first_visible_start: usize,
    last_visible_end: usize,
}

impl EventEmitter<Nav> for NotificationsView {}

impl NotificationsView {
    /// Fetched at construction — a GPUI pane is built when shown, so this is
    /// the GTK page's fetch-on-show hook. Opening also marks seen: the
    /// pre-visit high-water splits the page into New / Earlier.
    pub fn new(core: Arc<Core>, cx: &mut Context<Self>) -> Self {
        crate::theme::watch(cx); // repaint on theme change
        crate::timefmt::watch(cx); // repaint on mode/height change
        crate::video::watch(cx); // repaint on player open/toggle/close
        let prev = satori_core::read_state::load().notif;
        core.mark_notifications_seen();
        let engagement = engagement::Engagement::new(&core);
        let view = Self {
            core,
            rows: vec![],
            class_filter: None,
            window: NotifWindow::from_label(
                &crate::prefs::get_string("notifCountWindow").unwrap_or_default(),
            ),
            window_open: false,
            profiles: HashMap::new(),
            quotes: HashMap::new(),
            parents: HashMap::new(),
            parents_asked: HashSet::new(),
            me: String::new(),
            status: states::loading("Gathering…"),
            error: None,
            prev,
            deep: false,
            receipts_open: false,
            engagement,
            list: ListState::new(0, ListAlignment::Top, px(400.)),
            first_visible_start: 0,
            last_visible_end: 0,
        };
        view.pump_at(prev, cx);
        // Deep-scroll whisper: same threshold and emission shape as the
        // feed's (feed.rs set_scroll_handler) — emit on change only. The
        // threshold is shallow (three rows): the button should arrive
        // early, not after the reader has given up looking for it.
        let this = cx.entity().downgrade();
        view.list
            .set_scroll_handler(move |ev: &ListScrollEvent, _w, cx| {
                let _ = this.update(cx, |n, cx| {
                    n.first_visible_start = ev.visible_range.start;
                    n.last_visible_end = ev.visible_range.end;
                    let deep = ev.visible_range.start >= nav::PANE_DEEP_AT;
                    if n.deep != deep {
                        n.deep = deep;
                        cx.emit(Nav::PaneDeep);
                    }
                    // The window moved: re-pin its media (the rows' fetches
                    // ride the item closures).
                    let rows = n.visible_rows();
                    n.pin_window(&rows, cx);
                });
            });
        // The wallet broadcast (D20): the rows' bolts follow every zap,
        // theirs or the sheet's, wherever it started.
        engagement::pump_wallet(&view.core, &cx.entity(), cx);
        view
    }

    /// Back to the top (rail re-click, the floating whisper): home is item
    /// zero (feed.rs scroll_top — no paging anchor to reset here).
    pub fn scroll_top(&mut self) {
        self.deep = false;
        self.list.scroll_to(ListOffset {
            item_ix: 0,
            offset_in_item: px(0.),
        });
    }

    fn pump_at(&self, prev_high_water: u64, cx: &mut Context<Self>) {
        let mut rx = self.core.notifications();
        cx.spawn(async move |this, cx| {
            while let Some(ev) = rx.recv().await {
                let _ = this.update(cx, |this, cx| this.on_event(ev, prev_high_water, cx));
            }
        })
        .detach();
    }

    /// The window's cutoff — rows AND chip tallies scope to this ONE
    /// number. The chip-vs-tap agreement ("a chip's count and its tap's
    /// row list agree by construction") holds only if both sides read
    /// the same cutoff, so it lives here, not at each site.
    fn window_cutoff(&self) -> u64 {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        now.saturating_sub(self.window.secs())
    }

    fn in_window(&self, created: u64, cutoff: u64) -> bool {
        created >= cutoff
    }

    /// The rows after the chip filter (None: all of them). Section
    /// labels survive — a filtered page keeps its New/Earlier rails.
    fn visible_rows(&self) -> Vec<Row> {
        // The window scopes the rows too (the chips count exactly this
        // set): a row older than the cutoff is out, whatever classified
        // it. The class chip filters on top. ONE pass, no intermediate:
        // each surviving row clones once.
        let cutoff = self.window_cutoff();
        let filtered: Vec<&Row> = self
            .rows
            .iter()
            .filter(|r| match r {
                Row::Label(_) => true,
                Row::Note(ev, t) => {
                    self.in_window(ev.created_at.as_secs(), cutoff)
                        && self.class_filter.is_none_or(|f| *t == f)
                }
            })
            .collect();
        // Drop a section label whose notes all filtered out — an orphan
        // "New" header promises rows that aren't there.
        let mut out = Vec::with_capacity(filtered.len());
        for (i, r) in filtered.iter().enumerate() {
            match r {
                Row::Label(_) => {
                    if filtered[i..].iter().any(|q| matches!(q, Row::Note(..))) {
                        out.push((*r).clone());
                    }
                }
                _ => out.push((*r).clone()),
            }
        }
        out
    }

    /// The visible row count WITHOUT cloning the rows (the reset/scroll
    /// sites only need the length).
    fn visible_row_count(&self) -> usize {
        let cutoff = self.window_cutoff();
        self.rows
            .iter()
            .filter(|r| match r {
                Row::Label(_) => true,
                Row::Note(ev, t) => {
                    self.in_window(ev.created_at.as_secs(), cutoff)
                        && self.class_filter.is_none_or(|f| *t == f)
                }
            })
            .count()
    }

    /// Ask the core to resolve the notes these notifications answer
    /// (feed.rs want_parents: store first, one relay round trip for
    /// misses, asked-set keeps it from looping).
    fn want_parents(&mut self, cx: &mut Context<Self>) {
        let mut ids: Vec<String> = Vec::new();
        for row in &self.rows {
            if let Row::Note(ev, _) = row
                && let Some(pid) = notif_parent_id(ev)
                && !self.parents.contains_key(&pid)
                && self.parents_asked.insert(pid.clone())
            {
                ids.push(pid);
            }
        }
        if ids.is_empty() {
            return;
        }
        let mut rx = self.core.load_parents(ids);
        cx.spawn(async move |this, cx| {
            while let Some(ev) = rx.recv().await {
                let _ = this.update(cx, |this, cx| this.on_event(ev, 0, cx));
            }
        })
        .detach();
    }

    fn on_event(&mut self, ev: FeedEvent, prev: u64, cx: &mut Context<Self>) {
        match ev {
            FeedEvent::Notifications(notifs, profiles) => {
                // Each event is a full page — the cached paint, then its
                // UNION with the relay results (a superset: the list only
                // grows, nothing reloads). Rebuild on each; the manager
                // owns the merge. The manager gates the types (kind-1
                // replies, NIP-22 comments, mutes); the view renders
                // whatever that stream vouches for.
                let notifs: Vec<Event> = notifs
                    .into_iter()
                    // Zap receipts have empty content — the label carries
                    // them (parse_zap_receipt does the trust work).
                    .filter(|e| !e.content.trim().is_empty() || u16::from(e.kind) == 9735)
                    .collect();
                for p in profiles {
                    self.profiles.insert(p.pubkey.clone(), p);
                }
                for n in &notifs {
                    self.want_media(n, cx);
                    quotes::want_quotes(self, n, cx);
                }
                self.rows = sectioned(prev, &notifs);
                self.me = self.core.me().unwrap_or_default();
                self.want_parents(cx);
                self.want_receipt_names(cx);
                self.status.clear();
                self.error = None;
            }
            FeedEvent::Parents(p) => {
                // The resolver's answer (store-first, relay for misses) —
                // whispers fill in as these land.
                self.parents.extend(p);
                cx.notify();
            }
            FeedEvent::Failed(e) => {
                // §4.3: transient — Retry re-asks with the same high-water.
                self.error = Some(states::PaneError::transient("Notifications", &e));
            }
            _ => {}
        }
        self.list.reset(self.visible_row_count());
        cx.notify();
    }

    fn want_media(&mut self, note: &Event, cx: &mut Context<Self>) {
        for url in content::media_urls_cached(note).iter().cloned() {
            media::fetch(&self.core, url, cx.entity_id(), cx);
        }
    }

    /// Pin the VISIBLE window's media, release the previous window's (the
    /// feed's pin_window discipline). Called at render (landings) and from
    /// the scroll stream — the two moments the on-screen set changes. The
    /// set is everything the visible rows paint: each row's author avatar
    /// plus the note's own media. The item closures fetch their rows on
    /// scroll (notif_card); this keeps the PIN matching what's on screen so
    /// an idle page survives landing bursts. `visible` is the caller's
    /// already-filtered rows (render computed them for the list; the scroll
    /// handler builds the window itself).
    fn pin_window(&mut self, visible: &[Row], cx: &mut Context<Self>) {
        let win_start = self.first_visible_start.min(visible.len());
        let win_end = self.last_visible_end.max(win_start + 8).min(visible.len());
        let mut painted: Vec<String> = Vec::new();
        for row in visible[win_start..win_end].iter() {
            let Row::Note(ev, _) = row else { continue };
            if let Some(p) = self.profiles.get(&ev.pubkey.to_string())
                && !p.picture.is_empty()
                && !painted.contains(&p.picture)
            {
                painted.push(p.picture.clone());
            }
            for url in content::media_urls_cached(ev).iter().cloned() {
                if !url.is_empty() && !painted.contains(&url) {
                    painted.push(url);
                }
            }
            // The og card's thumbnail paints preview.image — a URL the
            // parse never knew. Re-pin it like any picture (the row's own
            // item closure re-requests it; this set is the pin).
            for url in content::og_image_urls(ev) {
                if !painted.contains(&url) {
                    painted.push(url);
                }
            }
        }
        media::repin(cx.entity_id(), painted, cx);
    }

    /// The tally strip: the timeframe dropdown (scopes chips AND rows)
    /// plus one count chip per class with anything in the window. The
    /// counts are CLIENT-SIDE — computed here from the same classified
    /// rows the list renders, so a chip's number and its tap's row list
    /// agree by construction, instantly, with no network (relay COUNT
    /// can't see the row gates: WoT tier, mutes, the per-class caps —
    /// its numbers would phantom against this list). The dropdown
    /// expands in-flow (no popover, no clip traps) and the choice
    /// persists in prefs.json.
    fn counts_strip(&self, cx: &mut Context<Self>) -> Option<gpui::AnyElement> {
        // Count each class over the WINDOW's rows (the same rows the
        // list shows — visible_rows applies class on top of this). The
        // cutoff comes from the shared fn: chip counts and the tap's row
        // list cannot disagree about the window edge.
        let cutoff = self.window_cutoff();
        let mut tallies = [0usize; 7];
        let mut in_window = 0usize;
        for row in &self.rows {
            let Row::Note(ev, t) = row else { continue };
            if ev.created_at.as_secs() >= cutoff {
                tallies[*t as usize] += 1;
                in_window += 1;
            }
        }
        if in_window == 0 {
            return None;
        }
        // The dropdown button: the selected window's label. Open expands
        // the option menu right below (in the strip's own column — the
        // pane never loses its list to a clip-fighting popover).
        let button = div()
            .id("notif-window-button")
            .cursor_pointer()
            .flex()
            .items_center()
            .gap_1()
            .px_2()
            .py_1()
            .rounded(px(theme::R_EMBED))
            .border_1()
            .border_color(rgb(theme::hairline()))
            .text_size(px(theme::T_SMALL))
            .text_color(rgb(theme::ink()))
            // The clock says "this scopes time" at a glance (the chevron
            // alone read as a sort control).
            .child(icons::clock_icon(theme::muted()))
            .child(format!(
                "{} {}",
                self.window.label(),
                if self.window_open { "▴" } else { "▾" }
            ))
            .on_click(cx.listener(|this, _, _, cx| {
                this.window_open = !this.window_open;
                cx.notify();
            }));
        let menu = self.window_open.then(|| {
            div()
                .flex()
                .flex_col()
                .mt_1()
                .rounded(px(theme::R_EMBED))
                .border_1()
                .border_color(rgb(theme::hairline()))
                .bg(rgb(theme::panel()))
                .overflow_hidden()
                .children(NotifWindow::ALL.map(|w| {
                    let active = self.window == w;
                    div()
                        .id(SharedString::from(format!("notif-window-{}", w.label())))
                        .cursor_pointer()
                        .px_3()
                        .py_1()
                        .text_size(px(theme::T_SMALL))
                        .when(active, |d| {
                            d.bg(rgb(theme::ink())).text_color(rgb(theme::washi()))
                        })
                        .when(!active, |d| d.text_color(rgb(theme::muted())))
                        .child(w.label().to_string())
                        .on_click(cx.listener(move |this, _, _, cx| {
                            this.window_open = false;
                            if this.window != w {
                                this.window = w;
                                crate::prefs::set_string("notifCountWindow", w.label());
                                this.list.reset(this.visible_row_count());
                                this.list.scroll_to(ListOffset {
                                    item_ix: 0,
                                    offset_in_item: px(0.),
                                });
                            }
                            cx.notify();
                        }))
                }))
        });
        let strip = div()
            .flex()
            .flex_col()
            .w_full()
            .max_w(px(content::COL_W))
            .px_4()
            .py_2()
            .child(
                div()
                    .flex()
                    .flex_wrap()
                    .items_center()
                    .gap_2()
                    .child(button)
                    .children(NotifType::ALL.iter().filter_map(|t| {
                        let count = tallies[*t as usize];
                        if count == 0 {
                            return None; // an empty class is not a chip
                        }
                        let label = chip_label(*t);
                        let active = self.class_filter == Some(*t);
                        let chip = div()
                            .id(SharedString::from(format!("notif-chip-{label}")))
                            .cursor_pointer()
                            .px_2()
                            .py_1()
                            .rounded(px(theme::R_EMBED))
                            .border_1()
                            .text_size(px(theme::T_SMALL))
                            .when(active, |d| {
                                d.bg(rgb(theme::ink()))
                                    .text_color(rgb(theme::washi()))
                                    .border_color(rgb(theme::ink()))
                            })
                            .when(!active, |d| {
                                d.border_color(rgb(theme::hairline()))
                                    .text_color(rgb(theme::muted()))
                            })
                            .child(format!("{label} {count}"));
                        Some(chip.on_click(cx.listener(move |this, _, _, cx| {
                            this.class_filter = if this.class_filter == Some(*t) {
                                None
                            } else {
                                Some(*t)
                            };
                            this.list.reset(this.visible_rows().len());
                            this.list.scroll_to(ListOffset {
                                item_ix: 0,
                                offset_in_item: px(0.),
                            });
                            cx.notify();
                        })))
                    })),
            )
            .children(menu)
            .into_any_element();
        Some(strip)
    }

    /// WS4 receipts: resolve the suppressed authors' names so the audit
    /// trail shows who, not a bare npub (one ensure_profiles pump; the
    /// render-side strip reads the same profiles map).
    fn want_receipt_names(&mut self, cx: &mut Context<Self>) {
        let missing: Vec<PublicKey> = self
            .core
            .suppressed_notifications()
            .iter()
            .map(|s| s.event.pubkey)
            .filter(|pk| !self.profiles.contains_key(&pk.to_string()))
            .collect();
        if missing.is_empty() {
            return;
        }
        let mut rx = self.core.ensure_profiles(missing);
        cx.spawn(async move |this, cx| {
            while let Some(ev) = rx.recv().await {
                let _ = this.update(cx, |this, cx| this.on_event(ev, 0, cx));
            }
        })
        .detach();
    }
}

// The quote engine rides the default no-op `touched` (render reads the
// mirror directly).
impl quotes::Host for NotificationsView {
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

/// What this notification answers — the parent id to resolve and whisper
/// about. A mention answers you directly (no parent); a reply points at
/// the note it replies to (nip10.rs reply_parent), a comment at its
/// lowercase-e parent, a zap at the zapped note (profile zaps have no
/// e tag), a poll vote at the poll.
fn notif_parent_id(ev: &Event) -> Option<String> {
    match u16::from(ev.kind) {
        1 => nip10::reply_parent(ev)
            .map(|(id, _)| id)
            .or_else(|| q_tag(ev)),
        1111 => match comment::parse_refs(ev).parent {
            Some(comment::Ref::Event(id)) => Some(id.to_string()),
            // An addressable parent (an article, a picture): the parent
            // key is its coordinate — load_parents resolves it, the
            // whisper's click opens the thread by address.
            parent @ Some(comment::Ref::Address { .. }) => parent.map(|r| r.value()),
            _ => None,
        },
        9735 | 1018 | 16 => ev
            .tags
            .iter()
            .find(|t| t.as_slice().first().map(String::as_str) == Some("e"))
            .and_then(|t| t.as_slice().get(1).cloned()),
        // A kind-6 repost's subject: the e tag when the reposter's client
        // sent one, else the note embedded in the content.
        6 => ev
            .tags
            .iter()
            .find(|t| t.as_slice().first().map(String::as_str) == Some("e"))
            .and_then(|t| t.as_slice().get(1).cloned())
            .or_else(|| content::repost_inner_cached(ev).map(|n| n.id.to_string())),
        _ => None,
    }
}

/// The NIP-18 quote marker: the first `q` tag's event id.
fn q_tag(ev: &Event) -> Option<String> {
    ev.tags
        .iter()
        .find(|t| t.as_slice().first().map(String::as_str) == Some("q"))
        .and_then(|t| t.as_slice().get(1).cloned())
}

/// The row's toggles (actions.rs's state-blind contract): the behavior
/// lives in engagement.rs (the extracted engine; thread.rs's impl was the
/// template). The failure whispers land in the pane's status line.
impl actions::ActionHost for NotificationsView {
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

impl engagement::Host for NotificationsView {
    fn engagement(&mut self) -> &mut engagement::Engagement {
        &mut self.engagement
    }
    fn core(&self) -> &Arc<Core> {
        &self.core
    }
    fn whisper(&mut self, msg: String) {
        self.status = msg;
    }
}

/// The parent reference, the timeline whisper's voice aimed at YOUR
/// things: "↳ on your note" / "↳ on {name}'s note", the parent's words
/// in serif italic beneath, clickable into the parent's thread.
/// Unresolved parents whisper nothing — the pump fills them in.
fn notif_whisper<V: EventEmitter<Nav> + 'static>(
    idx: usize,
    parent_id: &str,
    parents: &HashMap<String, ParentNote>,
    profiles: &HashMap<String, Profile>,
    me: &str,
    handle: Entity<V>,
) -> Option<gpui::AnyElement> {
    let parent = parents.get(parent_id)?;
    let label = if parent.author == me {
        "\u{21b3} on your note".to_string()
    } else {
        let name = content::display_name(profiles.get(&parent.author), &parent.author);
        format!("\u{21b3} on {name}'s note")
    };
    let snippet = (!parent.snippet.is_empty()).then(|| parent.snippet.clone());
    let id = parent_id.to_string();
    Some(
        div()
            .id(SharedString::from(format!("notif-parent-{idx}")))
            .cursor_pointer()
            .pl(px(36.0)) // under the avatar column, like the feed whisper
            .flex()
            .flex_col()
            .gap_0p5()
            .on_click(move |_, _, cx| {
                let id = id.clone();
                handle.update(cx, |_, cx| {
                    // Hex = the parent's event id; a NIP-33 coordinate
                    // ("kind:author:d") = an addressable parent — the
                    // thread opens by address (the NIP-22 door).
                    if let Ok(event_id) = EventId::from_hex(&id) {
                        cx.emit(Nav::OpenThread(event_id));
                    } else if let Some(comment::Ref::Address { kind, author, d }) =
                        comment::Ref::from_coordinate(&id)
                    {
                        cx.emit(Nav::OpenThreadAddr(kind, author, d));
                    }
                });
            })
            .children({
                let mut kids = vec![
                    div()
                        .text_size(px(theme::T_SMALL))
                        .font_weight(FontWeight::SEMIBOLD)
                        .text_color(rgb(theme::ink()))
                        .child(label)
                        .into_any_element(),
                ];
                if let Some(snippet) = snippet {
                    kids.push(
                        // The parent's words read as the note's words: ink
                        // serif at body size, not a faded aside — the
                        // whisper IS the subject of the row.
                        div()
                            .font_family(theme::SERIF)
                            .text_size(px(theme::T_UI + 2.0))
                            .text_color(rgb(theme::ink()))
                            .child(snippet)
                            .into_any_element(),
                    );
                }
                kids
            })
            .into_any_element(),
    )
}

/// A notification row. The action word lives in the body — it's the
/// news, not a timestamp garnish — and the parent whisper above it
/// references what the notification answers (the timeline's trick).
#[allow(clippy::too_many_arguments)]
fn notif_card(
    idx: usize,
    ev: &Event,
    t: NotifType,
    st: actions::ActionState,
    profiles: &HashMap<String, Profile>,
    parents: &HashMap<String, ParentNote>,
    media: &media::Snapshot,
    quotes: &content::Quotes,
    me: &str,
    time: String,
    core: &Arc<Core>,
    cx: &mut gpui::App,
    handle: Entity<NotificationsView>,
) -> gpui::AnyElement {
    let key = ev.pubkey.to_string();
    let name = content::display_name(profiles.get(&key), &key);
    let picture = profiles
        .get(&key)
        .map(|p| p.picture.clone())
        .unwrap_or_default();
    let parent_id = notif_parent_id(ev);
    // Clicking opens the conversation: the parent's thread when there is
    // one (your note's thread, for a reply), else the note itself. A
    // profile zap has no thread to open.
    // The reference links a notice to the thread ROOT, never the immediate
    // parent — a reply-to-a-reply lands in the root's conversation.
    let open: Option<EventId> = satori_core::nip::nip10::reply_root(ev)
        .and_then(|(id, _)| EventId::from_hex(&id).ok())
        .or_else(|| parent_id.as_ref().and_then(|p| EventId::from_hex(p).ok()))
        .or_else(|| matches!(t, NotifType::Reply | NotifType::Mention).then_some(ev.id));
    let ctx = content::Body {
        media,
        quotes,
        profiles,
        emoji: content::body_parse(ev).emoji.clone(),
    };
    // The verb rides the header (the Dark Wisp anatomy): glyph, actor,
    // "name verb", time — one line, the news at a glance. Zap sats set
    // in ink: the amount is the second thing the eye hits.
    let (verb, emph) = action_parts(t, ev);
    let verb_el: gpui::AnyElement = match emph {
        Some(sats) => div()
            .flex()
            .items_center()
            .gap_1()
            .text_size(px(theme::T_UI))
            .text_color(rgb(theme::muted()))
            .child(verb)
            .child(
                div()
                    .text_color(rgb(theme::ink()))
                    .font_weight(FontWeight::SEMIBOLD)
                    .child(sats),
            )
            .into_any_element(),
        None => div()
            .text_size(px(theme::T_UI))
            .text_color(rgb(theme::muted()))
            .child(verb)
            .into_any_element(),
    };

    let mut row = div()
        .w_full()
        .flex()
        .flex_col()
        .gap_2()
        .px_4()
        .py_3()
        .child(content::actor_header(
            Some(glyph_slot(t, ev, media, core, handle.entity_id(), cx)),
            media,
            &picture,
            name,
            Some(verb_el),
            time,
            format!("notif-{idx}"),
            Some(ev.pubkey),
            // No id seal: the header announces an action on some other
            // note — the seal would copy the announcement, not the note.
            None,
            handle.clone(),
        ));
    if let Some(pid) = &parent_id
        && let Some(w) = notif_whisper(idx, pid, parents, profiles, me, handle.clone())
    {
        row = row.child(w);
    }
    // The reaction's content is its glyph (a `+` rendered twice helps
    // nobody); a repost has no content of its own — the whisper below
    // IS the boosted note. Everything else wears its body.
    let has_body = !matches!(t, NotifType::Reaction | NotifType::Repost);
    let handle_body = handle.clone();
    let handle_actions = handle.clone();
    if has_body {
        // The id is unconditional (the click only exists when there is
        // somewhere to go) — both arms stay one type.
        let block = div()
            .id(SharedString::from(format!("notif-open-{idx}")))
            .child(content::body(ev, &ctx, handle_body.clone()));
        let block = match open {
            Some(target) => block.cursor_pointer().on_click(move |_, _, cx| {
                let target = target;
                handle_body.update(cx, |_, cx| cx.emit(Nav::OpenThread(target)));
            }),
            None => block,
        };
        row = row.child(block);
    }
    // The one-row rule (#16): reply, mention and quote rows ARE notes —
    // they wear the timeline's full action row, so the most common
    // response to a notification (a like, a zap) doesn't demand opening
    // the thread. Receipt rows (reactions, zaps, poll votes, reposts)
    // aren't notes; no row for them.
    if !matches!(t, NotifType::Reply | NotifType::Mention | NotifType::Quote) {
        return row.into_any_element();
    }
    let ev_arc = Arc::new(ev.clone());
    row.child(actions::action_row(
        &ev.id.to_string(),
        &ev_arc,
        st,
        handle_actions,
    ))
    .into_any_element()
}

/// The glyph slot leading the actor header: the type's news at a glance.
/// Reactions wear their own content (NIP-30 image when the shortcode
/// resolves through the emoji tags, else the raw emoji); every other
/// type wears a stroke icon. The fixed-width slot keeps the avatar
/// column aligned across types.
fn glyph_slot(
    t: NotifType,
    ev: &Event,
    media: &media::Snapshot,
    core: &Arc<Core>,
    view_id: gpui::EntityId,
    cx: &mut gpui::App,
) -> gpui::AnyElement {
    let glyph: gpui::AnyElement = match t {
        NotifType::Reaction => reaction_glyph(ev, media, core, view_id, cx),
        NotifType::Repost => icons::repost_icon(theme::muted()).into_any_element(),
        NotifType::Quote => icons::quote_icon(theme::muted()).into_any_element(),
        NotifType::Reply => icons::bubble_icon(theme::muted()).into_any_element(),
        NotifType::Mention => icons::at_icon(theme::muted()).into_any_element(),
        NotifType::PollVote => icons::check_icon(theme::muted()).into_any_element(),
        NotifType::Zap => icons::bolt_icon(theme::muted()).into_any_element(),
    };
    div()
        .w(px(24.0))
        .flex_none()
        .flex()
        .justify_center()
        .child(glyph)
        .into_any_element()
}

/// A reaction's own content as the glyph: a NIP-30 `:shortcode:` resolves
/// through the event's emoji tags to an image — fetched through the
/// guarded media pipeline (the text shortcode shows until it lands);
/// anything else renders as-is (the plain emoji most reactions carry).
fn reaction_glyph(
    ev: &Event,
    media: &media::Snapshot,
    core: &Arc<Core>,
    view_id: gpui::EntityId,
    cx: &mut gpui::App,
) -> gpui::AnyElement {
    let raw = ev.content.trim();
    let shortcode = raw
        .strip_prefix(':')
        .and_then(|r| r.strip_suffix(':'))
        .filter(|c| !c.is_empty());
    let url = shortcode.and_then(|code| {
        ev.tags.iter().find_map(|t| {
            let s = t.as_slice();
            (s.first().map(String::as_str) == Some("emoji")
                && s.get(1).map(String::as_str) == Some(code))
            .then(|| s.get(2).cloned())
            .flatten()
        })
    });
    let fallback = || {
        // The color emoji face for emoji runs (theme::EMOJI note): the
        // notification face's fallback chain paints them monochrome.
        let emoji = crate::emoji::is_emoji_run(raw);
        let mut el = div().text_size(px(20.0)).line_height(px(24.0));
        if emoji {
            el = el.font_family(theme::EMOJI);
        }
        el.child(raw.to_string()).into_any_element()
    };
    match url.filter(|u| !u.is_empty()) {
        Some(u) => match media.thumb(&u) {
            Some(png) => img(png).size(px(22.0)).into_any_element(),
            None => {
                media::fetch(core, u, view_id, cx);
                fallback()
            }
        },
        None => fallback(),
    }
}

/// New / Earlier section labels at the high-water boundary
/// (routes/notifications.ts) — only when the page straddles it.
fn sectioned(prev: u64, notifs: &[Event]) -> Vec<Row> {
    let new_count = notifs
        .iter()
        .filter(|n| n.created_at.as_secs() > prev)
        .count();
    let split = (new_count > 0 && new_count < notifs.len()).then_some(new_count);
    notifs
        .iter()
        .enumerate()
        .flat_map(|(i, n)| {
            let label = match split {
                Some(at) if i == at => Some("Earlier"),
                _ if split.is_some() && i == 0 => Some("New"),
                _ => None,
            };
            let label = label.map(Row::Label);
            label
                .into_iter()
                .chain(std::iter::once(Row::Note(n.clone(), notif_type(n))))
                .collect::<Vec<_>>()
        })
        .collect()
}

impl Render for NotificationsView {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let handle = cx.entity();
        let status = self.status.clone();
        let rows = self.visible_rows();
        let profiles = self.profiles.clone();
        let media = media::Snapshot::new(cx);
        // Evicted media comes back on render — a notifications page is
        // bounded content, so sweep everything it paints (thread.rs render,
        // same shape): the rows' authors AND the notes' own media. The
        // sweep matters: want_media only runs at rebuild, and once the
        // cache evicted a note's image under feed-photo pressure NOTHING
        // asked again — the tile went dark mid-session (owner: the image
        // "first loads, then disappears"). fetch is a silent no-op for
        // entries the cache holds; only a landing notifies, so this can't
        // loop a render.
        let viewer = cx.entity_id();
        let _ = viewer;
        // The VISIBLE window only: pin + sweep in one place (pin_window).
        // The item closures fetch their own rows on scroll (notif_card), so
        // this is the landing-time backstop; fetch is a silent no-op for
        // entries the cache holds, so this can't loop a render.
        self.pin_window(&rows, cx);
        let quotes = self.quotes.clone();
        let parents = self.parents.clone();
        let me = self.me.clone();
        // The action row's glyph states, snapshotted per render (feed.rs's
        // FeedSnap discipline, inline — the page is bounded content). One
        // mirror clone seeds the rows' action_state lookups.
        let engagement = Arc::new(self.engagement.clone());
        let reduced_motion = actions::reduced_motion(cx);
        let empty = rows.is_empty();
        // WS4 receipts: the suppressed page (core's last notifications
        // build) — the pane's bottom strip lists each hidden item (author,
        // verdict, reason) with a per-item one-session "show anyway".
        let suppressed = self.core.suppressed_notifications();
        let receipts_open = self.receipts_open;
        let receipts: Vec<(String, String, String, String)> = suppressed
            .iter()
            .map(|s| {
                let key = s.event.pubkey.to_string();
                let name = content::display_name(self.profiles.get(&key), &key);
                (
                    name,
                    action_parts(notif_type(&s.event), &s.event).0.to_string(),
                    s.reason.clone(),
                    key,
                )
            })
            .collect();

        div()
            .flex_1()
            .min_h_0()
            .overflow_hidden()
            .bg(rgb(theme::washi()))
            .text_color(rgb(theme::ink()))
            .font_family(theme::SANS)
            .flex()
            .flex_col()
            // The NIP-45 tally chips: their own strip ABOVE the list (a
            // filter bar reads top-down; the bottom is the receipts')
            // — NOT inside the centering row below (the chips stretched
            // to the pane's full height there, and the list sat beside
            // them in a sliver).
            .children(self.counts_strip(cx))
            .child(
                div()
                    .flex_1()
                    .min_h_0()
                    .flex()
                    .justify_center()
                    // §4.3: the kinded error strip — Retry re-asks with the same
                    // pre-visit high-water.
                    .when_some(self.error.clone(), |d, err| {
                        d.child(div().px_4().py_2().child(states::error_strip(
                            &err,
                            cx.listener(move |this, _, _, cx| {
                                let prev = this.prev;
                                this.error = None;
                                this.pump_at(prev, cx);
                                cx.notify();
                            }),
                            cx.listener(move |this, _, _, cx| {
                                this.error = None;
                                cx.notify();
                            }),
                        )))
                    })
                    .child(if empty {
                        div()
                            .w_full()
                            .max_w(px(content::COL_W))
                            .p_8()
                            .text_color(rgb(theme::muted()))
                            .child(if !self.class_filter.is_some() {
                                if status.is_empty() {
                                    "Nothing new. Sit quietly.".to_string()
                                } else {
                                    status
                                }
                            } else {
                                "Nothing in this filter.".to_string()
                            })
                            .into_any_element()
                    } else {
                        let list_handle = handle.clone();
                        let core = self.core.clone();
                        list(self.list.clone(), move |idx, _w, cx| {
                            match rows.get(idx) {
                                Some(Row::Label(text)) => div()
                                    .w_full()
                                    .max_w(px(content::COL_W))
                                    .px_4()
                                    .pt_3()
                                    .text_size(px(theme::T_SMALL))
                                    .font_family(theme::SERIF)
                                    .text_color(rgb(theme::muted()))
                                    .child(text.to_string())
                                    .into_any_element(),
                                Some(Row::Note(ev, t)) => {
                                    // The stamp reads the current mode +
                                    // blocktime cache per frame; ensure
                                    // refines Block mode from the bridge.
                                    let secs = ev.created_at.as_secs();
                                    let time = crate::timefmt::stamp(secs, cx);
                                    crate::timefmt::ensure(secs, cx);
                                    // Evicted media comes back on render —
                                    // want_media only runs at rebuild, so
                                    // once the cache dropped a row's image
                                    // under feed-photo pressure nothing
                                    // asked again and the tile went dark
                                    // mid-session (the disappearing-image
                                    // class; feed.rs's item closure is the
                                    // same backstop). fetch is a silent
                                    // no-op for entries the cache holds;
                                    // only a landing notifies, so this
                                    // can't loop a render. (pin_window's
                                    // old comment claimed notif_card did
                                    // this — it never did.)
                                    if let Some(p) = profiles.get(&ev.pubkey.to_string())
                                        && !p.picture.is_empty()
                                    {
                                        media::fetch(
                                            &core,
                                            p.picture.clone(),
                                            list_handle.entity_id(),
                                            cx,
                                        );
                                    }
                                    for u in content::media_urls_cached(ev).iter().cloned() {
                                        if !u.is_empty() {
                                            media::fetch(&core, u, list_handle.entity_id(), cx);
                                        }
                                    }
                                    for u in content::og_image_urls(ev) {
                                        media::fetch(&core, u, list_handle.entity_id(), cx);
                                    }
                                    let id_hex = ev.id.to_string();
                                    // The notification IS the reply.
                                    let st = engagement.action_state(&id_hex, 0, reduced_motion);
                                    notif_card(
                                        idx,
                                        ev,
                                        *t,
                                        st,
                                        &profiles,
                                        &parents,
                                        &media,
                                        &quotes,
                                        &me,
                                        time,
                                        &core,
                                        cx,
                                        list_handle.clone(),
                                    )
                                }
                                None => div().into_any_element(),
                            }
                        })
                        .w_full()
                        .max_w(px(content::COL_W))
                        .h_full()
                        .into_any_element()
                    }),
            )
            // WS4 receipts: "N hidden, see why" at the bottom of the pane
            // — the audit trail is the core requirement; a silent void is
            // a bug. Open, it lists every suppressed item (author, verdict,
            // reason) with a per-item one-session "show anyway".
            .when(!suppressed.is_empty(), |d| {
                let mut strip = div()
                    .w_full()
                    .flex_none()
                    .border_t_1()
                    .border_color(rgb(theme::hairline()))
                    .flex()
                    .flex_col()
                    .px_4()
                    .py_2()
                    .child(
                        div()
                            .id("receipts-toggle")
                            .cursor_pointer()
                            .text_size(px(theme::T_SMALL))
                            .text_color(rgb(theme::muted()))
                            .hover(|s| s.text_color(rgb(theme::ink())))
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.receipts_open = !this.receipts_open;
                                cx.notify();
                            }))
                            .child(if receipts_open {
                                format!("{} hidden, close", suppressed.len())
                            } else {
                                format!("{} hidden, see why", suppressed.len())
                            }),
                    );
                if receipts_open {
                    for (i, (name, action, reason, key)) in receipts.iter().enumerate() {
                        let hex = key.clone();
                        strip = strip.child(
                            div()
                                .w_full()
                                .flex()
                                .items_center()
                                .gap_2()
                                .py_0p5()
                                .child(
                                    div()
                                        .text_size(px(theme::T_UI))
                                        .font_weight(FontWeight::SEMIBOLD)
                                        .text_color(rgb(theme::ink()))
                                        .child(name.clone()),
                                )
                                .child(
                                    div()
                                        .flex_1()
                                        .min_w_0()
                                        .text_size(px(theme::T_SMALL))
                                        .text_color(rgb(theme::muted()))
                                        .child(format!("{action} · {reason}")),
                                )
                                .child(
                                    div()
                                        .id(SharedString::from(format!("receipt-show-{i}")))
                                        .cursor_pointer()
                                        .text_size(px(theme::T_SMALL))
                                        .child(theme::pressable(div().child("show anyway")))
                                        .on_click({
                                            let handle = handle.clone();
                                            move |_, _, cx| {
                                                let hex = hex.clone();
                                                handle.update(cx, |view, cx| {
                                                    // One-session exemption: the
                                                    // tier stops gating this author
                                                    // until sign-out; the pane
                                                    // re-asks so the item paints.
                                                    view.core.show_suppressed_author(&hex);
                                                    let prev = view.prev;
                                                    view.pump_at(prev, cx);
                                                    cx.notify();
                                                });
                                            }
                                        }),
                                ),
                        );
                    }
                }
                d.child(strip)
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn note(kind: Kind, tags: Tags, content: &str) -> Event {
        let k = Keys::generate();
        let unsigned = UnsignedEvent::new(
            k.public_key(),
            Timestamp::from_secs(1000),
            kind,
            tags,
            content.to_string(),
        );
        k.sign_event(unsigned).unwrap()
    }

    fn tags_for(kind: &str, id: &EventId) -> Tags {
        let mut tags = Tags::new();
        tags.push(Tag::custom(kind, [id.to_string()]));
        tags
    }

    #[test]
    fn kinds_classify() {
        // Direct kinds.
        assert!(matches!(
            notif_type(&note(Kind::Repost, Tags::new(), "{}")),
            NotifType::Repost
        ));
        assert!(matches!(
            notif_type(&note(Kind::Custom(16), Tags::new(), "")),
            NotifType::Repost
        ));
        assert!(matches!(
            notif_type(&note(Kind::Custom(9735), Tags::new(), "")),
            NotifType::Zap
        ));
        assert!(matches!(
            notif_type(&note(Kind::Reaction, Tags::new(), "+")),
            NotifType::Reaction
        ));
        // kind 1: e is the reply marker, q the quote marker, neither a mention.
        let mine = EventId::from_byte_array([3u8; 32]);
        let mut p = Tags::new();
        p.push(Tag::public_key(Keys::generate().public_key()));
        assert!(matches!(
            notif_type(&note(Kind::TextNote, p, "gm")),
            NotifType::Mention
        ));
        assert!(matches!(
            notif_type(&note(Kind::TextNote, tags_for("e", &mine), "gm")),
            NotifType::Reply
        ));
        assert!(matches!(
            notif_type(&note(Kind::TextNote, tags_for("q", &mine), "gm")),
            NotifType::Quote
        ));
        // A note that both replies and quotes is a reply (e wins).
        let mut eq = tags_for("q", &mine);
        eq.push(Tag::event(mine));
        assert!(matches!(
            notif_type(&note(Kind::TextNote, eq, "gm")),
            NotifType::Reply
        ));
    }

    #[test]
    fn repost_subject_via_tag_or_content() {
        let mine = EventId::from_byte_array([7u8; 32]);
        // The e tag wins when the reposter's client sent one.
        assert_eq!(
            notif_parent_id(&note(Kind::Repost, tags_for("e", &mine), "{}")).as_deref(),
            Some(mine.to_string()).as_deref()
        );
        // Else the boosted note rides in the content.
        let inner = note(Kind::TextNote, Tags::new(), "the words");
        let content = serde_json::to_string(&inner).unwrap();
        assert_eq!(
            notif_parent_id(&note(Kind::Repost, Tags::new(), &content)).as_deref(),
            Some(inner.id.to_string()).as_deref()
        );
        // Quotes point at the quoted note through q.
        assert_eq!(
            notif_parent_id(&note(Kind::TextNote, tags_for("q", &mine), "gm")).as_deref(),
            Some(mine.to_string()).as_deref()
        );
    }
}
