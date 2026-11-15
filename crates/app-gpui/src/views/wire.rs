//! Wire — the live-wire relay column (D68's kind expansion): ONE relay,
//! subscribed directly (manager::subscribe_relay_wire, live-wire v1 — the
//! owner's call). Notes and long-form arrive since launch only: no
//! history, the column starts empty and fills with what the relay pushes
//! while it's open. Newest-first, bounded buffer. The receiver's lifetime
//! IS the subscription: the pump task exits when the view does (update
//! failing), the core task notices on its next send or idle tick and
//! unsubscribes — a closed column stops paying for its socket.

use std::{
    collections::{HashMap, HashSet, VecDeque},
    sync::Arc,
};

use gpui::{
    Context, Entity, EventEmitter, ListAlignment, ListOffset, ListScrollEvent, ListState, Render,
    SharedString, Window, div, list, prelude::*, px, rgb,
};
use nostr::prelude::*;
use satori_core::manager::{Core, FeedEvent, Profile};

use super::{actions, content, engagement, nav, nav::Nav, quotes, states};
use crate::{media, theme};

/// The newest-first buffer's cap: a busy relay can outpace reading; the
/// oldest notes drop past this.
const WIRE_CAP: usize = 200;
/// The author mirror's cap (FIFO by first sight): a relay firehose meets
/// far more authors than the home feed, and nothing else bounded this —
/// the audit's memory lens. Evicted authors re-resolve on the next note.
const PROFILE_CAP: usize = 2000;
/// The quote-mirror's cap (FIFO by first sight, the content.rs memo
/// convention): dropped rows leave their embeds behind otherwise, and
/// the wire's ingest rate is relay-paced.
const QUOTES_CAP: usize = 4096;
/// The in-flight author ledger's bound (the audit's memory lens).
const PENDING_CAP: usize = 1024;

/// The render snapshot (feed.rs's FeedSnap discipline, verbatim): the
/// list closures are 'static, so they capture THIS instead of cloning
/// the maps per render. Rebuilt only when `snap_dirty` — data changes,
/// not frames.
#[derive(Clone)]
struct WireSnap {
    rows: Arc<Vec<Arc<Event>>>,
    profiles: Arc<HashMap<String, Profile>>,
    quotes: Arc<content::Quotes>,
    engagement: Arc<engagement::Engagement>,
}

pub struct WireView {
    core: Arc<Core>,
    /// The relay this wire listens to (the status whisper's host).
    relay: String,
    rows: Vec<Arc<Event>>,
    profiles: HashMap<String, Profile>,
    /// First-sight ledger for the profile eviction (FIFO, seen.rs's
    /// convention).
    profiles_order: VecDeque<String>,
    /// Authors with a fetch in flight: one ask per author, ever in
    /// flight — a never-resolving kind-0 must not re-fire per note.
    /// FIFO-capped like its siblings (the audit's memory lens: a
    /// never-resolving author used to hold its hex for the view's
    /// lifetime; the firehose grows those fast). Re-asking an evicted
    /// author is harmless — one refetch.
    pending: HashSet<String>,
    pending_order: VecDeque<String>,
    quotes: content::Quotes,
    quotes_order: VecDeque<String>,
    engagement: engagement::Engagement,
    /// The quiet status whisper (the failure voice).
    status: String,
    list: ListState,
    deep: bool,
    /// The render snapshot rebuilds on the next render after this.
    snap_dirty: bool,
    snap: Option<WireSnap>,
}

impl EventEmitter<Nav> for WireView {}

impl WireView {
    pub fn new(core: Arc<Core>, relay: String, cx: &mut Context<Self>) -> Self {
        crate::theme::watch(cx); // repaint on theme change
        crate::timefmt::watch(cx); // repaint on mode/height change
        crate::video::watch(cx); // repaint on player open/toggle/close
        let engagement = engagement::Engagement::new(&core);
        let mut view = Self {
            core,
            relay,
            rows: vec![],
            profiles: HashMap::new(),
            profiles_order: VecDeque::new(),
            pending: HashSet::new(),
            pending_order: VecDeque::new(),
            quotes: HashMap::new(),
            quotes_order: VecDeque::new(),
            engagement,
            status: states::loading("Listening…"),
            list: ListState::new(0, ListAlignment::Top, px(400.)),
            deep: false,
            snap_dirty: true,
            snap: None,
        };
        view.pump(cx);
        // Deep-scroll whisper: notifications.rs's shape — emit on change
        // only; the shell's floating back-to-top covers this pane too.
        let this = cx.entity().downgrade();
        view.list
            .set_scroll_handler(move |ev: &ListScrollEvent, _w, cx| {
                let _ = this.update(cx, |n, cx| {
                    let deep = ev.visible_range.start >= nav::PANE_DEEP_AT;
                    if n.deep != deep {
                        n.deep = deep;
                        cx.emit(Nav::PaneDeep);
                    }
                });
            });
        // The wallet broadcast (D20): the rows' bolts follow every zap.
        engagement::pump_wallet(&view.core, &cx.entity(), cx);
        view
    }

    /// Back to the top (rail re-click, the floating whisper).
    pub fn scroll_top(&mut self) {
        self.deep = false;
        self.list.scroll_to(ListOffset {
            item_ix: 0,
            offset_in_item: px(0.),
        });
    }

    fn pump(&mut self, cx: &mut Context<Self>) {
        let mut rx = self.core.subscribe_relay_wire(self.relay.clone());
        cx.spawn(async move |this, cx| {
            // Lagged (the buffer outran us) skips ahead, not out: the wire
            // is a live feed, the missed notes are gone by choice.
            loop {
                match rx.recv().await {
                    Ok(ev) => {
                        // Batch-drain the backlog: one reset, one repaint
                        // per burst, not per note (a busy relay would
                        // otherwise re-measure the list and deep-clone
                        // the snapshot ten times for ten notes). The
                        // update FAILING is the pump's exit — the view
                        // is gone, and holding rx any longer would pin
                        // the relay subscription open (the ghost-pump
                        // bug the audit caught: engagement.rs pump_wallet
                        // is the house shape).
                        let mut batch = vec![ev];
                        while let Ok(more) = rx.try_recv() {
                            batch.push(more);
                        }
                        if this
                            .update(cx, |this, cx| this.on_notes(batch, cx))
                            .is_err()
                        {
                            break;
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(_) => break,
                }
            }
        })
        .detach();
    }

    fn on_notes(&mut self, notes: Vec<Event>, cx: &mut Context<Self>) {
        self.status.clear();
        self.snap_dirty = true;
        let mut unknown: Vec<PublicKey> = Vec::new();
        for ev in notes {
            // The og: keys are NOT fetched here (audit system-usage #1):
            // on_notes runs per firehose batch — previewing every link the
            // relays push at us is third-party contact at the attacker's
            // posting rate (a crafted note stream induces arbitrary-origin
            // fetches per second). The wire pane is a live monitor: rows
            // scroll by in seconds, and it keeps its links as bare rows —
            // no preview cards.
            for url in content::media_urls_cached(&ev).iter().cloned() {
                if url.starts_with("og:") {
                    continue;
                }
                media::fetch(&self.core, url, cx.entity_id(), cx);
            }
            // Ledger the refs want_quotes is about to add (new keys only),
            // then the FIFO trim can evict in insertion order.
            for bech in content::note_refs(&ev) {
                if !self.quotes.contains_key(&bech) {
                    self.quotes_order.push_back(bech);
                }
            }
            quotes::want_quotes(self, &ev, cx);
            content::fifo_trim(&mut self.quotes, &mut self.quotes_order, QUOTES_CAP);
            let pk = ev.pubkey;
            self.rows.insert(0, Arc::new(ev));
            let hex = pk.to_string();
            if !self.profiles.contains_key(&hex) && self.pending.insert(hex.clone()) {
                self.pending_order.push_back(hex);
                // FIFO by first ask: the set must not grow with the
                // relay's count of never-resolving authors.
                while self.pending_order.len() > PENDING_CAP
                    && let Some(old) = self.pending_order.pop_front()
                {
                    self.pending.remove(&old);
                }
                unknown.push(pk);
            }
        }
        self.rows.truncate(WIRE_CAP);
        self.list.reset(self.rows.len());
        // The authors' faces: ONE pump per batch (per-author pumps had
        // been ratcheting with the firehose), and the pending set keeps
        // a never-resolving author from re-firing on every note.
        if !unknown.is_empty() {
            let mut rx = self.core.ensure_profiles(unknown);
            cx.spawn(async move |this, cx| {
                while let Some(fe) = rx.recv().await {
                    // A failed update ends the pump with the view.
                    if this
                        .update(cx, |this, cx| this.on_profiles(fe, cx))
                        .is_err()
                    {
                        break;
                    }
                }
            })
            .detach();
        }
        cx.notify();
    }

    fn on_profiles(&mut self, fe: FeedEvent, cx: &mut Context<Self>) {
        if let FeedEvent::Profiles(profs) = fe {
            for p in profs {
                let hex = p.pubkey.clone();
                self.pending.remove(&hex);
                if let Some(pos) = self.pending_order.iter().position(|h| *h == hex) {
                    self.pending_order.remove(pos);
                }
                if self.profiles.insert(hex.clone(), p).is_none() {
                    self.profiles_order.push_back(hex);
                }
            }
            // FIFO by first sight: the map must not grow with the
            // relay's author count (the audit's memory lens).
            content::fifo_trim(&mut self.profiles, &mut self.profiles_order, PROFILE_CAP);
            self.snap_dirty = true;
            cx.notify();
        }
    }
}

impl actions::ActionHost for WireView {
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

impl engagement::Host for WireView {
    fn engagement(&mut self) -> &mut engagement::Engagement {
        &mut self.engagement
    }
    fn core(&self) -> &Arc<Core> {
        &self.core
    }
    fn whisper(&mut self, msg: String) {
        self.status = msg;
    }
    /// The snapshot invalidation: engagement toggles AND quote landings
    /// both arrive through here (quotes.rs:67, pump_wallet's tail).
    fn touched(&mut self) {
        self.snap_dirty = true;
    }
}

impl quotes::Host for WireView {
    fn quotes(&mut self) -> &mut content::Quotes {
        &mut self.quotes
    }
    fn core(&self) -> &Arc<Core> {
        &self.core
    }
    fn profiles(&self) -> &HashMap<String, Profile> {
        &self.profiles
    }
    /// Re-ledger an embed that landed after its reservation was evicted
    /// (the audit's memory lens): back onto the order queue, so the next
    /// trim can evict it again — otherwise it sat outside the cap for
    /// the view's lifetime, one owned Event per occurrence.
    fn quote_landed(&mut self, bech: &str) {
        if !self.quotes_order.iter().any(|b| b == bech) {
            self.quotes_order.push_back(bech.to_string());
        }
    }
}

/// A wire row: the actor header, the note's body (kind 1) or the
/// article's title + summary card (kind 30023), the timeline's action
/// row beneath (notifications.rs's one-row rule: the row IS a note).
#[allow(clippy::too_many_arguments)]
fn wire_card(
    idx: usize,
    ev: &Arc<Event>,
    st: actions::ActionState,
    profiles: &HashMap<String, Profile>,
    media_snap: &media::Snapshot,
    quotes: &content::Quotes,
    time: String,
    handle: Entity<WireView>,
) -> gpui::AnyElement {
    let key = ev.pubkey.to_string();
    let name = content::display_name(profiles.get(&key), &key);
    let picture = profiles
        .get(&key)
        .map(|p| p.picture.clone())
        .unwrap_or_default();
    let mut row = div()
        .w_full()
        .flex()
        .flex_col()
        .gap_2()
        .px_4()
        .py_3()
        .child(content::actor_header(
            None,
            media_snap,
            &picture,
            name,
            None,
            time,
            format!("wire-{idx}"),
            Some(ev.pubkey),
            Some(satori_core::nip::nip19::uri(ev)),
            handle.clone(),
        ));
    let id_hex = ev.id.to_string();
    match u16::from(ev.kind) {
        // The article card: serif title + summary, the reader opens on
        // the click (cards.rs article_card's compact shape — same
        // summary rule, one kernel). The title is capped: a relay's
        // title tag is attacker-written and this renders unthrottled.
        30023 => {
            const TITLE_CAP: usize = 200;
            let data = content::article_data_cached(ev);
            let title = data
                .as_ref()
                .map(|d| d.title.chars().take(TITLE_CAP).collect::<String>())
                .unwrap_or_else(|| "Article".into());
            let summary = data
                .as_ref()
                .map(|d| content::article_summary(d, &ev.content))
                .unwrap_or_default();
            let ev_open = (**ev).clone();
            let handle_open = handle.clone();
            row = row.child(
                div()
                    .id(SharedString::from(format!("wire-open-{idx}")))
                    .cursor_pointer()
                    .flex()
                    .flex_col()
                    .gap_1()
                    .on_click(move |_, _, cx| {
                        let ev = ev_open.clone();
                        handle_open.update(cx, |_, cx| cx.emit(Nav::OpenArticle(ev)));
                    })
                    .child(
                        div()
                            .font_family(theme::SERIF)
                            .text_size(px(theme::T_UI + 3.0))
                            .text_color(rgb(theme::ink()))
                            .child(title),
                    )
                    .when(!summary.is_empty(), |d| {
                        d.child(
                            div()
                                .text_size(px(theme::T_UI))
                                .text_color(rgb(theme::muted()))
                                .child(summary),
                        )
                    }),
            );
        }
        // The note itself: the body pipeline (quotes, media, emoji), the
        // click opens its thread.
        _ => {
            let emoji = content::body_parse(ev).emoji.clone();
            let ctx = content::Body {
                media: media_snap,
                quotes,
                profiles,
                emoji,
            };
            let target = ev.id;
            let handle_body = handle.clone();
            row = row.child(
                div()
                    .id(SharedString::from(format!("wire-open-{idx}")))
                    .child(content::body(ev, &ctx, handle.clone()))
                    .cursor_pointer()
                    .on_click(move |_, _, cx| {
                        handle_body.update(cx, |_, cx| cx.emit(Nav::OpenThread(target)));
                    }),
            );
        }
    }
    row.child(actions::action_row(&id_hex, ev, st, handle))
        .into_any_element()
}

impl Render for WireView {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let handle = cx.entity();
        let status = self.status.clone();
        let media_snap = media::Snapshot::new(cx);
        // The snapshot rebuilds on data change only (feed.rs's
        // snap_dirty discipline): the wire re-renders per arriving note
        // and per media landing, and the maps must not deep-clone for
        // every one of those frames.
        if self.snap_dirty || self.snap.is_none() {
            self.snap = Some(WireSnap {
                rows: Arc::new(self.rows.clone()),
                profiles: Arc::new(self.profiles.clone()),
                quotes: Arc::new(self.quotes.clone()),
                engagement: Arc::new(self.engagement.clone()),
            });
            self.snap_dirty = false;
        }
        let snap = self.snap.as_ref().unwrap().clone();
        let empty = snap.rows.is_empty();
        let host = self.relay.clone();
        let reduced_motion = actions::reduced_motion(cx);
        let core = self.core.clone();

        div()
            .flex_1()
            .min_h_0()
            .overflow_hidden()
            .bg(rgb(theme::washi()))
            .text_color(rgb(theme::ink()))
            .font_family(theme::SANS)
            .flex()
            .flex_col()
            .child(
                div()
                    .flex_1()
                    .min_h_0()
                    .flex()
                    .justify_center()
                    .child(if empty {
                        div()
                            .w_full()
                            .max_w(px(content::COL_W))
                            .p_8()
                            .text_color(rgb(theme::muted()))
                            .child(if status.is_empty() {
                                format!("Listening to {host}… nothing has arrived yet.")
                            } else {
                                status
                            })
                            .into_any_element()
                    } else {
                        list(self.list.clone(), move |idx, _w, cx| {
                            match snap.rows.get(idx) {
                                Some(ev) => {
                                    // Evicted media comes back on render —
                                    // on_notes only fetches at ARRIVAL, so a
                                    // wire row's avatar (and any picture tile)
                                    // whose bytes the cache dropped under
                                    // pressure used to go dark forever (the
                                    // disappearing-image class; feed.rs's
                                    // item closure is the same backstop). No
                                    // og: keys — the wire never fetches
                                    // previews (on_notes's doc). fetch is a
                                    // silent no-op for entries the cache
                                    // holds; only a landing notifies.
                                    if let Some(p) = snap.profiles.get(&ev.pubkey.to_string())
                                        && !p.picture.is_empty()
                                    {
                                        media::fetch(
                                            &core,
                                            p.picture.clone(),
                                            handle.entity_id(),
                                            cx,
                                        );
                                    }
                                    for u in content::media_urls_cached(ev).iter().cloned() {
                                        if !u.is_empty() && !u.starts_with("og:") {
                                            media::fetch(&core, u, handle.entity_id(), cx);
                                        }
                                    }
                                    let secs = ev.created_at.as_secs();
                                    let time = crate::timefmt::stamp(secs, cx);
                                    crate::timefmt::ensure(secs, cx);
                                    let st = snap.engagement.action_state(
                                        &ev.id.to_string(),
                                        0,
                                        reduced_motion,
                                    );
                                    wire_card(
                                        idx,
                                        ev,
                                        st,
                                        &snap.profiles,
                                        &media_snap,
                                        &snap.quotes,
                                        time,
                                        handle.clone(),
                                    )
                                }
                                None => div().into_any_element(),
                            }
                        })
                        .into_any_element()
                    }),
            )
    }
}
