//! The window shell: header + navigation stack over the views.
//!
//! TODO(port): crates/app/src/shell.rs (AdwNavigationSplitView + header bar)
//! and main.rs Escape-to-back — P1. The GTK sidebar collapses for now; the
//! sumi-e header carries back/title until P1's sidebar pass. Escape-to-back is
//! ported as a root key-down listener (gpui actions land with the composer in
//! P2, when there are more keys to bind).

use std::str::FromStr;
use std::sync::Arc;

use gpui::{
    AnyElement, AnyView, App, ClickEvent, Context, Div, DragMoveEvent, Entity, EventEmitter,
    FocusHandle, Focusable, KeyDownEvent, ObjectFit, Render, ScrollHandle, SharedString, Stateful,
    Window, div, img, prelude::*, px, rgb,
};
use nostr::prelude::*;
use satori_core::manager::{Core, FeedEvent, Profile, PublishEvent};

use super::{
    composer::{Composer, Draft, Surface},
    content,
    edit_profile::EditProfileView,
    feed::Feed,
    library::LibraryView,
    nav::Nav,
    notifications::NotificationsView,
    profile::ProfileView,
    reader::ArticleView,
    search::SearchView,
    settings::SettingsView,
    states,
    thread::ThreadView,
    wallet::WalletView,
    wire::WireView,
    zap::ZapSheet,
};
use crate::{icons, input::Input, media, theme};

impl Pane {
    /// Release the pane's media pins (shell.back: the pane is about to
    /// drop — its pin set must drop with it; D60's close path). The
    /// registry is owner-keyed (D62), so the release is the owner key —
    /// urls still pinned by another surface ride on.
    fn release_media(&self, cx: &mut Context<Shell>) {
        let id = match self {
            Pane::Feed(e) | Pane::Articles(e) | Pane::Hashtag(e) => e.entity_id(),
            Pane::Thread(e) => e.entity_id(),
            Pane::Profile(e) => e.entity_id(),
            Pane::Library(e) => e.entity_id(),
            Pane::Notifications(e) => e.entity_id(),
            Pane::Search(e) => e.entity_id(),
            Pane::Article(e) => e.entity_id(),
            Pane::EditProfile(e) => e.entity_id(),
            Pane::Settings(e) => e.entity_id(),
            Pane::Composer(e) => e.entity_id(),
            Pane::Wallet(e) => e.entity_id(),
            Pane::Wire(e) => e.entity_id(),
        };
        media::release(id, cx);
    }
}

#[derive(Clone)]
pub enum Pane {
    Feed(Entity<Feed>),
    /// The articles shelf — a second Feed entity in articles mode.
    Articles(Entity<Feed>),
    /// A hashtag timeline — a third Feed entity in hashtag mode (Phase 2 §4.2).
    Hashtag(Entity<Feed>),
    Thread(Entity<ThreadView>),
    Profile(Entity<ProfileView>),
    /// The profile edit form (D38) — the own-profile header's button.
    EditProfile(Entity<EditProfileView>),
    /// The Library pane (D38): Bookmarks | Drafts | Lists.
    Library(Entity<LibraryView>),
    Notifications(Entity<NotificationsView>),
    Search(Entity<SearchView>),
    Settings(Entity<SettingsView>),
    Article(Entity<ArticleView>),
    Composer(Entity<Composer>),
    /// The NWC wallet connect pane (D20).
    Wallet(Entity<WalletView>),
    /// The live-wire relay column (D68's kind expansion): ONE relay,
    /// subscribed directly, since-launch traffic only.
    Wire(Entity<WireView>),
}

/// The columns workspace's hard cap (D68): six streams is the owner's
/// budget — horizontal scrolling removed the width pressure (PR #73),
/// and six stays well inside the live-receiver and on-screen-pin
/// surface the audits flagged.
const COLUMN_CAP: usize = 6;

/// Per-column width bounds (phase 2 resize): narrower than this a
/// stream is unreadable, wider than this it starves the row.
const COL_MIN_W: f32 = 280.0;
const COL_MAX_W: f32 = 960.0;

/// The drill stack's cap (D67's watch item, closed in D68 phase 3):
/// each stacked pane pins its own notes, quotes and engagement maps
/// for the session; deep nav must not ratchet. Past the cap the
/// OLDEST drill drops (media released with it). The drop is an
/// eviction, not a navigation: back()'s pop semantics (composer
/// draft stash, edit-profile refresh) don't run — a trail deep
/// enough to hit this means twelve panes were left unattended. The
/// base feed (single-pane stack[0]) never drops.
const PANE_CAP: usize = 12;

/// The stream kinds a column can pin (D68): the ambient surfaces, the
/// hashtag stream (phase 2, pinned from the hashtag drill's title row),
/// and the kind expansion (owner call): @user columns (the profile
/// drill's timeline as a Feed in author mode) and live-wire relay
/// columns (one relay, since-launch traffic — v1 of relay columns; the
/// store-attribution version is documented as the "real" one). The
/// parameterized kinds carry their persistence tag: the author's
/// pubkey hex, the relay's URL.
#[derive(Clone, PartialEq)]
enum ColumnKind {
    Feed,
    Articles,
    Notifications,
    Search,
    Hashtag(String),
    Author(PublicKey),
    Relay(String),
}

impl ColumnKind {
    fn label(&self) -> SharedString {
        match self {
            ColumnKind::Feed => "Home".into(),
            ColumnKind::Articles => "Articles".into(),
            ColumnKind::Notifications => "Notifications".into(),
            ColumnKind::Search => "Search".into(),
            ColumnKind::Hashtag(tag) => format!("#{tag}").into(),
            // The author column resolves its label through the profile
            // cache at render (Shell::column_label); the hex is the
            // fallback face.
            ColumnKind::Author(pk) => pk.to_string().into(),
            ColumnKind::Relay(url) => url.into(),
        }
    }

    fn icon(&self, color: u32) -> AnyElement {
        match self {
            ColumnKind::Feed => icons::stream_icon(color).into_any_element(),
            ColumnKind::Articles => icons::article_icon(color).into_any_element(),
            ColumnKind::Notifications => icons::bell_icon(color).into_any_element(),
            ColumnKind::Search => icons::search_icon(color).into_any_element(),
            ColumnKind::Hashtag(_) => icons::hash_icon(color).into_any_element(),
            ColumnKind::Author(_) => icons::at_icon(color).into_any_element(),
            ColumnKind::Relay(_) => icons::wire_icon(color).into_any_element(),
        }
    }

    /// The persistence key (prefs.json `columns.cols[].kind`).
    fn key(&self) -> &'static str {
        match self {
            ColumnKind::Feed => "feed",
            ColumnKind::Articles => "articles",
            ColumnKind::Notifications => "notifications",
            ColumnKind::Search => "search",
            ColumnKind::Hashtag(_) => "hashtag",
            ColumnKind::Author(_) => "author",
            ColumnKind::Relay(_) => "relay",
        }
    }

    /// The parameterized variants' tag (the persistence tag + the dedupe
    /// key): the hashtag's tag, the author's pubkey hex, the relay's URL.
    fn tag(&self) -> Option<String> {
        match self {
            ColumnKind::Hashtag(tag) => Some(tag.clone()),
            ColumnKind::Author(pk) => Some(pk.to_string()),
            ColumnKind::Relay(url) => Some(url.clone()),
            _ => None,
        }
    }

    /// The fixed kinds, menu order — the add-column menu walks this and
    /// offers the ones not already pinned (hashtag pins elsewhere).
    const ALL: [ColumnKind; 4] = [
        ColumnKind::Feed,
        ColumnKind::Articles,
        ColumnKind::Notifications,
        ColumnKind::Search,
    ];
}

/// One pinned column of the workspace (D68): a stream surface living
/// OUTSIDE the navigation stack — its own pane entity, pumping and
/// scrolling independently. Detail views never land here; they stack
/// over the whole workspace (D68's drill-in rule).
struct Column {
    kind: ColumnKind,
    pane: Pane,
    /// Per-column width px (phase 2 drag handle); None = the flexible
    /// default (equal share capped at the reading column).
    width: Option<f32>,
}

/// A column drag's payload (phase 2 reorder): the source index and the
/// header label for the ghost chip.
#[derive(Clone)]
struct ColumnDrag {
    from: usize,
    label: SharedString,
}

/// A width handle drag's payload (phase 2 resize): which column.
#[derive(Clone, Copy)]
struct WidthDrag {
    col: usize,
}

/// The drag ghost: a small labeled chip riding the cursor (phase 2).
struct DragGhost {
    label: SharedString,
}

impl Render for DragGhost {
    fn render(&mut self, _: &mut Window, _: &mut Context<Self>) -> impl IntoElement {
        div()
            .px(px(10.0))
            .py(px(4.0))
            .rounded(px(theme::R_EMBED))
            .border_1()
            .border_color(rgb(theme::vermilion()))
            .bg(rgb(theme::washi()))
            .text_size(px(theme::T_UI))
            .text_color(rgb(theme::ink()))
            .child(self.label.clone())
    }
}

/// Shell-to-root events. The root subscribes at both shell-creation sites
/// (startup session resume and Login::Approved) — today only the sign-out
/// handoff, which swaps the window back to the login doors.
#[derive(Debug)]
pub enum ShellEvent {
    SignedOut,
}

/// State of the shell's undo toast: the held token + its deadline, or the
/// terminal whisper (undone) / sticky error.
struct HoldToast {
    token: u64,
    deadline: std::time::Instant,
    undone: bool,
    err: Option<String>,
}

pub struct Shell {
    core: Arc<Core>,
    focus: FocusHandle,
    /// First render claims keyboard focus for the shell handle — without it
    /// nothing is focused and the N/escape shortcuts are dead until a click.
    focused_once: bool,
    /// Set when a pane was popped: the popped pane's Input may still hold
    /// window focus, dead-keying the shell until the next render refocuses.
    refocus: bool,
    /// The lightbox overlay — full-screen image viewer over any pane
    /// (lightbox.rs: Esc/‹/› keys, click closes).
    lightbox: Option<(Vec<String>, usize)>,
    /// The video overlay (Phase 3) — full-screen player over any pane:
    /// the URL + its imeta mime (the inline gate rode the Nav).
    video_overlay: Option<(String, Option<String>)>,
    /// The zap amount sheet (bolt hold / right-click) — a floating card
    /// over the pane, not a page: zapping never costs you your place.
    zap_overlay: Option<Entity<ZapSheet>>,
    /// The reply sheet (#21) — the COMPOSER in reply mode floating in a
    /// card (its tab strip is already suppressed for replies): the quick
    /// surface carries everything a note compose does — attachments,
    /// alt text, preview, schedule.
    reply_overlay: Option<Entity<Composer>>,
    /// The undo window's floating toast (compose.ts undo-toast): the
    /// composer pops on Held, so the countdown lives HERE, over any pane.
    /// Undone flashes briefly; a Failed error sticks until the next try.
    hold: Option<HoldToast>,
    /// Bell dot: anything newer than the read-state high-water? Polled every
    /// 90s like the GTK shell (poll_notif); cleared when the pane opens.
    notif_unread: bool,
    /// D36's honesty state (research §3.4): pending outbox items — notes
    /// signed and saved but not yet ACKed by any relay. A quiet pill, not
    /// an error (D26's split); the drainer owns the retries.
    outbox_pending: usize,
    /// The rail's live dot left (D56): the failure mode it covered is
    /// either self-healed (the suspend watchdog recycles the sockets) or
    /// discovered at the point of action (publish/zap whispers). The
    /// durable diagnostics live in the settings pane's relay-health rows.
    stack: Vec<Pane>,
    /// The columns workspace (D68): pinned stream surfaces shown while
    /// `columns_on` AND the drill stack is empty. Toggled from the rail
    /// (or `c`); the layout persists in Phase 2.
    columns_on: bool,
    columns: Vec<Column>,
    /// The focused column: owns Esc's target, the j/k feed cursor and
    /// the rail's stream-spot ticking while the workspace is up.
    focused_col: usize,
    /// The add-column menu's open flag (the workspace's + affordance).
    add_menu: bool,
    /// The column a drag is over right now (phase 2 reorder cue): its
    /// header lights vermilion; cleared on drop.
    reorder_over: Option<usize>,
    /// The workspace row's horizontal scroll (the columns keep their
    /// measure and the row scrolls — the owner's amendment to D68's
    /// collapse fork); h/l and focus moves scroll the target in view.
    row_scroll: ScrollHandle,
    /// The + menu's hashtag and relay-URL inputs (the kind expansion):
    /// type a tag or a wss:// URL, tap Add, the column pins.
    tag_input: Entity<Input>,
    relay_input: Entity<Input>,
    /// The signed-in identity: the rail's top mark is the user's avatar
    /// (replacing the ensō as the home glyph).
    me: Option<PublicKey>,
    me_profile: Option<Profile>,
}

impl Shell {
    pub fn new(core: Arc<Core>, cx: &mut Context<Self>) -> Self {
        crate::theme::watch(cx); // repaint on theme change
        crate::video::watch(cx); // repaint on player open/toggle/close
        let feed = cx.new(|cx| Feed::new(core.clone(), cx));
        // The base pane rides the same Nav dispatch as every stacked one
        // (subscribe_nav below) — the hand-written match that used to live
        // here was the forgot-one-copy trap: the next Nav variant would
        // have worked on every pane except the feed. The subscribe is
        // rebuilt below the literal, where `self` methods are borrowable.
        let mut shell = Self {
            core,
            focus: cx.focus_handle(),
            focused_once: false,
            refocus: false,
            lightbox: None,
            video_overlay: None,
            zap_overlay: None,
            reply_overlay: None,
            hold: None,
            notif_unread: false,
            outbox_pending: 0,
            stack: vec![],
            columns_on: false,
            columns: Vec::new(),
            focused_col: 0,
            add_menu: false,
            reorder_over: None,
            row_scroll: ScrollHandle::new(),
            tag_input: cx.new(|cx| Input::single_line("#", cx)),
            relay_input: cx.new(|cx| Input::single_line("wss://…", cx)),
            me: None,
            me_profile: None,
        };
        shell.stack.push(Pane::Feed(feed.clone()));
        // The base pane's Nav dispatch: the same one every stacked pane
        // gets (audit DRY — Shell::new hand-wrote a second copy of this
        // match, the forgot-one-copy trap for the next Nav variant).
        shell.subscribe_nav(&feed, cx);
        // The columns workspace restores at launch (phase 2): a persisted
        // on-layout re-enters the mode with its columns rebuilt — the pane
        // entities are session-local, only the layout persists. The fresh
        // base feed above never renders; it drops.
        let layout = crate::prefs::columns_layout();
        if layout.on && !layout.cols.is_empty() {
            shell.columns_on = true;
            shell.stack.clear();
            for pref in layout.cols.iter().take(COLUMN_CAP) {
                if let Some(col) = shell.column_from_pref(pref, cx) {
                    shell.subscribe_pane(&col.pane, cx);
                    shell.columns.push(col);
                }
            }
            shell.focused_col = 0;
        }
        // The rail avatar: session pubkey synchronously, profile via the
        // usual ensure_profiles pump (name/picture arrive from the store or
        // the relays a beat later).
        shell.me = satori_core::session::load()
            .map(|s| s.pubkey)
            .and_then(|hex| PublicKey::from_str(&hex).ok());
        shell.want_avatar(cx);
        shell.watch_notif(cx);
        shell.outbox_pending = Core::outbox_pending();
        shell
    }

    /// One ensure_profiles pump for the rail avatar. The profiles service
    /// resolves a miss exactly once — and this pump fires at Shell::new, a
    /// beat before the relays connect, so the first ask usually misses.
    /// Retry (2s apart, ~30s ceiling) until the profile lands.
    fn want_avatar(&self, cx: &mut Context<Self>) {
        let Some(me) = self.me else { return };
        let me_hex = me.to_string();
        cx.spawn(async move |this, cx| {
            for _ in 0..15 {
                let mut rx = this
                    .update(cx, |shell, _| shell.core.clone().ensure_profiles(vec![me]))
                    .expect("shell alive");
                // One resolution per ask (the debouncer drops the waiter
                // after its single send); a miss waits out the 2s, retries.
                if let Some(FeedEvent::Profiles(ps)) = rx.recv().await
                    && let Some(p) = ps.into_iter().find(|p| p.pubkey == me_hex)
                {
                    let _ = this.update(cx, |shell, cx| {
                        shell.me_profile = Some(p);
                        cx.notify();
                    });
                    return;
                }
                cx.background_executor()
                    .timer(std::time::Duration::from_secs(2))
                    .await;
            }
        })
        .detach();
    }

    fn subscribe_nav<V: EventEmitter<Nav> + 'static>(
        &self,
        view: &Entity<V>,
        cx: &mut Context<Self>,
    ) {
        cx.subscribe(view, |this, _view, ev: &Nav, cx| match ev {
            Nav::OpenThread(id) => this.open_thread(*id, cx),
            Nav::OpenThreadAddr(kind, who, d) => this.open_thread_addr(*kind, *who, d.clone(), cx),
            Nav::OpenProfile(who) => this.open_profile(*who, cx),
            Nav::OpenEditProfile(me) => this.open_edit_profile(*me, cx),
            Nav::OpenHashtag(tag) => this.open_hashtag(tag.clone(), cx),
            Nav::OpenReply(ev) => this.open_reply_sheet(ev.clone(), cx),
            Nav::OpenDraft(text, attachments, reply, quote) => this.open_draft(
                text,
                attachments.clone(),
                reply.as_deref().cloned(),
                quote.as_deref().cloned(),
                cx,
            ),
            Nav::OpenQuote(ev) => this.open_composer(None, Some(ev.clone()), cx),
            Nav::OpenArticle(ev) => this.open_article(ev.clone(), cx),
            Nav::OpenLightbox(urls, idx) => this.open_lightbox(urls.clone(), *idx, cx),
            Nav::OpenVideo(url, mime) => this.open_video(url.clone(), mime.clone(), cx),
            Nav::OpenZapSheet(ev) => this.open_zap_sheet(ev.clone(), cx),
            Nav::OpenWallet => this.open_wallet(cx),
            Nav::PaneDeep => cx.notify(), // whisper re-reads the pane at render
            Nav::Pop => this.back(cx),
            Nav::SetTheme(dark) => this.set_theme(*dark, cx),
            Nav::SignOut => this.sign_out(cx),
        })
        .detach();
    }

    /// Live palette switch (settings.rs SetTheme): persist the pref,
    /// select, and wake every watching view (theme.rs ThemeSignal).
    fn set_theme(&mut self, dark: bool, cx: &mut Context<Self>) {
        let mut p = crate::prefs::load();
        let changed = p.dark != Some(dark);
        p.dark = Some(dark);
        crate::prefs::save(&p);
        theme::select(if dark { theme::DARK } else { theme::LIGHT });
        cx.set_global(theme::ThemeSignal);
        cx.notify();
        // NIP-78: sync the theme slot (Phase 2 §4.1) — fire and forget.
        if changed {
            crate::prefs::sync(&self.core, "dark", serde_json::Value::Bool(dark));
        }
    }

    /// pub(crate): the NIP-21 seam (main.rs) routes incoming `nostr:` URIs
    /// through the same navigation the in-app taps use.
    pub(crate) fn open_thread(&mut self, id: EventId, cx: &mut Context<Self>) {
        let view = cx.new(|cx| ThreadView::new(self.core.clone(), id, cx));
        self.subscribe_nav(&view, cx);
        self.push_drill(Pane::Thread(view), cx);
    }

    /// The address door (NIP-22): a comment notification on an addressable
    /// parent opens the thread by its coordinate; the anchor lands by
    /// address, and a long-form parent redirects into the reader (the
    /// thread's own landing rule).
    pub(crate) fn open_thread_addr(
        &mut self,
        kind: u16,
        who: PublicKey,
        d: String,
        cx: &mut Context<Self>,
    ) {
        let view = cx.new(|cx| ThreadView::new_addr(self.core.clone(), kind, who, d, cx));
        self.subscribe_nav(&view, cx);
        self.push_drill(Pane::Thread(view), cx);
    }

    pub(crate) fn open_profile(&mut self, who: PublicKey, cx: &mut Context<Self>) {
        let view = cx.new(|cx| ProfileView::new(self.core.clone(), who, self.me == Some(who), cx));
        self.subscribe_nav(&view, cx);
        self.push_drill(Pane::Profile(view), cx);
    }

    /// The profile edit form (D38): the own-profile header's Edit button.
    fn open_edit_profile(&mut self, who: PublicKey, cx: &mut Context<Self>) {
        let view = cx.new(|cx| EditProfileView::new(self.core.clone(), who, cx));
        self.subscribe_nav(&view, cx);
        self.push_drill(Pane::EditProfile(view), cx);
    }

    /// The articles shelf: a second feed entity, kind 30023 from the same
    /// follows. It stacks on the timeline (back returns to it).
    fn open_articles(&mut self, cx: &mut Context<Self>) {
        let view = cx.new(|cx| Feed::articles(self.core.clone(), cx));
        self.subscribe_nav(&view, cx);
        self.push_drill(Pane::Articles(view), cx);
    }

    /// The Library pane (D38): Bookmarks | Drafts | Lists — the user's own
    /// stuff in one place.
    fn open_library(&mut self, cx: &mut Context<Self>) {
        let view = cx.new(|cx| LibraryView::new(self.core.clone(), cx));
        self.subscribe_nav(&view, cx);
        self.push_drill(Pane::Library(view), cx);
    }

    /// Reopen a synced draft (D38): the composer with its context back, the
    /// buffer prefilled over any stash restore.
    fn open_draft(
        &mut self,
        text: &str,
        attachments: Vec<Vec<String>>,
        reply: Option<Event>,
        quote: Option<Event>,
        cx: &mut Context<Self>,
    ) {
        self.open_composer(reply, quote, cx);
        if let Some(Pane::Composer(c)) = self.stack.last().cloned() {
            c.update(cx, |composer, cx| composer.prefill(text, attachments, cx));
        }
    }

    /// The hashtag timeline: a Feed entity in hashtag mode — a #tag tap in
    /// a note body lands here (Phase 2 §4.2).
    fn open_hashtag(&mut self, tag: String, cx: &mut Context<Self>) {
        let view = cx.new(|cx| Feed::hashtag(self.core.clone(), tag, cx));
        self.subscribe_nav(&view, cx);
        self.push_drill(Pane::Hashtag(view), cx);
    }

    fn open_composer(
        &mut self,
        reply_to: Option<Event>,
        quote: Option<Event>,
        cx: &mut Context<Self>,
    ) {
        let view = cx.new(|cx| Composer::new(self.core.clone(), reply_to, quote, cx));
        self.subscribe_nav(&view, cx);
        self.push_drill(Pane::Composer(view), cx);
    }

    pub(crate) fn open_article(&mut self, ev: Event, cx: &mut Context<Self>) {
        let view = cx.new(|cx| ArticleView::new(self.core.clone(), ev, cx));
        self.subscribe_nav(&view, cx);
        self.push_drill(Pane::Article(view), cx);
    }

    /// The zap amount sheet (bolt hold / right-click): a floating card
    /// over the current pane (the overlay layer, like the lightbox) —
    /// zapping keeps you where you were.
    fn open_zap_sheet(&mut self, ev: Event, cx: &mut Context<Self>) {
        let view = cx.new(|cx| ZapSheet::new(self.core.clone(), ev, cx));
        self.subscribe_nav(&view, cx);
        self.zap_overlay = Some(view);
        cx.notify();
    }

    /// The reply sheet (#21): the composer's reply mode floating over the
    /// current pane (the overlay layer, like the zap sheet) — the action
    /// row's bubble opens this, never the compose page.
    fn open_reply_sheet(&mut self, ev: Event, cx: &mut Context<Self>) {
        let view = cx.new(|cx| {
            let mut composer = Composer::new(self.core.clone(), Some(ev), None, cx);
            composer.surface = Surface::Sheet;
            composer
        });
        self.subscribe_nav(&view, cx);
        self.reply_overlay = Some(view);
        cx.notify();
    }

    /// The NWC wallet pane (settings door, or a bolt tap with no wallet).
    fn open_wallet(&mut self, cx: &mut Context<Self>) {
        let view = cx.new(|cx| WalletView::new(self.core.clone(), cx));
        self.subscribe_nav(&view, cx);
        self.push_drill(Pane::Wallet(view), cx);
    }

    fn open_settings(&mut self, cx: &mut Context<Self>) {
        let view = cx.new(|cx| SettingsView::new(self.core.clone(), cx));
        self.subscribe_nav(&view, cx);
        self.push_drill(Pane::Settings(view), cx);
    }

    /// Settings' sign-out row: clear the session + secrets, then hand the
    /// window back to the login doors (Root swaps on SignedOut).
    fn sign_out(&mut self, cx: &mut Context<Self>) {
        self.core.sign_out();
        cx.emit(ShellEvent::SignedOut);
    }

    /// The notifications pane. Opening marks seen (the view constructor does
    /// the read-state advance); the dot goes quiet at once and the next poll
    /// confirms.
    fn open_notifications(&mut self, cx: &mut Context<Self>) {
        let view = cx.new(|cx| NotificationsView::new(self.core.clone(), cx));
        self.subscribe_nav(&view, cx);
        self.notif_unread = false;
        self.push_drill(Pane::Notifications(view), cx);
    }

    fn open_search(&mut self, cx: &mut Context<Self>) {
        let view = cx.new(|cx| SearchView::new(self.core.clone(), cx));
        self.subscribe_nav(&view, cx);
        self.push_drill(Pane::Search(view), cx);
    }

    /// The drill stack's capped push (D67's watch item, closed): past
    /// PANE_CAP the oldest drill drops, media released with it.
    fn push_drill(&mut self, pane: Pane, cx: &mut Context<Self>) {
        if self.stack.len() >= PANE_CAP {
            // Columns mode: the stack holds ONLY drills, so the oldest
            // is stack[0]; single-pane mode keeps the base feed.
            let i = if self.columns_on { 0 } else { 1 };
            let dropped = self.stack.remove(i);
            dropped.release_media(cx);
        }
        self.stack.push(pane);
        cx.notify();
    }

    // --- the columns workspace (D68) --------------------------------------

    /// Wire a pane's Nav dispatch (the same one every pane gets) — only
    /// the stream variants a column can hold.
    fn subscribe_pane(&mut self, pane: &Pane, cx: &mut Context<Self>) {
        match pane {
            Pane::Feed(v) | Pane::Articles(v) | Pane::Hashtag(v) => self.subscribe_nav(v, cx),
            Pane::Notifications(v) => self.subscribe_nav(v, cx),
            Pane::Search(v) => self.subscribe_nav(v, cx),
            Pane::Wire(v) => self.subscribe_nav(v, cx),
            _ => {}
        }
    }

    /// The rail hides a stream button whose surface is already pinned
    /// as a column (columns mode, owner call): the column IS the
    /// affordance, a rail twin would be two doors to the same room.
    fn rail_hides(&self, kind: &ColumnKind) -> bool {
        self.columns_on && self.columns.iter().any(|c| &c.kind == kind)
    }

    /// Rail toggle (or `c`): enter the workspace if off, leave it if on.
    fn toggle_columns(&mut self, cx: &mut Context<Self>) {
        if self.columns_on {
            self.exit_columns(cx);
        } else {
            self.enter_columns(cx);
        }
    }

    /// Enter the workspace: unwind the drill stack with its earned pop
    /// semantics (composer draft stash, edit-profile refresh), release
    /// the base pane's media pins, then rebuild the columns — the
    /// persisted layout first (phase 2), the Home+Notifications seed
    /// once if nothing is saved. The stack drains EMPTY in columns mode
    /// — the base feed entity would sit unrendered but alive (live
    /// receiver, page in memory) otherwise; a fresh one is built on exit.
    fn enter_columns(&mut self, cx: &mut Context<Self>) {
        if self.columns_on {
            return;
        }
        self.columns_on = true;
        while !self.stack.is_empty() {
            self.back(cx);
        }
        if self.columns.is_empty() {
            let saved = crate::prefs::columns_layout();
            for pref in saved.cols.iter().take(COLUMN_CAP) {
                if let Some(col) = self.column_from_pref(pref, cx) {
                    self.subscribe_pane(&col.pane, cx);
                    self.columns.push(col);
                }
            }
            if self.columns.is_empty() {
                self.pin_column(ColumnKind::Feed, cx);
                self.pin_column(ColumnKind::Notifications, cx);
            }
        }
        self.focused_col = 0;
        cx.notify();
    }

    /// Leave the workspace: the layout persists first (mode off, the
    /// live widths), then the columns drop (media released) and a fresh
    /// base feed fills the stack.
    fn exit_columns(&mut self, cx: &mut Context<Self>) {
        if !self.columns_on {
            return;
        }
        self.columns_on = false;
        self.save_layout();
        self.add_menu = false;
        for col in self.columns.drain(..) {
            col.pane.release_media(cx);
        }
        self.focused_col = 0;
        let feed = cx.new(|cx| Feed::new(self.core.clone(), cx));
        self.subscribe_nav(&feed, cx);
        self.stack.push(Pane::Feed(feed));
        cx.notify();
    }

    /// Pin a new column of the kind (the add menu only offers unpinned
    /// kinds, and the cap bounds the workspace — a full workspace ignores
    /// the ask).
    fn pin_column(&mut self, kind: ColumnKind, cx: &mut Context<Self>) {
        if self.columns.len() >= COLUMN_CAP {
            return;
        }
        self.push_column(kind, cx);
    }

    /// The shared pin tail: build, subscribe, append, focus, scroll,
    /// persist, repaint. pin_column and pin_tagged's push arm had been
    /// two copies of these twelve lines with exactly one line of drift
    /// (the notifications dot clearing) — the kind of implicit invariant
    /// a third copy would have broken (the audit's duplication lens).
    fn push_column(&mut self, kind: ColumnKind, cx: &mut Context<Self>) {
        let pane = self.build_pane(&kind, cx);
        self.subscribe_pane(&pane, cx);
        if kind == ColumnKind::Notifications {
            // Opening notifications marks seen (the constructor does
            // the read-state advance); the dot goes quiet at once,
            // same as the drill-in open below.
            self.notif_unread = false;
        }
        self.columns.push(Column {
            kind,
            pane,
            width: None,
        });
        self.focused_col = self.columns.len() - 1;
        self.scroll_col_into_view(self.focused_col);
        self.save_layout();
        cx.notify();
    }

    /// Pin (or focus) a hashtag column — the pin affordance on the
    /// hashtag drill's title row, columns mode only.
    fn pin_hashtag(&mut self, tag: &str, cx: &mut Context<Self>) {
        self.pin_tagged(ColumnKind::Hashtag(tag.to_string()), cx);
    }

    /// Pin (or focus) an @user column — the profile drill's + Column
    /// affordance (the owner's entry point: a button the reader already
    /// knows from the hashtag drill).
    fn pin_author(&mut self, pk: PublicKey, cx: &mut Context<Self>) {
        self.pin_tagged(ColumnKind::Author(pk), cx);
    }

    /// Pin (or focus) a live-wire relay column — the + menu's URL row.
    fn pin_relay(&mut self, url: String, cx: &mut Context<Self>) {
        self.pin_tagged(ColumnKind::Relay(url), cx);
    }

    /// The parameterized kinds' shared pin: a column with the same tag
    /// focuses instead of a duplicate pin (the hashtag drill's rule,
    /// generalized — the tag IS the dedupe key for author hex and relay
    /// URL alike).
    fn pin_tagged(&mut self, kind: ColumnKind, cx: &mut Context<Self>) {
        match self.columns.iter().position(|c| c.kind.tag() == kind.tag()) {
            Some(i) if i == self.focused_col => self.column_to_top(i, cx),
            Some(i) => {
                self.focused_col = i;
                self.scroll_col_into_view(i);
                cx.notify();
            }
            None => {
                if self.columns.len() >= COLUMN_CAP {
                    return;
                }
                self.push_column(kind, cx);
            }
        }
    }

    /// A column pane's entity, per kind (pin, restore-from-prefs).
    fn build_pane(&self, kind: &ColumnKind, cx: &mut Context<Self>) -> Pane {
        match kind {
            ColumnKind::Feed => Pane::Feed(cx.new(|cx| Feed::new(self.core.clone(), cx))),
            ColumnKind::Articles => {
                Pane::Articles(cx.new(|cx| Feed::articles(self.core.clone(), cx)))
            }
            // NOTE: the constructor advances the seen marker — a restored
            // notifications column opens quiet at launch (the pre-launch
            // backlog doesn't relight the bell), the same face pinning
            // the column has. Live notes after startup ring as ever.
            ColumnKind::Notifications => {
                Pane::Notifications(cx.new(|cx| NotificationsView::new(self.core.clone(), cx)))
            }
            ColumnKind::Search => Pane::Search(cx.new(|cx| SearchView::new(self.core.clone(), cx))),
            ColumnKind::Hashtag(tag) => {
                Pane::Hashtag(cx.new(|cx| Feed::hashtag(self.core.clone(), tag.clone(), cx)))
            }
            // The author column IS a Feed (profile mode): j/k, the cursor
            // and the paging come free (owner call — pin from the profile
            // drill's title row).
            ColumnKind::Author(pk) => {
                Pane::Feed(cx.new(|cx| Feed::author(self.core.clone(), *pk, cx)))
            }
            ColumnKind::Relay(url) => {
                Pane::Wire(cx.new(|cx| WireView::new(self.core.clone(), url.clone(), cx)))
            }
        }
    }

    /// A column from its persisted pref (phase 2 restore): unknown kind
    /// strings (a future layout) return None — the layout degrades,
    /// never fails.
    fn column_from_pref(
        &self,
        pref: &crate::prefs::ColumnPref,
        cx: &mut Context<Self>,
    ) -> Option<Column> {
        let kind = match (pref.kind.as_str(), pref.tag.as_deref()) {
            ("feed", _) => ColumnKind::Feed,
            ("articles", _) => ColumnKind::Articles,
            ("notifications", _) => ColumnKind::Notifications,
            ("search", _) => ColumnKind::Search,
            ("hashtag", Some(tag)) => ColumnKind::Hashtag(tag.to_string()),
            ("author", Some(hex)) => match PublicKey::from_str(hex) {
                Ok(pk) => ColumnKind::Author(pk),
                // A corrupt hex degrades the layout (never fails).
                Err(_) => return None,
            },
            ("relay", Some(url)) => {
                // The prefs entry passes the same core screen the typed
                // path's dial will run (`routable_relay`): a corrupt or
                // hostile prefs.json can never aim the wire transport at
                // a private endpoint — the column degrades out of the
                // layout instead of dialing (the audit's security lens).
                if !satori_core::net_guard::routable_relay(url) {
                    return None;
                }
                ColumnKind::Relay(url.to_string())
            }
            _ => return None,
        };
        Some(Column {
            pane: self.build_pane(&kind, cx),
            kind,
            width: pref.width,
        })
    }

    /// The layout to prefs.json (phase 2): mode flag, order, widths.
    /// Local-only for now — NIP-78 sync rides later polish.
    fn save_layout(&self) {
        let layout = crate::prefs::ColumnsPref {
            on: self.columns_on,
            cols: self
                .columns
                .iter()
                .map(|c| crate::prefs::ColumnPref {
                    kind: c.kind.key().to_owned(),
                    tag: c.kind.tag(),
                    width: c.width,
                })
                .collect(),
        };
        crate::prefs::save_columns_layout(&layout);
    }

    /// A rail stream tap in columns mode: focus the column of the kind,
    /// pin it if missing (up to the cap). Re-tapping the FOCUSED
    /// column's kind scrolls it back to the top (the re-click affordance).
    fn ensure_column(&mut self, kind: ColumnKind, cx: &mut Context<Self>) {
        match self.columns.iter().position(|c| c.kind == kind) {
            Some(i) if i == self.focused_col => self.column_to_top(i, cx),
            Some(i) => {
                self.focused_col = i;
                self.scroll_col_into_view(i);
                if kind == ColumnKind::Notifications {
                    self.notif_unread = false;
                }
                cx.notify();
            }
            None => self.pin_column(kind, cx),
        }
    }

    /// A column's header label: the fixed kinds' static ones; the author
    /// column's resolved through the profile cache (display name, the
    /// hex as fallback).
    fn column_label(&self, kind: &ColumnKind) -> SharedString {
        match kind {
            ColumnKind::Author(pk) => {
                content::display_name(self.core.profile_of(pk).as_ref(), &pk.to_string()).into()
            }
            _ => kind.label(),
        }
    }

    /// The + menu's hashtag row: pin (or focus) the typed tag. Leading
    /// `#` stripped — the row is a door, not a prefix quiz.
    fn add_tag_column(&mut self, cx: &mut Context<Self>) {
        let raw = self.tag_input.read(cx).content.trim().to_string();
        let tag = raw.trim_start_matches('#').trim().to_string();
        if tag.is_empty() {
            return;
        }
        self.tag_input.update(cx, Input::clear);
        self.add_menu = false;
        self.pin_hashtag(&tag, cx);
    }

    /// The + menu's relay row: the URL is validated and normalized like
    /// settings' add field (the shared `net_guard::is_relay_url` shape
    /// predicate; the CORE gate behind it is the stricter
    /// `routable_relay`, so a ws:// URL would pin a dead column — the
    /// field corrects to wss:// before that). Anything else leaves the
    /// field standing with a corrective placeholder, then the live wire
    /// pins.
    fn add_relay_column(&mut self, cx: &mut Context<Self>) {
        let url = self.relay_input.read(cx).content.trim().to_string();
        if url.is_empty() {
            return;
        }
        if !satori_core::net_guard::is_relay_url(&url) || !url.starts_with("wss://") {
            self.relay_input.update(cx, |input, _| {
                input.set_placeholder("needs wss://");
            });
            return;
        }
        self.relay_input.update(cx, Input::clear);
        self.add_menu = false;
        self.pin_relay(url, cx);
    }

    /// Unpin column `i` (the header's ×): media released, focus clamped.
    fn remove_column(&mut self, i: usize, cx: &mut Context<Self>) {
        if i >= self.columns.len() {
            return;
        }
        let col = self.columns.remove(i);
        col.pane.release_media(cx);
        if self.focused_col >= self.columns.len() {
            self.focused_col = self.columns.len().saturating_sub(1);
        }
        // The invariant every focused_col mutation keeps: the focus
        // scrolls into view (the clamp can land the focus on a column
        // that is partially offscreen after the removal).
        self.scroll_col_into_view(self.focused_col);
        self.save_layout();
        cx.notify();
    }

    /// The focused column's stream back to its top (the re-click
    /// affordance; j/k's cursor lives in the pane).
    fn column_to_top(&self, i: usize, cx: &mut Context<Self>) {
        match self.columns.get(i).map(|c| &c.pane) {
            Some(Pane::Feed(v)) | Some(Pane::Articles(v)) | Some(Pane::Hashtag(v)) => {
                v.update(cx, |feed, _| feed.scroll_top());
            }
            Some(Pane::Notifications(v)) => {
                v.update(cx, |n, _| n.scroll_top());
            }
            Some(Pane::Wire(v)) => {
                v.update(cx, |n, _| n.scroll_top());
            }
            _ => {}
        }
    }

    /// True while the workspace owns the view (columns mode, no drill up).
    fn workspace_up(&self) -> bool {
        self.columns_on && self.stack.is_empty()
    }

    /// Scroll a column into view (h/l hops, pin, focus moves): the row's
    /// children are the columns in order — the scroll handle tracks
    /// them, and scroll_to_item takes the minimal nudge.
    fn scroll_col_into_view(&self, i: usize) {
        if !self.columns.is_empty() {
            self.row_scroll.scroll_to_item(i);
        }
    }

    /// h/l: the focused column steps left/right, clamped at the ends
    /// (phase 3's keyboard column-hopping; nothing to hop below two).
    fn hop_columns(&mut self, delta: isize, cx: &mut Context<Self>) {
        let n = self.columns.len();
        if n < 2 {
            return;
        }
        let next = (self.focused_col as isize + delta).clamp(0, n as isize - 1) as usize;
        if next != self.focused_col {
            self.focused_col = next;
            self.scroll_col_into_view(next);
            cx.notify();
        }
    }

    /// The focused column's stream pane, if the workspace is up.
    fn focused_stream(&self) -> Option<&Pane> {
        self.columns.get(self.focused_col).map(|c| &c.pane)
    }

    /// Bell-dot poll, every 90s (shell.rs poll_notif): one notifications()
    /// drain, kept until the NotifDot verdict.
    fn watch_notif(&self, cx: &mut Context<Self>) {
        // First beat lands at once, not after the first interval (D48):
        // the full notifications computation runs at startup — the
        // store warms (mentions/replies since the last session land in
        // the cache) so the pane's first paint is complete, and the dot
        // reads the truth from boot. The interval loop below stays the
        // correctness net.
        cx.spawn(async move |this, cx| {
            let _ = this.update(cx, |shell, cx| shell.check_notif_dot(cx));
        })
        .detach();
        // The live subscription is the first line (instant); this poll is
        // only a correctness net for a dead stream — 15 minutes, and the
        // full notifications computation it runs is why it must be rare.
        cx.spawn(async move |this, cx| {
            loop {
                cx.background_executor()
                    .timer(std::time::Duration::from_secs(900))
                    .await;
                // Dead shell (sign-out): stop ticking (no exit at all before).
                if this
                    .update(cx, |shell, cx| shell.check_notif_dot(cx))
                    .is_err()
                {
                    break;
                }
            }
        })
        .detach();
        // The outbox count's slow poll: the drainer's backoff retries and
        // restart-time queue loads land between publish events — 30s keeps
        // the honesty pill from sticking after a silent drain.
        cx.spawn(async move |this, cx| {
            loop {
                cx.background_executor()
                    .timer(std::time::Duration::from_secs(30))
                    .await;
                if this.update(cx, |shell, cx| shell.check_outbox(cx)).is_err() {
                    break;
                }
            }
        })
        .detach();
        // Push: any reply/mention tagging me lights the bell at once.
        let mut live_rx = self.core.subscribe_live();
        cx.spawn(async move |this, cx| {
            loop {
                match live_rx.recv().await {
                    Ok(satori_core::manager::Live::Mention) => {
                        if this
                            .update(cx, |shell, cx| {
                                shell.notif_unread = true;
                                cx.notify();
                            })
                            .is_err()
                        {
                            break; // dead shell
                        }
                    }
                    Ok(satori_core::manager::Live::PrefsSynced) => {
                        // NIP-78 login sync landed and remote prefs won —
                        // re-read what the shell renders live (the theme).
                        // Not a user action: no publish, no echo.
                        if this
                            .update(cx, |_shell, cx| {
                                if let Some(dark) = crate::prefs::load().dark {
                                    theme::select(if dark { theme::DARK } else { theme::LIGHT });
                                    cx.set_global(theme::ThemeSignal);
                                }
                                cx.notify();
                            })
                            .is_err()
                        {
                            break; // dead shell
                        }
                    }
                    Ok(_) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                    Err(_) => continue,
                }
            }
        })
        .detach();
        // The undo window's toast: the composer pops on Held, so the
        // countdown floats here — over the feed, like the reference's
        // bottom toast. Undo calls core.undo(token); outcomes resolve it.
        let mut hold_rx = self.core.subscribe_hold();
        cx.spawn(async move |this, cx| {
            loop {
                match hold_rx.recv().await {
                    Ok(PublishEvent::Held {
                        token, hold_secs, ..
                    }) => {
                        if this
                            .update(cx, |shell, cx| {
                                shell.hold = Some(HoldToast {
                                    token,
                                    deadline: std::time::Instant::now()
                                        + std::time::Duration::from_secs(hold_secs),
                                    undone: false,
                                    err: None,
                                });
                                cx.notify();
                            })
                            .is_err()
                        {
                            break; // dead shell
                        }
                        // One tick a second keeps the countdown honest; it
                        // dies when the toast resolves.
                        let weak = this.clone();
                        cx.spawn(async move |cx| {
                            loop {
                                cx.background_executor()
                                    .timer(std::time::Duration::from_secs(1))
                                    .await;
                                let alive = weak
                                    .update(cx, |shell, cx| {
                                        let running = shell
                                            .hold
                                            .as_ref()
                                            .is_some_and(|h| !h.undone && h.err.is_none());
                                        if running {
                                            cx.notify();
                                        }
                                        running
                                    })
                                    .unwrap_or(false);
                                if !alive {
                                    break;
                                }
                            }
                        })
                        .detach();
                    }
                    Ok(PublishEvent::Committed { .. }) => {
                        if this
                            .update(cx, |shell, cx| {
                                shell.hold = None;
                                shell.check_outbox(cx);
                            })
                            .is_err()
                        {
                            break; // dead shell
                        }
                    }
                    Ok(PublishEvent::Undone { .. }) => {
                        if this
                            .update(cx, |shell, cx| {
                                if let Some(h) = shell.hold.as_mut() {
                                    h.undone = true;
                                }
                                cx.notify();
                            })
                            .is_err()
                        {
                            break; // dead shell
                        }
                        // The undone whisper clears itself.
                        let weak = this.clone();
                        cx.spawn(async move |cx| {
                            cx.background_executor()
                                .timer(std::time::Duration::from_millis(2500))
                                .await;
                            let _ = weak.update(cx, |shell, cx| {
                                if shell.hold.as_ref().is_some_and(|h| h.undone) {
                                    shell.hold = None;
                                    cx.notify();
                                }
                            });
                        })
                        .detach();
                    }
                    Ok(PublishEvent::Failed { error, .. }) => {
                        if this
                            .update(cx, |shell, cx| {
                                match shell.hold.as_mut() {
                                    Some(h) => h.err = Some(error),
                                    None => {
                                        shell.hold = Some(HoldToast {
                                            token: 0,
                                            deadline: std::time::Instant::now(),
                                            undone: false,
                                            err: Some(error),
                                        })
                                    }
                                }
                                // Zero-accept publishes keep their outbox item.
                                shell.check_outbox(cx);
                            })
                            .is_err()
                        {
                            break; // dead shell
                        }
                    }
                    Ok(_) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                    Err(_) => continue,
                }
            }
        })
        .detach();
    }

    fn check_notif_dot(&mut self, cx: &mut Context<Self>) {
        let mut rx = self.core.notifications();
        cx.spawn(async move |this, cx| {
            while let Some(ev) = rx.recv().await {
                match ev {
                    FeedEvent::NotifDot(unread) => {
                        let _ = this.update(cx, |shell, cx| {
                            shell.notif_unread = unread;
                            cx.notify();
                        });
                        break;
                    }
                    FeedEvent::Failed(_) => break,
                    _ => {}
                }
            }
        })
        .detach();
    }

    /// The outbox honesty count (D36): re-read on every publish event and
    /// on a slow poll (the drainer's retries land between events).
    fn check_outbox(&mut self, cx: &mut Context<Self>) {
        let n = Core::outbox_pending();
        if n != self.outbox_pending {
            self.outbox_pending = n;
            cx.notify();
        }
    }

    /// j/k feed navigation (the shell's key handler): the active feed pane
    /// moves its row cursor one note down/up. Quiet — the list scrolls,
    /// nothing else changes.
    fn feed_nav(&mut self, delta: isize, cx: &mut Context<Self>) {
        // The workspace up: the cursor steps the FOCUSED column's feed.
        if self.workspace_up() {
            match self.focused_stream().cloned() {
                Some(Pane::Feed(view)) | Some(Pane::Articles(view)) | Some(Pane::Hashtag(view)) => {
                    view.update(cx, |feed, _| feed.key_nav(delta));
                }
                _ => {}
            }
            return;
        }
        match self.stack.last().cloned() {
            Some(Pane::Feed(view)) | Some(Pane::Articles(view)) | Some(Pane::Hashtag(view)) => {
                view.update(cx, |feed, _| feed.key_nav(delta));
            }
            _ => {}
        }
    }

    /// ←/→ carousel control (content.rs's per-carousel selection): the
    /// active feed pane's cursor row steps if it paints a multi-image
    /// carousel, and the pane repaints; otherwise the key does nothing.
    fn carousel_nav(&mut self, delta: isize, cx: &mut Context<Self>) {
        // The workspace up: the FOCUSED column's carousel steps.
        if self.workspace_up() {
            match self.focused_stream().cloned() {
                Some(Pane::Feed(view)) | Some(Pane::Articles(view)) | Some(Pane::Hashtag(view)) => {
                    view.update(cx, |feed, cx| {
                        feed.carousel_nav(delta, cx);
                    });
                }
                _ => {}
            }
            return;
        }
        match self.stack.last().cloned() {
            Some(Pane::Feed(view)) | Some(Pane::Articles(view)) | Some(Pane::Hashtag(view)) => {
                view.update(cx, |feed, cx| {
                    feed.carousel_nav(delta, cx);
                });
            }
            _ => {}
        }
    }

    /// The lightbox: show `urls[idx]` full-screen (lightbox.rs open). Every
    /// URL is pre-joined into the shared media cache so ‹/› are instant once
    /// tiles have loaded.
    fn open_lightbox(&mut self, urls: Vec<String>, idx: usize, cx: &mut Context<Self>) {
        for url in &urls {
            media::fetch(&self.core, url.clone(), cx.entity_id(), cx);
        }
        self.lightbox = Some((urls, idx));
        cx.notify();
    }

    fn lightbox_nav(&mut self, delta: isize, cx: &mut Context<Self>) {
        if let Some((urls, idx)) = self.lightbox.as_mut()
            && !urls.is_empty()
        {
            *idx = (*idx as isize + delta).rem_euclid(urls.len() as isize) as usize;
            cx.notify();
        }
    }

    /// The video overlay (Phase 3): full-screen player when the URL is
    /// inline-able (video.rs gates strict Tor/YouTube), else the browser
    /// link — the honest pre-Phase-3 behavior.
    fn open_video(&mut self, url: String, mime: Option<String>, cx: &mut Context<Self>) {
        if !crate::views::content::web_url(&url)
            || !crate::video::inline_able(&url, mime.as_deref())
        {
            if crate::views::content::web_url(&url) {
                cx.open_url(&url);
            }
            return;
        }
        self.video_overlay = Some((url.clone(), mime.clone()));
        crate::video::open(url, mime, cx);
        cx.notify();
    }

    /// The video overlay closes: the player's pipeline tears down with it
    /// (video.rs close — deferred drop, off the UI thread).
    fn close_video(&mut self, cx: &mut Context<Self>) {
        if self.video_overlay.take().is_some() {
            crate::video::close(cx);
            cx.notify();
        }
    }

    fn back(&mut self, cx: &mut Context<Self>) {
        // An overlay owns the back door while it's up: the reply and zap
        // sheets close first (their Nav::Pop and the Esc key both land
        // here), the pane underneath never notices.
        if self.reply_overlay.take().is_some() || self.zap_overlay.take().is_some() {
            cx.notify();
            return;
        }
        // The workspace owns the view when no drill is up: Esc closes the
        // add-column menu if it's open, and nothing pops.
        if self.workspace_up() {
            if self.add_menu {
                self.add_menu = false;
                cx.notify();
            }
            return;
        }
        // In columns mode the stack holds ONLY drills, so a single pane
        // pops (back to the workspace); single-pane mode keeps the base
        // pane (len 1 is home, nothing to pop).
        if self.stack.len() > 1 || self.columns_on {
            // Closing a composer stashes the top-level buffer (composer.rs:288);
            // reply composers leave the draft untouched (`draft_candidate`).
            if let Some(Pane::Composer(c)) = self.stack.last()
                && let Some(stash) = c.read(cx).draft_candidate(cx)
            {
                cx.default_global::<Draft>().0 = Some(stash);
            }
            // D38: the SYNCED draft (NIP-78 kind 30078) — every compose
            // syncs its buffer on close (replies/quotes keyed; an empty
            // buffer clears the slot). Fire and forget: the outbox retries
            // the publish, a failed save leaves the slot intact, and the
            // session global above still covers the instant reopen.
            if let Some(Pane::Composer(c)) = self.stack.last()
                && let Some((reply, quote, text, attachments)) = c.read(cx).draft_sync_candidate(cx)
            {
                let _ = self.core.save_draft(reply, quote, text, attachments, false);
            }
            // D38: closing the edit form — a save may have landed a fresh
            // kind 0 while it was up. Refresh the rail's own-profile copy
            // and the profile pane underneath from the store (the profiles
            // service's 12h TTL cache won't).
            if matches!(self.stack.last(), Some(Pane::EditProfile(_))) {
                let mut rx = self.core.own_profile();
                let target = match self.stack.get(self.stack.len() - 2) {
                    Some(Pane::Profile(v)) => Some(v.clone()),
                    _ => None,
                };
                cx.spawn(async move |this, cx| {
                    if let Some(Some(p)) = rx.recv().await {
                        let _ = this.update(cx, |shell, cx| {
                            if let Some(target) = &target {
                                target.update(cx, |pane, cx| pane.refresh_profile(p.clone(), cx));
                            }
                            shell.me_profile = Some(p);
                            cx.notify();
                        });
                    }
                })
                .detach();
            }
            // D60: the outgoing pane's media pins release with it — the
            // registry is global, so a popped pane's set would ratchet
            // (its entries skip every eviction sweep) for the session.
            self.stack.last().inspect(|pane| pane.release_media(cx));
            self.stack.pop();
            self.refocus = true;
            cx.notify();
        }
    }

    fn title(&self, cx: &App) -> SharedString {
        match self.stack.last() {
            Some(Pane::Feed(_)) => "Feed".into(),
            Some(Pane::Articles(_)) => "Articles".into(),
            Some(Pane::Library(_)) => "Library".into(),
            Some(Pane::Hashtag(f)) => f.read(cx).header().into(),
            Some(Pane::Thread(_)) => "Thread".into(),
            Some(Pane::Profile(_)) => "Profile".into(),
            Some(Pane::EditProfile(_)) => "Edit profile".into(),
            Some(Pane::Notifications(_)) => "Notifications".into(),
            Some(Pane::Search(_)) => "Search".into(),
            Some(Pane::Settings(_)) => "Settings".into(),
            Some(Pane::Article(_)) => "Read".into(),
            Some(Pane::Composer(_)) => "Compose".into(),
            Some(Pane::Wallet(_)) => "Wallet".into(),
            Some(Pane::Wire(_)) => "Relay wire".into(),
            None => "Satori".into(),
        }
    }
}

/// A rail tooltip: ink chip, washi text, nothing more. gpui paints these
/// itself near the cursor after a hover (window.rs prepaint_tooltip).
struct Tip {
    label: &'static str,
}
impl Render for Tip {
    fn render(&mut self, _: &mut Window, _: &mut Context<Self>) -> impl IntoElement {
        div()
            .px_2()
            .py_1()
            .rounded(px(theme::R_EMBED))
            .bg(rgb(theme::ink()))
            .text_color(rgb(theme::washi()))
            .text_size(px(theme::T_SMALL))
            .font_family(theme::SANS)
            .child(self.label)
    }
}
/// The `.tooltip(...)` builder for a static label.
pub(crate) fn tip(label: &'static str) -> impl Fn(&mut Window, &mut App) -> AnyView + 'static {
    move |_, cx| cx.new(|_| Tip { label }).into()
}

// --- the rail (P1's sidebar pass) ------------------------------------------

/// Which rail spot (if any) the active pane corresponds to — the tick marks
/// the active spot, and re-clicking it is an affordance (feed: back to top).
#[derive(Clone, Copy, PartialEq)]
enum Spot {
    /// The user's avatar (D38) — ticks when the top pane is the OWN
    /// profile; a visit to someone else's profile doesn't tick it.
    Profile,
    /// The Library pane (D38).
    Library,
    Feed,
    Articles,
    Search,
    Notif,
    Compose,
    Settings,
}

impl Shell {
    /// The workspace up: the FOCUSED column's stream ticks; a drill over
    /// the workspace reads like any stacked pane.
    fn active_spot(&self, cx: &App) -> Option<Spot> {
        if self.workspace_up() {
            return match self.focused_stream() {
                Some(Pane::Feed(_)) => Some(Spot::Feed),
                Some(Pane::Articles(_)) => Some(Spot::Articles),
                Some(Pane::Search(_)) => Some(Spot::Search),
                Some(Pane::Notifications(_)) => Some(Spot::Notif),
                _ => None,
            };
        }
        match self.stack.last() {
            Some(Pane::Feed(_)) => Some(Spot::Feed),
            Some(Pane::Articles(_)) => Some(Spot::Articles),
            Some(Pane::Search(_)) => Some(Spot::Search),
            Some(Pane::Notifications(_)) => Some(Spot::Notif),
            Some(Pane::Composer(_)) => Some(Spot::Compose),
            Some(Pane::Settings(_)) => Some(Spot::Settings),
            // The avatar spot is the OWN profile only — a visit to someone
            // else's profile pane is not the spot.
            Some(Pane::Profile(view)) if view.read(cx).is_me => Some(Spot::Profile),
            Some(Pane::Library(_)) => Some(Spot::Library),
            _ => None,
        }
    }

    /// Home: back to the feed, unstacking whatever depth we're at (back()
    /// handles each pop, including the composer draft stash). In columns
    /// mode home is the workspace — every drill pops off.
    fn go_home(&mut self, cx: &mut Context<Self>) {
        if self.columns_on {
            while !self.stack.is_empty() {
                self.back(cx);
            }
            return;
        }
        while self.stack.len() > 1 {
            self.back(cx);
        }
    }

    /// The active pane's own deep-scroll state, read straight from the view
    /// at render — the shell keeps no copy (a stored flag goes stale across
    /// pane switches; Nav::PaneDeep is only the repaint signal).
    fn pane_deep(pane: &Pane, cx: &Context<Self>) -> bool {
        match pane {
            Pane::Feed(view) | Pane::Articles(view) | Pane::Hashtag(view) => view.read(cx).deep,
            Pane::Notifications(view) => view.read(cx).deep,
            Pane::Library(view) => view.read(cx).deep,
            // The profile pane's notes list is an embedded feed; the view
            // mirrors the child's flag (PaneDeep forwarding).
            Pane::Profile(view) => view.read(cx).deep,
            _ => false,
        }
    }

    /// The active pane's scroll-to-top (rail re-click, the floating
    /// whisper): whichever scrollable list is on top of the stack.
    fn pane_to_top(&self, cx: &mut Context<Self>) {
        // The workspace up: the focused column's stream scrolls.
        if self.workspace_up() {
            let i = self.focused_col;
            self.column_to_top(i, cx);
            return;
        }
        match self.stack.last().cloned() {
            Some(Pane::Feed(view)) | Some(Pane::Articles(view)) | Some(Pane::Hashtag(view)) => {
                view.update(cx, |feed, _| feed.scroll_top());
            }
            Some(Pane::Notifications(view)) => {
                view.update(cx, |n, _| n.scroll_top());
            }
            Some(Pane::Library(view)) => {
                view.update(cx, |v, cx| v.scroll_top(cx));
            }
            Some(Pane::Profile(view)) => {
                view.update(cx, |p, cx| p.scroll_top(cx));
            }
            _ => {}
        }
    }

    fn rail(&mut self, cx: &mut Context<Self>) -> Div {
        let active = self.active_spot(cx);
        let ink = |on: bool| if on { theme::ink() } else { theme::muted() };
        let feed_active = active == Some(Spot::Feed);

        // The avatar's snapshot comes from the cache's own epoch memo —
        // Snapshot::new is a refcount bump between landings.
        let rail_snap = media::Snapshot::new(cx);
        let (me_pic, me_name) = match (&self.me_profile, self.me) {
            (Some(p), _) => (p.picture.clone(), p.display()),
            (None, Some(pk)) => (String::new(), content::display_name(None, &pk.to_string())),
            _ => (String::new(), "You".to_string()),
        };
        // The rail avatar comes back if the cache evicted it (silent no-op
        // when the cache still holds it). Pin it too: the shell only
        // re-renders on events, so while the feed idles or scrolls the
        // LRU touch freezes and the grace expires — photo pressure then
        // flashed the avatar to the ink initial and refetched, repeating.
        // Pinned, eviction skips it for the session.
        if !me_pic.is_empty() {
            media::fetch(&self.core, me_pic.clone(), cx.entity_id(), cx);
            // repin, not pin: the rail's owner set is exactly THIS avatar
            // (a profile-picture change must release the old one).
            media::repin(cx.entity_id(), vec![me_pic.clone()], cx);
        }
        let me_avatar = media::avatar(rail_snap.as_ref(), &me_pic, &me_name, 26.0);

        div()
            .flex_none()
            .h_full()
            .w(px(52.0))
            .flex()
            .flex_col()
            .items_center()
            // Glyph top lands at 19+9=28 — level with the feed's first
            // avatar (16px page band + 12px note-card padding).
            .pt(px(19.0))
            .gap_1()
            // The user's avatar is the Profile spot (D38): clicking opens
            // the own profile, re-clicking the active one scrolls it back
            // up; the tick marks it (Home remains the Feed spot's re-click
            // — go_home below). It LEADS the rail — including in columns
            // mode, where the toggle follows it (owner correction: the
            // toggle-first order was their earlier mistake).
            .child(self.rail_button(
                "rail-profile",
                "Profile",
                me_avatar,
                active == Some(Spot::Profile),
                cx.listener(move |shell, _, _, cx| {
                    if shell.active_spot(cx) == Some(Spot::Profile) {
                        shell.pane_to_top(cx);
                    } else if let Some(me) = shell.me {
                        shell.open_profile(me, cx);
                    }
                }),
            ))
            // The columns toggle second while the workspace is up (the
            // owner's standing order); off, it sits in its slot by the pen.
            .when(self.columns_on, |d| d.child(self.columns_toggle_button(cx)))
            .when(!self.rail_hides(&ColumnKind::Feed), |d| {
                d.child(self.rail_button(
                    "rail-feed",
                    "Feed",
                    icons::stream_icon(ink(feed_active)),
                    feed_active,
                    cx.listener(move |shell, _, _, cx| {
                        if shell.columns_on {
                            shell.ensure_column(ColumnKind::Feed, cx);
                        } else if feed_active {
                            // Re-click the active spot: back to the top.
                            shell.pane_to_top(cx);
                        } else {
                            shell.go_home(cx);
                        }
                    }),
                ))
            })
            .when(!self.rail_hides(&ColumnKind::Articles), |d| {
                d.child(self.rail_button(
                    "rail-articles",
                    "Articles",
                    icons::article_icon(ink(active == Some(Spot::Articles))),
                    active == Some(Spot::Articles),
                    cx.listener(move |shell, _, _, cx| {
                        if shell.columns_on {
                            shell.ensure_column(ColumnKind::Articles, cx);
                        } else if shell.active_spot(cx) != Some(Spot::Articles) {
                            shell.open_articles(cx);
                        }
                    }),
                ))
            })
            .child(self.rail_button(
                "rail-library",
                "Library",
                icons::book_icon(ink(active == Some(Spot::Library))),
                active == Some(Spot::Library),
                cx.listener(move |shell, _, _, cx| {
                    if shell.active_spot(cx) != Some(Spot::Library) {
                        shell.open_library(cx);
                    }
                }),
            ))
            .when(!self.rail_hides(&ColumnKind::Search), |d| {
                d.child(self.rail_button(
                    "rail-search",
                    "Search",
                    icons::search_icon(ink(active == Some(Spot::Search))),
                    active == Some(Spot::Search),
                    cx.listener(move |shell, _, _, cx| {
                        if shell.columns_on {
                            shell.ensure_column(ColumnKind::Search, cx);
                        } else if shell.active_spot(cx) != Some(Spot::Search) {
                            shell.open_search(cx);
                        }
                    }),
                ))
            })
            .when(!self.rail_hides(&ColumnKind::Notifications), |d| {
                d.child(
                    self.rail_button(
                        "rail-notifications",
                        "Notifications",
                        div()
                            .relative()
                            .child(icons::bell_icon(ink(active == Some(Spot::Notif))))
                            .when(self.notif_unread, |dd| {
                                dd.child(
                                    div()
                                        .absolute()
                                        .top(px(-1.))
                                        .right(px(-1.))
                                        .size(px(6.))
                                        .rounded_full()
                                        .bg(rgb(theme::vermilion())),
                                )
                            }),
                        active == Some(Spot::Notif),
                        cx.listener(move |shell, _, _, cx| {
                            if shell.columns_on {
                                shell.ensure_column(ColumnKind::Notifications, cx);
                            } else if shell.active_spot(cx) != Some(Spot::Notif) {
                                shell.open_notifications(cx);
                            }
                        }),
                    ),
                )
            })
            // The columns workspace toggle (D68): the same ink-at-rest /
            // ink-when-active discipline as the other state buttons — the
            // tick carries the state, the glyph needs no second voice.
            // In its slot only when the mode is OFF (on, it leads the
            // rail — see the top of this chain).
            .when(!self.columns_on, |d| {
                d.child(self.columns_toggle_button(cx))
            })
            // The add-column button, above Settings (owner's move: in
            // columns mode the workspace's + slot sat after the last
            // column, so adding one meant scrolling the row first). Only
            // while the workspace owns the view and the cap allows; the
            // menu it opens is the same add_menu card.
            .when(
                self.workspace_up() && self.columns.len() < COLUMN_CAP,
                |d| {
                    d.child(self.rail_button(
                        "rail-add-column",
                        "Add column",
                        icons::plus_icon(if self.add_menu {
                            theme::vermilion()
                        } else {
                            theme::ink()
                        }),
                        self.add_menu,
                        cx.listener(move |shell, _, _, cx| {
                            shell.add_menu = !shell.add_menu;
                            cx.notify();
                        }),
                    ))
                },
            )
            // Compose speaks (it broadcasts) — the pen wears vermilion.
            .child(self.rail_button(
                "rail-settings",
                "Settings",
                icons::gear_icon(ink(active == Some(Spot::Settings))),
                active == Some(Spot::Settings),
                cx.listener(move |shell, _, _, cx| {
                    if shell.active_spot(cx) != Some(Spot::Settings) {
                        shell.open_settings(cx);
                    }
                }),
            ))
            .child(self.rail_button(
                "rail-compose",
                "Compose",
                icons::pen_icon(theme::vermilion()),
                active == Some(Spot::Compose),
                cx.listener(move |shell, _, _, cx| {
                    // Never clobber an open composer (its draft is live).
                    if shell.active_spot(cx) != Some(Spot::Compose) {
                        shell.open_composer(None, None, cx);
                    }
                }),
            ))
    }

    /// The columns toggle's button — built per slot (it renders second
    /// from the top, right under the avatar, while the mode is on, in
    /// its slot by the pen when off; an element can't be Childed twice).
    fn columns_toggle_button(&self, cx: &mut Context<Self>) -> Stateful<Div> {
        self.rail_button(
            "rail-columns",
            "Columns",
            icons::columns_icon(if self.columns_on {
                theme::ink()
            } else {
                theme::muted()
            }),
            self.columns_on,
            cx.listener(move |shell, _, _, cx| shell.toggle_columns(cx)),
        )
    }

    fn rail_button(
        &self,
        id: &'static str,
        label: &'static str,
        glyph: impl IntoElement + 'static,
        active: bool,
        on_click: impl Fn(&ClickEvent, &mut Window, &mut App) + 'static,
    ) -> Stateful<Div> {
        div()
            .id(SharedString::from(id))
            .relative()
            .cursor_pointer()
            .w(px(52.0))
            .py(px(9.0))
            .flex()
            .justify_center()
            .tooltip(tip(label))
            .on_click(on_click)
            // The active tick: a small vermilion brush accent, not a pill.
            .when(active, |d| {
                d.child(
                    div()
                        .absolute()
                        .left(px(11.0))
                        .top(px(11.0))
                        .bottom(px(11.0))
                        .w(px(2.0))
                        .rounded_full()
                        .bg(rgb(theme::vermilion())),
                )
            })
            .child(glyph)
    }

    /// The deep panes' quiet top row: back + title. The feed (depth 1) has
    /// none — the rail's ensō is home and the stream needs no label.
    fn title_row(&self, cx: &mut Context<Self>) -> Div {
        div()
            .flex()
            .items_center()
            .gap_3()
            .px_4()
            // Title ink at ~28px — level with the feed's first note (the
            // column's 16px band + 10 here ≈ 26px text box, ~2px leading).
            .pt(px(10.0))
            .pb(px(4.0))
            .child(
                div()
                    .id("back")
                    .cursor_pointer()
                    .text_size(px(theme::T_UI))
                    .text_color(rgb(theme::muted()))
                    .on_click(cx.listener(|shell, _, _, cx| shell.back(cx)))
                    .child("‹ Back"),
            )
            .child(
                div()
                    .flex_1()
                    .text_size(px(theme::T_UI))
                    .text_color(rgb(theme::ink()))
                    .child(self.title(cx)),
            )
            // The columns workspace (D68 phase 2): a hashtag or profile
            // drill over the workspace offers to pin that stream as a
            // column (the kind expansion's author entry point).
            .children(self.column_pin(cx))
    }

    /// A drill's + Column affordance (columns mode only): the hashtag
    /// drill pins its tag, the profile drill pins its author (the
    /// @user column's entry point — owner call).
    fn column_pin(&self, cx: &mut Context<Self>) -> Option<Stateful<Div>> {
        let kind = match self.stack.last() {
            Some(Pane::Hashtag(view)) => {
                let tag = view.read(cx).tag()?;
                ColumnKind::Hashtag(tag.to_string())
            }
            Some(Pane::Profile(view)) => ColumnKind::Author(view.read(cx).who),
            _ => return None,
        };
        Some(
            div()
                .id("col-pin-tag")
                .cursor_pointer()
                .px(px(8.0))
                .py(px(2.0))
                .rounded(px(theme::R_EMBED))
                .border_1()
                .border_color(rgb(theme::hairline()))
                .text_size(px(theme::T_UI))
                .text_color(rgb(theme::muted()))
                .hover(|s| {
                    s.border_color(rgb(theme::vermilion()))
                        .text_color(rgb(theme::vermilion()))
                })
                .on_click(cx.listener(move |shell, _, _, cx| {
                    cx.stop_propagation();
                    match &kind {
                        ColumnKind::Author(pk) => shell.pin_author(*pk, cx),
                        _ => shell.pin_tagged(kind.clone(), cx),
                    };
                }))
                .child("+ Column"),
        )
    }

    /// The floating back-to-top whisper — bottom-right of the content
    /// column, only when the feed is scrolled well down.
    /// The floating back-to-top whisper — bottom-right of the content
    /// column, only when the active pane is scrolled deep. The click is
    /// SEALED (stop_propagation): the button floats OVER the note cards,
    /// and an unsealed click falls through to the card beneath — the
    /// owner saw the thread open instead of a scroll-to-top. (Same house
    /// rule as the cards' own click seals.) 44px, not 38: a round target
    /// this small catches edge misses on the card under it.
    fn floating_top(&self, cx: &mut Context<Self>) -> Stateful<Div> {
        div()
            .id("back-to-top")
            .absolute()
            .bottom(px(20.0))
            .right(px(24.0))
            .size(px(44.0))
            .rounded_full()
            .cursor_pointer()
            .border_1()
            .border_color(rgb(theme::hairline()))
            .bg(rgb(theme::washi()))
            // Hover like the new-notes chip: the ring takes the accent.
            .hover(|s| s.border_color(rgb(theme::vermilion())))
            .flex()
            .items_center()
            .justify_center()
            .tooltip(tip("Back to top"))
            .on_click(cx.listener(|shell, _, _, cx| {
                cx.stop_propagation();
                shell.pane_to_top(cx);
                cx.notify();
            }))
            // The arrow in vermilion: the button's washi-on-washi surfaces
            // are quiet by design, but a quiet GLYPH reads as furniture —
            // the affordance lives in the color pop (the one loud accent
            // the theme reserves for attention).
            .child(icons::arrow_up_icon(theme::vermilion()))
    }
}

impl EventEmitter<ShellEvent> for Shell {}

impl Focusable for Shell {
    fn focus_handle(&self, _cx: &App) -> FocusHandle {
        self.focus.clone()
    }
}

impl Render for Shell {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        // Built before the pane borrow: rail() takes &mut self (snapshot
        // memo). The content is the columns workspace while the mode is
        // on and no drill is up; otherwise the single-pane reading
        // column. Narrow windows scroll the row horizontally — the
        // columns keep their measure (the owner's amendment to D68's
        // collapse fork).
        let rail = self.rail(cx);
        let content: AnyElement = if self.workspace_up() {
            self.workspace(cx).into_any_element()
        } else {
            self.pane_column(cx).into_any_element()
        };
        if !self.focused_once || self.refocus {
            self.focused_once = true;
            self.refocus = false;
            window.focus(&self.focus, cx);
        }

        div()
            .relative()
            .track_focus(&self.focus)
            .on_key_down(cx.listener(|shell, ev: &KeyDownEvent, window, cx| {
                // The video overlay owns Esc while it's up: Esc closes it
                // (and tears the player down) instead of popping the pane.
                if shell.video_overlay.is_some() {
                    if ev.keystroke.key == "escape" {
                        shell.close_video(cx);
                    }
                    cx.notify();
                    return;
                }
                // The lightbox owns the keyboard while it's up: Esc closes it
                // instead of popping the pane; arrows page through.
                if shell.lightbox.is_some() {
                    match ev.keystroke.key.as_str() {
                        "escape" => shell.lightbox = None,
                        "left" => shell.lightbox_nav(-1, cx),
                        "right" => shell.lightbox_nav(1, cx),
                        _ => {}
                    }
                    cx.notify();
                    return;
                }
                // Ported: crates/app/src/main.rs escape-to-back — P1.
                if ev.keystroke.key == "escape" {
                    shell.back(cx);
                    return;
                }
                // The single-letter shortcuts are for the SHELL: while any
                // text surface holds focus, typed letters are content, not
                // commands. (The pane-type guard this replaces was whack-
                // a-mole — "an 'n' in 'nostr' opened the composer" via the
                // search field, and D20's wallet URI field relit it. The
                // Input lets plain keys bubble, but it DOES take focus, and
                // that's the honest signal: shortcuts fire only when the
                // shell root itself holds focus — startup, after a pop's
                // refocus, after clicking dead space.)
                if !shell.focus.is_focused(window) {
                    return;
                }
                if !ev.keystroke.modifiers.modified() {
                    if ev.keystroke.key == "n" {
                        shell.open_composer(None, None, cx);
                    }
                    // The columns workspace toggle (D68).
                    if ev.keystroke.key == "c" {
                        shell.toggle_columns(cx);
                    }
                    // No GTK accel — the header seals are unclickable when the
                    // window is CSD-tiled (§9.1 finding), so the keyboard is
                    // the reliable way in.
                    if ev.keystroke.key == "u" {
                        if shell.columns_on {
                            shell.ensure_column(ColumnKind::Notifications, cx);
                        } else {
                            shell.open_notifications(cx);
                        }
                    }
                    // Ported: crates/app/src/main.rs — "/" opens search
                    // (app.goto-search accel).
                    if ev.keystroke.key == "/" {
                        if shell.columns_on {
                            shell.ensure_column(ColumnKind::Search, cx);
                        } else {
                            shell.open_search(cx);
                        }
                    }
                    // j/k: one note down/up in the active feed (the list
                    // model makes it a scroll_to — nothing fancy, §1.3
                    // quiet-by-default; the cursor rides the scroll stream,
                    // so a mouse scroll re-anchors it).
                    if ev.keystroke.key == "j" {
                        shell.feed_nav(1, cx);
                    }
                    if ev.keystroke.key == "k" {
                        shell.feed_nav(-1, cx);
                    }
                    // h/l: the focused column steps left/right (phase 3's
                    // keyboard column-hopping; workspace up only).
                    if ev.keystroke.key == "h" && shell.workspace_up() {
                        shell.hop_columns(-1, cx);
                    }
                    if ev.keystroke.key == "l" && shell.workspace_up() {
                        shell.hop_columns(1, cx);
                    }
                    // ←/→: the cursor row's multi-image carousel (the same
                    // selection the ‹ › arrows move). A row without one
                    // leaves the key unhandled.
                    if ev.keystroke.key == "left" {
                        shell.carousel_nav(-1, cx);
                    }
                    if ev.keystroke.key == "right" {
                        shell.carousel_nav(1, cx);
                    }
                    if ev.keystroke.key == "a" {
                        if shell.columns_on {
                            shell.ensure_column(ColumnKind::Articles, cx);
                        } else {
                            shell.open_articles(cx);
                        }
                    }
                    // No GTK accel — same CSD story: the header Settings seal
                    // needs a keyboard way in.
                    if ev.keystroke.key == "s" {
                        shell.open_settings(cx);
                    }
                }
            }))
            .size_full()
            .bg(rgb(theme::washi()))
            .text_color(rgb(theme::ink()))
            .font_family(theme::SANS)
            // The rail + content row. The pair is centered as a group —
            // the rail stands to the left of the reading column, not glued
            // to the window edge. The rail sits outside every pane's
            // scroll container, so anchoring is free; the deep panes carry
            // their back+title row above the pane (the feed carries none).
            .flex()
            .flex_row()
            .items_start()
            .justify_center()
            .child(rail)
            .child(content)
            .when(self.hold.is_some(), |d| d.child(self.hold_toast(cx)))
            .when_some(self.lightbox.clone(), |d, (urls, idx)| {
                d.child(lightbox_overlay(&urls, idx, cx))
            })
            .when_some(self.video_overlay.clone(), |d, (url, _mime)| {
                d.child(video_overlay(&url, cx))
            })
            .when_some(self.zap_overlay.clone(), |d, sheet| {
                d.child(card_overlay("zap", sheet, 420., None, cx))
            })
            .when_some(self.reply_overlay.clone(), |d, sheet| {
                d.child(card_overlay("reply", sheet, 560., Some(560.), cx))
            })
    }
}

impl Shell {
    /// The single-pane reading column (mode off, or a drill over the
    /// workspace): the rail-content contract — capped width, the quiet
    /// top band, the title row over depth 1 (or any drill in columns
    /// mode, whose back door returns to the workspace), the outbox pill,
    /// the pane, the deep-scroll whisper.
    fn pane_column(&mut self, cx: &mut Context<Self>) -> Div {
        let depth = self.stack.len();
        let pane = self.stack.last().unwrap();
        div()
            .relative()
            .flex_1()
            .max_w(px(content::COL_W))
            .min_w_0()
            .h_full()
            .flex()
            .flex_col()
            // The quiet band every page starts under (uniform top
            // padding — the feed's first note, the deep panes'
            // title row: all begin 16px down).
            .pt(px(16.0))
            .when(depth > 1 || self.columns_on, |d| {
                d.child(self.title_row(cx))
            })
            // The reading column's top band is the pane's, but the
            // outbox honesty pill (D26: a state, not an error; §4.4)
            // floats over any pane — queued notes are the SHELL's
            // news, whatever you're reading.
            .when(self.outbox_pending > 0, |d| {
                let n = self.outbox_pending;
                d.child(states::offline_pill(&format!(
                    "{n} note{} queued for delivery, the relays will answer",
                    if n == 1 { "" } else { "s" }
                )))
            })
            .child(Self::pane_element(pane))
            // The floating back-to-top whisper: the ACTIVE pane's own
            // deep state, read straight from the view (never a shell
            // copy — a stale flag would show the whisper over the
            // wrong pane after a switch).
            .when(
                Self::pane_deep(pane, cx)
                    && matches!(
                        pane,
                        Pane::Feed(_)
                            | Pane::Articles(_)
                            | Pane::Hashtag(_)
                            | Pane::Notifications(_)
                            | Pane::Library(_)
                    ),
                |d| d.child(self.floating_top(cx)),
            )
    }

    /// The columns workspace (D68): the pinned streams side by side, each
    /// its own scrolling pane entity, separated by hairlines (the
    /// no-card-box aesthetic — a hairline, not a card). Equal widths
    /// capped at the reading column for v1; drag-to-reorder and
    /// per-column widths ride Phase 2. Clicking a column focuses it
    /// (sealed child clicks never reach the container); a drill pushes
    /// over the WHOLE workspace and Esc pops back.
    fn workspace(&mut self, cx: &mut Context<Self>) -> Div {
        let focused = self.focused_col;
        let mut row = div()
            .id("columns-row")
            .flex()
            .flex_row()
            .flex_1()
            .min_w_0()
            .h_full()
            // The columns keep their measure and the row scrolls
            // horizontally (the owner's amendment to D68's collapse
            // fork): no narrow columns, TweetDeck's own answer.
            // restrict_scroll_to_axis is load-bearing: without it gpui's
            // wheel handler applies the VERTICAL delta to this row's x
            // offset (its "single-axis fallback"), so scrolling a column
            // also slid the row sideways (user report).
            .overflow_x_scroll()
            .track_scroll(&self.row_scroll)
            .restrict_scroll_to_axis();
        if self.columns.is_empty() {
            // The unpinned extreme: a quiet word, the + slot beside it.
            row = row.child(
                div()
                    .flex_1()
                    .h_full()
                    .flex()
                    .items_center()
                    .justify_center()
                    .text_size(px(theme::T_UI))
                    .text_color(rgb(theme::muted()))
                    .child("No columns — add a stream with +"),
            );
        }
        for i in 0..self.columns.len() {
            let label = self.column_label(&self.columns[i].kind);
            let element = Self::pane_element(&self.columns[i].pane);
            // The column's measure: the persisted width, else the reading
            // column's — never squeezed by the row (it scrolls instead).
            let col_w = self.columns[i]
                .width
                .unwrap_or(content::COL_W)
                .min(COL_MAX_W);
            let is_last = i + 1 == self.columns.len();
            let is_focused = i == focused;
            let is_drop_target = self.reorder_over == Some(i);
            row = row.child(
                div()
                    .relative()
                    .flex()
                    .flex_col()
                    .flex_none()
                    .w(px(col_w))
                    .h_full()
                    .overflow_hidden()
                    .when(!is_last, |d| {
                        d.border_r_1().border_color(rgb(theme::hairline()))
                    })
                    // The quiet band, level with the single-pane column's.
                    .pt(px(16.0))
                    .px(px(12.0))
                    // Clicking dead space focuses the column.
                    .id(SharedString::from(format!("col-{i}")))
                    .on_click(cx.listener(move |shell, _, _, cx| {
                        if shell.focused_col != i {
                            shell.focused_col = i;
                            shell.scroll_col_into_view(i);
                            cx.notify();
                        }
                    }))
                    // The reorder cue (phase 2): a column drag over this
                    // column lights its header; the drop commits.
                    .on_drag_move::<ColumnDrag>(cx.listener(
                        move |shell, ev: &DragMoveEvent<ColumnDrag>, _, cx| {
                            let d = ev.drag(cx);
                            if d.from == i {
                                return;
                            }
                            if ev.bounds.contains(&ev.event.position)
                                && shell.reorder_over != Some(i)
                            {
                                shell.reorder_over = Some(i);
                                cx.notify();
                            }
                        },
                    ))
                    // The drop: the dragged column takes this slot.
                    .on_drop::<ColumnDrag>(cx.listener(move |shell, d: &ColumnDrag, _, cx| {
                        shell.reorder_over = None;
                        if d.from != i && d.from < shell.columns.len() {
                            let col = shell.columns.remove(d.from);
                            shell.columns.insert(i, col);
                            shell.focused_col = i;
                            shell.save_layout();
                        }
                        cx.notify();
                    }))
                    // The width handle's moves: the dragged column's width
                    // follows the pointer, anchored at its own left edge
                    // (these bounds — a column's left never moves under a
                    // right-edge drag, so the width is exact).
                    .on_drag_move::<WidthDrag>(cx.listener(
                        move |shell, ev: &DragMoveEvent<WidthDrag>, _, cx| {
                            let d = ev.drag(cx);
                            if d.col != i {
                                return;
                            }
                            let w = (ev.event.position.x - ev.bounds.origin.x)
                                .clamp(px(COL_MIN_W), px(COL_MAX_W));
                            if shell.columns[i].width != Some(w.into()) {
                                shell.columns[i].width = Some(w.into());
                                cx.notify();
                            }
                        },
                    ))
                    // The column's slim header: the stream's name (ink when
                    // focused, vermilion while a drag targets it, muted
                    // beside it) and the unpin ×. The header is the
                    // reorder drag's grabber.
                    .child(
                        div()
                            .id(SharedString::from(format!("col-h-{i}")))
                            .flex()
                            .items_center()
                            .gap_2()
                            .px_2()
                            .pb(px(8.0))
                            .on_drag(
                                ColumnDrag {
                                    from: i,
                                    label: label.clone(),
                                },
                                |value: &ColumnDrag, _, _, cx| {
                                    cx.new(|_| DragGhost {
                                        label: value.label.clone(),
                                    })
                                },
                            )
                            .child(
                                div()
                                    .text_size(px(theme::T_UI))
                                    .text_color(rgb(if is_drop_target {
                                        theme::vermilion()
                                    } else if is_focused {
                                        theme::ink()
                                    } else {
                                        theme::muted()
                                    }))
                                    .child(label),
                            )
                            .child(div().flex_1())
                            .when(self.columns.len() > 1, |d| {
                                d.child(
                                    div()
                                        .id(SharedString::from(format!("col-x-{i}")))
                                        .cursor_pointer()
                                        .text_size(px(theme::T_UI))
                                        // Ink, not muted: an affordance you
                                        // can't see is a broken affordance
                                        // (user report); the hover keeps
                                        // vermilion as the destructive tint.
                                        .text_color(rgb(theme::ink()))
                                        .hover(|s| s.text_color(rgb(theme::vermilion())))
                                        .on_click(cx.listener(move |shell, _, _, cx| {
                                            cx.stop_propagation();
                                            shell.remove_column(i, cx);
                                        }))
                                        .child("×"),
                                )
                            }),
                    )
                    .child(element)
                    // The width drag handle: a thin hit strip straddling
                    // the right hairline (the last column has one too —
                    // its drag narrows or widens from its left edge).
                    .child(
                        div()
                            .id(SharedString::from(format!("col-w-{i}")))
                            .absolute()
                            .top_0()
                            .bottom_0()
                            .right(px(-3.0))
                            .w(px(6.0))
                            .cursor_ew_resize()
                            .on_drag(WidthDrag { col: i }, |_, _, _, cx| {
                                cx.new(|_| DragGhost {
                                    label: "↔".into()
                                })
                            }),
                    ),
            );
        }
        div()
            .relative()
            .flex_1()
            .min_w_0()
            .h_full()
            .flex()
            .flex_col()
            .pt(px(16.0))
            // A width drag ends here (the row covers the whole
            // workspace): the live widths persist.
            .on_drop::<WidthDrag>(cx.listener(|shell, _, _, cx| {
                shell.save_layout();
                cx.notify();
            }))
            // The outbox honesty pill floats over the workspace too (it is
            // the SHELL's news, D26).
            .when(self.outbox_pending > 0, |d| {
                let n = self.outbox_pending;
                d.child(states::offline_pill(&format!(
                    "{n} note{} queued for delivery, the relays will answer",
                    if n == 1 { "" } else { "s" }
                )))
            })
            .child(row)
            // The add-column menu: an absolute card over the + slot; Esc
            // closes (back()'s workspace branch), a pick pins and closes.
            .when(self.add_menu, |d| d.child(self.add_menu_card(cx)))
    }

    /// The add-column menu: the kinds not already pinned, one row each.
    fn add_menu_card(&self, cx: &mut Context<Self>) -> Div {
        let pinned: Vec<ColumnKind> = self.columns.iter().map(|c| c.kind.clone()).collect();
        let mut card = div()
            .absolute()
            // Anchored to the rail now: the + lives in the sidebar (the
            // workspace row's slot is gone), so the card opens beside it
            // — top of the workspace, just clear of the 52px rail.
            .top(px(52.0))
            .left(px(12.0))
            .w(px(220.0))
            .rounded(px(theme::R_EMBED))
            .border_1()
            .border_color(rgb(theme::hairline()))
            .bg(rgb(theme::washi()))
            .py(px(4.0));
        for kind in ColumnKind::ALL {
            if pinned.contains(&kind) {
                continue;
            }
            let kind = kind.clone();
            let menu_kind = kind.clone();
            card = card.child(
                div()
                    .id(SharedString::from(format!("col-add-{}", kind.label())))
                    .cursor_pointer()
                    .px(px(12.0))
                    .py(px(8.0))
                    .flex()
                    .items_center()
                    .gap_2()
                    .text_size(px(theme::T_UI))
                    .text_color(rgb(theme::ink()))
                    .hover(|s| s.bg(rgb(theme::ink())))
                    .on_click(cx.listener(move |shell, _, _, cx| {
                        shell.add_menu = false;
                        shell.pin_column(menu_kind.clone(), cx);
                    }))
                    .child(kind.icon(theme::muted()))
                    .child(kind.label()),
            );
        }
        // The kind expansion's input rows (owner call): a hashtag and a
        // relay URL typed straight into the menu — no drill to visit
        // first. The relay column is the live wire (v1): since-launch
        // traffic from that one relay, no history.
        let tag_input = self.tag_input.clone();
        let relay_input = self.relay_input.clone();
        card = card
            .child(Self::menu_input_row(
                "Hashtag column",
                tag_input,
                "col-tag-field",
                cx.listener(move |shell, _, _, cx| shell.add_tag_column(cx)),
            ))
            .child(Self::menu_input_row(
                "Relay wire",
                relay_input,
                "col-relay-field",
                cx.listener(move |shell, _, _, cx| shell.add_relay_column(cx)),
            ));
        card
    }

    /// One + menu input row: the label, the field, the Add button.
    fn menu_input_row(
        label: &str,
        input: Entity<Input>,
        id: &'static str,
        on_add: impl Fn(&ClickEvent, &mut Window, &mut App) + 'static,
    ) -> Div {
        let focus_target = input.clone();
        div()
            .border_t_1()
            .border_color(rgb(theme::hairline()))
            .mt(px(4.0))
            .px(px(12.0))
            .py(px(8.0))
            .flex()
            .flex_col()
            .gap_1()
            .child(
                div()
                    .text_size(px(theme::T_SMALL))
                    .text_color(rgb(theme::muted()))
                    .child(label.to_string()),
            )
            .child(
                div()
                    .id(id)
                    .cursor_text()
                    .h(px(28.0))
                    .px_2()
                    .rounded(px(theme::R_INPUT))
                    .bg(rgb(theme::panel()))
                    .border_1()
                    .border_color(rgb(theme::hairline()))
                    .child(input)
                    .on_click(move |_, window, cx| {
                        let fh = focus_target.read(cx).focus_handle(cx);
                        window.focus(&fh, cx);
                    }),
            )
            .child(
                div()
                    .id(SharedString::from(format!("{id}-add")))
                    .cursor_pointer()
                    .self_start()
                    .px(px(8.0))
                    .py(px(2.0))
                    .rounded(px(theme::R_EMBED))
                    .border_1()
                    .border_color(rgb(theme::hairline()))
                    .text_size(px(theme::T_UI))
                    .text_color(rgb(theme::muted()))
                    .hover(|s| {
                        s.border_color(rgb(theme::vermilion()))
                            .text_color(rgb(theme::vermilion()))
                    })
                    .on_click(on_add)
                    .child("Add"),
            )
    }

    /// A pane as an element (the shared match the single-pane column and
    /// every workspace column ride).
    fn pane_element(pane: &Pane) -> AnyElement {
        match pane {
            Pane::Feed(view) => view.clone().into_any_element(),
            Pane::Articles(view) => view.clone().into_any_element(),
            Pane::Library(view) => view.clone().into_any_element(),
            Pane::Hashtag(view) => view.clone().into_any_element(),
            Pane::Thread(view) => view.clone().into_any_element(),
            Pane::Profile(view) => view.clone().into_any_element(),
            Pane::EditProfile(view) => view.clone().into_any_element(),
            Pane::Notifications(view) => view.clone().into_any_element(),
            Pane::Search(view) => view.clone().into_any_element(),
            Pane::Settings(view) => view.clone().into_any_element(),
            Pane::Article(view) => view.clone().into_any_element(),
            Pane::Composer(view) => view.clone().into_any_element(),
            Pane::Wallet(view) => view.clone().into_any_element(),
            Pane::Wire(view) => view.clone().into_any_element(),
        }
    }

    /// The undo-window toast: floats bottom-center over any pane —
    /// countdown + Undo while held, a brief "undone" whisper, a sticky
    /// failure line (cleared by the next publish).
    fn hold_toast(&mut self, cx: &mut Context<Self>) -> impl IntoElement {
        let held = self.hold.as_ref().unwrap();
        let text = if let Some(e) = &held.err {
            format!("failed: {e}")
        } else if held.undone {
            "undone, nothing was sent".to_string()
        } else {
            let left = held
                .deadline
                .saturating_duration_since(std::time::Instant::now());
            if left.is_zero() {
                // The undo window closed; the commit rides the relays
                // (seconds over Tor). The old fake "1s" read as stuck.
                "sending…".to_string()
            } else {
                format!("publishing in {}s", left.as_secs().max(1))
            }
        };
        div()
            .absolute()
            .left(px(0.))
            .right(px(0.))
            .bottom(px(16.))
            .flex()
            .justify_center()
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_3()
                    .rounded(px(theme::R_EMBED))
                    .border_1()
                    .border_color(rgb(theme::hairline()))
                    .bg(rgb(theme::panel()))
                    .px_4()
                    .py_2()
                    .text_size(px(theme::T_UI))
                    .text_color(rgb(theme::muted()))
                    .child(text)
                    .when(held.undone || held.err.is_some(), |d| d), // shape only
            )
            .when(!held.undone && held.err.is_none(), |d| {
                d.child(
                    div()
                        .id("hold-undo")
                        .flex()
                        // Center the label in its own box: a plain text
                        // child paints at the top of the button's padded
                        // box and reads as misaligned against the toast's
                        // centered line.
                        .items_center()
                        .justify_center()
                        .cursor_pointer()
                        .px_2()
                        .py(px(2.))
                        .rounded(px(theme::R_EMBED))
                        // Solid, like the Reply/Publish buttons: a
                        // border-only ghost on the pill read as a
                        // transparent non-button.
                        .bg(rgb(theme::vermilion()))
                        .text_color(rgb(theme::washi()))
                        .text_size(px(theme::T_UI))
                        .on_click(cx.listener(|shell, _, _, cx| {
                            if let Some(h) = shell.hold.as_ref() {
                                shell.core.undo(h.token);
                            }
                            cx.notify();
                        }))
                        .child("Undo"),
                )
            })
    }
}

/// A single-line input for the shell's + menu (settings.rs single_line's
/// shape: multiline off, a placeholder that shows the expected shape).
/// A sheet overlay (the zap amount card, the reply box, #21): the card
/// floats centered over a dim scrim — the pane you were reading stays
/// visible underneath. Any click that bubbles to the overlay root closes
/// — the card stops propagation so a stray click inside it doesn't; Esc
/// goes through back(), which the overlay owns. The scrim is a separate
/// visual layer because opacity washes the whole subtree.
fn card_overlay<V: gpui::Render>(
    id: &'static str,
    card: Entity<V>,
    w: f32,
    max_h: Option<f32>,
    cx: &mut Context<Shell>,
) -> impl IntoElement {
    div()
        .id(SharedString::from(format!("{id}-overlay")))
        .absolute()
        .inset_0()
        .on_mouse_down(
            gpui::MouseButton::Left,
            cx.listener(|shell, _, _, cx| {
                shell.back(cx);
            }),
        )
        .child(div().absolute().inset_0().bg(rgb(0x000000)).opacity(0.55))
        .child(
            div()
                .absolute()
                .inset_0()
                .flex()
                .items_center()
                .justify_center()
                .child(
                    div()
                        .id(SharedString::from(format!("{id}-card")))
                        .w(px(w))
                        .max_w(px(content::COL_W + 120.))
                        // Content-sized: the card HUGS the form (a fixed height
                        // strands dead space under the action bar). A cap turns
                        // the card into the scroller — the form outgrows it, the
                        // card never outgrows the window.
                        .when_some(max_h, |d, h| d.max_h(px(h)))
                        .when(max_h.is_some(), |d| d.overflow_y_scroll())
                        .rounded(px(theme::R_INPUT))
                        .border_1()
                        .border_color(rgb(theme::hairline()))
                        .bg(rgb(theme::washi()))
                        .shadow_lg()
                        .on_mouse_down(gpui::MouseButton::Left, |_, _, cx| {
                            cx.stop_propagation();
                        })
                        .child(card),
                ),
        )
}

/// The lightbox overlay (lightbox.rs): dark full-screen viewer, fit-to-screen
/// image, ‹ › pager zones, Esc/arrow keys, click-to-advance on the picture.
fn lightbox_overlay(urls: &[String], idx: usize, cx: &mut Context<Shell>) -> impl IntoElement {
    let snap = media::Snapshot::new(cx);
    let n = urls.len();
    let png = urls.get(idx).and_then(|u| snap.png(u));
    let caption = format!("{} / {}", idx + 1, n);

    div()
        .absolute()
        .inset_0()
        .bg(rgb(0x000000))
        .opacity(0.94)
        .flex()
        .flex_col()
        .font_family(theme::SANS)
        // Top bar: index + close.
        .child(
            div()
                .flex()
                .items_center()
                .justify_between()
                .px_4()
                .py_2()
                .child(
                    div()
                        .text_size(px(theme::T_SMALL))
                        .text_color(rgb(0xb8b2a6))
                        .child(caption),
                )
                .child(
                    div()
                        .id("lb-close")
                        .cursor_pointer()
                        .px_2()
                        .text_size(px(theme::T_UI))
                        .text_color(rgb(0xb8b2a6))
                        .on_click(cx.listener(|shell, _, _, cx| {
                            shell.lightbox = None;
                            cx.notify();
                        }))
                        .child("✕"),
                ),
        )
        // Middle: pager zones flanking the fit-to-screen image.
        .child(
            div()
                .flex_1()
                .min_h_0()
                .flex()
                .child(
                    div()
                        .id("lb-prev")
                        .cursor_pointer()
                        .w(px(64.))
                        .flex()
                        .items_center()
                        .justify_center()
                        .on_click(cx.listener(|shell, _, _, cx| shell.lightbox_nav(-1, cx)))
                        .child(
                            div()
                                .text_size(px(22.0))
                                .text_color(rgb(0xb8b2a6))
                                .child("‹"),
                        ),
                )
                .child(
                    div()
                        .flex_1()
                        .min_w_0()
                        .flex()
                        .items_center()
                        .justify_center()
                        .p_2()
                        .child(match png {
                            Some(p) => img(p)
                                .size_full()
                                .object_fit(ObjectFit::Contain)
                                .into_any_element(),
                            None => div()
                                .text_size(px(theme::T_SMALL))
                                .text_color(rgb(0xb8b2a6))
                                .child("…")
                                .into_any_element(),
                        }),
                )
                .child(
                    div()
                        .id("lb-next")
                        .cursor_pointer()
                        .w(px(64.))
                        .flex()
                        .items_center()
                        .justify_center()
                        .on_click(cx.listener(|shell, _, _, cx| shell.lightbox_nav(1, cx)))
                        .child(
                            div()
                                .text_size(px(22.0))
                                .text_color(rgb(0xb8b2a6))
                                .child("›"),
                        ),
                ),
        )
        .child(
            // Clicking anywhere else in the dark closes (lightbox.rs Esc).
            div()
                .id("lb-backdrop")
                .flex_1()
                .cursor_pointer()
                .on_click(cx.listener(|shell, _, _, cx| {
                    shell.lightbox = None;
                    cx.notify();
                })),
        )
}

/// The video overlay (Phase 3): dark full-screen player mirroring the
/// lightbox — the crate's element aspect-fit inside a centered box, the
/// control row under it (⏸/▶, ↗ browser), ✕/Esc/backdrop close (the
/// pipeline tears down via close_video).
fn video_overlay(url: &str, cx: &mut Context<Shell>) -> impl IntoElement {
    let video = crate::video::active(url);
    let paused_now = video.as_ref().is_some_and(|v| v.paused());
    let browser = url.to_string();

    div()
        .absolute()
        .inset_0()
        .bg(rgb(0x000000))
        .opacity(0.94)
        .flex()
        .flex_col()
        .font_family(theme::SANS)
        // Top bar: the mark + close.
        .child(
            div()
                .flex()
                .items_center()
                .justify_between()
                .px_4()
                .py_2()
                .child(
                    div()
                        .text_size(px(theme::T_SMALL))
                        .text_color(rgb(0xb8b2a6))
                        .child("▶"),
                )
                .child(
                    div()
                        .id("vid-close")
                        .cursor_pointer()
                        .px_2()
                        .text_size(px(theme::T_UI))
                        .text_color(rgb(0xb8b2a6))
                        .on_click(cx.listener(|shell, _, _, cx| shell.close_video(cx)))
                        .child("✕"),
                ),
        )
        // Middle: the player centered in the spare space, its control row
        // directly beneath.
        .child(
            div()
                .flex_1()
                .min_h_0()
                .flex()
                .flex_col()
                .child(
                    div()
                        .flex_1()
                        .min_h_0()
                        .flex()
                        .items_center()
                        .justify_center()
                        .p_2()
                        .child(match video {
                            Some(v) => crate::video::element(&v, content::COL_W - 64.0, 480.0)
                                .into_any_element(),
                            None => div()
                                .text_size(px(theme::T_SMALL))
                                .text_color(rgb(0xb8b2a6))
                                .child("…")
                                .into_any_element(),
                        }),
                )
                .child(
                    div()
                        .flex()
                        .items_center()
                        .justify_center()
                        .gap_4()
                        .py_2()
                        .child(
                            div()
                                .id("vid-toggle")
                                .cursor_pointer()
                                .text_size(px(theme::T_BODY))
                                .text_color(rgb(0xb8b2a6))
                                .on_click(|_, _, cx| {
                                    cx.stop_propagation();
                                    crate::video::toggle(cx);
                                })
                                .child(if paused_now { "▶" } else { "⏸" }),
                        )
                        .child(
                            div()
                                .id("vid-browser")
                                .cursor_pointer()
                                .text_size(px(theme::T_BODY))
                                .text_color(rgb(0xb8b2a6))
                                .on_click(move |_, _, cx| {
                                    cx.stop_propagation();
                                    if crate::views::content::web_url(&browser) {
                                        cx.open_url(&browser);
                                    }
                                })
                                .child("↗"),
                        ),
                ),
        )
        .child(
            // Clicking the dark closes (lightbox.rs Esc), pipeline with it.
            div()
                .id("vid-backdrop")
                .flex_1()
                .cursor_pointer()
                .on_click(cx.listener(|shell, _, _, cx| shell.close_video(cx))),
        )
}
