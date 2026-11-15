//! Profile view: an author's header, their notes as a feed, and media strips.
//!
//! TODO(port): crates/app/src/profile.rs — P1 (D30 reworked the notes list).
//! Header: banner strip (cover-fit, hairline, nothing when absent), 72px
//! avatar, NIP-05 verification badge, click-to-copy npub/Lightning rows,
//! live about text. The Notes tab hosts an embedded `Feed`
//! (`FeedMode::Profile`) — the timeline's exact cards; Photos/Videos are
//! 3-column thumbnail grids that page endlessly (`profile_older`, deduped).
//! Follow/mute management ports with the rest of the settings scope (P3).

use std::{collections::HashMap, collections::HashSet, sync::Arc, time::Duration};

use gpui::{
    AnyElement, Context, Div, Entity, EventEmitter, FontWeight, ListAlignment, ListScrollEvent,
    ListState, ObjectFit, Render, SharedString, Window, div, img, list, prelude::*, px, rgb,
};
use nostr::prelude::*;
use satori_core::manager::{Core, FeedEvent, FeedRx, Profile};

use super::{content, feed::Feed, nav, nav::Nav, states};
use crate::{icons, media, theme};
use satori_core::wot::Verdict;

/// Which profile surface is up: the notes body or the media strips
/// (Phase 2 §4.3 — Photos/Videos, three-column thumbnails).
/// One Videos-strip tile: (url, poster, blurhash, imeta mime).
pub(crate) type VidTile = (String, Option<String>, Option<String>, Option<String>);

#[derive(Clone, Copy, PartialEq)]
enum ProfileTab {
    Notes,
    Photos,
    Videos,
}

/// One list row of the active tab (render-time projection).
enum Row {
    /// Up to three thumbnails: (url, index into the tab's lightbox list).
    Pics(Vec<(String, usize)>),
    /// Up to three video tiles: (url, poster, blurhash, imeta mime) — the
    /// same 3-column grid as the photos, the play badge marking them.
    Vids(Vec<VidTile>),
}

pub struct ProfileView {
    core: Arc<Core>,
    /// The profile this pane shows (the workspace's + Column affordance
    /// reads it to pin the @user column — D68's kind expansion).
    pub(crate) who: PublicKey,
    profile: Option<Profile>,
    notes: Vec<Event>,
    /// The active surface (notes body / media strips — Phase 2 §4.3).
    tab: ProfileTab,
    following: bool,
    /// This pane IS the signed-in user (D38): the own profile shows the
    /// Edit-profile button in place of Follow/Mute.
    pub(crate) is_me: bool,
    /// Mirror of the mute list (Core::is_muted at construction) — the
    /// header's Mute button flips it optimistically.
    muted: bool,
    /// Known profiles — mention names in note bodies (word_flow).
    profiles: HashMap<String, Profile>,
    /// The Notes tab: an embedded Feed (FeedMode::Profile) — the timeline's
    /// exact rows (avatar, media, the reaction row) scoped to this author.
    /// The profile owns the header + strips; the list itself is the child's.
    notes_feed: Entity<Feed>,
    /// Mirror of the child feed's deep-scroll state — the shell reads the
    /// pane view's field for the back-to-top whisper (Nav::PaneDeep).
    pub(crate) deep: bool,
    /// Endless scroll for the media strips (the feed's pattern): a page in
    /// flight, whether relays may hold more, the paging anchor (the oldest
    /// timestamp EVER absorbed — `notes` is newest-first, so its last row),
    /// the scroll stream's last visible end, and the absorbed ids (dedupe).
    has_more: bool,
    paging: bool,
    oldest_ts: Option<u64>,
    last_visible_end: usize,
    /// The scroll stream's first visible row (the strip window's head):
    /// the fetch/pin sweep covers ONLY this window, so a photo-heavy
    /// profile queues the viewport's tiles, not the whole scroll history.
    first_visible_start: usize,
    note_ids: HashSet<EventId>,
    status: String,
    /// §4.3: the kinded error strip (replaces the raw `… {e}` status dump).
    error: Option<states::PaneError>,
    /// NIP-05 verdict memo: (address, verdict — None while the check is in
    /// flight). Keyed by the address so a changed one re-fires; unproven
    /// and failed both stay visually quiet (the badge is an affordance,
    /// never an accusation).
    nip05_memo: Option<(String, Option<bool>)>,
    /// Which copy seal is flashing "copied" ("link" | "lud"); a 2s timer
    /// clears it (login.rs's copied pattern).
    copied: Option<&'static str>,
    list: ListState,
    /// The strips' URL projections, rebuilt once per DATA change (the
    /// notes vec), not per scroll tick or render: photo_urls/video_urls
    /// used to re-parse every note's imeta + tags (uncached media_assets
    /// over the WHOLE paged history) on every wheel event — O(total
    /// notes) tag parsing on the UI thread to slice ~9 tiles.
    photo_cache: Vec<String>,
    video_cache: Vec<VidTile>,
}

impl EventEmitter<Nav> for ProfileView {}

impl ProfileView {
    pub fn new(core: Arc<Core>, who: PublicKey, is_me: bool, cx: &mut Context<Self>) -> Self {
        crate::theme::watch(cx); // repaint on theme change
        crate::timefmt::watch(cx); // repaint on mode/height change
        crate::video::watch(cx); // repaint on player open/toggle/close
        let notes_feed = cx.new(|cx| Feed::author(core.clone(), who, cx));
        // The child feed owns the notes list; forward its navs upward (the
        // shell only subscribes to the pane view) and mirror the deep flag.
        cx.subscribe(&notes_feed, |this, feed, ev: &Nav, cx| {
            if matches!(ev, Nav::PaneDeep) {
                this.deep = feed.read(cx).deep;
            }
            cx.emit(ev.clone());
        })
        .detach();
        let view = Self {
            following: core.is_following(&who),
            is_me,
            muted: core.is_muted(&who),
            who,
            profile: None,
            notes: vec![],
            tab: ProfileTab::Notes,
            profiles: HashMap::new(),
            notes_feed,
            deep: false,
            has_more: true,
            paging: false,
            oldest_ts: None,
            last_visible_end: 0,
            first_visible_start: 0,
            note_ids: HashSet::new(),
            status: "loading…".into(),
            error: None,
            nip05_memo: None,
            copied: None,
            list: ListState::new(0, ListAlignment::Top, px(400.)),
            photo_cache: vec![],
            video_cache: vec![],
            core,
        };
        // Endless scroll for the strips (the feed's pattern): the list's
        // scroll stream orders the next older page near the end cap, and
        // floats the back-to-top whisper a few rows down. The handler runs
        // on &mut App; WeakEntity::update accepts that. (The Notes tab's
        // list belongs to the child feed — its own handler pages there.)
        let this = cx.entity().downgrade();
        view.list
            .set_scroll_handler(move |ev: &ListScrollEvent, _w, cx| {
                let _ = this.update(cx, |this, cx| {
                    this.first_visible_start = ev.visible_range.start;
                    this.last_visible_end = ev.visible_range.end;
                    let deep = ev.visible_range.start >= nav::PANE_DEEP_AT;
                    if this.deep != deep {
                        this.deep = deep;
                        cx.emit(Nav::PaneDeep);
                    }
                    this.maybe_older(this.last_visible_end, cx);
                    // The window moved: fetch + pin its tiles (the feed's
                    // scroll-handler pin).
                    this.pin_window(cx);
                });
            });
        let rx = view.core.profile(view.who);
        view.pump(rx, cx);
        view
    }

    /// The profile's fetch + pin discipline in ONE place: the header
    /// identity plus the VISIBLE strip tiles (three tiles per strip row,
    /// the feed's window discipline). Called at render (landings) and from
    /// the scroll stream — the two moments the on-screen set changes. The
    /// Notes tab is the child Feed's list: it pins its own window.
    fn pin_window(&mut self, cx: &mut Context<Self>) {
        let viewer = cx.entity_id();
        let mut painted: Vec<String> = Vec::new();
        if let Some(p) = self.profile.as_ref() {
            painted.push(p.picture.clone());
            painted.push(p.banner.clone());
            if let Some(h) = &p.banner_blurhash {
                painted.push(crate::poster::blurhash_key(h));
            }
            media::fetch(&self.core, p.picture.clone(), viewer, cx);
            media::fetch(&self.core, p.banner.clone(), viewer, cx);
            // NIP-92: the banner's blurhash placeholder decodes locally
            // (virtual key, no network).
            if let Some(h) = &p.banner_blurhash {
                media::fetch(&self.core, crate::poster::blurhash_key(h), viewer, cx);
            }
        }
        match self.tab {
            ProfileTab::Photos => {
                let urls = self.photo_urls();
                let start = self.first_visible_start.min(urls.len().div_ceil(3));
                let end = self
                    .last_visible_end
                    .max(start + 3)
                    .min(urls.len().div_ceil(3));
                for url in urls.iter().take(end * 3).skip(start * 3) {
                    media::fetch(&self.core, url.clone(), viewer, cx);
                    if !url.is_empty() && !painted.contains(url) {
                        painted.push(url.clone());
                    }
                }
            }
            ProfileTab::Videos => {
                let urls = self.video_urls();
                let start = self.first_visible_start.min(urls.len().div_ceil(3));
                let end = self
                    .last_visible_end
                    .max(start + 3)
                    .min(urls.len().div_ceil(3));
                for (url, poster, blurhash, _) in urls.iter().take(end * 3).skip(start * 3) {
                    // A tile paints its poster when there is one, else the
                    // sniffed first frame (queued here; a real frame beats
                    // an impression), else the blurhash filler (the same
                    // ladder the feed paints). The VIDEO url itself is
                    // never pinned: the tile never paints it as an image,
                    // and pinning it would pin whole files.
                    if let Some(p) = poster {
                        media::fetch(&self.core, p.clone(), viewer, cx);
                        if !p.is_empty() && !painted.contains(p) {
                            painted.push(p.clone());
                        }
                    } else {
                        let key = crate::poster::poster_key(url);
                        media::fetch(&self.core, key.clone(), viewer, cx);
                        if !painted.contains(&key) {
                            painted.push(key);
                        }
                        if let Some(h) = blurhash {
                            let key = crate::poster::blurhash_key(h);
                            media::fetch(&self.core, key.clone(), viewer, cx);
                            if !painted.contains(&key) {
                                painted.push(key);
                            }
                        }
                    }
                }
            }
            ProfileTab::Notes => {}
        }
        media::repin(cx.entity_id(), painted, cx);
    }

    /// Back to the top (rail re-click, the floating whisper): the notes
    /// list is the child feed's.
    pub fn scroll_top(&mut self, cx: &mut Context<Self>) {
        self.deep = false;
        self.notes_feed.update(cx, |feed, _| feed.scroll_top());
    }

    fn pump(&self, mut rx: FeedRx, cx: &mut Context<Self>) {
        cx.spawn(async move |this, cx| {
            while let Some(ev) = rx.recv().await {
                let _ = this.update(cx, |this, cx| this.on_event(ev, cx));
            }
        })
        .detach();
    }

    /// D38: the edit form just landed a fresh kind 0 — swap the header's
    /// copy (name/about/picture/banner re-derive at render; a changed
    /// NIP-05 re-fires its memo, a changed picture refetches by URL).
    pub(crate) fn refresh_profile(&mut self, p: Profile, cx: &mut Context<Self>) {
        self.profiles.insert(p.pubkey.clone(), p.clone());
        self.profile = Some(p);
        cx.notify();
    }

    fn on_event(&mut self, ev: FeedEvent, cx: &mut Context<Self>) {
        match ev {
            FeedEvent::Loaded(page) => {
                for p in &page.profiles {
                    self.profiles.insert(p.pubkey.clone(), p.clone());
                }
                self.profile = page
                    .profiles
                    .iter()
                    .find(|p| p.pubkey == self.who.to_string())
                    .cloned();
                if let Some(p) = self.profile.clone() {
                    self.want_avatar(&p, cx);
                    self.want_nip05(&p, cx);
                }
                // All visible kinds land; each tab filters (the strips read
                // kind 20 + imeta-bearing kind 1 — Phase 2 §4.3). The notes
                // LIST is the child feed's; this Vec feeds the strips.
                self.notes = page.notes;
                self.note_ids = self.notes.iter().map(|n| n.id).collect();
                self.oldest_ts = self.notes.last().map(|n| n.created_at.as_secs());
                self.refresh_strips();
                for note in self.notes.clone() {
                    self.want_media(&note, cx);
                }
                self.status.clear();
                self.error = None;
            }
            // The strips' next page (endless scroll): dedupe by id — the
            // store page may hand back rows the page boundary already
            // delivered — then append behind the window (newest-first
            // order throughout). Then chain, like the feed: the reader may
            // still be at the end cap, and waiting for a wheel tick that
            // may never come strands them there.
            FeedEvent::Older(page, has_more) => {
                self.paging = false;
                self.has_more = has_more;
                for p in &page.profiles {
                    self.profiles.insert(p.pubkey.clone(), p.clone());
                }
                for n in page.notes {
                    if self.note_ids.insert(n.id) {
                        self.want_media(&n, cx);
                        self.notes.push(n);
                    }
                }
                self.oldest_ts = self.notes.last().map(|n| n.created_at.as_secs());
                self.refresh_strips();
                self.status.clear();
                if self.has_more {
                    self.maybe_older(self.last_visible_end, cx);
                }
            }
            FeedEvent::Failed(e) => {
                // §4.3: transient — Retry re-asks the profile + strips.
                self.error = Some(states::PaneError::transient("The profile", &e));
            }
            _ => {}
        }
        self.list.reset(self.row_count());
        cx.notify();
    }

    // --- the strips' projections (Phase 2 §4.3) -------------------------------

    /// Rebuild the strips' URL projections (once per notes change — see
    /// the field comment).
    fn refresh_strips(&mut self) {
        self.photo_cache = self
            .notes
            .iter()
            .filter(|n| u16::from(n.kind) == 20 || n.kind == Kind::TextNote)
            .flat_map(content::media_assets)
            .filter_map(|a| match a {
                content::MediaAsset::Picture { url } => Some(url),
                _ => None,
            })
            .collect();
        self.video_cache = self
            .notes
            .iter()
            .filter(|n| matches!(u16::from(n.kind), 1 | 21 | 22))
            .flat_map(|n| {
                content::media_assets(n)
                    .into_iter()
                    .filter_map(|a| match a {
                        content::MediaAsset::Video {
                            url,
                            poster,
                            blurhash,
                            mime,
                        } => Some((url, poster, blurhash, mime)),
                        _ => None,
                    })
            })
            .collect();
    }

    /// The Photos strip: every picture URL in timeline order (kind 20 +
    /// imeta-bearing kind 1), flat — the grid chunks it into threes.
    fn photo_urls(&self) -> &[String] {
        &self.photo_cache
    }

    /// The Videos strip: every video asset in timeline order (kind 21/22,
    /// plus imeta/link videos on kind 1) — url + poster + blurhash + imeta
    /// mime. All of a note's videos, the same way Photos takes all of its
    /// pictures. Video files themselves are never fetched; the preview is
    /// the publisher's poster, a blurhash, or a sniffed first frame (D32).
    fn video_urls(&self) -> &[VidTile] {
        &self.video_cache
    }

    /// The active tab's list-row count (list.reset wants it at event time).
    /// The Notes tab keeps no rows here — the list is the child feed's.
    fn row_count(&self) -> usize {
        match self.tab {
            ProfileTab::Notes => 0,
            ProfileTab::Photos => self.photo_urls().len().div_ceil(3),
            ProfileTab::Videos => self.video_urls().len().div_ceil(3),
        }
    }

    /// Near the end of a media strip, order the next older page (the feed's
    /// endless-scroll lookahead, in strip rows — three media each). The
    /// Notes tab never pages here: its list is the child feed's.
    fn maybe_older(&mut self, visible_end: usize, cx: &mut Context<Self>) {
        const LOOKAHEAD: usize = 3;
        if !self.has_more || self.paging || self.notes.is_empty() {
            return;
        }
        let total = match self.tab {
            ProfileTab::Notes => return,
            ProfileTab::Photos => self.photo_urls().len().div_ceil(3),
            ProfileTab::Videos => self.video_urls().len().div_ceil(3),
        };
        if visible_end + LOOKAHEAD < total {
            return;
        }
        self.paging = true;
        let oldest = self.oldest_ts.unwrap_or(0);
        let rx = self.core.profile_older(self.who, oldest);
        self.pump(rx, cx);
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

    /// Fire the NIP-05 verification once per profile arrival: the domain's
    /// nostr.json is asked (one guarded fetch, core-side) whether the name
    /// maps to this pubkey. The memo skips refires across re-renders; a
    /// changed address re-fires. The answer lands as the badge's state.
    fn want_nip05(&mut self, p: &Profile, cx: &mut Context<Self>) {
        if p.nip05.is_empty() {
            self.nip05_memo = None;
            return;
        }
        if self
            .nip05_memo
            .as_ref()
            .is_some_and(|(addr, _)| addr == &p.nip05)
        {
            return; // in flight or answered for this address
        }
        self.nip05_memo = Some((p.nip05.clone(), None));
        let rx = self
            .core
            .verify_nip05(p.nip05.clone(), self.who.to_string());
        let h = cx.entity().downgrade();
        cx.spawn(async move |_this, cx| {
            let verdict = {
                let mut rx = rx;
                rx.recv().await
            }
            .flatten();
            let _ = h.update(cx, |this, cx| {
                if let Some(memo) = &mut this.nip05_memo {
                    memo.1 = verdict;
                }
                cx.notify();
            });
        })
        .detach();
    }

    /// Copy `payload` and flash the clicked seal's label to "copied" for
    /// 2s (login.rs's copied pattern — acknowledgment, not chrome).
    fn flash_copy(&mut self, which: &'static str, payload: String, cx: &mut Context<Self>) {
        cx.write_to_clipboard(gpui::ClipboardItem::new_string(payload));
        self.copied = Some(which);
        cx.notify();
        let reset = cx.spawn(async move |this, cx| {
            cx.background_executor().timer(Duration::from_secs(2)).await;
            let _ = this.update(cx, |this, cx| {
                if this.copied == Some(which) {
                    this.copied = None;
                    cx.notify();
                }
            });
        });
        reset.detach();
    }

    /// Queue core fetches for every media URL in a note (avatars share the
    /// same cache; URLs are unique so there's no clash).
    fn want_media(&mut self, note: &Event, cx: &mut Context<Self>) {
        for url in content::media_urls_cached(note).iter().cloned() {
            media::fetch(&self.core, url, cx.entity_id(), cx);
        }
    }

    /// One strip tab: a quiet label, the active one ink + underlined.
    fn tab_btn(
        &self,
        which: ProfileTab,
        label: &'static str,
        active: ProfileTab,
        cx: &Context<Self>,
    ) -> AnyElement {
        let on = which == active;
        div()
            .id(SharedString::from(format!("tab-{label}")))
            .cursor_pointer()
            .text_size(px(theme::T_UI))
            .text_color(rgb(if on { theme::ink() } else { theme::muted() }))
            .when(on, |d| d.underline())
            .child(label)
            .on_click(cx.listener(move |view, _, _, cx| {
                if view.tab != which {
                    view.tab = which;
                    view.list.reset(view.row_count());
                    cx.notify();
                }
            }))
            .into_any_element()
    }
}

impl Render for ProfileView {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let who_hex = self.who.to_string();
        let name = content::display_name(self.profile.as_ref(), &who_hex);
        let about = self
            .profile
            .as_ref()
            .map(|p| p.about.clone())
            .unwrap_or_default();
        let picture = self
            .profile
            .as_ref()
            .map(|p| p.picture.clone())
            .unwrap_or_default();
        let banner = self
            .profile
            .as_ref()
            .map(|p| p.banner.clone())
            .unwrap_or_default();
        let banner_blurhash = self
            .profile
            .as_ref()
            .and_then(|p| p.banner_blurhash.clone());
        let nip05 = self
            .profile
            .as_ref()
            .map(|p| p.nip05.clone())
            .unwrap_or_default();
        let lud = self
            .profile
            .as_ref()
            .map(|p| p.lud.clone())
            .unwrap_or_default();
        // The share payload: the profile as a NIP-21 URI (npub form — D27's
        // scheme; settings.rs uses the same bech32 encoding).
        let npub_uri = format!(
            "nostr:{}",
            self.who.to_bech32().unwrap_or_else(|_| who_hex.clone())
        );
        // Brief display form (login.rs's uri_brief shape): scheme stripped,
        // leading chars + ellipsis. The full URI still rides the clipboard.
        let npub_brief = format!(
            "{}…",
            npub_uri
                .strip_prefix("nostr:")
                .unwrap_or(&npub_uri)
                .chars()
                .take(16)
                .collect::<String>()
        );
        let tab = self.tab;
        let rows: Vec<Row> = match tab {
            // The notes list is the child feed's — only the strips project
            // rows here.
            ProfileTab::Notes => vec![],
            ProfileTab::Photos => self
                .photo_urls()
                .chunks(3)
                .enumerate()
                .map(|(r, chunk)| {
                    Row::Pics(
                        chunk
                            .iter()
                            .enumerate()
                            .map(|(i, u)| (u.clone(), r * 3 + i))
                            .collect(),
                    )
                })
                .collect(),
            ProfileTab::Videos => self
                .video_urls()
                .chunks(3)
                .map(|chunk| Row::Vids(chunk.to_vec()))
                .collect(),
        };
        // The Photos strip's lightbox list (tile taps index into it) —
        // owned: it escapes into the list closure, past pin_window's &mut.
        let pics_all = self.photo_urls().to_vec();
        let empty = rows.is_empty();
        let following = self.following;
        let muted = self.muted;
        // Copy-seal states: which seal (if any) is flashing "copied", and
        // whether the domain's nostr.json vouched for the NIP-05 address.
        let link_flash = self.copied == Some("link");
        let lud_flash = self.copied == Some("lud");
        let nip05_ok = self
            .nip05_memo
            .as_ref()
            .is_some_and(|(addr, v)| addr == &nip05 && matches!(v, Some(true)));
        let media = media::Snapshot::new(cx);
        // The profile's media discipline is ONE place (pin_window): the
        // header identity plus the VISIBLE strip tiles, fetched AND pinned.
        // The window matters in both directions — the old render swept and
        // pinned EVERY note's media: a photo-heavy profile queued its whole
        // scroll history through the six-slot gate (scrolling starved
        // behind the queue — the "images won't load while scrolling"
        // report) and held every decoded 24MP picture past the caps (the
        // valve skips pins when picking victims). The item closures fetch
        // their rows on scroll; this is the landing-time backstop, and
        // fetch is a silent no-op for entries the cache holds.
        self.pin_window(cx);
        let profiles = self.profiles.clone();
        // The about block's token context: about text never embeds quotes —
        // an empty map satisfies Body.
        let quotes = content::Quotes::default();
        let handle = cx.entity();
        let follow_handle = handle.clone();
        let edit_handle = handle.clone();
        let mute_handle = handle.clone();
        // The profile trust badge (WS3): one quiet pill under the name,
        // the shared verdict vocabulary's answer for this author. Unknown
        // renders NOTHING — the graph declining to answer is not a
        // judgment, and an honest absence beats a wrong label. Vermilion
        // stays a seal: the pill is washi + muted, never tinted.
        let badge = crate::prefs::get_bool_or("profile_badge", true)
            .then(|| {
                let (v, shared) = self
                    .core
                    .verdict(&self.who)
                    .with_count(self.core.shared_follows(&self.who));
                match v {
                    Verdict::Follow => Some("You follow".to_string()),
                    Verdict::Trusted => Some(format!("In your network · {shared} shared follows")),
                    Verdict::NotInNetwork => Some("Outside your network".to_string()),
                    _ => None,
                }
            })
            .flatten();
        let ctx = content::Body {
            media: &media,
            quotes: &quotes,
            profiles: &profiles,
            // A bio is the kind-0 about text — no emoji tags of its own.
            emoji: std::sync::Arc::default(),
        };

        div()
            .flex_1()
            .min_h_0()
            .overflow_hidden()
            .flex()
            .flex_col()
            .child(
                // Header: banner strip, identity, lightning pointer, about —
                // inner content rides the same centered column as the notes
                // below.
                div()
                    .w_full()
                    .flex()
                    .flex_col()
                    .items_center()
                    .border_b_1()
                    .border_color(rgb(theme::hairline()))
                    .bg(rgb(theme::panel()))
                    // The banner: a quiet strip under a hairline, cover-fit —
                    // no gradient, no chrome. A profile without a banner
                    // renders nothing here at all. The frame clips (flex_none
                    // + overflow_hidden — content.rs's media-tile frame): an
                    // unclipped img paints its texture over the siblings
                    // below.
                    .when(!banner.is_empty(), |d| {
                        d.child(
                            div()
                                .flex_none()
                                .overflow_hidden()
                                .w_full()
                                .h(px(120.0))
                                .border_b_1()
                                .border_color(rgb(theme::hairline()))
                                .bg(rgb(theme::panel()))
                                .child(match media.png(&banner) {
                                    Some(png) => img(png)
                                        .w_full()
                                        .h_full()
                                        .object_fit(ObjectFit::Cover)
                                        .into_any_element(),
                                    // Bytes in flight: the banner's blurhash
                                    // gradient (NIP-92 kind-0 imeta) stands in
                                    // for the flat panel.
                                    None => {
                                        match banner_blurhash.as_deref().and_then(|h| {
                                            media.png(&crate::poster::blurhash_key(h))
                                        }) {
                                            Some(png) => img(png)
                                                .w_full()
                                                .h_full()
                                                .object_fit(ObjectFit::Cover)
                                                .into_any_element(),
                                            None => div().into_any_element(),
                                        }
                                    }
                                }),
                        )
                    })
                    .child(
                        div()
                            .w(px(content::COL_W))
                            .flex()
                            .flex_col()
                            .gap_2()
                            .p_4()
                            .child(
                                // Identity row: avatar + (name, NIP-05 badge)
                                // left; share + follow seals right.
                                div()
                                    .flex()
                                    .items_center()
                                    .justify_between()
                                    .gap_4()
                                    .child(
                                        div()
                                            .flex()
                                            .items_center()
                                            .gap_4()
                                            .child(media::avatar(&media, &picture, &name, 72.0))
                                            .child(
                                                div()
                                                    .flex()
                                                    .flex_col()
                                                    .gap_1()
                                                    .child(
                                                        div()
                                                            .text_size(px(20.0))
                                                            .font_weight(FontWeight::SEMIBOLD)
                                                            .text_color(rgb(theme::ink()))
                                                            .child(name.clone()),
                                                    )
                                                    .when(!nip05.is_empty(), |d| {
                                                        // Verified (the domain's
                                                        // nostr.json vouches) = check +
                                                        // ink; in flight, unproven or
                                                        // disproven stays a muted
                                                        // address — never red (an
                                                        // affordance, not an accusation).
                                                        d.child(
                                                            div()
                                                                .flex()
                                                                .items_center()
                                                                .gap_1()
                                                                .text_size(px(theme::T_SMALL))
                                                                .text_color(rgb(if nip05_ok {
                                                                    theme::ink()
                                                                } else {
                                                                    theme::muted()
                                                                }))
                                                                .when(nip05_ok, |d| d.child("✓"))
                                                                .child(nip05.clone()),
                                                        )
                                                    })
                                                    .child(
                                                        // The npub as the share
                                                        // affordance: the quiet
                                                        // click-to-copy line (same
                                                        // voice as the lud row); the
                                                        // full nostr: URI rides the
                                                        // clipboard, the brief form is
                                                        // only ever shown.
                                                        div()
                                                            .id("npub-copy")
                                                            .cursor_pointer()
                                                            .text_size(px(theme::T_SMALL))
                                                            .text_color(rgb(theme::muted()))
                                                            .hover(|s| {
                                                                s.text_color(
                                                                    rgb(theme::vermilion()),
                                                                )
                                                            })
                                                            .on_click(cx.listener(
                                                                move |this, _, _, cx| {
                                                                    this.flash_copy(
                                                                        "link",
                                                                        npub_uri.clone(),
                                                                        cx,
                                                                    );
                                                                },
                                                            ))
                                                            .child(if link_flash {
                                                                format!("{npub_brief} · copied")
                                                            } else {
                                                                format!(
                                                                    "{npub_brief} · click to copy"
                                                                )
                                                            })
                                                            // The trust badge: a washi pill under the
                                                            // name (WS3). Unknown renders nothing —
                                                            // the graph declining to answer is honest.
                                                            .children(badge.map(|text| {
                                                                div()
                                                                    .flex_none()
                                                                    .px_2()
                                                                    .py_0p5()
                                                                    .rounded_full()
                                                                    .border_1()
                                                                    .border_color(rgb(
                                                                        theme::hairline(),
                                                                    ))
                                                                    .bg(rgb(theme::washi()))
                                                                    .text_size(px(theme::T_SMALL))
                                                                    .text_color(rgb(theme::muted()))
                                                                    .child(text)
                                                                    .into_any_element()
                                                            })),
                                                    ),
                                            ),
                                    )
                                    // Someone else: Follow + Mute ride the
                                    // header as ONE right-hand group —
                                    // justify_between with separate children
                                    // flings them to opposite ends of the row.
                                    // Optimistic flips; publish events drained
                                    // and ignored (P1). The own profile hides
                                    // both (D38) — the edit form takes their
                                    // place.
                                    .when(!self.is_me, |d| {
                                        d.child(
                                            div()
                                                .flex()
                                                .items_center()
                                                .gap_2()
                                                .child(
                                                    div()
                                                        .id("follow")
                                                        .cursor_pointer()
                                                        .px_2()
                                                        .py_1()
                                                        .rounded(px(theme::R_EMBED))
                                                        .border_1()
                                                        .border_color(rgb(theme::hairline()))
                                                        .hover(|s| {
                                                            s.border_color(rgb(theme::muted()))
                                                        })
                                                        .text_size(px(theme::T_SMALL))
                                                        .on_click(move |_, _, cx| {
                                                            let h = follow_handle.clone();
                                                            h.update(cx, |view, cx| {
                                                                view.following = !view.following;
                                                                // Optimistic flip; publish events are
                                                                // drained and ignored (P1).
                                                                let mut rx =
                                                                    view.core.set_following(
                                                                        view.who,
                                                                        view.following,
                                                                    );
                                                                cx.spawn(async move |_, _| {
                                                                    while rx.recv().await.is_some()
                                                                    {
                                                                    }
                                                                })
                                                                .detach();
                                                                cx.notify();
                                                            });
                                                        })
                                                        .when(following, |d| {
                                                            d.text_color(rgb(theme::muted()))
                                                                .child("Following")
                                                        })
                                                        .when(!following, |d| {
                                                            d.text_color(rgb(theme::vermilion()))
                                                                .child("Follow")
                                                        }),
                                                )
                                                // Mute rides next to Follow — an
                                                // optimistic flip, publish events
                                                // drained and ignored (the Follow
                                                // button's pattern).
                                                .child(
                                                    div()
                                                        .id("mute")
                                                        .cursor_pointer()
                                                        .px_2()
                                                        .py_1()
                                                        .rounded(px(theme::R_EMBED))
                                                        .border_1()
                                                        .border_color(rgb(theme::hairline()))
                                                        .hover(|s| {
                                                            s.border_color(rgb(theme::muted()))
                                                        })
                                                        .text_size(px(theme::T_SMALL))
                                                        .on_click(move |_, _, cx| {
                                                            let h = mute_handle.clone();
                                                            h.update(cx, |view, cx| {
                                                                view.muted = !view.muted;
                                                                let mut rx = view.core.set_muted(
                                                                    view.who, view.muted,
                                                                );
                                                                cx.spawn(async move |_, _| {
                                                                    while rx.recv().await.is_some()
                                                                    {
                                                                    }
                                                                })
                                                                .detach();
                                                                cx.notify();
                                                            });
                                                        })
                                                        .when(muted, |d| {
                                                            d.text_color(rgb(theme::muted()))
                                                                .child("Muted")
                                                        })
                                                        .when(!muted, |d| {
                                                            d.text_color(rgb(theme::vermilion()))
                                                                .child("Mute")
                                                        }),
                                                ),
                                        )
                                    })
                                    // Own profile (D38): the edit form replaces
                                    // Follow/Mute.
                                    .when(self.is_me, |d| {
                                        d.child(
                                            div()
                                                .id("edit-profile")
                                                .cursor_pointer()
                                                .px_2()
                                                .py_1()
                                                .rounded(px(theme::R_EMBED))
                                                .border_1()
                                                .border_color(rgb(theme::hairline()))
                                                .hover(|s| s.border_color(rgb(theme::muted())))
                                                .text_size(px(theme::T_SMALL))
                                                .on_click(move |_, _, cx| {
                                                    let h = edit_handle.clone();
                                                    h.update(cx, |view, cx| {
                                                        cx.emit(Nav::OpenEditProfile(view.who));
                                                    });
                                                })
                                                .child("Edit profile"),
                                        )
                                    }),
                            )
                            .when(!lud.is_empty(), |d| {
                                // The lightning pointer (lud16 as-is; a bech32
                                // lud06 reads as just "Lightning"): click copies
                                // the raw pointer for pasting into a zap sheet.
                                let label = if lud.contains('@') {
                                    lud.clone()
                                } else {
                                    "Lightning".to_string()
                                };
                                d.child(
                                    div()
                                        .id("lud-copy")
                                        .cursor_pointer()
                                        .flex()
                                        .items_center()
                                        .gap_2()
                                        .text_size(px(theme::T_SMALL))
                                        .text_color(rgb(theme::muted()))
                                        .hover(|s| s.text_color(rgb(theme::vermilion())))
                                        .on_click(cx.listener(move |this, _, _, cx| {
                                            this.flash_copy("lud", lud.clone(), cx);
                                        }))
                                        .child(icons::bolt_icon(theme::muted()))
                                        .child(if lud_flash {
                                            format!("{label} · copied")
                                        } else {
                                            format!("{label} · click to copy")
                                        }),
                                )
                            })
                            .when(!about.is_empty(), |d| {
                                d.child(about_flow(&about, &ctx, &handle))
                            }),
                    ),
            )
            .child(
                // The strips' tabs (Phase 2 §4.3): quiet labels, the active
                // one ink + underlined.
                div()
                    .w_full()
                    .border_b_1()
                    .border_color(rgb(theme::hairline()))
                    .bg(rgb(theme::panel()))
                    .flex()
                    .justify_center()
                    .child(
                        div()
                            .w(px(content::COL_W))
                            .flex()
                            .gap_4()
                            .px_4()
                            .py_2()
                            .child(self.tab_btn(ProfileTab::Notes, "Notes", tab, cx))
                            .child(self.tab_btn(ProfileTab::Photos, "Photos", tab, cx))
                            .child(self.tab_btn(ProfileTab::Videos, "Videos", tab, cx)),
                    ),
            )
            // §4.3: the kinded error strip — retry re-asks the profile.
            .when_some(self.error.clone(), |d, err| {
                d.child(states::error_strip(
                    &err,
                    cx.listener(move |this, _, _, cx| {
                        let rx = this.core.profile(this.who);
                        this.pump(rx, cx);
                        this.error = None;
                        cx.notify();
                    }),
                    cx.listener(move |this, _, _, cx| {
                        this.error = None;
                        cx.notify();
                    }),
                ))
            })
            .child(match tab {
                // The Notes tab IS a feed (FeedMode::Profile): the timeline's
                // exact rows — avatar, media, the reaction row — scoped to
                // the author, endless scroll included; the profile keeps the
                // column rhythm and the header above it.
                ProfileTab::Notes => div()
                    .w_full()
                    .h_full()
                    .max_w(px(content::COL_W))
                    .flex()
                    .flex_col()
                    .child(self.notes_feed.clone())
                    .into_any_element(),
                ProfileTab::Photos | ProfileTab::Videos => div()
                    .flex_1()
                    .min_h_0()
                    .flex()
                    .justify_center()
                    .child(if empty {
                        div()
                            .w_full()
                            .max_w(px(content::COL_W))
                            .p_4()
                            .text_color(rgb(theme::muted()))
                            .child(if self.status.is_empty() {
                                match tab {
                                    ProfileTab::Notes => "No notes here yet.",
                                    ProfileTab::Photos => "No pictures yet.",
                                    ProfileTab::Videos => "No videos yet.",
                                }
                                .to_string()
                            } else {
                                self.status.clone()
                            })
                            .into_any_element()
                    } else {
                        list(self.list.clone(), move |idx, _w, _cx| {
                            match rows.get(idx) {
                                Some(Row::Pics(tiles)) => {
                                    let mut grid = div()
                                        .w_full()
                                        .flex()
                                        .gap_1()
                                        .px_4()
                                        .py_1()
                                        .border_b_1()
                                        .border_color(rgb(theme::hairline()));
                                    for (url, gix) in tiles {
                                        grid = grid.child(thumb_tile(
                                            &media,
                                            SharedString::from(format!("pic-{gix}")),
                                            url,
                                            None,
                                            Some((&pics_all, *gix)),
                                            None,
                                            None,
                                            handle.clone(),
                                        ));
                                    }
                                    grid.into_any_element()
                                }
                                Some(Row::Vids(tiles)) => {
                                    let mut grid = div()
                                        .w_full()
                                        .flex()
                                        .gap_1()
                                        .px_4()
                                        .py_1()
                                        .border_b_1()
                                        .border_color(rgb(theme::hairline()));
                                    // One tile per video, the poster thumb when the
                                    // bytes landed, the quiet play frame otherwise.
                                    for (i, (url, poster, blurhash, mime)) in
                                        tiles.iter().enumerate()
                                    {
                                        grid = grid.child(thumb_tile(
                                            &media,
                                            SharedString::from(format!("vid-{idx}-{i}")),
                                            poster.as_deref().unwrap_or(""),
                                            blurhash.as_deref(),
                                            None,
                                            Some(url.as_str()),
                                            mime.as_deref(),
                                            handle.clone(),
                                        ));
                                    }
                                    grid.into_any_element()
                                }
                                None => div().into_any_element(),
                            }
                        })
                        .w_full()
                        .max_w(px(content::COL_W))
                        .h_full()
                        .into_any_element()
                    })
                    .into_any_element(),
            })
    }
}

/// One 3-column strip thumbnail (Phase 2 §4.3): the cached bytes
/// cover-cropped to a square, a quiet frame until they land. Photos tap
/// into the lightbox at their strip index; videos ask for the shell's
/// video overlay (Phase 3 — video.rs degrades strict-Tor/YouTube to the
/// browser; the play badge marks them, the poster is the thumb).
#[allow(clippy::too_many_arguments)]
fn thumb_tile(
    snap: &media::Snapshot,
    key: SharedString,
    thumb: &str,
    blurhash: Option<&str>,
    lightbox: Option<(&[String], usize)>,
    video_url: Option<&str>,
    video_mime: Option<&str>,
    handle: Entity<ProfileView>,
) -> AnyElement {
    let size = (content::COL_W - 32.0 - 8.0) / 3.0;
    let video = video_url.is_some();
    let target = video_url.unwrap_or_default().to_string();
    let mime = video_mime.map(str::to_string);
    let urls: Vec<String> = lightbox.map(|(l, _)| l.to_vec()).unwrap_or_default();
    let idx = lightbox.map(|(_, i)| i).unwrap_or(0);
    let frame = div()
        .id(key)
        .cursor_pointer()
        .flex_none()
        .overflow_hidden()
        // §1.4 ladder: media tiles ride R_MEDIA, not the embed radius.
        .rounded(px(theme::R_MEDIA))
        .border_1()
        .border_color(rgb(theme::hairline()))
        .bg(rgb(theme::panel()))
        .size(px(size))
        .on_click(move |_, _, cx| {
            cx.stop_propagation();
            if video {
                // The shell's video overlay (Phase 3): the full-screen
                // player when the URL is inline-able, else the browser.
                handle.update(cx, |_, cx| {
                    cx.emit(Nav::OpenVideo(target.clone(), mime.clone()))
                });
            } else {
                let urls = urls.clone();
                handle.update(cx, |_, cx| cx.emit(Nav::OpenLightbox(urls, idx)));
            }
        });
    let badge = |f: Div| {
        if video {
            f.child(
                div()
                    .absolute()
                    .inset_0()
                    .flex()
                    .items_center()
                    .justify_center()
                    .text_size(px(22.0))
                    .text_color(rgb(theme::vermilion()))
                    .child("▶"),
            )
        } else {
            f
        }
    };
    // The preview ladder (D32, reordered D72): the publisher's poster, then
    // a locally sniffed first frame — a real frame beats an impression —
    // then the blurhash gradient as the local filler. The picture a video
    // tile paints is whichever the cache holds, best first.
    let shown = if !thumb.is_empty() {
        snap.png(thumb)
    } else {
        None
    }
    .or_else(|| video_url.and_then(|u| snap.png(&crate::poster::poster_key(u))))
    .or_else(|| blurhash.and_then(|b| snap.png(&crate::poster::blurhash_key(b))));
    match shown {
        Some(png) => frame
            .child(
                div()
                    .relative()
                    .size_full()
                    .child(img(png).size_full().object_fit(ObjectFit::Cover))
                    .map(badge),
            )
            .into_any_element(),
        None => frame
            .child(
                div()
                    .size_full()
                    .flex()
                    .items_center()
                    .justify_center()
                    .text_size(px(if video { 22.0 } else { theme::T_SMALL }))
                    .text_color(rgb(if video {
                        theme::vermilion()
                    } else {
                        theme::muted()
                    }))
                    .child(if video { "▶" } else { "…" }),
            )
            .into_any_element(),
    }
}

/// The about block as live paragraphs: one `word_flow` per non-empty line
/// (newlines in the raw about split paragraphs), so links, mentions and
/// hashtags click through exactly as they do in note bodies.
fn about_flow(text: &str, ctx: &content::Body, handle: &Entity<ProfileView>) -> Div {
    let mut flow = div().w_full().flex().flex_col().gap_1();
    for para in text.lines().map(str::trim).filter(|l| !l.is_empty()) {
        flow = flow.child(content::word_flow(para, &[], ctx, handle));
    }
    flow
}
