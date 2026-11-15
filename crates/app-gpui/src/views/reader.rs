//! Article reader page — the markdown port (TODO(port): crates/app/src/cards.rs
//! `article_reader` — the GTK reader pushed an adw page; here it's a pane).
//! Head: title, byline (avatar, author, published, reading time), cover.
//! Then the markdown blocks: paragraphs through the word flow (entities
//! resolve, markdown styles ride along), headings, quotes, ordered/unordered
//! lists, code, rules, own-line images. The blocks ride a `list` (the feed's
//! scroll machinery — plain overflow divs don't take wheel input), one item
//! per block, built from data inside the item closure. Comments (NIP-22)
//! stay with the GTK original for now — no comments section yet.

use std::{collections::HashMap, sync::Arc};

use gpui::{
    AnyElement, Context, Div, Entity, EventEmitter, FontWeight, ListAlignment, ListScrollEvent,
    ListState, Render, SharedString, Window, div, img, list, prelude::*, px, relative, rgb,
};
use nostr::prelude::*;
use satori_core::manager::{Core, FeedEvent, FeedRx, Profile};
use satori_core::nip::article;

use super::{content, nav::Nav};
use crate::{markdown, media, theme};

pub struct ArticleView {
    core: Arc<Core>,
    ev: Event,
    data: article::ArticleData,
    profiles: HashMap<String, Profile>,
    /// The NIP-22 comments on this article (kind 1111, oldest first —
    /// manager::comments's order), pumped in as they land.
    comments: Vec<Event>,
    list: ListState,
    /// The comments list's visible range (the scroll handler), so the
    /// avatar fetch/pin window follows the scroll — the whole comment
    /// set must never pin (D60: a viral article's 5000 avatars would
    /// ratchet the registry and starve the gate).
    vis_start: usize,
    vis_end: usize,
    /// The full body's markdown blocks, computed once (#31's rich-card
    /// rider): render re-blocked the whole article per repaint.
    blocks: std::sync::Arc<[markdown::Block]>,
}

impl EventEmitter<Nav> for ArticleView {}

impl ArticleView {
    pub fn new(core: Arc<Core>, ev: Event, cx: &mut Context<Self>) -> Self {
        crate::theme::watch(cx); // repaint on theme change
        crate::timefmt::watch(cx); // repaint on mode/height change
        let data = article::parse(&ev).unwrap_or_else(|| article::ArticleData {
            title: "Untitled".into(),
            summary: String::new(),
            image: None,
            published_at: None,
            slug: String::new(),
        });
        let blocks: std::sync::Arc<[markdown::Block]> = markdown::blocks(&ev.content).into();
        let view = Self {
            core,
            ev,
            data,
            profiles: HashMap::new(),
            comments: vec![],
            list: ListState::new(0, ListAlignment::Top, px(400.)),
            vis_start: 0,
            vis_end: 0,
            blocks,
        };
        // Mentions in the body resolve to @names, same as the feed and
        // thread panes (TODO(port): content.ts mentionPubkeys) — and the
        // author, for the byline.
        view.want_names(cx);
        view.want_media(cx);
        // The comment rows' avatar fetch/pin window: track the visible
        // range (notifications.rs set_scroll_handler, same shape) and let
        // render pin exactly those avatars.
        let this = cx.entity().downgrade();
        view.list
            .set_scroll_handler(move |ev: &ListScrollEvent, _w, cx| {
                let _ = this.update(cx, |r, cx| {
                    r.vis_start = ev.visible_range.start;
                    r.vis_end = ev.visible_range.end;
                    cx.notify();
                });
            });
        // The comments section (NIP-22): the article is an addressable
        // root — its d tag IS the thread's address (CommentTarget::Address;
        // reply_tags preserves it for nested replies). No d tag (blank
        // identifier is a publish-time invention) → no address → no
        // fetch; the section stays empty rather than hanging off air.
        if let Some(target) = view.comment_target() {
            view.pump(view.core.comments(target), cx);
        }
        view
    }

    /// The article's comment root: kind 30023 + author + d tag. None
    /// without a d tag (the address is what other clients hang the
    /// thread off — an id-based target would fork it).
    fn comment_target(&self) -> Option<satori_core::nip::comment::CommentTarget> {
        let d = self
            .ev
            .tags
            .iter()
            .find(|t| t.as_slice().first().map(String::as_str) == Some("d"))
            .and_then(|t| t.as_slice().get(1).cloned())?;
        Some(satori_core::nip::comment::CommentTarget::Address {
            kind: 30023,
            author: self.ev.pubkey,
            d,
        })
    }

    /// Hydrate names for the byline + mentioned pubkeys — otherwise the
    /// byline degrades to @npub1… (thread.rs want_names, same seam).
    fn want_names(&self, cx: &mut Context<Self>) {
        let mut want = vec![self.ev.pubkey];
        want.extend(content::mention_pks(&self.ev.content));
        let mut seen = std::collections::HashSet::new();
        let missing: Vec<PublicKey> = want
            .into_iter()
            .filter(|pk| {
                !self.profiles.contains_key(&pk.to_string()) && seen.insert(pk.to_string())
            })
            .collect();
        if !missing.is_empty() {
            self.pump(self.core.ensure_profiles(missing), cx);
        }
    }

    /// Queue fetches for the cover + every own-line image in the body.
    fn want_media(&self, cx: &mut Context<Self>) {
        let mut urls = content::media_urls_cached(&self.ev)
            .iter()
            .cloned()
            .collect::<Vec<_>>();
        if let Some(image) = &self.data.image {
            urls.push(image.clone());
        }
        for block in self.blocks.iter() {
            if let markdown::Block::Image { url } = block {
                urls.push(url.clone());
            }
        }
        for url in urls {
            media::fetch(&self.core, url, cx.entity_id(), cx);
        }
    }

    fn pump(&self, mut rx: FeedRx, cx: &mut Context<Self>) {
        cx.spawn(async move |this, cx| {
            while let Some(ev) = rx.recv().await {
                let _ = this.update(cx, |this, cx| this.on_event(ev, cx));
            }
        })
        .detach();
    }

    fn on_event(&mut self, ev: FeedEvent, cx: &mut Context<Self>) {
        match ev {
            FeedEvent::Profiles(profiles) => {
                for p in profiles {
                    self.profiles.insert(p.pubkey.clone(), p);
                }
                cx.notify();
            }
            FeedEvent::Comments(comments, profiles) => {
                for p in profiles {
                    self.profiles.insert(p.pubkey.clone(), p);
                }
                self.comments = comments;
                cx.notify();
            }
            _ => {}
        }
    }

    fn name_for(&self, pk: &PublicKey) -> String {
        let hex = pk.to_string();
        content::display_name(self.profiles.get(&hex), &hex)
    }
}

/// One list item: the reading column's width (content::COL_W — the same
/// measure every pane reads at; §1.2) + the block's bottom rhythm
/// (list items carry no gaps of their own; pads are theme::S steps).
pub(crate) fn block_item(el: Div, pad: f32) -> Div {
    div()
        .w_full()
        .max_w(px(content::COL_W))
        .pb(px(pad))
        .child(el)
}

/// Render one markdown block (the free fn stands behind the list's item
/// closure, which rebuilds items from data on each visible row). Generic
/// over the host view (content::body's shape): the composer's preview
/// renders its drafts through this same path, Nav emissions riding the
/// host entity — an image click opens the lightbox over the composer.
pub(crate) fn render_block<V: EventEmitter<Nav> + 'static>(
    block: markdown::Block,
    idx: usize,
    ctx: &content::Body,
    handle: &Entity<V>,
) -> AnyElement {
    match block {
        markdown::Block::Para(text) => block_item(
            md_flow(&text, theme::T_READER, false, ctx, handle),
            theme::S4,
        )
        .into_any_element(),
        markdown::Block::Heading(level, text) => {
            // The ladder sits UNDER the title (H1 just below it, deeper
            // levels stepping down to T_READER then T_BODY — no 14.5/14.0
            // stragglers off the type scale, §1.3); a little air ABOVE each
            // heading separates it from the paragraph it introduces — the
            // reading rhythm hangs on that gap (air on the S scale too).
            let size = [
                18.0,
                16.0,
                theme::T_READER,
                theme::T_READER,
                theme::T_BODY,
                theme::T_BODY,
            ][(level - 1).clamp(0, 5)];
            let top = [
                theme::S3,
                theme::S3,
                theme::S2,
                theme::S2,
                theme::S1,
                theme::S0,
            ][(level - 1).clamp(0, 5)];
            let head = div()
                .w_full()
                .pt(px(top))
                .font_family(theme::SERIF)
                .text_size(px(size))
                .line_height(relative(1.2))
                .font_weight(FontWeight::SEMIBOLD)
                .text_color(rgb(theme::ink()))
                .child(text);
            block_item(head, theme::S3).into_any_element()
        }
        markdown::Block::Quote(text) => {
            let q = div()
                .w_full()
                .pl_3()
                .py_1()
                .border_l_2()
                .border_color(rgb(theme::hairline()))
                .child(md_flow(&text, theme::T_BODY, true, ctx, handle));
            block_item(q, theme::S4).into_any_element()
        }
        markdown::Block::List { items, ordered } => {
            let mut list_el = div().w_full().flex().flex_col().gap_1();
            for (n, li) in items.into_iter().enumerate() {
                // A task item's marker is its checkbox: a stroke-drawn
                // square, the check riding the vermilion when done.
                let marker = if let Some(checked) = li.task {
                    div().flex_shrink_0().child(
                        div()
                            .mt(px(2.))
                            .size(px(13.))
                            .rounded(px(3.))
                            .border_1()
                            .border_color(rgb(theme::hairline()))
                            .flex()
                            .items_center()
                            .justify_center()
                            .text_size(px(10.))
                            .text_color(rgb(if checked {
                                theme::vermilion()
                            } else {
                                theme::muted()
                            }))
                            .child(if checked { "✓" } else { "" }),
                    )
                } else if ordered {
                    div()
                        .font_family(theme::SERIF)
                        .text_size(px(theme::T_READER))
                        .text_color(rgb(theme::muted()))
                        .child(format!("{}.", n + 1))
                } else {
                    div()
                        .font_family(theme::SERIF)
                        .text_size(px(theme::T_READER))
                        .text_color(rgb(theme::muted()))
                        .child("·")
                };
                let body = md_flow(&li.text, theme::T_READER, false, ctx, handle);
                let body = if li.task == Some(true) {
                    // A checked task reads quiet — it's done.
                    div().opacity(0.65).child(body)
                } else {
                    body
                };
                list_el = list_el.child(div().w_full().flex().gap_2().child(marker).child(body));
            }
            block_item(list_el, theme::S4).into_any_element()
        }
        markdown::Block::Table { head, rows, aligns } => {
            // The grid: hairline row rules, the header semibold over a
            // slightly stronger rule; cells flow markdown like paragraphs.
            let ncol = head.len().max(1);
            let cell_el = |text: String, col: usize, header: bool| {
                let justify = match aligns.get(col) {
                    Some(markdown::Align::Center) => "center",
                    Some(markdown::Align::Right) => "right",
                    _ => "left",
                };
                let cell = md_flow(&text, theme::T_UI, false, ctx, handle);
                div()
                    .flex_1()
                    .min_w_0()
                    .px_1()
                    .flex()
                    .when(justify == "center", |d| d.justify_center())
                    .when(justify == "right", |d| d.justify_end())
                    .when(header, |d| d.font_weight(FontWeight::SEMIBOLD))
                    .child(cell)
            };
            let mut table = div()
                .w_full()
                .flex()
                .flex_col()
                .rounded(px(theme::R_EMBED))
                .border_1()
                .border_color(rgb(theme::hairline()))
                .child(
                    div()
                        .w_full()
                        .flex()
                        .border_b_1()
                        .border_color(rgb(theme::hairline()))
                        .bg(rgb(theme::panel()))
                        .py_1()
                        .children(
                            head.into_iter()
                                .enumerate()
                                .map(|(c, h)| cell_el(h, c, true)),
                        ),
                );
            for mut row in rows {
                // Pad the body out to the header's column count (jagged
                // rows shouldn't shift the grid).
                row.resize(ncol, String::new());
                table = table.child(
                    div()
                        .w_full()
                        .flex()
                        .border_b_1()
                        .border_color(rgb(theme::hairline()))
                        .py_1()
                        .children(
                            row.into_iter()
                                .enumerate()
                                .map(|(c, cell)| cell_el(cell, c, false)),
                        ),
                );
            }
            // Pad the body out to the header's column count (jagged rows
            // shouldn't shift the grid).
            block_item(table, theme::S4).into_any_element()
        }
        markdown::Block::Code(text) => {
            let code = div()
                .id(SharedString::from(format!("code-{idx}")))
                .overflow_x_scroll()
                .w_full()
                .p_3()
                .rounded(px(theme::R_EMBED))
                .bg(rgb(theme::panel()))
                .font_family(theme::MONO)
                .text_size(px(theme::T_UI))
                .line_height(relative(1.35))
                .text_color(rgb(theme::ink()))
                .child(text);
            block_item(div().w_full().child(code), theme::S4).into_any_element()
        }
        markdown::Block::Break => {
            // An author's own <br>: a quiet spacer, not a rule.
            block_item(div().w_full().h(px(theme::S2)), 0.0).into_any_element()
        }
        markdown::Block::Rule => {
            let rule = div()
                .w_full()
                .py_1()
                .border_b_1()
                .border_color(rgb(theme::hairline()));
            block_item(rule, theme::S4).into_any_element()
        }
        markdown::Block::Image { url } => {
            block_item(image_tile(&url, ctx.media), theme::S4).into_any_element()
        }
    }
}

/// One markdown paragraph through the word flow: markdown spans carry the
/// styling; plain words classify as entities (urls, mentions) exactly like
/// note bodies. Link spans wrap as one unit — a link is one word to the
/// reader's eye anyway. (Line height 1.35: long-form serif needs the air —
/// the note cards' 1.2 is for short bursts.) Generic over the host view
/// (render_block's shape) — the composer's preview shares it.
pub(crate) fn md_flow<V: EventEmitter<Nav> + 'static>(
    para: &str,
    size: f32,
    quiet: bool,
    ctx: &content::Body,
    handle: &Entity<V>,
) -> Div {
    let mut flow = div().w_full().flex().flex_wrap().gap_1();
    for span in markdown::spans(para) {
        // A <br> span: a full-width spacer — flex-wrap pushes the rest of
        // the flow to the next line (the web's literal line break).
        if span.br {
            flow = flow.child(div().w_full().h(px(theme::S1)));
            continue;
        }
        let is_link = span.link.is_some();
        let label = span.text.clone();
        let styled = |text: String| {
            div()
                .font_family(if span.code { theme::MONO } else { theme::SERIF })
                .text_size(px(if span.code { size * 0.88 } else { size }))
                .line_height(relative(1.35))
                .text_color(rgb(if quiet || is_link {
                    theme::muted()
                } else {
                    theme::ink()
                }))
                .when(span.bold, |d| d.font_weight(FontWeight::BOLD))
                .when(span.italic, |d| d.italic())
                .when(span.strike, |d| d.line_through())
                .when(is_link || span.code, |d| d.underline())
                .child(text)
        };
        match span.link {
            Some(url) => {
                let id = SharedString::from(format!("mdlink-{label}-{url}"));
                let openable = crate::views::content::web_url(&url);
                flow = flow.child(styled(label).id(id).cursor_pointer().on_click(
                    move |_, _, cx| {
                        if openable {
                            cx.open_url(&url);
                        }
                    },
                ));
            }
            None => {
                // Plain words ride the entity classifier: bare urls and
                // npub mentions stay clickable inside styled runs.
                for word in span.text.split_whitespace() {
                    let (core, punct) = content::split_trailing(word);
                    match content::classify_token(core) {
                        content::Tok::Word(w) => {
                            flow = flow.child(styled(if punct.is_empty() {
                                w
                            } else {
                                format!("{w}{punct}")
                            }));
                        }
                        tok => {
                            flow =
                                flow.child(content::token_el(tok, punct, core.len(), ctx, handle));
                        }
                    }
                }
            }
        }
    }
    flow
}

/// One image tile: the media frame at a fixed reading height — media_tile
/// semantics, fed by the shared cache. (pub(crate): the composer's article
/// preview renders its cover with the same tile.)
pub(crate) fn image_tile(url: &str, snap: &media::Snapshot) -> Div {
    let png = snap.png(url);
    // Aspect-correct once the bytes are in (reading column content::COL_W
    // minus the frame's side padding); a provisional box until then.
    let height = snap
        .size(url)
        .filter(|(w, _)| *w > 0)
        .map_or(360.0, |(w, h)| {
            ((content::COL_W - 32.0) * h as f32 / w as f32).clamp(80.0, 560.0)
        });
    let frame = div()
        .w_full()
        .h(px(height))
        .flex_none()
        .overflow_hidden()
        .rounded(px(theme::R_EMBED))
        .border_1()
        .border_color(rgb(theme::hairline()))
        .bg(rgb(theme::panel()));
    match png {
        Some(png) => frame.child(img(png).size_full()),
        None => frame,
    }
}

impl Render for ArticleView {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let media_snap = media::Snapshot::new(cx);
        let quotes: content::Quotes = HashMap::new();
        let handle = cx.entity();

        // Data the item closure rebuilds elements from (AnyElement isn't
        // Clone — the thread pane's closure does the same dance).
        let title = self.data.title.clone();
        let author_pk = self.ev.pubkey;
        let author = self.name_for(&author_pk);
        let author_pic = self
            .profiles
            .get(&author_pk.to_string())
            .map(|p| p.picture.clone())
            .unwrap_or_default();
        // Evicted media comes back on render (thread.rs render, same
        // shape — fetch is a silent no-op for entries the cache holds, and
        // only a landing notifies, so no render loop): the byline avatar,
        // the cover, and every body image. A long read outlives the
        // cache's photo budget; without the sweep an evicted mid-article
        // image stayed dark for good (want_media only ran at construction).
        // The markdown parses once, at construction: the sweep and the
        // render list share the `blocks` field (render used to re-block
        // the whole article per repaint, and the sweep re-ran the scan).
        let cover = content::article_cover(&self.ev);
        let blocks = std::sync::Arc::clone(&self.blocks);
        let block_count = blocks.len();
        // Head items (title, byline, cover), one per markdown block, then
        // the comments section: a header (count + the reply affordance)
        // and one row per comment.
        let head_count = 2 + cover.is_some() as usize;
        let comments_base = head_count + block_count;
        if !author_pic.is_empty() {
            media::fetch(&self.core, author_pic.clone(), cx.entity_id(), cx);
        }
        if let Some(url) = &cover {
            media::fetch(&self.core, url.clone(), cx.entity_id(), cx);
        }
        for url in content::media_urls_cached(&self.ev).iter().cloned() {
            media::fetch(&self.core, url, cx.entity_id(), cx);
        }
        // The og card's thumbnail paints preview.image — a URL the parse
        // never knew; re-request it like any picture (long-read flash
        // recovery below repins the same set).
        for url in content::og_image_urls(&self.ev) {
            media::fetch(&self.core, url, cx.entity_id(), cx);
        }
        for block in blocks.iter() {
            if let markdown::Block::Image { url } = block {
                media::fetch(&self.core, url.clone(), cx.entity_id(), cx);
            }
        }
        // The long-read flash (media.rs's idle-pane eviction): a reader
        // sits minutes on one article — renders stop, the grace window
        // expires, and foreign landings evict exactly the images on
        // screen. Pin this render's set, release the previous one's
        // (the feed's window discipline): the set is fixed per article,
        // so after the first render every pin is a no-op. EVERYTHING the
        // pane paints pins: the byline avatar rode unpinned once (the
        // render fetched it, the idle fetch never came, the burst took
        // it) — the articles page's disappearing image.
        let mut painted: Vec<String> = content::media_urls_cached(&self.ev)
            .iter()
            .cloned()
            .collect();
        if !author_pic.is_empty() {
            painted.push(author_pic.clone());
        }
        if let Some(c) = &cover
            && !c.is_empty()
            && !painted.contains(c)
        {
            painted.push(c.clone());
        }
        for block in blocks.iter() {
            if let markdown::Block::Image { url } = block
                && !url.is_empty()
                && !painted.contains(url)
            {
                painted.push(url.clone());
            }
        }
        // The comments section's avatars: fetched here (a silent no-op
        // once ready; the landing notifies the view) and pinned with the
        // rest — but ONLY the visible rows' avatars (D60 windowing; the
        // scroll handler feeds vis_start/vis_end). A viral article's
        // whole comment set used to pin: 5000 avatars ratchet the
        // registry forever and starve the media gate on open.
        let av_lo = self.vis_start.saturating_sub(comments_base + 1);
        let av_hi = self
            .vis_end
            .saturating_sub(comments_base + 1)
            .min(self.comments.len());
        for c in self.comments[av_lo..av_hi.max(av_lo)].iter() {
            let pic = self
                .profiles
                .get(&c.pubkey.to_string())
                .map(|p| p.picture.clone())
                .unwrap_or_default();
            if !pic.is_empty() {
                media::fetch(&self.core, pic.clone(), cx.entity_id(), cx);
                if !painted.contains(&pic) {
                    painted.push(pic);
                }
            }
        }
        media::repin(cx.entity_id(), painted, cx);
        // Mode-aware stamp; ensure refines Block mode from the bridge
        // (render-path spawns are silent no-ops when cached — media.rs's
        // eviction re-request is the same pattern).
        let published = self.data.published_at.map(|ts| {
            crate::timefmt::ensure(ts, cx);
            crate::timefmt::stamp(ts, cx)
        });
        // Reading time at ~220 wpm (content.ts's readingMinutes rate).
        let minutes = self.ev.content.split_whitespace().count() / 220 + 1;
        let profiles = self.profiles.clone();
        let media = media_snap;

        let item_count = comments_base + 1 + self.comments.len();
        if self.list.item_count() != item_count {
            self.list.reset(item_count);
        }
        // Comment-row snapshot data (AnyElement isn't Clone — the block
        // closure rebuilds per row): names, avatars, timestamps (mode
        // ensured + stamped at render, like the byline).
        let comments: Vec<Event> = self.comments.clone();
        let anchor_emoji = content::body_parse(&self.ev).emoji.clone();
        let comment_rows: Vec<(String, String, String)> = comments
            .iter()
            .map(|c| {
                let ts = c.created_at.as_secs();
                crate::timefmt::ensure(ts, cx);
                (
                    self.name_for(&c.pubkey),
                    self.profiles
                        .get(&c.pubkey.to_string())
                        .map(|p| p.picture.clone())
                        .unwrap_or_default(),
                    crate::timefmt::stamp(ts, cx),
                )
            })
            .collect();
        let reply_ev = self.ev.clone();

        div()
            .flex_1()
            .min_h_0()
            .overflow_hidden()
            .flex()
            .flex_col()
            .child(
                div().flex_1().min_h_0().flex().justify_center().child(
                    // list() has no intrinsic height — it must be told to
                    // fill its container or it lays out at 0px and paints
                    // nothing (the feed carries the same comment).
                    list(self.list.clone(), move |idx, _w, _cx| {
                        let body_ctx = content::Body {
                            media: &media,
                            quotes: &quotes,
                            profiles: &profiles,
                            // The article's own emoji map (the anchor's
                            // tags); the comment rows below resolve their
                            // per-comment maps in their arm.
                            emoji: anchor_emoji.clone(),
                        };
                        match idx {
                            0 => block_item(
                                div()
                                    .w_full()
                                    .font_family(theme::SERIF)
                                    // Display serif for the h1 (spec
                                    // §1.3: 17–20; top of the ladder).
                                    .text_size(px(20.0))
                                    .line_height(relative(1.25))
                                    .font_weight(FontWeight::SEMIBOLD)
                                    .text_color(rgb(theme::ink()))
                                    .child(title.clone()),
                                theme::S3,
                            )
                            .into_any_element(),
                            1 => block_item(
                                div()
                                    .flex()
                                    .items_center()
                                    .gap_2()
                                    .child(media::avatar(&media, &author_pic, &author, 24.0))
                                    .child(
                                        div()
                                            .flex()
                                            .items_baseline()
                                            .gap_2()
                                            .text_size(px(theme::T_UI))
                                            .text_color(rgb(theme::muted()))
                                            .child(
                                                div()
                                                    .font_weight(FontWeight::SEMIBOLD)
                                                    .text_color(rgb(theme::ink()))
                                                    .child(author.clone()),
                                            )
                                            .children(published.clone().map(|t| {
                                                // The timestamp is
                                                // the third mode
                                                // toggle (timefmt.rs):
                                                // tap cycles.
                                                div()
                                                    .id("reader-published")
                                                    .cursor_pointer()
                                                    .on_click(|_, _, cx| crate::timefmt::cycle(cx))
                                                    .child(format!("· {t}"))
                                            }))
                                            .child(format!("· {minutes} min read")),
                                    ),
                                theme::S5,
                            )
                            .into_any_element(),
                            2 if cover.is_some() => block_item(
                                image_tile(cover.as_deref().unwrap_or(""), &media),
                                theme::S5,
                            )
                            .into_any_element(),
                            i if i == comments_base => block_item(
                                div()
                                    .w_full()
                                    .flex()
                                    .items_center()
                                    .justify_between()
                                    .child(
                                        div()
                                            .text_size(px(theme::T_UI))
                                            .font_weight(FontWeight::SEMIBOLD)
                                            .text_color(rgb(theme::ink()))
                                            .child(format!("Comments · {}", comments.len())),
                                    )
                                    .child(
                                        // The reply affordance: opens the
                                        // composer on the ARTICLE — the
                                        // composer routes kind≠1 parents to
                                        // core.comment (kind 1111), whose
                                        // tags name this address as root.
                                        div()
                                            .id("comments-reply")
                                            .cursor_pointer()
                                            .px_2()
                                            .py_1()
                                            .rounded(px(theme::R_INPUT))
                                            .border_1()
                                            .border_color(rgb(theme::hairline()))
                                            .text_size(px(theme::T_SMALL))
                                            .text_color(rgb(theme::muted()))
                                            .hover(|s| s.text_color(rgb(theme::ink())))
                                            .on_click({
                                                let reply_ev = reply_ev.clone();
                                                let handle = handle.clone();
                                                move |_, _, cx| {
                                                    let ev = reply_ev.clone();
                                                    handle.update(cx, |_, cx| {
                                                        cx.emit(Nav::OpenReply(ev))
                                                    });
                                                }
                                            })
                                            .child("Reply"),
                                    ),
                                theme::S5,
                            )
                            .into_any_element(),
                            i if i > comments_base => {
                                let ci = i - comments_base - 1;
                                let (name, picture, time) = comment_rows[ci].clone();
                                let ev = comments[ci].clone();
                                block_item(
                                    div()
                                        .w_full()
                                        .flex()
                                        .flex_col()
                                        .gap_1()
                                        .child(
                                            div()
                                                .flex()
                                                .items_center()
                                                .justify_between()
                                                .child(
                                                    div()
                                                        .flex()
                                                        .items_center()
                                                        .gap_2()
                                                        .child(media::avatar(
                                                            &media, &picture, &name, 20.0,
                                                        ))
                                                        .child(
                                                            div()
                                                                .text_size(px(theme::T_SMALL))
                                                                .font_weight(FontWeight::SEMIBOLD)
                                                                .text_color(rgb(theme::ink()))
                                                                .child(name),
                                                        ),
                                                )
                                                .child(
                                                    div()
                                                        .flex()
                                                        .items_center()
                                                        .gap_1()
                                                        .child(content::copy_seal(
                                                            &format!("comment-{ci}"),
                                                            satori_core::nip::nip19::uri(&ev),
                                                        ))
                                                        .child(content::time_toggle(
                                                            SharedString::from(format!(
                                                                "comment-time-{ci}"
                                                            )),
                                                            time,
                                                        )),
                                                ),
                                        )
                                        .child(content::body(
                                            &ev,
                                            &content::Body {
                                                media: &media,
                                                quotes: &quotes,
                                                profiles: &profiles,
                                                emoji: content::body_parse(&ev).emoji.clone(),
                                            },
                                            handle.clone(),
                                        )),
                                    theme::S3,
                                )
                                .into_any_element()
                            }
                            i => render_block(
                                blocks[i - head_count].clone(),
                                i - head_count,
                                &body_ctx,
                                &handle,
                            ),
                        }
                    })
                    .w_full()
                    .max_w(px(content::COL_W))
                    .h_full(),
                ),
            )
    }
}
