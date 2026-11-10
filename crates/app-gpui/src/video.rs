//! Inline video playback — Phase 3 (satori-plan.md §5).
//!
//! TODO(port): feather AGENTS.md — Phase 3 §5. One player per process,
//! click-to-play: this module owns at most one `gpui_video_player::Video`
//! (GStreamer-backed; the element paints frames, the handle drives the
//! pipeline). Nothing plays until a video tile is tapped — no autoplay, no
//! feed-wide players (Feather's autoplay/multi-player system is out of
//! scope). Strict Tor degrades every tap to the browser link — the media
//! facade rule (DESIGN.md §4): nothing media-heavy may fetch direct, and a
//! GStreamer pipeline can't ride the Tor transport.
//!
//! Threading (the crate's contract): `Video::new` BLOCKS up to ~5s waiting
//! for the pipeline's caps, and `Drop` (the last Arc ref) joins the worker
//! thread — so creation runs on the background executor and a replaced
//! player's drop is deferred to a spare OS thread. Registry reads are
//! cx-less (item closures have no App); a unit gpui-global ([`Signal`])
//! wakes the watching views when the player opens, toggles or closes.

use std::sync::RwLock;

use gpui::px;
use gpui_video_player::Video;

use crate::views::content;

/// The at-most-one player: the URL it plays + the pipeline handle.
struct Player {
    url: String,
    video: Video,
}

static ACTIVE: RwLock<Option<Player>> = RwLock::new(None);

/// A player that has been asked for but hasn't finished building (Video::new
/// blocks up to ~5s on the pipeline's caps) — the tile renders a breathing
/// play mark instead of sitting dead-silent between tap and first frame.
static OPENING: RwLock<Option<String>> = RwLock::new(None);

/// The wake-up global (theme.rs ThemeSignal pattern): set when the player
/// opens/toggles/closes — every video-bearing view observes it and
/// repaints poster ↔ player.
pub struct Signal;

impl gpui::Global for Signal {}

/// Watch for player changes (beside timefmt::watch, in any view that can
/// render a video tile).
pub fn watch<V: 'static>(cx: &mut gpui::Context<V>) {
    cx.observe_global::<Signal>(|_, cx| cx.notify()).detach();
}

/// The active player's handle, when it is playing `url` — cx-less. The
/// handle is a cheap Arc clone; the element and the controls share it.
pub fn active(url: &str) -> Option<Video> {
    let guard = ACTIVE.read().ok()?;
    let p = guard.as_ref()?;
    (p.url == url).then(|| p.video.clone())
}

/// Is a player for `url` still being built? (The tile's breathing state.)
pub fn opening(url: &str) -> bool {
    OPENING
        .read()
        .ok()
        .map(|g| g.as_deref() == Some(url))
        .unwrap_or(false)
}

/// Can this video play inline (Phase 3 §5)? Video by extension or imeta
/// mime, https-only (the player dials the URL itself — playbin with its
/// own redirects — and every guarded fetch path in the app is https;
/// a cleartext video degrades to the browser link, where the user's own
/// client stack makes the fetch), never a YouTube watch/shorts page
/// (GStreamer can't stream those — they stay browser links), never under
/// strict Tor (the facade rule).
pub fn inline_able(url: &str, mime: Option<&str>) -> bool {
    if crate::prefs::privacy_mode() == satori_core::privacy::PrivacyMode::Strict {
        return false;
    }
    if content::youtube_thumb(url).is_some() {
        return false;
    }
    // Cleartext stays out of the player: web_url() admits http:// for the
    // browser handoff, but the inline pipeline is a GET we dial ourselves.
    if !url.starts_with("https://") {
        return false;
    }
    mime.is_some_and(|m| m.starts_with("video/")) || content::is_video_url(url)
}

/// Tap on a video tile: open the inline player when the URL is inline-able,
/// else the browser (the honest link the tile showed before Phase 3).
pub fn open(url: String, mime: Option<String>, cx: &mut gpui::App) {
    // The browser allow-list (audit security M2): feed-derived URLs only
    // ever open as http(s).
    let openable = crate::views::content::web_url(&url);
    if !openable || !inline_able(&url, mime.as_deref()) {
        if openable {
            cx.open_url(&url);
        }
        return;
    }
    let Ok(parsed) = url::Url::parse(&url) else {
        cx.open_url(&url);
        return;
    };
    // Already open or opening — a second tap on the same tile is a no-op,
    // not a second pipeline.
    if active(&url).is_some() || opening(&url) {
        return;
    }
    // The tile breathes while the pipeline builds (Signal wakes the views).
    if let Ok(mut g) = OPENING.write() {
        *g = Some(url.clone());
    }
    cx.set_global(Signal);
    // Video::new blocks up to ~5s (playbin state + caps) — the background
    // executor, never the UI thread.
    cx.spawn(async move |cx| {
        let res = cx
            .background_executor()
            .spawn(async move { Video::new(&parsed) })
            .await;
        cx.update(|cx| {
            // Whatever the outcome, the wait is over.
            if let Ok(mut g) = OPENING.write()
                && g.as_deref() == Some(&url)
            {
                *g = None;
            }
            match res {
                Ok(video) => {
                    // One player per process: a replaced player's Drop joins
                    // its worker — defer that off the UI thread.
                    let old = {
                        let mut guard = match ACTIVE.write() {
                            Ok(g) => g,
                            Err(_) => return,
                        };
                        guard.replace(Player {
                            url: url.clone(),
                            video,
                        })
                    };
                    if let Some(old) = old {
                        std::thread::spawn(move || drop(old));
                    }
                }
                // The pipeline failed (missing plugins, dead URL): the honest
                // fallback is the browser — the pre-Phase-3 behavior.
                Err(_) => {
                    if crate::views::content::web_url(&url) {
                        cx.open_url(&url);
                    }
                }
            }
            cx.set_global(Signal);
        });
    })
    .detach();
}

/// Play/pause the active player (the control row's toggle). Interior
/// mutability — the handle's methods take &self.
pub fn toggle(cx: &mut gpui::App) {
    let Some(video) = ACTIVE
        .read()
        .ok()
        .and_then(|g| g.as_ref().map(|p| p.video.clone()))
    else {
        return;
    };
    video.set_paused(!video.paused());
    cx.set_global(Signal);
}

/// Stop and drop the active player (the ✕ control, Esc in the overlay).
pub fn close(cx: &mut gpui::App) {
    let old = ACTIVE.write().ok().and_then(|mut g| g.take());
    if let Some(old) = old {
        // Drop joins the GStreamer worker thread — off the UI thread.
        std::thread::spawn(move || drop(old));
        cx.set_global(Signal);
    }
}

/// The player element in an aspect box: the crate's element aspect-fits and
/// centers its frame within the given bounds, so the box IS the layout
/// contract — callers hand the area they can spare.
pub fn element(video: &Video, box_w: f32, box_h: f32) -> gpui_video_player::VideoElement {
    gpui_video_player::video(video.clone()).size(px(box_w), px(box_h))
}
