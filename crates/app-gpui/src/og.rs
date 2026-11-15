//! Link-preview cards (D73): one `og:` metadata fetch per linked page, a
//! bounded in-memory store, and the repaint plumbing.
//!
//! A note's FIRST non-media link gets a card: nothing paints until the
//! preview lands (the link row is already there), then the card shows
//! site, title, description, and its og:image riding the ORDINARY media
//! cache (all the image validation and caps apply; the og fetch only
//! hands over the URL). The owner picked auto-fetch: a preview fetches
//! when the note scrolls into view, the same discipline every avatar and
//! picture rides. Strict Tor keeps it off entirely (the facade rule: a
//! preview is third-party bytes) — `media_urls_cached` never emits the
//! key, and this module double-checks.
//!
//! Why a separate store and not the media Cache: that cache is image-
//! shaped end to end (decodes, thumbs, RGBA byte budgets); a preview is
//! text plus a reference to an image URL. This store is small on purpose:
//! previews are ~a hundred bytes, so a FIFO cap bounds it without LRU
//! machinery, and the failure discipline is the media pattern (transient
//! weather cools off with a doubling backoff; a NotMedia verdict is
//! terminal for the session).

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use gpui::EntityId;
use satori_core::manager::Core;
use satori_core::media::{LinkPreview, MediaError};

const FIFO_CAP: usize = 512;
const BACKOFF_START: Duration = Duration::from_secs(4);
const BACKOFF_MAX: Duration = Duration::from_secs(300);
/// Transient attempts before a URL goes terminal for the session: without
/// a cap, an offline or dead host re-fetched every BACKOFF_MAX forever
/// (a 256 KiB ranged GET per URL per 5 min, per flaky link).
const RETRY_CAP: u8 = 5;

/// TEST SEAM ONLY: plant a Ready verdict in the store. The regression
/// tests need a landed preview without a Core/gpui App around — the
/// store's own discipline (land-over-Loading-only) is exercised by the
/// real pipeline, this only opens the lock.
#[cfg(test)]
pub(crate) fn seed_test_preview(page_url: &str, preview: LinkPreview) {
    let mut store = store().lock().unwrap();
    store
        .map
        .insert(page_url.to_string(), State::Ready(Arc::new(preview)));
    store.order.push_back(page_url.to_string());
    let store = &mut *store;
    crate::views::content::fifo_trim(&mut store.map, &mut store.order, FIFO_CAP);
}

enum State {
    Loading(Vec<EntityId>),
    Ready(Arc<LinkPreview>),
    /// Terminal: the page has no preview (404, no og:/title) — retrying
    /// can never help this session.
    NotMedia,
    /// Transient weather; `backoff` doubles per failure, media-style.
    /// `attempts` counts transient fetches spent — at RETRY_CAP the entry
    /// converts to NotMedia (terminal) instead of fetching again.
    Failed {
        at: Instant,
        backoff: Duration,
        attempts: u8,
    },
}

struct Store {
    map: HashMap<String, State>,
    order: VecDeque<String>,
}

fn store() -> &'static Mutex<Store> {
    static STORE: OnceLock<Mutex<Store>> = OnceLock::new();
    STORE.get_or_init(|| {
        Mutex::new(Store {
            map: HashMap::new(),
            order: VecDeque::new(),
        })
    })
}

/// The preview for `page_url`, when one landed.
pub(crate) fn get(page_url: &str) -> Option<Arc<LinkPreview>> {
    match store().lock().unwrap().map.get(page_url) {
        Some(State::Ready(p)) => Some(Arc::clone(p)),
        _ => None,
    }
}

/// Queue the preview fetch for `page_url` on behalf of `view`. The sweep
/// calls this per visible row per frame — the media::fetch entry
/// discipline: join in-flight, backoff on weather, terminal on verdicts.
pub(crate) fn fetch(core: &Arc<Core>, page_url: String, view: EntityId, cx: &mut gpui::App) {
    // Defense in depth with media_urls_cached's strict-mode gate.
    if crate::prefs::privacy_mode() == satori_core::privacy::PrivacyMode::Strict {
        return;
    }
    enum Action {
        Start { backoff: Duration, attempts: u8 },
        Done,
    }
    let action = {
        let mut store = store().lock().unwrap();
        match store.map.get_mut(&page_url) {
            Some(State::Ready(_) | State::NotMedia) => Action::Done,
            Some(State::Loading(waiters)) => {
                if !waiters.contains(&view) {
                    waiters.push(view);
                }
                Action::Done
            }
            Some(State::Failed {
                at,
                backoff,
                attempts,
            }) => {
                if at.elapsed() < *backoff {
                    Action::Done
                } else if *attempts >= RETRY_CAP {
                    // The cap is spent: terminal, matching a NotMedia
                    // verdict — retrying a dead host can never help.
                    store.map.insert(page_url.clone(), State::NotMedia);
                    Action::Done
                } else {
                    let next = (*backoff * 2).min(BACKOFF_MAX);
                    let attempts = *attempts + 1;
                    // Convert to Loading NOW (the media cache's shape): the
                    // landing only accepts a verdict over a Loading entry —
                    // leaving Failed in place discarded every retry's
                    // verdict, so one transient round meant no card all
                    // session and a fetch every cool-off forever.
                    *at = Instant::now();
                    *backoff = next;
                    store
                        .map
                        .insert(page_url.clone(), State::Loading(vec![view]));
                    Action::Start {
                        backoff: next,
                        attempts,
                    }
                }
            }
            None => {
                store
                    .map
                    .insert(page_url.clone(), State::Loading(vec![view]));
                store.order.push_back(page_url.clone());
                // Destructured: fifo_trim's two disjoint borrows both go
                // through the MutexGuard's DerefMut — one borrow to the
                // checker — so the split-field call needs the raw &mut.
                let store = &mut *store;
                crate::views::content::fifo_trim(&mut store.map, &mut store.order, FIFO_CAP);
                Action::Start {
                    backoff: BACKOFF_START,
                    attempts: 1,
                }
            }
        }
    };
    if let Action::Start { backoff, attempts } = action {
        eprintln!("[og] fetch {page_url:?} attempts={attempts}");
        let core = core.clone();
        cx.spawn(async move |cx| {
            let mut rx = core.fetch_link_preview(page_url.clone());
            let verdict = { rx.recv() }.await.unwrap_or(Err(MediaError::Transient));
            match &verdict {
                Ok(p) => {
                    eprintln!("[og] {page_url:?} -> ok: {:?}", p.title);
                }
                Err(e) => {
                    eprintln!("[og] {page_url:?} -> {e:?}");
                }
            }
            let state = match &verdict {
                Ok(preview) => State::Ready(Arc::new(preview.clone())),
                Err(MediaError::NotMedia) => State::NotMedia,
                Err(MediaError::Transient) => State::Failed {
                    at: Instant::now(),
                    backoff,
                    attempts,
                },
            };
            // Land over OUR Loading entry only: a re-entrant fetch during
            // the await put a fresh one there — its waiters keep waiting.
            // `replaced` rides out of the lock: the image handoff and the
            // retry booking below only fire for a verdict we actually
            // landed.
            let (waiters, replaced) = {
                let mut store = store().lock().unwrap();
                let replaced = matches!(store.map.get(&page_url), Some(State::Loading(_)));
                if replaced {
                    let waiters = match store.map.insert(page_url.clone(), state) {
                        Some(State::Loading(w)) => w,
                        _ => Vec::new(),
                    };
                    // Refresh the FIFO position (a landing is a touch).
                    store.order.retain(|u| u != &page_url);
                    store.order.push_back(page_url.clone());
                    (waiters, true)
                } else {
                    (Vec::new(), false)
                }
            };
            // The og:image rides the ORDINARY media cache: queue it for
            // this view now that its URL is known. Its own landing
            // notifies again; the card reads it via the snapshot like any
            // picture. Gated on the landing: a verdict we dropped (the
            // entry was evicted or re-entered mid-flight) must not fetch
            // image bytes for a card that will never render.
            if replaced
                && let Ok(preview) = &verdict
                && let Some(img) = &preview.image
            {
                let core = core.clone();
                let img = img.clone();
                cx.update(|app| {
                    crate::media::fetch(&core, img, view, app);
                });
            }
            // A transient failure books exactly one retry — inside the
            // landing (media.rs's discipline: booked where the Failed
            // entry actually lands) — the timer re-enters fetch when the
            // backoff is spent.
            if replaced && let Err(MediaError::Transient) = &verdict {
                let core = core.clone();
                let page_url = page_url.clone();
                cx.update(|app| {
                    let core = core.clone();
                    let page_url = page_url.clone();
                    app.spawn(async move |app| {
                        app.background_executor().timer(backoff).await;
                        app.update(|app| fetch(&core, page_url, view, app));
                    })
                    .detach();
                });
            }
            for id in waiters {
                cx.update(|app| app.notify(id));
            }
        })
        .detach();
    }
}
