//! Media pipeline — guarded fetch, sha256-keyed disk cache, strict decode.
//!
//! Port of `src/routes/image-proxy.ts` + `src/ssrf.ts` discipline, reduced to
//! the client surface: scheme allowlist (https only), IP-literal and
//! internal-host rejection, sha256-keyed disk cache, strict decode to pixels
//! (SVG never rendered as a trusted format — `image` decodes raster only).
//!
//! Reliability contract (polish pass): every network step is timed and
//! byte-capped; transient failures retry with backoff and report themselves
//! as such (the UI cools off instead of giving up); bytes are validated by
//! decode BEFORE they touch the disk (a poisoned cache file — an HTML error
//! page keyed as an image — used to outlive restarts); and decodes of disc-
//! sized needs ship a ≤128px PNG beside the original so an avatar never
//! costs a 48MB full-res decode inside gpui's asset thread.
//!
//! Resource bounds (perf/security pass): downloads are gated — at most six
//! in flight, so a media-heavy top-up queues instead of opening forty TLS
//! connections; the decode runs on tokio's BLOCKING pool, off the 2-worker
//! relay runtime; and the decode ceiling is checked from the container
//! HEADER before any pixel allocation, so a 20MB compressed bomb never
//! becomes 1.6GB of RGBA.
//!
//! TODO(port): remaining SSRF set — Tor transport, NIP-B7 healing (M2/M4).
//! DNS-rebinding-safe resolution LANDED (issue #3 WS4): SafeResolver filters
//! every connection's address list to global IPs (the guard moved from the
//! URL string to the resolved addresses). Per-redirect re-validation
//! LANDED earlier (F5): every hop re-runs the URL guard.

use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::sync::OnceLock;
use std::time::Duration;

use sha2::{Digest, Sha256};
use url::Url;

use crate::config;
use crate::net_guard::SafeResolver;

/// Connect + per-read idle bounds for the guarded client. There is NO
/// total-request timeout on the media path: a hard 20s total killed
/// exactly the biggest legitimate files (hodlbod's 2–5.5MB article
/// covers) whenever the link ran slow — each attempt raced the clock
/// whole, failed as Transient, and the covers never landed while every
/// small avatar sailed through (the "some images won't load" report).
/// A flowing download now finishes no matter how slow; a STALLED one
/// dies in READ_IDLE via the per-chunk read timeout, and the byte cap
/// still bounds the transfer itself.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
pub const READ_IDLE: Duration = Duration::from_secs(15);
/// One fetch attempt's total budget — generous (20MB at ~170KB/s clears
/// it), so only a genuinely stalled server spends it. The retry ladder
/// (RETRY_ATTEMPTS here, the app's backoff above) converges after.
pub const ATTEMPT_BUDGET: Duration = Duration::from_secs(120);
/// JSON surfaces (oEmbed, LNURL) are small and user-facing: keep the
/// snappy total the media path can't afford.
pub const JSON_BUDGET: Duration = Duration::from_secs(20);

#[derive(Debug)]
pub struct DecodedImage {
    pub width: u32,
    pub height: u32,
    /// The ORIGINAL encoded bytes (jpeg/png/webp/gif) — the UI hands them to
    /// gpui's image pipeline, which decodes on its own asset thread.
    pub bytes: Vec<u8>,
    /// Format of `bytes` (gpui maps it onto its own enum).
    pub format: image::ImageFormat,
    /// A ≤128px PNG re-encode for disc-sized renders (avatars). gpui decodes
    /// `bytes` at full resolution — a 4000×3000 photo costs ~48MB of decode
    /// for a 28px circle without this. None when the original is already
    /// small (the full decode is cheap) or the re-encode failed.
    pub thumb: Option<Vec<u8>>,
}

/// Why a fetch failed. The distinction is the UI's retry policy: Transient
/// cools off and tries again later; NotMedia is a verdict — the bytes
/// arrived whole and are not an image (an HTML error page, a blossom page
/// URL) — retrying can never help.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MediaError {
    /// Network hiccup, timeout, server error, rate limit — worth another
    /// attempt (immediately backed-off here, then again on a later look).
    Transient,
    /// Verified not-an-image (or unsafe/over-cap): terminal for this session.
    NotMedia,
}

impl std::fmt::Display for MediaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MediaError::Transient => write!(f, "media fetch failed, will retry"),
            MediaError::NotMedia => write!(f, "not an image"),
        }
    }
}

/// Download caps: media files average whole MBs, and every stream fetched
/// through here is by definition user-adjacent — 20MB covers any picture
/// worth showing (bigger is a distribution, not an image); JSON previews
/// get 2MB. Over-cap reads are verdicts, not errors: no retry helps.
const MAX_IMAGE_BYTES: usize = 20 * 1024 * 1024;
const MAX_JSON_BYTES: usize = 2 * 1024 * 1024;

/// The decode ceiling in PIXELS (checked from the header before any
/// allocation — see decode): 40MP ≈ a full-frame camera photo ≈ 160MB of
/// RGBA at the absolute peak. Compressed bombs die here instead.
const MAX_PIXELS: u64 = 40_000_000;

/// Bounded retry cadence for transient failures: three attempts, 0.6s →
/// 1.2s apart — enough to absorb a CDN hiccup, short enough that the UI's
/// own cool-off (media.rs) picks the next attempt up promptly.
const RETRY_ATTEMPTS: usize = 3;

/// The fetch gate: at most six media downloads in flight. A top-up page is
/// 40+ pictures — ungated, that's forty parallel TLS connections against one
/// CDN and a thundering herd of decodes right behind them. Queued, the page
/// still fills promptly and nothing else in the process drowns. JSON
/// fetches (oEmbed, LNURL) stay ungated: they're small, rare, and a zap
/// invoice must not queue behind pictures.
const MAX_CONCURRENT_FETCHES: usize = 6;

fn gate() -> &'static tokio::sync::Semaphore {
    static GATE: OnceLock<tokio::sync::Semaphore> = OnceLock::new();
    GATE.get_or_init(|| tokio::sync::Semaphore::const_new(MAX_CONCURRENT_FETCHES))
}

/// One shared client for every fetch in this module. Three hard rules baked
/// in: a browser-style User-Agent (CDNs — Cloudflare in front of the
/// blossoms especially — 403 requests with no UA, and those 403s read as
/// verdicts, so avatars died permanently), connect + read-idle timeouts
/// (a hung fetch used to pin the cache entry Loading forever, joining
/// every later waiter onto a corpse — the avatar that never loads all
/// session; the READ_IDLE floor keeps that protection without the total
/// cap that starved big files), and a per-hop SSRF re-validation policy
/// (below).
fn http() -> &'static reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .user_agent(
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 \
                 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
            )
            .connect_timeout(CONNECT_TIMEOUT)
            .read_timeout(READ_IDLE)
            // Issue #3 WS4 (the media.rs TODO): the resolver is the last
            // guard — reqwest dials WHATEVER it returns, so the address
            // list is filtered to global IPs (see SafeResolver). Every
            // connection — first party, every redirect hop, every retry —
            // re-walks it, so a rebinding rotation between hops re-runs
            // the check.
            .dns_resolver(std::sync::Arc::new(SafeResolver))
            // F5 (four-lens review): reqwest's DEFAULT policy follows up to
            // ten redirects with no re-validation — a friendly CDN 302-ing
            // to http://localhost:8080 or https://127.1/ was followed
            // blindly. Every hop now re-runs the full URL guard; a failed
            // hop STOPs (the last 3xx response surfaces through
            // guarded_get's status map as a NotMedia verdict, so nothing
            // retries it) and hops are capped below the old default.
            .redirect(reqwest::redirect::Policy::custom(|attempt| {
                if attempt.previous().len() > 5 || !is_safe_media_url(attempt.url().as_str()) {
                    attempt.stop()
                } else {
                    attempt.follow()
                }
            }))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new())
    })
}

/// The shared guarded client for the other core HTTP surfaces (PR #6):
/// NIP-11 relay documents ride the same SSRF discipline as every image —
/// SafeResolver on every hop, per-hop `is_safe_media_url` re-validation,
/// hop cap 5. Bounded but real before: a hostile relay-list entry could
/// 302 the document fetch at any http(s) URL.
pub(crate) fn client() -> &'static reqwest::Client {
    http()
}

/// GET through the guarded client with the status→verdict mapping: 429/5xx
/// and every transport-level failure are Transient; the other 4xx are
/// verdicts (a 404 will not heal by Tuesday).
async fn guarded_get(url: &str, range: Option<usize>) -> Result<reqwest::Response, MediaError> {
    let mut req = http().get(url).timeout(ATTEMPT_BUDGET);
    if let Some(cap) = range {
        // A ranged GET: a server that honors it replies 206 with a
        // within-cap content-length, so read_capped's declared-length
        // rejection never fires for a big file we only wanted the head of.
        req = req.header(reqwest::header::RANGE, format!("bytes=0-{}", cap - 1));
    }
    let res = req
        .send()
        .await
        // Timeouts, connect failures, TLS hiccups: all weather, all transient.
        .map_err(|_| MediaError::Transient)?;
    match res.status().as_u16() {
        200..=299 => Ok(res),
        429 | 500..=599 => Err(MediaError::Transient),
        _ => Err(MediaError::NotMedia),
    }
}

/// Read the body under a hard cap (declared length rejected up-front, the
/// chunk stream cut off if it lies). Shared with the upload path — a
/// server's response is bounded the same way its fetches are.
pub(crate) async fn read_capped(
    mut res: reqwest::Response,
    cap: usize,
) -> Result<Vec<u8>, MediaError> {
    if let Some(len) = res.content_length()
        && len as usize > cap
    {
        return Err(MediaError::NotMedia);
    }
    let mut body = Vec::new();
    while let Some(chunk) = res.chunk().await.map_err(|_| MediaError::Transient)? {
        if body.len() + chunk.len() > cap {
            return Err(MediaError::NotMedia);
        }
        body.extend_from_slice(chunk.as_ref());
    }
    Ok(body)
}

/// GET + byte cap + bounded transient retries. Permanent verdicts return at
/// once — nothing below this layer ever re-sees a network error. `range`
/// turns the GET into `bytes=0-<cap-1>` (the poster head fetch: big files
/// answer 206 with a within-cap length instead of tripping read_capped's
/// declared-length rejection); image fetches stay full-body.
async fn fetch_capped(url: &str, cap: usize, range: bool) -> Result<Vec<u8>, MediaError> {
    let mut wait = Duration::from_millis(600);
    for attempt in 0..RETRY_ATTEMPTS {
        // One gate slot per ATTEMPT, not per URL: the permit is released
        // during the backoff sleep, so a dead CDN can't pin a slot for its
        // whole retry cycle and starve the queue behind it.
        let outcome = {
            let _permit = gate().acquire().await.map_err(|_| MediaError::Transient)?;
            match guarded_get(url, range.then_some(cap)).await {
                // The permit is held through the body read — the transfer
                // is the thing being bounded.
                Ok(res) => return read_capped(res, cap).await,
                Err(e) => e,
            }
        };
        if outcome == MediaError::NotMedia || attempt + 1 == RETRY_ATTEMPTS {
            return Err(outcome);
        }
        tokio::time::sleep(wait).await;
        wait *= 2;
    }
    Err(MediaError::Transient)
}

/// GET for the JSON surfaces (oEmbed, LNURL-pay): unlike the media path the
/// failure text reaches the user (the zap sheet shows it), so statuses keep
/// their own honest wording instead of media verdicts.
async fn json_get(url: &str) -> Result<reqwest::Response, String> {
    let res = http()
        .get(url)
        .timeout(JSON_BUDGET)
        .send()
        .await
        .map_err(|e| e.to_string())?;
    let status = res.status();
    if !status.is_success() {
        return Err(format!("HTTP {status}"));
    }
    Ok(res)
}

/// Fetch a JSON document (oEmbed etc.) through the same guarded, cached
/// path. Cache read-through keeps repeat previews instant; the parse is
/// validated BEFORE the disk write (a cached non-JSON body would poison the
/// preview permanently — same discipline as fetch_image's decode).
/// Cache IO off the relay runtime, same reasoning as decode_async: the
/// 2-worker rt serves relays, zaps, and the wallet, and a disk read must
/// not pin a worker while it waits on the page cache. Read Err = cache
/// miss, exactly as the inline `std::fs::read` it replaced.
async fn read_cache_off_rt(path: PathBuf) -> std::io::Result<Vec<u8>> {
    tokio::task::spawn_blocking(move || std::fs::read(path))
        .await
        .unwrap_or_else(|_| Err(std::io::Error::other("cache read task lost")))
}

pub async fn fetch_json(url: &str) -> Result<serde_json::Value, String> {
    if !is_safe_media_url(url) {
        return Err("unsafe URL".into());
    }
    let path = cache_path(&cache_key(url));
    if let Ok(cached) = read_cache_off_rt(path.clone()).await {
        return serde_json::from_slice(&cached).map_err(|e| e.to_string());
    }
    let res = json_get(url).await?;
    let body = read_capped(res, MAX_JSON_BYTES)
        .await
        .map_err(|e| e.to_string())?;
    let value: serde_json::Value = serde_json::from_slice(&body).map_err(|e| e.to_string())?;
    tokio::task::spawn_blocking(move || write_cache(&path, &body))
        .await
        .ok();
    Ok(value)
}

/// A guarded JSON fetch with NO disk cache — for answers that must never be
/// replayed (LNURL-pay callbacks return one-time bolt11 invoices; a cached
/// invoice would double-fail after its first spend). Same SSRF discipline as
/// every other fetch (D20: the wallet's LNURL path rides this).
pub async fn fetch_json_uncached(url: &str) -> Result<serde_json::Value, String> {
    if !is_safe_media_url(url) {
        return Err("unsafe URL".into());
    }
    let res = json_get(url).await?;
    let body = read_capped(res, MAX_JSON_BYTES)
        .await
        .map_err(|e| e.to_string())?;
    serde_json::from_slice(&body).map_err(|e| e.to_string())
}

pub async fn fetch_image(url: &str) -> Result<DecodedImage, MediaError> {
    if !is_safe_media_url(url) {
        return Err(MediaError::NotMedia);
    }

    // Cache read-through, keyed by sha256(url). Only validated decodes are
    // ever on disk (below), so a cache hit cannot poison the decode.
    let key = cache_key(url);
    let path = cache_path(&key);
    match read_cache_off_rt(path.clone()).await {
        Ok(cached) => decode_async(cached).await,
        Err(_) => {
            let body = fetch_capped(url, MAX_IMAGE_BYTES, false).await?;
            // Validate BEFORE the disk write. The write used to precede the
            // decode, so an HTML error page or truncated body keyed as an
            // image stayed there forever — a broken avatar that survived
            // restarts. (The decode result doubles as the return value:
            // fresh bytes decode exactly once.) The write runs off the
            // runtime too: every 10th write triggers the trim, a stat pass
            // over a few hundred cache files plus removals.
            let decoded = decode_async(body.clone()).await?;
            tokio::task::spawn_blocking(move || write_cache(&path, &body))
                .await
                .ok();
            Ok(decoded)
        }
    }
}

/// The pre-polish cache dir could hold poisoned files (bytes hit disk before
/// decode validated them); the versioned dir starts clean and this drops the
/// legacy one. Best-effort, once per process start (manager init).
pub fn purge_legacy_cache() {
    let legacy = config::data_dir().join("media-cache");
    if legacy.exists() {
        let _ = std::fs::remove_dir_all(legacy);
    }
}

/// The whole poster job (D32, D72's fourth rung): cache read-through, the
/// capped guarded head fetch + injected byte sniffer, and — when the head
/// can't decode (the moov atom at the file's END makes the head useless to
/// any demuxer, however big) — the injected URL sniffer: the same guarded
/// door inline playback uses (video_proxy's range requests), letting
/// GStreamer pull exactly the bytes it needs, tail included. Runs ON a
/// tokio runtime — every call below (reqwest, `spawn_blocking`) needs that
/// context, so the UI awaits the verdict through `Core::fetch_poster`'s
/// channel: `fetch_image`'s exact seam. (The first cut of this let the UI
/// poll these futures on gpui's executor — no tokio context there, thread
/// 'main panicked at `read_cache_off_rt`, the app died the day D32
/// shipped.) The sniffers are injected because gstreamer lives in the UI
/// crate; both block (a bounded decode) and run on the blocking pool,
/// never on the 2-worker relay runtime itself.
pub async fn fetch_poster(
    url: String,
    cap: usize,
    sniff: impl FnOnce(&[u8]) -> std::result::Result<(u32, u32, Vec<u8>), ()> + Send + 'static,
    sniff_uri: impl FnOnce(&str) -> std::result::Result<(u32, u32, Vec<u8>), ()> + Send + 'static,
) -> Result<DecodedImage, MediaError> {
    if !is_safe_media_url(&url) {
        return Err(MediaError::NotMedia);
    }
    // Cache read-through: a sniff survives restarts.
    if let Some(png) = poster_cached(&url).await {
        return decode_async(png).await;
    }
    // The head bytes are a partial media file BY DESIGN — they validate as
    // nothing and so never touch the image cache; only the sniffed frame
    // (`poster_store`) earns a cache slot. The GET is ranged, so a big file
    // answers 206 within the cap; a server that IGNORES Range answers 200
    // with its full declared length and read_capped rejects it — not fatal,
    // the ranged sniff below has its own door.
    let head = fetch_capped(&url, cap, true).await;
    // The head's verdict survives its bytes being moved into the sniffer:
    // if the ranged sniff also misses, this (a 404 = NotMedia, not weather)
    // is the honest thing to return.
    let head_verdict: Option<MediaError> = head.as_ref().err().copied();
    // JoinError = the sniff task itself died (a bug, but the tile staying
    // bare beats the app following it down); Err(()) = no decodable frame
    // from these bytes (moov at the end, audio-only) — fall through to the
    // ranged sniff before calling it transient.
    let frame = match head {
        Ok(head) => tokio::task::spawn_blocking(move || sniff(&head))
            .await
            .map_err(|_| MediaError::Transient)?
            .ok(),
        // The head fetch itself failed (over-cap declared length, 404,
        // dead server): not the end — the ranged sniff fetches exactly the
        // bytes the demuxer asks for, no head needed.
        Err(_) => None,
    };
    let frame = match frame {
        Some(frame) => frame,
        None => {
            // The ranged sniff fetches through the same pinned client the
            // player uses (the URL already passed the safe-URL gate); a
            // miss here returns the head's verdict when there was one —
            // a 404 is NotMedia, not weather — else transient, the
            // backoff decides.
            let url = url.clone();
            match tokio::task::spawn_blocking(move || sniff_uri(&url))
                .await
                .map_err(|_| MediaError::Transient)?
            {
                Ok(frame) => frame,
                Err(()) => match head_verdict {
                    Some(verdict) => return Err(verdict),
                    None => return Err(MediaError::Transient),
                },
            }
        }
    };
    let (_, _, png) = frame;
    poster_store(&url, &png).await;
    decode_async(png).await
}

/// A sniffed poster's cache key: namespaced apart from `fetch_image`
/// content (`poster\0…` hashes differently) so a partial-file decode can
/// never collide with a whole-file one.
fn poster_key(url: &str) -> String {
    cache_key(&format!("poster\x00{url}"))
}

/// The cached poster frame for `url`, when one was sniffed before (raw
/// PNG bytes — decoded by `fetch_poster`'s ordinary validate path).
async fn poster_cached(url: &str) -> Option<Vec<u8>> {
    read_cache_off_rt(cache_path(&poster_key(url))).await.ok()
}

/// Store a sniffed poster (a PNG the sniffer encoded — valid by
/// construction). Rides the ordinary cache trim: posters are a few tens
/// of KB and re-derivable, so they age out like any other media.
async fn poster_store(url: &str, png: &[u8]) {
    let path = cache_path(&poster_key(url));
    let png = png.to_vec();
    tokio::task::spawn_blocking(move || write_cache(&path, &png))
        .await
        .ok();
}

// --- link previews (og: metadata cards) -------------------------------------

/// Tracking/analytics params stripped from body-text links (display,
/// click-through, and preview fetches): the ad/analytics click-ids plus
/// the utm_* family. The TS reference's conservative set (content.ts
/// TRACKING_PARAMS): every entry is a well-known tracker that never
/// changes page content, so removing one can't break a link — a search
/// page's `s=` or a YouTube timestamp (`t=`) stay untouched. "Your clicks
/// don't carry their tags."
const TRACKING_PARAMS: [&str; 21] = [
    "fbclid",
    "gclid",
    "gbraid",
    "wbraid",
    "dclid",
    "msclkid",
    "yclid",
    "twclid",
    "igshid",
    "ttclid",
    "mc_eid",
    "mc_cid",
    "mkt_tok",
    "oly_anon_id",
    "oly_enc_id",
    "vero_id",
    "_hsenc",
    "_hsmi",
    "mibextid",
    "fb_action_ids",
    "s_cid",
];

/// The link without its tracking params. Unparseable / non-http(s) /
/// tracker-free URLs return verbatim; a parseable URL re-serializes only
/// when something was removed.
pub fn strip_tracking_params(url: &str) -> String {
    let Ok(mut u) = url::Url::parse(url) else {
        return url.to_string();
    };
    if !matches!(u.scheme(), "http" | "https") {
        return url.to_string();
    }
    let trackers: Vec<String> = u
        .query_pairs()
        .map(|(k, _)| k.into_owned())
        .filter(|k| {
            TRACKING_PARAMS.iter().any(|t| t.eq_ignore_ascii_case(k))
                || k.to_ascii_lowercase().starts_with("utm_")
        })
        .collect();
    if trackers.is_empty() {
        return url.to_string();
    }
    // Rebuild the query without the trackers (the serializer has no
    // per-pair remove): keep every non-tracker pair verbatim.
    let kept: Vec<(String, String)> = u
        .query_pairs()
        .filter(|(k, _)| {
            !TRACKING_PARAMS.iter().any(|t| t.eq_ignore_ascii_case(k))
                && !k.to_ascii_lowercase().starts_with("utm_")
        })
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    u.set_query(None);
    if !kept.is_empty() {
        u.query_pairs_mut().extend_pairs(kept);
    }
    u.into()
}

/// The HTML head fetch cap: og: meta tags live in `<head>`, which even
/// bloated pages fit in — the read cuts at `</head>` anyway. A server that
/// declares a bigger length answers a 206 (the GET is ranged).
pub const OG_CAP: usize = 256 * 1024;

/// What a link preview card paints: all fields attacker-writable, so the
/// renderer caps them before display.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LinkPreview {
    pub title: String,
    pub description: Option<String>,
    /// og:site_name, else the page's bare host.
    pub site: String,
    /// og:image / twitter:image when the page offers one (absolute http(s)).
    pub image: Option<String>,
}

/// Fetch + extract a link's preview metadata: cache read-through (a
/// preview survives restarts), one ranged guarded GET (the head of the
/// HTML is all a `<meta>` scan needs), parse validated BEFORE the disk
/// write (the fetch_image discipline — a poisoned cache entry would kill
/// the card forever). The verdict mapping is the media path's: 404 et al
/// are NotMedia (terminal for the session), 429/5xx/network are Transient.
pub async fn fetch_link_preview(url: &str) -> Result<LinkPreview, MediaError> {
    // Defense in depth: the UI gates strict mode twice (the mode-keyed
    // memo and og::fetch's entry check) — the core seam gates it too, so
    // no caller can bypass the facade rule (a preview is third-party
    // bytes; strict fetches none).
    if crate::privacy::privacy_mode() == crate::privacy::PrivacyMode::Strict {
        return Err(MediaError::NotMedia);
    }
    // The stripped form is the cache key: the same link with and without
    // utm noise shares one preview, and no tracker lands in the store.
    let url = strip_tracking_params(url);
    if !is_safe_media_url(&url) {
        return Err(MediaError::NotMedia);
    }
    let path = cache_path(&cache_key(&format!("og\x00{url}")));
    // A corrupt entry is a miss (the write below replaces it).
    if let Ok(bytes) = read_cache_off_rt(path.clone()).await
        && let Ok(preview) = serde_json::from_slice::<LinkPreview>(&bytes)
    {
        return Ok(preview);
    }
    let head = fetch_capped(&url, OG_CAP, true).await?;
    // JoinError = the parse task died (a bug; the card staying absent beats
    // the app following it down).
    let preview = tokio::task::spawn_blocking(move || extract_preview(&head, &url))
        .await
        .map_err(|_| MediaError::Transient)?
        .ok_or(MediaError::NotMedia)?;
    let json = serde_json::to_vec(&preview).unwrap_or_default();
    tokio::task::spawn_blocking(move || write_cache(&path, &json))
        .await
        .ok();
    Ok(preview)
}

/// The og: extraction: scan the (capped, `</head>`-cut) HTML for meta tags
/// carrying og:/twitter: card fields, fall back to `<title>`. None when the
/// page offers no title at all — nothing worth a card. A hand parser on
/// purpose: the input is attacker-written HTML, the fields we want are a
/// fixed handful, and a general HTML dependency is a parser-of-attacker-
/// input surface the audit would flag.
fn extract_preview(head: &[u8], url: &str) -> Option<LinkPreview> {
    let text = String::from_utf8_lossy(head);
    // Everything we want lives before </head> (case-insensitive); cut there
    // so <body> prose can never smuggle a <meta> in. ASCII-only lowering:
    // full Unicode `to_lowercase` changes byte lengths (Ⅰ → i), skewing
    // every offset used to slice the ORIGINAL — a char-boundary panic on
    // hostile pages, silent mis-scoping otherwise.
    let lower = text.to_ascii_lowercase();
    let scope = lower
        .find("</head")
        .map(|end| &text[..end])
        .unwrap_or(&text);

    let mut title = None;
    let mut description = None;
    let mut image = None;
    let mut site = None;
    for tag in meta_tags(scope) {
        let props = tag_attrs(&tag);
        let kind = props.iter().find(|(k, _)| k == "property" || k == "name");
        let Some((_, kind)) = kind else { continue };
        let content = props
            .iter()
            .find(|(k, _)| k == "content")
            .map(|(_, v)| v.clone())
            .unwrap_or_default();
        // First tag wins (publishers repeat og: tags per attachment).
        match kind.as_str() {
            "og:title" | "twitter:title" => {
                title.get_or_insert(content);
            }
            "og:description" | "twitter:description" => {
                description.get_or_insert(content);
            }
            "og:image" | "twitter:image" => {
                image.get_or_insert(content);
            }
            "og:site_name" => {
                site.get_or_insert(content);
            }
            _ => {}
        }
    }
    // No og: title: the page's <title> still names it.
    let title = title.or_else(|| html_title(scope)).map(|t| cap(&t, 200))?;

    // The image must be an absolute http(s) URL: a relative one would need
    // resolving against an attacker-chosen base, a data:/javascript: one is
    // not a picture. The IMAGE fetch re-validates everything again.
    let image = image
        .filter(|i| i.starts_with("https://") || i.starts_with("http://"))
        .map(|i| cap(&i, 2048));

    // The site: og:site_name, else the URL's bare host (no scheme, no path).
    let site = site
        .map(|s| cap(&s, 100))
        .or_else(|| host_of(url))
        .unwrap_or_default();

    Some(LinkPreview {
        title,
        description: description.map(|d| cap(&d, 300)),
        site,
        image,
    })
}

fn cap(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let cut: String = s.chars().take(max).collect();
        format!("{cut}\u{2026}")
    }
}

fn host_of(url: &str) -> Option<String> {
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))?;
    let host = rest.split(['/', '?', '#']).next()?;
    (!host.is_empty()).then(|| host.trim_start_matches("www.").to_string())
}

/// Each `<meta …>` tag in `scope`, as its raw tag text. Case-insensitive
/// opener scan; the tag ends at the first `>` (og: tags are never quoted-
/// gt inside). ASCII-only lowering keeps the found offsets valid slice
/// indices into `scope` (Unicode case expansion would skew them).
fn meta_tags(scope: &str) -> Vec<String> {
    let lower = scope.to_ascii_lowercase();
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(start) = lower[from..].find("<meta").map(|i| i + from) {
        let after = start + "<meta".len();
        // A tag boundary check: `<meta` must not be `<metaxy` — the next
        // char is whitespace, `>` or `/`.
        if lower[after..]
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphanumeric())
        {
            from = after;
            continue;
        }
        match lower[after..].find('>') {
            Some(end) => {
                out.push(scope[after..after + end].to_string());
                from = after + end + 1;
            }
            None => break, // truncated head — the cap ran out mid-tag
        }
    }
    out
}

/// A tag's attributes: lowercased names, entity-decoded values. Quoted and
/// unquoted values both parse; junk is skipped, never panicked on.
fn tag_attrs(tag: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let b = tag.as_bytes();
    let mut i = 0;
    while i < b.len() {
        // Attribute name: skip anything that isn't one.
        while i < b.len() && !b[i].is_ascii_alphanumeric() && b[i] != b'/' {
            i += 1;
        }
        let name_start = i;
        while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == b':' || b[i] == b'-') {
            i += 1;
        }
        if i == name_start {
            i += 1;
            continue;
        }
        let name = tag[name_start..i].to_ascii_lowercase();
        // Optional `=` + value (quoted or a bare token).
        let mut j = i;
        while j < b.len() && b[j].is_ascii_whitespace() {
            j += 1;
        }
        let value = if j < b.len() && b[j] == b'=' {
            j += 1;
            while j < b.len() && b[j].is_ascii_whitespace() {
                j += 1;
            }
            if j < b.len() && (b[j] == b'"' || b[j] == b'\'') {
                let quote = b[j];
                j += 1;
                let vstart = j;
                while j < b.len() && b[j] != quote {
                    j += 1;
                }
                let v = &tag[vstart..j.min(b.len())];
                i = (j + 1).min(b.len());
                decode_entities(v)
            } else {
                let vstart = j;
                while j < b.len() && !b[j].is_ascii_whitespace() && b[j] != b'>' {
                    j += 1;
                }
                i = j;
                decode_entities(&tag[vstart..j])
            }
        } else {
            i = j;
            String::new()
        };
        out.push((name, value));
    }
    out
}

/// The handful of entities HTML previews actually carry (&amp; &lt; &gt;
/// &quot; &#39; and the numeric forms); unknown entities stay verbatim —
/// a mangled title beats a mangled everything.
fn decode_entities(s: &str) -> String {
    if !s.contains('&') {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] != b'&' {
            let ch = s[i..].chars().next().unwrap();
            out.push(ch);
            i += ch.len_utf8();
            continue;
        }
        let Some(semi) = s[i..].find(';').map(|p| i + p) else {
            out.push('&');
            i += 1;
            continue;
        };
        let ent = &s[i + 1..semi];
        let decoded = match ent {
            "amp" => Some('&'),
            "lt" => Some('<'),
            "gt" => Some('>'),
            "quot" => Some('"'),
            "apos" => Some('\''),
            "nbsp" => Some(' '),
            numeric if ent.starts_with("#x") || ent.starts_with("#X") => {
                u32::from_str_radix(&numeric[2..], 16)
                    .ok()
                    .and_then(char::from_u32)
            }
            numeric if ent.starts_with('#') => {
                numeric[1..].parse::<u32>().ok().and_then(char::from_u32)
            }
            _ => None,
        };
        match decoded {
            Some(c) => {
                out.push(c);
                i = semi + 1;
            }
            None => {
                out.push('&');
                i += 1;
            }
        }
    }
    out
}

/// The `<title>` text (first one, entity-decoded, whitespace-collapsed).
/// ASCII-only lowering keeps the found offsets valid slice indices into
/// `scope` (Unicode case expansion would skew them).
fn html_title(scope: &str) -> Option<String> {
    let lower = scope.to_ascii_lowercase();
    let start = lower.find("<title")?;
    let after = scope[start..].find('>')? + start + 1;
    let end = lower[after..].find("</title")? + after;
    let raw = scope[after..end].trim();
    (!raw.is_empty()).then(|| raw.split_whitespace().collect::<Vec<_>>().join(" "))
}

pub fn cache_key(url: &str) -> String {
    let mut h = Sha256::new();
    h.update(url.as_bytes());
    hex(&h.finalize())
}

fn cache_path(key: &str) -> PathBuf {
    config::media_cache_dir().join(key)
}

fn write_cache(path: &std::path::Path, body: &[u8]) {
    if std::fs::create_dir_all(config::media_cache_dir()).is_err() {
        return;
    }
    let _ = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .and_then(|mut f| f.write_all(body));
    WRITE_COUNT.fetch_add(1, Ordering::Relaxed);
    // Trim cadence vs overshoot: media files average whole MBs, so a
    // sparse cadence lets the dir balloon between trims (every 50th
    // write ≈ +150MB observed); every 10th keeps the overshoot to tens
    // of MB for a stat() pass over a few hundred files.
    if WRITE_COUNT.load(Ordering::Relaxed).is_multiple_of(10) {
        trim_cache(200 * 1024 * 1024, 150 * 1024 * 1024);
    }
}

/// Decode OFF the relay runtime. fetch_image runs on the same 2-worker
/// tokio rt that serves relays, zaps, and the wallet — a 12MP decode
/// (hundreds of ms, plus the AVIF re-encode) belongs on the blocking pool,
/// whose threads exist precisely so event-loop workers never stall.
async fn decode_async(bytes: Vec<u8>) -> Result<DecodedImage, MediaError> {
    tokio::task::spawn_blocking(move || decode(&bytes))
        .await
        .map_err(|_| MediaError::Transient)?
}

fn decode(bytes: &[u8]) -> Result<DecodedImage, MediaError> {
    // The ceiling is checked from the CONTAINER HEADER before any pixel
    // allocation: a 20MB compressed bomb decodes to ~1.6GB of RGBA, and the
    // byte cap bounds the compressed size, not the pixels. 40MP (~160MB of
    // RGBA at peak) is far past anything a timeline shows and far below
    // bomb scale. NotMedia is the honest verdict: the bytes arrived whole
    // and will not be shown.
    let (w0, h0) = image::ImageReader::new(std::io::Cursor::new(bytes))
        .with_guessed_format()
        .map_err(|_| MediaError::NotMedia)?
        .into_dimensions()
        .map_err(|_| MediaError::NotMedia)?;
    if w0 as u64 * h0 as u64 > MAX_PIXELS {
        return Err(MediaError::NotMedia);
    }
    // The full decode validates the bytes (a blossom page URL is not media)
    // and yields the true dims for aspect-correct frames; the UI never
    // touches these pixels — it re-decodes from `bytes` on its own thread.
    let img = image::load_from_memory(bytes).map_err(|_| MediaError::NotMedia)?;
    let rgba = img.to_rgba8();
    let (width, height) = rgba.dimensions();
    let mut format = image::guess_format(bytes).map_err(|_| MediaError::NotMedia)?;
    let mut out = bytes.to_vec();
    // gpui's image pipeline maps png/jpeg/webp/gif only — AVIF bytes would
    // die at the UI layer and read as not-media. The pixels are validated
    // here, so a one-time re-encode (on the fetch thread, disk-cached after)
    // is all the format needs to travel the rest of the pipe.
    if format == image::ImageFormat::Avif {
        let mut png = Vec::new();
        if img
            .write_to(&mut std::io::Cursor::new(&mut png), image::ImageFormat::Png)
            .is_ok()
        {
            out = png;
            format = image::ImageFormat::Png;
        }
    }
    // Disc thumb: only when the original dwarfs a disc — at ≤256 on the long
    // edge the full decode is already cheap. `thumbnail` is the fast path
    // (nearest sampling); a disc is 28px, quality is not the question.
    let thumb = if width.max(height) > 256 {
        let mut png = Vec::new();
        img.thumbnail(128, 128)
            .write_to(&mut std::io::Cursor::new(&mut png), image::ImageFormat::Png)
            .ok()
            .map(|_| png)
    } else {
        None
    };
    Ok(DecodedImage {
        width,
        height,
        bytes: out,
        format,
        thumb,
    })
}

/// SSRF guard, reduced surface: https only; rejects IP literals and
/// internal/metadata hosts.
pub fn is_safe_media_url(url: &str) -> bool {
    let parsed = match Url::parse(url) {
        Ok(u) => u,
        Err(_) => return false,
    };
    if parsed.scheme() != "https" {
        return false;
    }
    match parsed.host_str() {
        Some(host) => !is_internal_host(host),
        None => false,
    }
}

fn is_internal_host(host: &str) -> bool {
    let host = host.trim_end_matches('.');
    if host.starts_with('[') {
        // IPv6 literal — reject all in this slice.
        return true;
    }
    if host == "localhost" || host.ends_with(".local") || host.ends_with(".internal") {
        return true;
    }
    // IPv4 literal forms — INCLUDING the ones glibc's getaddrinfo accepts
    // but Rust's Ipv4Addr::parse rejects: "127.1" (fewer than 4 parts),
    // "2130706433" (raw u32), "0x7f.1" (hex per part), "0177.0.0.1"
    // (octal). Every one of those resolves to loopback on this platform.
    if host.parse::<std::net::Ipv4Addr>().is_ok() {
        return true;
    }
    // The literal spellings beyond the dotted quad. Strictness matters in
    // BOTH directions: "0x7f.1" must die, but "bee.cd" — every part made
    // of hex LETTERS — is a legal DNS name, because inet_aton only reads
    // hex with an explicit 0x prefix. So a part counts as numeric only in
    // 0x-hex form or plain decimal (which covers octal spellings); a host
    // is treated as a literal only when EVERY dot-part is numeric.
    host.split('.').all(part_is_numeric)
}

/// The part classifier for the literal check above (host-side names).
fn part_is_numeric(part: &str) -> bool {
    if let Some(hexpart) = part.strip_prefix("0x").or_else(|| part.strip_prefix("0X")) {
        return !hexpart.is_empty() && hexpart.bytes().all(|c| c.is_ascii_hexdigit());
    }
    !part.is_empty() && part.bytes().all(|c| c.is_ascii_digit())
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

use std::sync::atomic::{AtomicU64, Ordering};
static WRITE_COUNT: AtomicU64 = AtomicU64::new(0);

/// LRU trim of the media cache by mtime (avatar-cache.ts: 200MB cap,
/// draining to 150MB). Best-effort; runs inline on the fetch path. A file
/// COUNT cap rides along: og previews are ~200 bytes of JSON each — the
/// byte floor is ~a million files away, so the all-tiny og population
/// needs its own bound.
fn trim_cache(cap: u64, floor: u64) {
    const FILE_CAP: usize = 50_000;
    let dir = match std::fs::read_dir(config::media_cache_dir()) {
        Ok(d) => d,
        Err(_) => return,
    };
    let mut entries: Vec<(std::path::PathBuf, u64, std::time::SystemTime)> = dir
        .flatten()
        .filter_map(|e| {
            let m = e.metadata().ok()?;
            Some((e.path(), m.len(), m.modified().ok()?))
        })
        .collect();
    entries.sort_by_key(|(_, _, m)| *m);
    let mut total: u64 = entries.iter().map(|(_, s, _)| s).sum();
    let mut remaining = total;
    if entries.len() > FILE_CAP {
        let excess = entries.len() - FILE_CAP;
        for (path, size, _) in entries.iter().take(excess) {
            if std::fs::remove_file(path).is_ok() {
                remaining -= size;
            }
        }
        total = remaining;
    }
    if total < cap {
        return;
    }
    let mut remaining = total;
    for (path, size, _) in entries {
        if remaining < floor {
            break;
        }
        if std::fs::remove_file(&path).is_ok() {
            remaining -= size;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn media_error_display() {
        assert_eq!(
            MediaError::Transient.to_string(),
            "media fetch failed, will retry"
        );
        assert_eq!(MediaError::NotMedia.to_string(), "not an image");
    }

    #[test]
    fn ssrf_guard_unchanged() {
        assert!(is_safe_media_url("https://blossom.primal.net/abc.png"));
        assert!(!is_safe_media_url("http://blossom.primal.net/abc.png"));
        assert!(!is_safe_media_url("https://127.0.0.1/x.png"));
        assert!(!is_safe_media_url("https://localhost/x.png"));
        assert!(!is_safe_media_url("https://host.internal/x.png"));
        assert!(!is_safe_media_url("not a url"));
    }

    /// WS4: the resolver's filter — only public-unicast addresses survive; every
    /// loopback/private/link-local/ULA spelling dies. This is the list
    /// hyper dials, so a rebinding name has nothing left to dial.
    #[test]
    fn resolver_filter_keeps_only_global() {
        // The rules live in net_guard now (M5); this pins the resolver
        // contract against the shared authority.
        let s = |ip: std::net::IpAddr| std::net::SocketAddr::new(ip, 0);
        let keep = |ips: &[std::net::IpAddr]| -> Vec<_> {
            ips.iter()
                .map(|i| s(*i))
                .filter(|a| crate::net_guard::is_public_ip(&a.ip()))
                .collect()
        };
        let global: std::net::IpAddr = "8.8.8.8".parse().unwrap();
        let v6: std::net::IpAddr = "2606:4700::1111".parse().unwrap();
        for hostile in [
            "127.0.0.1",
            "10.0.0.5",
            "192.168.1.1",
            "172.16.0.9",
            "169.254.169.254",
            "0.0.0.0",
            "100.64.0.1",
            "198.18.0.9",
            "240.0.0.1",
            "::1",
            "fe80::1",
            "fc00::5",
            "2001:db8::9",
            "::ffff:127.0.0.1",
        ] {
            let ip: std::net::IpAddr = hostile.parse().unwrap();
            assert_eq!(keep(&[ip, global]), vec![s(global)], "{hostile} must drop");
        }
        assert_eq!(keep(&[v6]), vec![s(v6)], "a global v6 survives");
        assert_eq!(
            keep(&["::ffff:8.8.8.8".parse().unwrap()]),
            vec![s("::ffff:8.8.8.8".parse().unwrap())],
            "a mapped GLOBAL v4 survives the v4 screen"
        );
        assert!(keep(&["127.0.0.1".parse().unwrap()]).is_empty());
    }

    /// PR #13's class: transition mechanisms embed IPv4 inside (or
    /// beside) 2000::/3. 6to4 and Teredo sailed past the global-unicast
    /// screen with a private leg; a NAT64 answer was refused wholesale,
    /// public leg included (now: the embedded leg decides).
    #[test]
    fn transition_mechanism_embedded_v4_is_screened() {
        let refused = |bad: &str| {
            let ip: std::net::IpAddr = bad.parse().unwrap();
            assert!(
                !crate::net_guard::is_public_ip(&ip),
                "{bad} must be refused"
            );
        };
        let passed = |good: &str| {
            let ip: std::net::IpAddr = good.parse().unwrap();
            assert!(crate::net_guard::is_public_ip(&ip), "{good} must pass");
        };
        // NAT64 (well-known prefix) with an internal or reserved leg.
        refused("64:ff9b::192.0.2.9"); // → TEST-NET-1
        refused("64:ff9b::127.0.0.1"); // → loopback
        refused("64:ff9b::10.0.0.5"); // → private
        // NAT64 with a PUBLIC leg now passes (previously died with the
        // whole prefix).
        passed("64:ff9b::8.8.8.8");
        // 6to4: the v4 rides segments 1+2, inside 2000::/3.
        refused("2002:7f00:1::1"); // → 127.0.0.1
        refused("2002:c0a8:101::1"); // → 192.168.1.1
        passed("2002:0808:0808::1"); // → 8.8.8.8
        // Teredo (2001:0::/32): server v4 in segments 2+3, client v4
        // XOR-obfuscated in 6+7 (RFC 4380 layout: 32 prefix, 32 server,
        // 16 flags, 16 port, 32 client) — BOTH legs screened.
        refused("2001:0:c0a8:101::1"); // server → 192.168.1.1
        // Public server 8.8.8.8, client 192.168.1.1 obfuscated:
        // 0xc0a8^0xffff = 0x3f57, 0x0101^0xffff = 0xfefe.
        refused("2001:0:0808:0808:0:0:3f57:fefe");
        // Both legs public (server 8.8.8.8, client 8.8.4.4 → 0xf7f7:0xfbfb).
        passed("2001:0:0808:0808:0:0:f7f7:fbfb");
    }

    /// F5: the guard holds for every IP-literal spelling getaddrinfo
    /// accepts — each of these resolves to loopback despite Ipv4Addr::parse
    /// rejecting them — and still passes real hostnames that merely LOOK
    /// hex-ish ("0xcd" would be a literal, "c0ffee.example.com" is not).
    #[test]
    fn ssrf_guard_covers_getaddrinfo_literal_forms() {
        for hostile in [
            "https://127.1/x.png",
            "https://127.0.0.1./x.png",
            "https://2130706433/x.png",
            "https://0x7f.1/x.png",
            "https://0x7f000001/x.png",
            "https://0177.0.0.1/x.png",
            "https://[::1]/x.png",
            "https://0xcd/x.png",
        ] {
            assert!(!is_safe_media_url(hostile), "must reject {hostile}");
        }
        for legit in [
            "https://c0ffee.example.com/x.png",
            "https://bee.cd/x.png",
            "https://black.white.pictures/x.png",
            "https://raw.githubusercontent.com/a/b/c.png",
        ] {
            assert!(is_safe_media_url(legit), "must allow {legit}");
        }
    }

    /// A minimal PNG header (signature + IHDR dims) — no pixel data, which
    /// is the point: the bomb must be rejected from the header alone,
    /// before any pixel allocation.
    fn png_header(w: u32, h: u32) -> Vec<u8> {
        let mut v = vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
        v.extend_from_slice(&[0, 0, 0, 13, b'I', b'H', b'D', b'R']);
        v.extend_from_slice(&w.to_be_bytes());
        v.extend_from_slice(&h.to_be_bytes());
        v.extend_from_slice(&[8, 6, 0, 0, 0, 0, 0, 0, 0]); // 8-bit RGBA, fake CRC
        v
    }

    fn real_png(w: u32, h: u32) -> Vec<u8> {
        let mut bytes = Vec::new();
        image::DynamicImage::new_rgba8(w, h)
            .write_to(
                &mut std::io::Cursor::new(&mut bytes),
                image::ImageFormat::Png,
            )
            .unwrap();
        bytes
    }

    #[test]
    fn decode_accepts_legit_and_rejects_bomb_dimensions() {
        let d = decode(&real_png(64, 64)).unwrap();
        assert_eq!((d.width, d.height), (64, 64));
        assert!(d.thumb.is_none(), "small sources need no thumb");

        // 225MP: the byte cap passes (1KB file!) but the header check must
        // reject before any allocation — a 20MB bomb would be ~900MB RGBA.
        assert!(matches!(
            decode(&png_header(15000, 15000)),
            Err(MediaError::NotMedia)
        ));
    }

    #[tokio::test]
    async fn decode_async_runs_off_the_relay_runtime() {
        let d = decode_async(real_png(300, 200)).await.unwrap();
        assert_eq!((d.width, d.height), (300, 200));
        assert!(d.thumb.is_some(), "long edge > 256 ships a disc thumb");
        assert!(matches!(
            decode_async(png_header(15000, 15000)).await,
            Err(MediaError::NotMedia)
        ));
    }
}

#[cfg(test)]
mod preview_tests {
    use super::*;

    // --- tracking params ---------------------------------------------------

    #[test]
    fn strip_removes_known_trackers_and_utm_family() {
        assert_eq!(
            strip_tracking_params(
                "https://ex.com/p?utm_source=rss&utm_medium=feed&id=7&fbclid=AbCd"
            ),
            "https://ex.com/p?id=7"
        );
        // Case-insensitive match on the well-known set (FBclid, GCLId…).
        assert_eq!(
            strip_tracking_params("https://ex.com/a?FBCLID=x&keep=1"),
            "https://ex.com/a?keep=1"
        );
        // UTM_ prefix is case-insensitive too.
        assert_eq!(
            strip_tracking_params("https://ex.com/a?UTM_CAMPAIGN=x"),
            "https://ex.com/a"
        );
        // Every param stripped: the bare query goes with it (the url crate
        // normalizes the empty path to `/`, like JS's URL.toString()).
        assert_eq!(
            strip_tracking_params("https://ex.com/a?gclid=1"),
            "https://ex.com/a"
        );
        // The whole conservative set survives one pass.
        let all = [
            "fbclid",
            "gclid",
            "gbraid",
            "wbraid",
            "dclid",
            "msclkid",
            "yclid",
            "twclid",
            "igshid",
            "ttclid",
            "mc_eid",
            "mc_cid",
            "mkt_tok",
            "oly_anon_id",
            "oly_enc_id",
            "vero_id",
            "_hsenc",
            "_hsmi",
            "mibextid",
            "fb_action_ids",
            "s_cid",
        ];
        let q: Vec<String> = all.iter().map(|k| format!("{k}=z")).collect();
        assert_eq!(
            strip_tracking_params(&format!("https://ex.com?{}", q.join("&"))),
            "https://ex.com/"
        );
    }

    #[test]
    fn strip_touches_nothing_else() {
        // Content-bearing params stay (a search page's `s=`, YouTube's `t=`).
        assert_eq!(
            strip_tracking_params("https://ex.com/?s=nostr"),
            "https://ex.com/?s=nostr"
        );
        assert_eq!(
            strip_tracking_params("https://youtu.be/x?t=42"),
            "https://youtu.be/x?t=42"
        );
        // No query / non-http(s) / unparseable: verbatim.
        assert_eq!(
            strip_tracking_params("https://ex.com/plain"),
            "https://ex.com/plain"
        );
        assert_eq!(
            strip_tracking_params("ftp://ex.com?fbclid=1"),
            "ftp://ex.com?fbclid=1"
        );
        assert_eq!(
            strip_tracking_params("not a url?fbclid=1"),
            "not a url?fbclid=1"
        );
    }

    // --- meta extraction ---------------------------------------------------

    #[test]
    fn og_tags_fill_the_card() {
        let head = b"<html><head><meta property=\"og:site_name\" content=\"Example\">\
<meta property=\"og:title\" content=\"Hello World\">\
<meta property=\"og:description\" content=\"A page\">\
<meta property=\"og:image\" content=\"https://img.ex/i.png\">\
<meta property=\"og:ignoreme\" content=\"x\">\
</head><body>prose must not scan</body></html>";
        let p = extract_preview(head, "https://ex.com/p").unwrap();
        assert_eq!(p.title, "Hello World");
        assert_eq!(p.description.as_deref(), Some("A page"));
        assert_eq!(p.site, "Example");
        assert_eq!(p.image.as_deref(), Some("https://img.ex/i.png"));
    }

    #[test]
    fn twitter_tags_fallback_and_title_fallback() {
        // twitter: card fields stand in for og:.
        let head = b"<head><meta name=\"twitter:title\" content=\"Tw Title\">\
<meta name=\"twitter:image\" content=\"https://img.ex/t.png\"></head>";
        let p = extract_preview(head, "https://ex.com/t").unwrap();
        assert_eq!(p.title, "Tw Title");
        assert_eq!(p.image.as_deref(), Some("https://img.ex/t.png"));
        assert_eq!(p.site, "ex.com", "host fallback carries the site");

        // No card tags at all: the page <title> names it, no image.
        let head = b"<html><head><title>Bare Title</title></head></html>";
        let p = extract_preview(head, "https://ex.com/b").unwrap();
        assert_eq!(p.title, "Bare Title");
        assert!(p.image.is_none());
        assert!(p.description.is_none());
    }

    #[test]
    fn body_never_smuggles_a_meta() {
        // og: tags after </head> are prose, not metadata.
        let head = b"<html><head><title>Real</title></head>\
<body><meta property=\"og:title\" content=\"Injected\"></body></html>";
        let p = extract_preview(head, "https://ex.com/i").unwrap();
        assert_eq!(p.title, "Real");
    }

    #[test]
    fn entities_decode_and_relative_images_reject() {
        let head =
            b"<head><meta property=\"og:title\" content=\"Fish &amp; Chips &#39;n&#39; Sauce\">\
<meta property=\"og:image\" content=\"/relative.png\"></head>";
        let p = extract_preview(head, "https://ex.com/e").unwrap();
        assert_eq!(p.title, "Fish & Chips 'n' Sauce");
        assert!(
            p.image.is_none(),
            "relative og:image needs an attacker base"
        );
    }

    #[test]
    fn a_titleless_page_is_no_card() {
        assert!(extract_preview(b"<head></head>", "https://ex.com/none").is_none());
        assert!(extract_preview(b"", "https://ex.com/none").is_none());
    }

    #[test]
    fn fields_carry_source_caps() {
        let long = "x".repeat(400);
        let head = format!(
            "<head><meta property=\"og:title\" content=\"{long}\">\
<meta property=\"og:image\" content=\"https://img.ex/{}\"></head>",
            "y".repeat(3000)
        );
        let p = extract_preview(head.as_bytes(), "https://ex.com/cap").unwrap();
        assert_eq!(p.title.chars().count(), 201); // 200 + the ellipsis
        assert_eq!(p.image.as_ref().unwrap().chars().count(), 2049);
    }
}
