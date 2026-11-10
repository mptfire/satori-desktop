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
/// verdicts, so avatars died permanently), connect/total timeouts (a
/// hung fetch used to pin the cache entry Loading forever, joining every
/// later waiter onto a corpse — the avatar that never loads all session),
/// and a per-hop SSRF re-validation policy (below).
fn http() -> &'static reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .user_agent(
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 \
                 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
            )
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(20))
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

/// The shared guarded client for the other core HTTP surfaces: NIP-11
/// relay documents ride the same SSRF discipline (SafeResolver on every
/// hop, redirect re-validation, byte-capped readers upstream).
pub(crate) fn client() -> &'static reqwest::Client {
    http()
}

/// GET through the guarded client with the status→verdict mapping: 429/5xx
/// and every transport-level failure are Transient; the other 4xx are
/// verdicts (a 404 will not heal by Tuesday).
async fn guarded_get(url: &str) -> Result<reqwest::Response, MediaError> {
    let res = http()
        .get(url)
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
/// once — nothing below this layer ever re-sees a network error.
async fn fetch_capped(url: &str, cap: usize) -> Result<Vec<u8>, MediaError> {
    let mut wait = Duration::from_millis(600);
    for attempt in 0..RETRY_ATTEMPTS {
        // One gate slot per ATTEMPT, not per URL: the permit is released
        // during the backoff sleep, so a dead CDN can't pin a slot for its
        // whole retry cycle and starve the queue behind it.
        let outcome = {
            let _permit = gate()
                .acquire()
                .await
                .map_err(|_| MediaError::Transient)?;
            match guarded_get(url).await {
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
    let res = http().get(url).send().await.map_err(|e| e.to_string())?;
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
            let body = fetch_capped(url, MAX_IMAGE_BYTES).await?;
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

/// The whole poster job (D32): cache read-through, the capped guarded head
/// fetch, the injected sniffer, the store. Runs ON a tokio runtime — every
/// call below (reqwest, `spawn_blocking`) needs that context, so the UI
/// awaits the verdict through `Core::fetch_poster`'s channel: `fetch_image`'s
/// exact seam. (The first cut of this let the UI poll these futures on
/// gpui's executor — no tokio context there, thread 'main panicked at
/// `read_cache_off_rt`, the app died the day D32 shipped.) The sniffer is
/// injected because gstreamer lives in the UI crate; it blocks (a bounded
/// decode) and runs on the blocking pool, never on the 2-worker relay
/// runtime itself.
pub async fn fetch_poster(
    url: String,
    cap: usize,
    sniff: impl FnOnce(&[u8]) -> std::result::Result<(u32, u32, Vec<u8>), ()> + Send + 'static,
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
    // (`poster_store`) earns a cache slot.
    let head = fetch_capped(&url, cap).await?;
    // JoinError = the sniff task itself died (a bug, but the tile staying
    // bare beats the app following it down); Err(()) = no decodable frame
    // (moov at the end, audio-only) — transient, the backoff decides.
    let frame = tokio::task::spawn_blocking(move || sniff(&head))
        .await
        .map_err(|_| MediaError::Transient)?
        .map_err(|_| MediaError::Transient)?;
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
    read_cache_off_rt(cache_path(&poster_key(url)))
        .await
        .ok()
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

/// The DNS resolver and the IP screen live in net_guard (M5): one
/// authority shared with the relay-pool screening transport, so the
/// rules cannot drift between the fetch path and the dial path.
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
/// draining to 150MB). Best-effort; runs inline on the fetch path.
fn trim_cache(cap: u64, floor: u64) {
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
    let total: u64 = entries.iter().map(|(_, s, _)| s).sum();
    if total < cap {
        return;
    }
    entries.sort_by_key(|(_, _, m)| *m);
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
        assert_eq!(MediaError::Transient.to_string(), "media fetch failed, will retry");
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

    /// WS4: the resolver's filter — only global addresses survive; every
    /// loopback/private/link-local/ULA spelling dies. This is the list
    /// hyper dials, so a rebinding name has nothing left to dial.
    #[test]
    fn resolver_filter_keeps_only_global() {
        // The rules live in net_guard now (M5); this pins the resolver
        // contract against the shared authority.
        use crate::net_guard::is_public_unicast_ip as is_global_ip;
        let s = |ip: std::net::IpAddr| std::net::SocketAddr::new(ip, 0);
        let keep = |ips: &[std::net::IpAddr]| -> Vec<_> {
            ips.iter()
                .map(|i| s(*i))
                .filter(|a| is_global_ip(a.ip()))
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
        assert_eq!(keep(&["::ffff:8.8.8.8".parse().unwrap()]), vec![s("::ffff:8.8.8.8".parse().unwrap())], "a mapped GLOBAL v4 survives the v4 screen");
        assert!(keep(&["127.0.0.1".parse().unwrap()]).is_empty());
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
            .write_to(&mut std::io::Cursor::new(&mut bytes), image::ImageFormat::Png)
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
        assert!(matches!(decode(&png_header(15000, 15000)), Err(MediaError::NotMedia)));
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
