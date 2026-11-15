//! Poster previews for video tiles (D32) — three sources, one ladder.
//!
//! A video tile paints, in order: the publisher's own poster (NIP-92
//! `image`/`thumb`), a blurhash gradient (NIP-92 `blurhash`, decoded
//! locally — no network), or a LOCAL FIRST-FRAME SNIFF: the head of the
//! video file (a capped, SSRF-guarded fetch — the video is never played
//! nor fully downloaded) is demuxed by GStreamer for its first usable
//! frame, encoded to PNG, and cached under a `poster:`-namespaced key.
//! The tap still gates PLAYBACK — a preview is picture-grade bytes, the
//! same commitment a photo makes; strict Tor keeps even that off (the
//! facade rule) and the tile stays bare.
//!
//! The virtual cache keys (`poster:<url>`, `blurhash:<hash>`) ride the
//! ordinary media cache (media.rs): LRU eviction, backoff, snapshots —
//! all borrowed, nothing new to bound.

use std::sync::atomic::{AtomicUsize, Ordering};

/// The virtual media-cache key for a video's sniffed poster frame.
pub fn poster_key(url: &str) -> String {
    format!("poster:{url}")
}

/// The virtual media-cache key for a blurhash placeholder.
pub fn blurhash_key(hash: &str) -> String {
    format!("blurhash:{hash}")
}

/// The sniff workshop is small on purpose: two pipelines at a time, so a
/// feed full of posterless videos sniffs politely behind the render loop
/// (an over-full workshop lands as a short backoff, retried by the
/// ordinary media-cache timer).
pub const MAX_IN_FLIGHT: usize = 2;

/// Counted from job start (head download included) to landing.
pub static IN_FLIGHT: AtomicUsize = AtomicUsize::new(0);

/// The head-download cap: the opener frames of most web-encoded faststart
/// mp4s. Trimmed from 2MB when the ranged sniff (D72's `sniff_uri`) took
/// over the files that need more — a faststart file whose opener isn't in
/// the first MB now falls through to ranged fetching instead of blind
/// over-fetching here. A file that needs more than this to show a frame
/// (moov at the end) fails this sniff and falls through.
pub const POSTER_HEAD_BYTES: usize = 1024 * 1024;

/// Sniffed frames encode down to this width: previews paint at ≤560px,
/// and a 1080p frame counts 8MB against the media cache's decoded-byte
/// budget while a 640px frame counts ~0.9MB — the difference between a
/// few posters and one poster evicting a photo.
const PREVIEW_MAX_W: u32 = 640;

/// Holds a slot in the sniff workshop; the count drops on drop.
pub struct InFlight;

impl InFlight {
    pub fn take() -> Option<Self> {
        (IN_FLIGHT.load(Ordering::Relaxed) < MAX_IN_FLIGHT).then(|| {
            IN_FLIGHT.fetch_add(1, Ordering::Relaxed);
            Self
        })
    }
}

/// D38: the upload-time first-frame grab. The whole file is in hand (the
/// composer's attachment), so moov-at-end files get posters too — the
/// runtime head-sniff can't reach their moov. Returns (poster PNG,
/// blurhash of the frame); None = no usable frame in the deadline (the
/// video still uploads, its tile falls back to the runtime ladder).
pub fn grab(bytes: &[u8]) -> Option<(Vec<u8>, String)> {
    let (_w, _h, png) = sniff_png(bytes).ok()?;
    let rgba = image::load_from_memory(&png).ok()?.to_rgba8();
    let hash = blurhash::encode(4, 3, rgba.width(), rgba.height(), rgba.as_raw()).ok()?;
    Some((png, hash))
}

impl Drop for InFlight {
    fn drop(&mut self) {
        IN_FLIGHT.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Decode a NIP-92 `blurhash` to a small PNG placeholder (RGBA decoded at
/// a thumbnail scale, re-encoded — gpui's pipeline wants encoded bytes).
/// Bad hashes decode to None → the tile degrades to the bare row, no
/// refetch (NotMedia semantics in the cache).
pub fn blurhash_png(hash: &str) -> Option<image::DynamicImage> {
    const W: u32 = 48;
    const H: u32 = 27;
    let rgba = blurhash::decode(hash, W, H, 1.0).ok()?;
    let img = image::RgbaImage::from_raw(W, H, rgba)?;
    Some(image::DynamicImage::ImageRgba8(img))
}

/// A decoded gradient as `DecodedImage`, encoded to PNG in passing.
pub fn decoded_dynamic(img: image::DynamicImage) -> Option<satori_core::media::DecodedImage> {
    let (w, h) = (img.width(), img.height());
    let mut png = Vec::new();
    img.write_to(&mut std::io::Cursor::new(&mut png), image::ImageFormat::Png)
        .ok()?;
    Some(satori_core::media::DecodedImage {
        width: w,
        height: h,
        bytes: png,
        format: image::ImageFormat::Png,
        thumb: None,
    })
}

/// The sniff: GStreamer demuxes the head bytes' FIRST usable frame
/// (skipping a black opener — many encoders start one) and encodes it to
/// PNG. Blocking, bounded (~10s worst case); runs on core's blocking pool,
/// injected into `fetch_poster` — gstreamer stays a UI-crate dependency.
/// Ok = (width, height, png).
pub fn sniff_png(head: &[u8]) -> Result<(u32, u32, Vec<u8>), ()> {
    // O_EXCL + 0600 (audit security L2): a predictable /tmp name let a
    // same-host user pre-plant a symlink for the write to follow.
    // create_new fails instead of following it; the sniff just gives up.
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let tmp = std::env::temp_dir().join(format!(
        "satori-poster-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    ));
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)
        .map_err(|_| ())?;
    f.write_all(head).map_err(|_| ())?;
    drop(f);
    let src = || {
        gstreamer::ElementFactory::make("filesrc")
            .property("location", tmp.to_string_lossy().to_string())
            .build()
            .map_err(|_| ())
    };
    let out = sniff_source(src, std::time::Duration::from_secs(10));
    let _ = std::fs::remove_file(&tmp);
    out
}

/// The ranged sniff (D72's fourth rung): the same decode against a URI —
/// the caller hands the ORIGIN url and this door it through the
/// RangeProxy (M5 WP3: no pipeline sees an origin URL; every fetch rides
/// the pinned media client). GStreamer's source speaks Range, so a
/// moov-at-end file — undecodable from any head — still previews: the
/// demuxer ranges to the tail itself. The pipeline dies after the first
/// frame, so the fetch is the moov plus a couple of frames, not the file.
/// Blocking, bounded; same workshop slot and cache slot as the head sniff.
pub fn sniff_uri(origin: &str) -> Result<(u32, u32, Vec<u8>), ()> {
    let proxy = satori_core::video_proxy::spawn(origin.to_string()).map_err(|_| ())?;
    let uri = proxy.uri();
    let src = move || {
        use gstreamer::prelude::*;
        // Build first, THEN set "uri": the factory builder validates
        // .property against the FACTORY's gobject props (no "uri" there —
        // it panics before the element ever exists).
        let src = gstreamer::ElementFactory::make("souphttpsrc")
            .build()
            .map_err(|_| ())?;
        // "location", not "uri": gst 1.26 (the freedesktop runtime) dropped
        // the "uri" alias; "location" is the property on every version.
        src.set_property("location", uri.clone());
        Ok(src)
    };
    // Ranged demuxing walks more round trips than the head sniff (the
    // moov can sit at the tail) — a wider deadline, same shape.
    let out = sniff_source(src, std::time::Duration::from_secs(15));
    drop(proxy);
    out
}

/// The shared sniff: decode `src`'s FIRST usable frame (skipping a black
/// opener — many encoders start one) and encode it to PNG.
fn sniff_source(
    src: impl FnOnce() -> Result<gstreamer::Element, ()>,
    deadline_budget: std::time::Duration,
) -> Result<(u32, u32, Vec<u8>), ()> {
    use gstreamer::prelude::*;

    gstreamer::init().map_err(|_| ())?;
    let pipeline = gstreamer::Pipeline::new();
    let src = src().map_err(|_| ())?;
    let dec = gstreamer::ElementFactory::make("decodebin")
        .build()
        .map_err(|_| ())?;
    let conv = gstreamer::ElementFactory::make("videoconvert")
        .build()
        .map_err(|_| ())?;
    let sink = gstreamer_app::AppSink::builder()
        .caps(
            &gstreamer::Caps::builder("video/x-raw")
                .field("format", "RGB")
                .build(),
        )
        .max_buffers(1)
        .drop(true)
        .sync(false)
        .build();
    let sink_el = sink.upcast_ref();
    pipeline
        .add_many([&src, &dec, &conv, sink_el])
        .map_err(|_| ())?;
    src.link(&dec).map_err(|_| ())?;
    conv.link(sink_el).map_err(|_| ())?;
    // decodebin's video pad shows up after typefinding: wire it to the
    // converter then, and only then (audio pads die here).
    let conv_sink = conv.static_pad("sink").ok_or(())?;
    dec.connect_pad_added(move |_d, pad| {
        let caps = pad.current_caps().unwrap_or_else(|| pad.query_caps(None));
        if caps.iter().any(|s| s.name().starts_with("video/")) {
            let _ = pad.link(&conv_sink);
        }
    });

    pipeline
        .set_state(gstreamer::State::Paused)
        .map_err(|_| ())?;

    // The deadline bounds the whole sniff: a server that trickles, a file
    // whose moov lives at the end (nothing decodable from head bytes), a
    // audio-only stream — all die here and the tile stays bare.
    let deadline = std::time::Instant::now() + deadline_budget;
    // Preroll hands the opener frame; many encoders start a black one.
    let Some(sample) = pull_until(&pipeline, &sink, deadline) else {
        let _ = pipeline.set_state(gstreamer::State::Null);
        return Err(());
    };
    let Ok(first) = sample_to_rgb(&sample) else {
        let _ = pipeline.set_state(gstreamer::State::Null);
        return Err(());
    };
    if mean_luma(&first.2) > 12.0 {
        let _ = pipeline.set_state(gstreamer::State::Null);
        return encode_png(&first.2, first.0, first.1);
    }
    // Black opener: seek ~1s in and take the next frame that lands (head
    // bytes usually reach it; a seek the head can't satisfy or a flush
    // that never re-prerolls just falls back to the opener).
    if pipeline
        .seek_simple(
            gstreamer::SeekFlags::FLUSH | gstreamer::SeekFlags::TRICKMODE,
            gstreamer::GenericFormattedValue::Time(Some(gstreamer::ClockTime::from_seconds(1))),
        )
        .is_ok()
        && let Some(sample) = pull_until(
            &pipeline,
            &sink,
            deadline.min(std::time::Instant::now() + std::time::Duration::from_secs(4)),
        )
        && let Ok((w, h, rgb)) = sample_to_rgb(&sample)
    {
        let _ = pipeline.set_state(gstreamer::State::Null);
        return encode_png(&rgb, w, h);
    }
    let _ = pipeline.set_state(gstreamer::State::Null);
    // Every frame was (near-)black: the opener is the honest preview.
    encode_png(&first.2, first.0, first.1)
}

/// One sample before `deadline`, else None (a cheap poll). While the
/// pipeline is paused the opener frame sits in the PREROLL slot —
/// `try_pull_sample` never sees it (the vendored player's worker knows
/// this: pull_preroll until Playing). Probe-verified D72: a Paused
/// pipeline with a prerolled frame returns None from try_pull_sample
/// for 15s straight.
fn pull_until(
    pipeline: &gstreamer::Pipeline,
    sink: &gstreamer_app::AppSink,
    deadline: std::time::Instant,
) -> Option<gstreamer::Sample> {
    use gstreamer::prelude::*;
    while std::time::Instant::now() < deadline {
        let playing = pipeline.state(gstreamer::ClockTime::ZERO).1 == gstreamer::State::Playing;
        let sample = if playing {
            sink.try_pull_sample(Some(gstreamer::ClockTime::from_mseconds(250)))
        } else {
            sink.try_pull_preroll(Some(gstreamer::ClockTime::from_mseconds(250)))
        };
        if let Some(s) = sample {
            return Some(s);
        }
    }
    None
}

/// Sample buffer → raw RGB planes (the caps' format is RGB by
/// construction; dims come from the caps, not the frame metadata).
fn sample_to_rgb(sample: &gstreamer::Sample) -> Result<(u32, u32, image::RgbImage), ()> {
    let buffer = sample.buffer().ok_or(())?;
    let caps = sample.caps().ok_or(())?;
    let s = caps.structure(0).ok_or(())?;
    let w = s.get::<i32>("width").map_err(|_| ())? as u32;
    let h = s.get::<i32>("height").map_err(|_| ())? as u32;
    if w == 0 || h == 0 {
        return Err(());
    }
    let map = buffer.map_readable().map_err(|_| ())?;
    let bytes = map.as_slice();
    if bytes.len() < (w as usize) * (h as usize) * 3 {
        return Err(());
    }
    let img = image::RgbImage::from_raw(w, h, bytes[..(w as usize) * (h as usize) * 3].to_vec())
        .ok_or(())?;
    Ok((w, h, img))
}

fn mean_luma(img: &image::RgbImage) -> f32 {
    let mut sum = 0.0f32;
    for p in img.pixels() {
        sum += 0.2126 * p[0] as f32 + 0.7152 * p[1] as f32 + 0.0722 * p[2] as f32;
    }
    sum / img.pixels().count().max(1) as f32
}

fn encode_png(img: &image::RgbImage, w: u32, h: u32) -> Result<(u32, u32, Vec<u8>), ()> {
    // Previews paint at ≤560px wide: anything wider encodes down (the
    // media cache counts decoded bytes — a full 1080p frame is
    // photo-class pressure for a thumbnail's worth of pixels).
    let (img, w, h) = if w > PREVIEW_MAX_W {
        let nh = (h * PREVIEW_MAX_W / w).max(1);
        (
            image::imageops::resize(
                img,
                PREVIEW_MAX_W,
                nh,
                image::imageops::FilterType::Triangle,
            ),
            PREVIEW_MAX_W,
            nh,
        )
    } else {
        (img.clone(), w, h)
    };
    let dynimg = image::DynamicImage::ImageRgb8(img);
    let mut png = Vec::new();
    dynimg
        .write_to(&mut std::io::Cursor::new(&mut png), image::ImageFormat::Png)
        .map_err(|_| ())?;
    Ok((w, h, png))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The real blurhash from a live NIP-92 video note ("Me, using the new
    /// Amethyst."), 94 chars, decodes to a 48x27 gradient.
    #[test]
    fn real_world_blurhash_decodes() {
        let img = blurhash_png(
            "]B8ZD.rUb^$+axv0kXs;bwjY7$O]tTJ,of-Wg1T0kEWA-Q%LXTwJjYPqjvwHXRs.e7XAo$NdX9pymiRiohV?x^TzbXr=sn",
        )
        .expect("a valid blurhash decodes");
        assert_eq!((img.width(), img.height()), (48, 27));
    }
}
