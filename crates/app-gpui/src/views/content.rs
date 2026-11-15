//! Note-body rendering: paragraphs, links, nostr mentions, media, quote embeds.
//!
//! TODO(port): crates/app/src/content.rs + note_card.rs embed_card — P2/P3.
//! Unlike the GTK markup pipeline (which styles runs inside one text block),
//! GPUI's div tree gets one element per whitespace token: plain words are
//! serif spans, links/mentions/refs become clickable elements and the
//! paragraph is a flex-wrap flow. Media (imeta + standalone links, blossom
//! URLs included — core sniffs bytes, not extensions) folds out into a
//! gallery section under the text; videos render as play-card links.

use std::{
    collections::HashMap,
    hash::{Hash, Hasher},
};

use gpui::{
    AnimationExt, AnyElement, Div, Entity, EventEmitter, FontWeight, ObjectFit, SharedString, div,
    img, prelude::*, px, relative, rgb,
};
use nostr::prelude::*;
use satori_core::manager::Profile;
use satori_core::nip::{article, fields, imeta};

use super::nav::Nav;
use crate::{icons, media, theme};

/// Timeline column width. Deliberately 640 — the webapp's was 720
/// (styles.css:100 `#app { max-width: 720px }`); at 12–14px desktop type,
/// 640 is right. Recorded as a DIVERGENCE, not drift (0.2-design-spec
/// §1.2 / deficiency 13). Media_picture is sized against 720px there.
pub const COL_W: f32 = 640.0;

/// A resolved note reference, for quote embeds (note_card.rs embed_card).
#[derive(Clone)]
pub struct Embed {
    pub event: Event,
    pub name: String,
}

/// bech32 ref → resolved embed. `None` = fetch in flight. Views fill this
/// from `core.event_by_id_dech32`; unresolved keys render as a quiet
/// placeholder.
pub type Quotes = HashMap<String, Option<Embed>>;

/// The display-name fallback (render/util.ts style): the profile's
/// display name, else a short npub. Was spelled out 19 times across the
/// views (two escape spellings of the ellipsis) — #31. `p` is the
/// profile if one is in hand (a fetch result or a map hit). `hex` is
/// a PUBKEY hex only, and the byte cut is safe for it (ASCII) — never
/// feed it a relay-controlled string (cards::short owns the
/// char-boundary cut for those).
pub(crate) fn display_name(p: Option<&satori_core::manager::Profile>, hex: &str) -> String {
    p.map(|p| p.display())
        .unwrap_or_else(|| format!("{}…", &hex[..8]))
}

/// Render-time context threaded from each view: the shared media snapshot,
/// resolved quote embeds and known profiles (mention names).
pub struct Body<'a> {
    pub media: &'a media::Snapshot,
    pub quotes: &'a Quotes,
    pub profiles: &'a HashMap<String, Profile>,
    /// The event's NIP-30 emoji map (shortcode → url): `:code:` tokens in
    /// the body resolve here. The urls also ride `media_urls`, so every
    /// view's media sweep fetches them and the thumb replaces the bare
    /// code when the bytes land. Shared from the BodyParse memo (audit:
    /// a per-row-per-frame HashMap rebuild for a map that never changes).
    pub emoji: std::sync::Arc<HashMap<String, String>>,
}

/// Deterministic element id — RandomState would re-hash every render, and a
/// changing id makes gpui drop the element's click state between the mouse
/// down and up (the down handler refreshes the window), killing every click.
fn seg_id(prefix: &str, token: &str) -> SharedString {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    token.hash(&mut h);
    SharedString::from(format!("{prefix}-{}", h.finish()))
}

/// If `token` is exactly one https link / mention, decode it.
enum Seg {
    Link(String),
    User(PublicKey),
}

fn standalone(token: &str) -> Option<Seg> {
    let t = token.trim();
    if let Some(rest) = t.strip_prefix("https://").or(t.strip_prefix("http://")) {
        // Single whitespace-free token = a link.
        return if rest.chars().any(char::is_whitespace) {
            None
        } else {
            Some(Seg::Link(t.to_string()))
        };
    }
    let bech = t.strip_prefix("nostr:").unwrap_or(t);
    if (bech.starts_with("npub1") || bech.starts_with("nprofile1"))
        && let Ok(pk) = PublicKey::from_bech32(bech)
    {
        return Some(Seg::User(pk));
    }
    None
}

/// If `token` is exactly one note/nevent reference, its bech32 (content.ts
/// quote refs — note1/nevent1, `nostr:` scheme or bare).
fn standalone_ref(token: &str) -> Option<String> {
    let t = token.trim();
    if t.chars().any(char::is_whitespace) {
        return None;
    }
    let bech = t.strip_prefix("nostr:").unwrap_or(t);
    (bech.starts_with("note1") || bech.starts_with("nevent1")).then(|| bech.to_string())
}

/// The URL's lowercase path extension (before ?/#), if the last path segment
/// has one. Blossom blobs (`…/b87…cf4` — no extension) return None.
fn path_ext(url: &str) -> Option<String> {
    let path = url.split(['?', '#']).next().unwrap_or("");
    let last = path.rsplit('/').next().unwrap_or("");
    let (stem, ext) = last.rsplit_once('.')?;
    (!stem.is_empty()).then(|| ext.to_ascii_lowercase())
}

/// Image URL by extension (content.rs is_image_url) — plus the byte-sniffing
/// fallback in core.fetch_image for extension-less blossom URLs.
fn is_image_url(url: &str) -> bool {
    matches!(
        path_ext(url).as_deref(),
        Some("png" | "jpg" | "jpeg" | "webp" | "gif")
    )
}

/// NIP-B7 blossom shape: the blob's sha256 IS the path's last segment (64
/// hex chars). The extension-less byte-sniff fallback exists for THESE —
/// a blob server serves raw bytes at an extension-less address. An
/// extension-less WEB PAGE (a wiki slug, an /app/idNNN store path) is a
/// page: it renders as a link row and carries an og: card — claiming it
/// as a picture used to swallow the link into a tile that could never
/// decode and suppress the card with it.
fn is_blob_url(url: &str) -> bool {
    let path = url.split(['?', '#']).next().unwrap_or("");
    path.rsplit('/')
        .next()
        .is_some_and(|last| last.len() == 64 && last.chars().all(|c| c.is_ascii_hexdigit()))
}

/// Video by extension — never fetched until asked; rendered as a play-card
/// (inline player since Phase 3 — video.rs).
pub(crate) fn is_video_url(url: &str) -> bool {
    matches!(
        path_ext(url).as_deref(),
        Some("mp4" | "webm" | "mov" | "mkv" | "m4v")
    )
}

/// Audio by extension (NIP-A0's common set plus the plain audio
/// containers). `.mp4` is deliberately NOT here — it is a video extension
/// first; inside a voice note (1222/1244) the kind decides, not the ext.
fn is_audio_url(url: &str) -> bool {
    matches!(
        path_ext(url).as_deref(),
        Some("mp3" | "ogg" | "oga" | "opus" | "wav" | "flac" | "m4a" | "aac" | "weba")
    )
}

/// One entry of the media section, in reading order: a picture (lightbox
/// tile), a video (poster tile; Phase 3 — inline click-to-play, the imeta
/// mime tells an extension-less blossom URL from a picture), or an audio
/// clip (NIP-A0 voice row: waveform + duration from imeta, playbin).
#[derive(Clone, Debug)]
pub enum MediaAsset {
    Picture {
        url: String,
    },
    Video {
        url: String,
        poster: Option<String>,
        blurhash: Option<String>,
        mime: Option<String>,
    },
    Audio {
        url: String,
        /// NIP-A0 imeta `duration` (seconds).
        duration: Option<f64>,
        /// NIP-A0 imeta `waveform` (amplitudes 0-100, already capped).
        waveform: Option<Vec<u32>>,
    },
}
impl MediaAsset {
    fn url(&self) -> &str {
        match self {
            MediaAsset::Picture { url } => url,
            MediaAsset::Video { url, .. } => url,
            MediaAsset::Audio { url, .. } => url,
        }
    }
}

/// The note's media in reading order: imeta-tagged items (a `video/*` mime
/// or extension makes it a video; its NIP-92 `image` attr is the poster),
/// then standalone text links — blossom video URLs, YouTube links (thumbnail
/// derived from the id), pictures, and extension-less blossom candidates.
/// The article's cover, wherever the author put it: the NIP-23 `image` tag
/// first, then the first imeta/content picture (some clients skip the tag —
/// article.ts header image). Memoized with the body parse (article::parse
/// clones the whole tag vec — it ran per article card per frame).
pub fn article_cover(ev: &Event) -> Option<String> {
    body_parse_cached(ev).cover.clone()
}

pub fn media_assets(ev: &Event) -> Vec<MediaAsset> {
    media_assets_with(article::parse(ev).as_ref(), ev)
}

/// `media_assets` with the article parse handed in (#31's rich-card
/// rider): the memo's miss path owns the one parse and shares it here,
/// instead of `article::parse` running twice per miss (here and for the
/// cover).
fn media_assets_with(parsed: Option<&article::ArticleData>, ev: &Event) -> Vec<MediaAsset> {
    let mut out: Vec<MediaAsset> = Vec::new();
    // NIP-23: an article's cover rides the `image` tag, not the content and
    // not imeta — without it no fetch is ever queued and the card's media
    // frame stays an empty panel (article.ts header image). First, so the
    // cover leads the reading order. Kind-gated: article::parse itself
    // accepts any event with a title tag, and a non-article `image` tag
    // must not lead the body's media.
    if u16::from(ev.kind) == 30023
        && let Some(cover) = parsed
            .and_then(|d| d.image.clone())
            .filter(|c| !c.is_empty())
    {
        out.push(MediaAsset::Picture { url: cover });
    }
    // NIP-A0 voice note: the content IS the audio URL, and the file rides
    // audio mimes inside video-shaped extensions (.m4a/.mp4) — the kind
    // decides, not the extension (the NIP's own example is .mp4).
    let voice = matches!(u16::from(ev.kind), 1222 | 1244);
    for m in imeta::parse(ev) {
        if m.url.is_empty() {
            continue;
        }
        let video =
            m.mime.as_deref().is_some_and(|m| m.starts_with("video/")) || is_video_url(&m.url);
        let audio = voice
            || m.mime.as_deref().is_some_and(|m| m.starts_with("audio/"))
            || is_audio_url(&m.url);
        out.push(if voice || (audio && !video) {
            MediaAsset::Audio {
                url: m.url,
                duration: m.duration,
                waveform: m.waveform,
            }
        } else if video {
            MediaAsset::Video {
                url: m.url,
                poster: m.poster,
                blurhash: m.blurhash,
                mime: m.mime.clone(),
            }
        } else {
            MediaAsset::Picture { url: m.url }
        });
    }
    // A voice note whose imeta tag is missing entirely: the content URL
    // still renders — as audio (NIP-A0 §Specification: content MUST be
    // the audio URL).
    if voice && !out.iter().any(|a| matches!(a, MediaAsset::Audio { .. })) {
        let url = ev.content.trim();
        if crate::views::content::web_url(url) {
            out.push(MediaAsset::Audio {
                url: url.to_string(),
                duration: None,
                waveform: None,
            });
        }
    }
    for para in ev.content.split('\n') {
        if let Some(Seg::Link(url)) = standalone(para) {
            let asset = if let Some(thumb) = youtube_thumb(&url) {
                MediaAsset::Video {
                    url: url.clone(),
                    poster: Some(thumb),
                    blurhash: None,
                    mime: None,
                }
            } else if is_video_url(&url) {
                MediaAsset::Video {
                    url: url.clone(),
                    poster: None,
                    blurhash: None,
                    mime: None,
                }
            } else if is_audio_url(&url) {
                MediaAsset::Audio {
                    url: url.clone(),
                    duration: None,
                    waveform: None,
                }
            } else if is_image_url(&url) || is_blob_url(&url) {
                MediaAsset::Picture { url: url.clone() }
            } else {
                continue;
            };
            if !out.iter().any(|a| a.url() == url) {
                out.push(asset);
            }
        }
    }
    out
}

/// Every url worth fetching for this event: the pictures plus, per video,
/// the preview sources that apply — the publisher's poster, else the
/// first-frame sniff (virtual key; the video FILE is never fetched, only a
/// capped head, then a ranged fetch through the proxy if the head can't
/// decode) AND the blurhash decode (virtual key, no network — the local
/// filler while the sniff runs, or forever when it fails). Strict Tor
/// keeps the sniff off entirely (the facade rule): the tile stays bare,
/// blurhash is its only placeholder. A cache may still hold a sniff from
/// before the switch — painting already-fetched bytes breaks no new
/// ground.
pub fn media_urls(ev: &Event) -> Vec<String> {
    media_urls_from(&media_assets(ev), ev)
}

/// The note's first link worth a PREVIEW CARD (D73): an http(s) URL that
/// isn't already a media tile (imeta pictures/videos, YouTube links —
/// those render tiles with their own thumbnails; a YouTube page fetch is
/// a Google contact the facade never makes), with tracking params
/// stripped (the stripped form is the cache key AND the click target, so
/// one link is one preview however many utm variants circulate). First
/// link only, the owner's call: one card per note keeps the feed calm.
fn og_candidate(ev: &Event, skip: &[String]) -> Option<String> {
    for para in ev.content.split('\n') {
        for token in para.split_whitespace() {
            let (core, _) = split_trailing(token);
            if !(core.starts_with("https://") || core.starts_with("http://")) {
                continue;
            }
            if skip.iter().any(|m| m == core) || youtube_thumb(core).is_some() {
                continue;
            }
            // A direct media file has no og: metadata to offer — the fetch
            // would land NotMedia every time (the byte-sniff classifies
            // these as tiles when they're standalone).
            if is_image_url(core) || is_video_url(core) || is_audio_url(core) {
                continue;
            }
            if web_url(core) {
                return Some(satori_core::media::strip_tracking_params(core));
            }
        }
    }
    None
}

/// The url projection of ALREADY-PARSED assets (the poster/blurhash/sniff
/// selection) plus the NIP-30 emoji urls. `media_urls` and the BodyParse
/// memo share it (audit: the memo had the assets in hand but re-ran the
/// whole imeta + line-scan parse to get the same urls back).
fn media_urls_from(assets: &[MediaAsset], ev: &Event) -> Vec<String> {
    let mut out: Vec<String> = assets
        .iter()
        .flat_map(|a| match a {
            MediaAsset::Picture { url } => vec![url.clone()],
            MediaAsset::Audio { .. } => vec![], // no prefetch: the waveform rides the imeta
            MediaAsset::Video {
                url,
                poster,
                blurhash,
                mime,
            } => match poster {
                Some(p) => vec![p.clone()],
                None => {
                    // The sniff is the real preview (a frame beats an
                    // impression); the blurhash is the local filler that
                    // paints while the sniff runs or when it fails — both
                    // keys queue, the paint ladder picks the best held.
                    let mut keys = Vec::new();
                    // inline_able refuses the facade (strict Tor) and
                    // YouTube pages (the sniffer would fetch a web page
                    // for nothing) — no sniff for either.
                    if crate::video::inline_able(url, mime.as_deref()) {
                        keys.push(crate::poster::poster_key(url));
                    }
                    if let Some(h) = blurhash {
                        keys.push(crate::poster::blurhash_key(h));
                    }
                    keys
                }
            },
        })
        .collect();
    // NIP-30: the emoji tags' urls ride the fetch sweeps too (the body
    // renders them inline; the gallery does NOT — assets don't carry
    // them, so an emoji image is never a media tile).
    out.extend(fields::emoji_tags(ev).into_iter().map(|(_, url)| url));
    out
}

/// `media_urls`, memoized per event. The parse (imeta + the content's
/// line scan) is a pure function of the event, but every pane's render
/// swept it per visible row per frame. Bounded, oldest-dropped at 4096
/// events; an entry is a handful of url strings.
pub fn media_urls_cached(ev: &Event) -> std::sync::Arc<[String]> {
    const CAP: usize = 4096;
    struct UrlsMemo {
        map: HashMap<String, std::sync::Arc<[String]>>,
        order: std::collections::VecDeque<String>,
    }
    static MEMO: std::sync::OnceLock<std::sync::Mutex<UrlsMemo>> = std::sync::OnceLock::new();
    let memo = MEMO.get_or_init(|| {
        std::sync::Mutex::new(UrlsMemo {
            map: HashMap::new(),
            order: std::collections::VecDeque::new(),
        })
    });
    let strict = crate::prefs::privacy_mode() == satori_core::privacy::PrivacyMode::Strict;
    // The mode rides the key: a strict-Tor switch must not keep emitting
    // the pre-switch sniffs for memoized events (and back).
    let key = format!("{strict}#{}", ev.id);
    let mut memo = memo.lock().unwrap();
    if let Some(hit) = memo.map.get(&key) {
        return hit.clone();
    }
    let urls: std::sync::Arc<[String]> = {
        let mut urls: Vec<String> = media_urls(ev);
        // The link-preview card's fetch rides the same sweep (D73): the
        // og: namespace delegates to og.rs inside media::fetch. Strict Tor
        // never sees the key (the memo is mode-keyed), the facade holds.
        if !strict && let Some(link) = body_parse_cached(ev).og_link.clone() {
            urls.push(format!("og:{link}"));
        }
        urls.into()
    };
    let memo = &mut *memo;
    fifo_trim(&mut memo.map, &mut memo.order, CAP);
    memo.order.push_back(key.clone());
    memo.map.insert(key, urls.clone());
    urls
}

/// The og: preview images ALREADY LANDED for this event's link. The og
/// fetch hands the image URL to the media cache once, at landing — a URL
/// no sweep knew about, so once RAM eviction dropped the bytes NOTHING
/// ever asked again: the card's thumbnail went dark mid-session (the
/// disappearing-image class the owner keeps hitting; the og card paints
/// `preview.image` directly). Every view's visible sweep appends this,
/// which both re-fetches an evicted image (disk cache hit, near instant)
/// and — via the same list — pins it while the row is on screen. Not
/// memoized on purpose: the verdict arrives asynchronously; the parse
/// memo's frozen answer would strand late landings.
pub(crate) fn og_image_urls(ev: &Event) -> Vec<String> {
    let mut out = Vec::new();
    for link in body_parse_cached(ev).og_link.iter() {
        if let Some(preview) = crate::og::get(link)
            && let Some(img) = &preview.image
        {
            out.push(img.clone());
        }
    }
    out
}

/// The thumbnail for a YouTube link (watch?v=, youtu.be/, shorts/) —
/// video.rs reuses the shape as the "is a YouTube page" test: GStreamer
/// can't stream watch pages, so they stay browser links.
/// mqdefault: always present, 16:9, no letterbox bars.
pub(crate) fn youtube_thumb(url: &str) -> Option<String> {
    let id = if let Some(rest) = url
        .strip_prefix("https://youtu.be/")
        .or_else(|| url.strip_prefix("http://youtu.be/"))
    {
        rest.split(['?', '/', '&', '#']).next()?
    } else if let Some((_, qs)) = url.split_once("youtube.com/watch")
        && let Some((_, v)) = qs.split_once("v=")
    {
        v.split('&').next()?
    } else if let Some((_, rest)) = url.split_once("youtube.com/shorts/") {
        rest.split(['?', '/', '#']).next()?
    } else {
        return None;
    };
    let id: String = id
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .take(11)
        .collect();
    (id.len() == 11).then(|| format!("https://img.youtube.com/vi/{id}/mqdefault.jpg"))
}

/// Standalone note/nevent references in reading order (quote embed
/// candidates; note_card.rs takes the first 3).
pub fn note_refs(ev: &Event) -> Vec<String> {
    ev.content
        .split('\n')
        .filter_map(standalone_ref)
        .collect::<Vec<_>>()
        .into_iter()
        .take(3)
        .collect()
}

/// Short display for a bech32 mention when the profile isn't known yet.
pub(crate) fn short_bech32(bech: &str) -> String {
    let bech = bech.strip_prefix("nostr:").unwrap_or(bech);
    format!("{}…", &bech[..bech.len().min(14)])
}

/// Link display text (content.rs display_url): schemeless host + 2 path
/// segments, truncated at 48 chars.
fn display_url(url: &str) -> String {
    let s = url.strip_prefix("https://").unwrap_or(url);
    let s = s.strip_prefix("http://").unwrap_or(s);
    let s = s.split('/').take(3).collect::<Vec<_>>().join("/");
    // Char-boundary-safe truncation: byte slicing panicked on multi-byte
    // URLs (String::truncate at a char edge), and a relay-controlled token
    // reaching 48 bytes is trivial to publish — the same regression class
    // as cards.rs short().
    if s.chars().count() > 48 {
        let t: String = s.chars().take(45).collect();
        format!("{t}…")
    } else {
        s
    }
}

/// The open-in-browser allow-list (audit security M2): feed-derived URLs
/// may only be http(s) — xdg-open dispatches any other scheme to whatever
/// desktop handler is registered. NIP-21/nostrconnect targets route
/// through uris.rs or the login flow, never through this.
pub(crate) fn web_url(url: &str) -> bool {
    url.starts_with("http://") || url.starts_with("https://")
}

/// The FIFO-cap kernel (the audit's duplication lens: the bound-trim
/// idiom had eight hand-copies across five files — seen.rs's convention,
/// UI-side). Maps and order queues grow in lockstep (insert both, evict
/// both), so one loop serves the pre-insert evict (`len >= cap` evicts
/// exactly once) and the batched trim alike.
pub(crate) fn fifo_trim<V>(
    map: &mut std::collections::HashMap<String, V>,
    order: &mut std::collections::VecDeque<String>,
    cap: usize,
) {
    while order.len() > cap
        && let Some(oldest) = order.pop_front()
    {
        map.remove(&oldest);
    }
}

// --- word-flow tokens ------------------------------------------------------

/// One whitespace token inside a paragraph.
pub(crate) enum Tok {
    /// npub/nprofile mention.
    Mention(PublicKey),
    /// note1/nevent1 reference, resolved to its event id.
    NoteRef(EventId),
    /// naddr — addressable-event reference, kept as bech32 (njump resolves).
    AddrRef(String),
    /// Plain https link.
    Url(String),
    /// A #hashtag — opens the hashtag timeline (Phase 2 §4.2).
    Hashtag(String),
    /// A bare `:shortcode:` (NIP-30) — resolves through the event's own
    /// emoji tags to an inline image.
    Emoji(String),
    Word(String),
}

/// Punctuation that commonly hugs a token ("(see nostr:nevent1…).") — split
/// off so the link stays clean and the punctuation stays text.
pub(crate) fn split_trailing(token: &str) -> (&str, &str) {
    // A quote can never appear inside a URL (RFC 3986): content that
    // embeds serialized-event JSON produces tokens like
    // `https://x/","created_at":…` where the real link ends at the first
    // quote — the trailer renders as plain text after the link.
    let token = token.split('"').next().unwrap_or(token);
    let core = token.trim_end_matches(['.', ',', ';', ':', '!', '?', ')', ']', '}', '"', '”']);
    (&token[..core.len()], &token[core.len()..])
}

pub(crate) fn classify_token(core: &str) -> Tok {
    let bech = core.strip_prefix("nostr:").unwrap_or(core);
    if let Ok(n) = Nip19::from_bech32(bech) {
        return match n {
            Nip19::Pubkey(pk) => Tok::Mention(pk),
            Nip19::Profile(p) => Tok::Mention(p.public_key),
            Nip19::EventId(id) => Tok::NoteRef(id),
            Nip19::Event(e) => Tok::NoteRef(e.event_id),
            Nip19::Coordinate(_) => Tok::AddrRef(bech.to_string()),
            _ => Tok::Word(core.to_string()),
        };
    }
    if bech.starts_with("naddr1") {
        return Tok::AddrRef(bech.to_string());
    }
    if core.starts_with("https://") || core.starts_with("http://") {
        return Tok::Url(core.to_string());
    }
    // #tag — the note's t tags mirror these (Phase 2 §4.2). Alphanumerics
    // and underscore, at least one; `##` or a bare `#` stays a word.
    if let Some(tag) = core
        .strip_prefix('#')
        .filter(|t| !t.is_empty() && t.chars().all(|c| c.is_alphanumeric() || c == '_'))
    {
        return Tok::Hashtag(tag.to_string());
    }
    Tok::Word(core.to_string())
}

/// Display text for an naddr (content.rs display_nostr_ref, kind-aware).
fn addr_label(bech: &str) -> String {
    let label = match Nip19::from_bech32(bech) {
        Ok(Nip19::Coordinate(c)) => match u16::from(c.kind) {
            30023 => "↗ article",
            31922 | 31923 => "↗ event",
            1068 => "↗ poll",
            _ => "↗ reference",
        },
        _ => "↗ reference",
    };
    label.to_string()
}

/// Serif text span (the word-flow baseline style).
fn word(text: String) -> Div {
    // Emoji runs ride theme::EMOJI as their primary font (see the note
    // there): through the SERIF face they paint as DejaVu/Adwaita
    // monochrome outlines. Trailing ASCII punctuation stays on the body
    // face ("👍." keeps the period typographically serif).
    if crate::emoji::is_emoji_run(&text) {
        return word_flow_glyph(text, None);
    }
    if let Some((core, punct)) = split_emoji_tail(&text) {
        return word_flow_glyph(core.to_string(), Some(punct.to_string()));
    }
    div()
        .font_family(theme::SERIF)
        .text_size(px(theme::T_READER))
        // P052's own line box is huge (URW vertical metrics); pin the pitch
        // or every wrapped line reads double-spaced.
        .line_height(relative(1.2))
        .text_color(rgb(theme::ink()))
        .child(text)
}

/// One emoji-run glyph at the body's size, plus its detached punctuation
/// (if any) on the body face. Both carry the metrics pin from `word`.
fn word_flow_glyph(core: String, punct: Option<String>) -> Div {
    let flow = div().flex().items_baseline().child(
        div()
            .font_family(theme::EMOJI)
            .text_size(px(theme::T_READER))
            .line_height(relative(1.2))
            .text_color(rgb(theme::ink()))
            .child(core),
    );
    match punct {
        Some(p) => flow.child(
            div()
                .font_family(theme::SERIF)
                .text_size(px(theme::T_READER))
                .line_height(relative(1.2))
                .text_color(rgb(theme::ink()))
                .child(p),
        ),
        None => flow,
    }
}

/// "👍!" → (👍, "!"): an emoji run followed by trailing ASCII punctuation.
/// None when the token isn't that shape.
fn split_emoji_tail(text: &str) -> Option<(&str, &str)> {
    let split = text
        .char_indices()
        .rev()
        .take_while(|(_, c)| c.is_ascii_punctuation())
        .map(|(i, _)| i)
        .last()?;
    let (core, punct) = text.split_at(split);
    (!core.is_empty() && crate::emoji::is_emoji_run(core)).then_some((core, punct))
}

/// One clickable word-flow token (link / mention / ref).
pub(crate) fn token_el<V: EventEmitter<Nav> + 'static>(
    tok: Tok,
    punct: &str,
    n: usize,
    ctx: &Body,
    handle: &Entity<V>,
) -> AnyElement {
    let base = |id: SharedString| {
        div()
            .id(id)
            .cursor_pointer()
            .font_family(theme::SERIF)
            .text_size(px(theme::T_READER))
            .line_height(relative(1.2))
            .text_color(rgb(theme::muted()))
            .underline()
            // One link system for every token: quiet muted ink at rest,
            // the seal color on hover — the same lift everywhere a click
            // would leave the note.
            .hover(|s| s.text_color(rgb(theme::vermilion())))
    };
    match tok {
        Tok::Word(w) => word(if punct.is_empty() {
            w
        } else {
            format!("{w}{punct}")
        })
        .into_any_element(),
        Tok::Emoji(code) => {
            // NIP-30: the shortcode resolves through the event's own emoji
            // tags (reaction_glyph's shape in notifications.rs). The fetch
            // rides the view's media sweep (the urls are in media_urls),
            // so a thumb not ready yet shows the bare code and the image
            // replaces it when the bytes land.
            match ctx.emoji.get(&code) {
                Some(url) => match ctx.media.thumb(url) {
                    Some(png) => img(png)
                        .size(px(20.0))
                        .object_fit(ObjectFit::Contain)
                        .into_any_element(),
                    None => word(format!(":{code}:")).into_any_element(),
                },
                None => word(format!(":{code}:")).into_any_element(),
            }
        }
        Tok::Url(url) => {
            let label = display_url(&url);
            let openable = web_url(&url);
            let el = base(seg_id("url", &format!("{n}{url}")))
                .on_click(move |_, _, cx| {
                    cx.stop_propagation();
                    if openable {
                        cx.open_url(&url);
                    }
                })
                .child(label);
            with_punct(el, punct)
        }
        Tok::Mention(pk) => {
            let key = pk.to_string();
            let label = ctx
                .profiles
                .get(&key)
                .map(|p| p.display())
                .unwrap_or_else(|| short_bech32(&key));
            let handle = handle.clone();
            let el = base(seg_id("mention", &format!("{n}{key}")))
                .on_click(move |_, _, cx| {
                    cx.stop_propagation();
                    handle.update(cx, |_, cx| cx.emit(Nav::OpenProfile(pk)));
                })
                .child(format!("@{label}"));
            with_punct(el, punct)
        }
        Tok::NoteRef(id) => {
            let handle = handle.clone();
            let el = base(seg_id("ref", &format!("{n}{id}")))
                .on_click(move |_, _, cx| {
                    cx.stop_propagation();
                    handle.update(cx, |_, cx| cx.emit(Nav::OpenThread(id)));
                })
                .child("↗ note");
            with_punct(el, punct)
        }
        Tok::Hashtag(tag) => {
            let handle = handle.clone();
            let label = format!("#{tag}");
            let el = base(seg_id("tag", &format!("{n}{tag}")))
                .on_click(move |_, _, cx| {
                    cx.stop_propagation();
                    let tag = tag.clone();
                    handle.update(cx, |_, cx| cx.emit(Nav::OpenHashtag(tag)));
                })
                .child(label);
            with_punct(el, punct)
        }
        Tok::AddrRef(bech) => {
            let label = addr_label(&bech);
            let el = base(seg_id("addr", &format!("{n}{bech}")))
                .on_click(move |_, _, cx| {
                    cx.stop_propagation();
                    // Addressable events have no local reader yet; njump
                    // renders any naddr (P3: resolve via event_by_address).
                    cx.open_url(&format!("https://njump.me/{bech}"));
                })
                .child(label);
            with_punct(el, punct)
        }
    }
}

/// A link token plus its trailing punctuation, as one flow fragment.
fn with_punct(el: impl IntoElement, punct: &str) -> AnyElement {
    if punct.is_empty() {
        el.into_any_element()
    } else {
        div()
            .flex()
            .items_baseline()
            .child(el)
            .child(word(punct.to_string()))
            .into_any_element()
    }
}

/// A whole paragraph as a wrapping flow of word elements — links, mentions
/// and refs become clickable anywhere in the text, which the GTK markup
/// pipeline got from rich runs and GPUI's div tree gets from flex-wrap.
/// Also the profile page's about block (profile.rs `about_flow`).
/// A bare `:shortcode:` token (NIP-30): colon-wrapped, non-empty, no
/// inner colons or whitespace. Runs on the RAW token — split_trailing
/// would eat the closing colon and hand classify_token a dead `:name`.
fn emoji_shortcode(token: &str) -> Option<String> {
    token
        .strip_prefix(':')
        .and_then(|t| t.strip_suffix(':'))
        .filter(|c| !c.is_empty() && !c.contains(':') && !c.contains(char::is_whitespace))
        .map(String::from)
}

/// The event's NIP-30 emoji map (Body.emoji): shortcode → url, first tag
/// wins.
pub fn emoji_map(ev: &Event) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for (code, url) in fields::emoji_tags(ev) {
        map.entry(code).or_insert(url);
    }
    map
}

pub(crate) fn word_flow<V: EventEmitter<Nav> + 'static>(
    para: &str,
    skip: &[String],
    ctx: &Body,
    handle: &Entity<V>,
) -> Div {
    let mut flow = div().w_full().flex().flex_wrap().gap_1();
    for (n, token) in para.split_whitespace().enumerate() {
        // The emoji check runs on the RAW token (split_trailing would eat
        // the closing colon); everything else classifies after the split.
        if let Some(code) = emoji_shortcode(token) {
            flow = flow.child(token_el(Tok::Emoji(code), "", n, ctx, handle));
            continue;
        }
        let (core, punct) = split_trailing(token);
        if core.is_empty() {
            continue;
        }
        let tok = classify_token(core);
        // NIP-92 (content.ts applyImetaMime parity): a media asset's URL is
        // painted by the media section — the text flow drops the duplicate
        // link.
        if let Tok::Url(u) = &tok
            && skip.contains(u)
        {
            continue;
        }
        flow = flow.child(token_el(tok, punct, n, ctx, handle));
    }
    flow
}

fn body_parse_cached(ev: &Event) -> std::sync::Arc<BodyParse> {
    const CAP: usize = 4096;
    struct Memo {
        map: HashMap<String, std::sync::Arc<BodyParse>>,
        order: std::collections::VecDeque<String>,
    }
    static MEMO: std::sync::OnceLock<std::sync::Mutex<Memo>> = std::sync::OnceLock::new();
    let memo = MEMO.get_or_init(|| {
        std::sync::Mutex::new(Memo {
            map: HashMap::new(),
            order: std::collections::VecDeque::new(),
        })
    });
    let key = ev.id.to_string();
    let mut memo = memo.lock().unwrap();
    if let Some(hit) = memo.map.get(&key) {
        return hit.clone();
    }
    let parsed_article = article::parse(ev).map(std::sync::Arc::new);
    let assets = media_assets_with(parsed_article.as_deref(), ev);
    let media_links: Vec<String> = assets.iter().map(|a| a.url().to_string()).collect();
    let cover = match parsed_article.as_deref().and_then(|d| d.image.clone()) {
        Some(img) if !img.is_empty() => Some(img),
        _ => assets.iter().find_map(|a| match a {
            MediaAsset::Picture { url } => Some(url.clone()),
            _ => None,
        }),
    };
    let dims: HashMap<String, Option<(u32, u32)>> = imeta::parse(ev)
        .iter()
        .map(|m| (m.url.clone(), m.dim))
        .collect();
    let alts: HashMap<String, String> = imeta::parse(ev)
        .iter()
        .filter_map(|m| m.alt.clone().map(|a| (m.url.clone(), a)))
        .collect();
    let og_link = og_candidate(ev, &media_links);
    if og_link.is_some() {
        // One line per note that carries a card candidate: the D73 probe
        // path — a note rendering without its card names itself here.
        eprintln!("[og] link {} {og_link:?}", &ev.id.to_string()[..8]);
    }
    let parsed = std::sync::Arc::new(BodyParse {
        cover,
        dims,
        alts,
        murls: media_urls_from(&assets, ev).into(),
        assets,
        media_links,
        og_link,
        article: parsed_article,
        emoji: std::sync::Arc::new(emoji_map(ev)),
    });
    let memo = &mut *memo;
    fifo_trim(&mut memo.map, &mut memo.order, CAP);
    memo.order.push_back(key.clone());
    memo.map.insert(key, parsed.clone());
    parsed
}

/// The RENDER path's per-event parse (audit perf H3): body() re-ran
/// imeta::parse (a full tag-vec clone), media_urls and media_assets per
/// visible card per frame — the fetch path's media_urls_cached existed,
/// but render never used it. One memo here, keyed by event id: the parse
/// is a pure function of the event (unlike the fetch memo, whose privacy
/// mode rides its key). Bounded, oldest-dropped at 4096 events; an entry
/// is a handful of url strings + the asset vec.
///
/// Exposed to sibling views (#31's rich-card riders): the article card
/// reads the memoized NIP-23 data instead of re-cloning the tag vec per
/// frame, and the classified card's gallery reads `dims`/`alts` instead
/// of running `imeta::parse` twice.
pub(crate) struct BodyParse {
    pub(crate) cover: Option<String>,
    pub(crate) dims: HashMap<String, Option<(u32, u32)>>,
    /// NIP-68 `alt` per url (WS4): the reader-side badge reads it here,
    /// the composer-side editor wrote it into the same tag.
    pub(crate) alts: HashMap<String, String>,
    murls: std::sync::Arc<[String]>,
    assets: Vec<MediaAsset>,
    media_links: Vec<String>,
    /// The note's first non-media http(s) link (D73): the link-preview
    /// card's URL, None for notes with none (or media-only links).
    pub(crate) og_link: Option<String>,
    article: Option<std::sync::Arc<article::ArticleData>>,
    /// The NIP-30 emoji map, computed on the memo's miss path and shared
    /// by every Body built from this parse (the audit's per-frame
    /// rebuild fix).
    pub(crate) emoji: std::sync::Arc<HashMap<String, String>>,
}

pub(crate) fn body_parse(ev: &Event) -> std::sync::Arc<BodyParse> {
    body_parse_cached(ev)
}

/// The NIP-23 article data, riding the same memo (#31's rich-card rider):
/// `article::parse` clones the whole tag vec, and it ran per visible card
/// per frame in cards.rs.
pub fn article_data_cached(ev: &Event) -> Option<std::sync::Arc<article::ArticleData>> {
    body_parse_cached(ev).article.clone()
}

/// The one actor header every "someone did X" row wears — notification
/// rows and the feed's repost card alike: optional leading glyph (the
/// reaction's emoji, or a stroke icon), avatar, name, optional verb (the
/// caller styles it; zap sats ride in here emphasized), and the time,
/// which is the third mode toggle (timefmt.rs) everywhere. The name opens
/// the actor's profile when `open_profile` is given. `copy_id` (the
/// note's NIP-21 URI) hangs the copy-the-id seal after the timestamp —
/// None where the header announces an action on some other note
/// (notification rows): the seal copies the note on screen, not the
/// announcement.
#[allow(clippy::too_many_arguments)]
pub fn actor_header<V: EventEmitter<Nav> + 'static>(
    glyph: Option<AnyElement>,
    snap: &media::Snapshot,
    picture: &str,
    name: String,
    verb: Option<AnyElement>,
    time: String,
    id_prefix: String,
    open_profile: Option<PublicKey>,
    copy_id: Option<String>,
    handle: Entity<V>,
) -> Div {
    // The name always carries an id (the click lives on it only when the
    // actor's profile is openable). The flex rides on whichever middle
    // element exists — verb when there is one, name otherwise — so the
    // time pins right in both shapes.
    let name_el = div()
        .text_size(px(theme::T_UI))
        .font_weight(FontWeight::SEMIBOLD)
        .text_color(rgb(theme::ink()))
        .id(SharedString::from(format!("{id_prefix}-author")));
    let name_el = match open_profile {
        Some(pk) => name_el.cursor_pointer().on_click(move |_, _, cx| {
            handle.update(cx, |_, cx| cx.emit(Nav::OpenProfile(pk)));
        }),
        None => name_el,
    }
    .child(name.clone());
    let mut head = div()
        .flex()
        .items_center()
        .gap_2()
        .children(glyph)
        .child(media::avatar(snap, picture, &name, 28.0));
    match verb {
        Some(v) => {
            head = head
                .child(name_el)
                .child(div().flex_1().min_w_0().flex().items_center().child(v))
        }
        None => head = head.child(name_el.flex_1()),
    }
    head.child(time_toggle(format!("{id_prefix}-time"), time))
        .children(copy_id.map(|payload| copy_seal(&id_prefix, payload)))
}

/// The header copy seal's flash: which payload was just copied and when.
/// A plain static (item closures have no cx to read an entity), keyed by
/// the payload — two different notes never share one. The repaint rides
/// timefmt::Signal, which every timestamp-bearing view already observes
/// for the mode cycle: one wake shows the check, the expiry wake turns
/// it back. profile.rs's flash_copy acknowledgment, generalized.
static COPIED: std::sync::Mutex<Option<(String, std::time::Instant)>> = std::sync::Mutex::new(None);

const COPY_FLASH: std::time::Duration = std::time::Duration::from_secs(2);

fn copied_now(payload: &str) -> bool {
    COPIED
        .lock()
        .unwrap()
        .as_ref()
        .is_some_and(|(p, _)| p == payload)
}

/// Copy `payload` (the note's NIP-21 URI) and flash the seal's glyph to a
/// check for [`COPY_FLASH`].
fn copy_id(payload: String, cx: &mut gpui::App) {
    cx.write_to_clipboard(gpui::ClipboardItem::new_string(payload.clone()));
    *COPIED.lock().unwrap() = Some((payload.clone(), std::time::Instant::now()));
    cx.set_global(crate::timefmt::Signal);
    cx.spawn(async move |cx| {
        cx.background_executor().timer(COPY_FLASH).await;
        if let Ok(mut held) = COPIED.lock()
            && held.as_ref().is_some_and(|(p, _)| *p == payload)
        {
            *held = None;
        }
        // Wake the flash off even if a newer copy replaced it (that seal
        // re-rendered anyway; the wake is one cheap repaint).
        cx.update(|cx| cx.set_global(crate::timefmt::Signal));
    })
    .detach();
}

/// The seal after the timestamp: a quiet copy glyph that writes the
/// note's NIP-21 URI (`nostr:nevent1…` / `nostr:naddr1…` — nip19.rs)
/// and flashes a check while the flash lasts.
pub(crate) fn copy_seal(id_prefix: &str, payload: String) -> impl IntoElement {
    let flashed = copied_now(&payload);
    div()
        .id(SharedString::from(format!("{id_prefix}-copy")))
        .cursor_pointer()
        .text_color(rgb(theme::muted()))
        .hover(|s| s.text_color(rgb(theme::ink())))
        .on_click(move |_, _, cx| {
            cx.stop_propagation();
            copy_id(payload.clone(), cx);
        })
        .child(if flashed {
            icons::check_icon(theme::muted()).into_any_element()
        } else {
            icons::copy_icon(theme::muted()).into_any_element()
        })
}

/// The timestamp tap target (timefmt.rs's third mode toggle: relative →
/// date → block height), shared by every header row. Was hand-rolled
/// five times; thread's reply copy (and compact_card, and the reader's
/// comment rows) had lost the hover affordance (#31).
pub(crate) fn time_toggle(id: impl Into<SharedString>, time: String) -> gpui::Stateful<Div> {
    div()
        .id(id.into())
        .cursor_pointer()
        .text_size(px(theme::T_SMALL))
        .text_color(rgb(theme::muted()))
        .hover(|s| s.text_color(rgb(theme::ink())))
        .on_click(|_, _, cx| crate::timefmt::cycle(cx))
        .child(time)
}

/// The note a kind-6/16 repost carries (Amethyst's repost guard: a repost
/// is not content of its own — the body is the boosted note's card).
pub(crate) fn repost_inner(ev: &Event) -> Option<Event> {
    let inner = serde_json::from_str::<Event>(&ev.content).ok()?;
    (inner.kind == Kind::TextNote || super::cards::is_feed_kind(inner.kind)).then_some(inner)
}

/// The article card's summary line: the tag summary, else the first ~140
/// chars of the body (article.ts). One home for the rule — cards.rs and
/// wire.rs had already twinned it, and the twin was one title-size
/// divergence away from drifting.
pub(crate) fn article_summary(data: &article::ArticleData, raw: &str) -> String {
    if data.summary.is_empty() {
        raw.chars().take(140).collect::<String>()
    } else {
        data.summary.clone()
    }
}

/// `repost_inner`, memoized per event (audit perf: a repost's content IS
/// the boosted event's full JSON, and the feed's item closure re-parsed
/// it twice per visible repost row per frame — card_media_urls and
/// repost_card — with notifications adding a third sweep. Pure function
/// of the event; bounded, oldest-dropped at 4096). Callers get an
/// `Arc<Event>`: render paths share one bump instead of re-parsing.
pub(crate) fn repost_inner_cached(ev: &Event) -> Option<std::sync::Arc<Event>> {
    const CAP: usize = 4096;
    struct RepostMemo {
        map: HashMap<String, Option<std::sync::Arc<Event>>>,
        order: std::collections::VecDeque<String>,
    }
    static MEMO: std::sync::OnceLock<std::sync::Mutex<RepostMemo>> = std::sync::OnceLock::new();
    let memo = MEMO.get_or_init(|| {
        std::sync::Mutex::new(RepostMemo {
            map: HashMap::new(),
            order: std::collections::VecDeque::new(),
        })
    });
    let key = ev.id.to_string();
    let mut memo = memo.lock().unwrap();
    if let Some(inner) = memo.map.get(&key) {
        return inner.clone();
    }
    let inner = repost_inner(ev).map(std::sync::Arc::new);
    let memo = &mut *memo;
    fifo_trim(&mut memo.map, &mut memo.order, CAP);
    memo.order.push_back(key.clone());
    memo.map.insert(key, inner.clone());
    inner
}

/// Render a note body: word-flow paragraphs, media gallery section, quote
/// embeds. Media fetches ride the shared cache (`media::Snapshot`); the view
/// queues them via `content::media_urls` + `media::fetch`.
pub fn body<V: EventEmitter<Nav> + 'static>(ev: &Event, ctx: &Body, handle: Entity<V>) -> Div {
    body_with(ev, ctx, handle, false)
}

/// The body with the first content line dropped (`skip_title_line`): a
/// card that already renders that line as its serif header (video cards,
/// NIP-71's "title is the first line") would otherwise paint the title —
/// and any hashtags riding it — twice.
pub fn body_with<V: EventEmitter<Nav> + 'static>(
    ev: &Event,
    ctx: &Body,
    handle: Entity<V>,
    skip_title_line: bool,
) -> Div {
    let mut body = div().w_full().flex().flex_col().gap_2();

    let parsed = body_parse_cached(ev);
    let dims = &parsed.dims;
    let murls = &parsed.murls;
    // Computed once: the media section below renders these, and the text
    // flow skips their URLs (a media URL never renders twice).
    let assets = &parsed.assets;
    let media_links = &parsed.media_links;

    // The text flow's source: the media parse above always sees the FULL
    // content (imeta-tagged media needs every line); only the TEXT drops
    // the title line.
    let text: &str = if skip_title_line {
        ev.content
            .split_once('\n')
            .map(|(_, rest)| rest)
            .unwrap_or("")
    } else {
        &ev.content
    };

    // Paragraph rhythm follows the TS renderer's pre-wrap semantics
    // (TODO(port): src/render/content.ts — `.content` is pre-wrap): a single
    // newline breaks the line tight (no paragraph gap); only blank lines
    // separate paragraphs. Consecutive lines collect into one block.
    let mut run: Vec<AnyElement> = Vec::new();
    fn push_block(body: Div, run: &mut Vec<AnyElement>) -> Div {
        match run.len() {
            0 => body,
            1 => body.child(run.remove(0)),
            _ => body.child(div().w_full().flex().flex_col().children(run.drain(..))),
        }
    }
    for para in text.split('\n') {
        let trimmed = para.trim();
        if trimmed.is_empty() {
            body = push_block(body, &mut run);
            continue;
        }
        // Quote refs fold out of the text into embed cards below (content.ts
        // collects refs and drops them from the markup).
        if standalone_ref(trimmed).is_some() {
            continue;
        }
        match standalone(trimmed) {
            // A paragraph that is one link: media folds into the gallery
            // section below; a link the cache couldn't decode (a blossom
            // page, say) degrades back to a plain link row here.
            Some(Seg::Link(url)) => {
                if is_video_url(&url) || youtube_thumb(&url).is_some() || is_audio_url(&url) {
                    // The gallery section below renders the video tile
                    // (poster + play overlay, opens the browser) or the
                    // voice row (#52).
                } else if ctx.media.not_media(&url)
                    || !(is_image_url(&url) || path_ext(&url).is_none())
                {
                    body = push_block(body, &mut run).child(link_row(&url));
                }
                // else: a media URL — the gallery section below renders it.
            }
            Some(Seg::User(pk)) => {
                let key = pk.to_string();
                let label = ctx
                    .profiles
                    .get(&key)
                    .map(|p| p.display())
                    .unwrap_or_else(|| short_bech32(&key));
                let seg_handle = handle.clone();
                let el = div()
                    .id(seg_id("mention", trimmed))
                    .cursor_pointer()
                    .text_size(px(theme::T_BODY))
                    .text_color(rgb(theme::muted()))
                    .hover(|s| s.text_color(rgb(theme::vermilion())))
                    .on_click(move |_, _, cx| {
                        cx.stop_propagation();
                        seg_handle.update(cx, |_, cx| cx.emit(Nav::OpenProfile(pk)));
                    })
                    .child(format!("@{label}"))
                    .into_any_element();
                run.push(el);
            }
            None => run.push(word_flow(para, media_links, ctx, &handle).into_any_element()),
        };
    }
    body = push_block(body, &mut run);

    // Media section (content.ts): pictures and videos in reading order — one
    // item full-width by its aspect, several as a horizontal strip; picture
    // tiles open the lightbox, video tiles open the browser.
    if !murls.is_empty()
        && let Some(section) = media_section(assets, dims, &parsed.alts, ctx, &handle)
    {
        body = body.child(section);
    }

    // The link-preview card (D73): the note's first non-media link, when
    // its og: preview has landed. Fetch rides the sweep; nothing paints
    // until then (the link row above already names the destination).
    if let Some(link) = &parsed.og_link
        && let Some(preview) = crate::og::get(link)
    {
        body = body.child(og_card(link, &preview, ctx));
    }

    // Quote embeds — compact previews, click opens the thread (embed_card).
    for bech in note_refs(ev) {
        match ctx.quotes.get(&bech) {
            Some(Some(e)) => body = body.child(embed_card(&bech, e, handle.clone())),
            _ => {
                body = body.child(
                    div()
                        .text_size(px(theme::T_SMALL))
                        .text_color(rgb(theme::muted()))
                        .child("…"),
                )
            }
        }
    }

    body
}

/// Pubkeys mentioned inline (nostr:npub / nprofile entities), so a pane can
/// hydrate their profiles before render — otherwise a mention degrades to
/// @npub1… (TODO(port): content.ts mentionPubkeys).
pub(crate) fn mention_pks(content: &str) -> Vec<PublicKey> {
    content
        .split_whitespace()
        .filter_map(|tok| match classify_token(split_trailing(tok).0) {
            Tok::Mention(pk) => Some(pk),
            _ => None,
        })
        .collect()
}

/// Schemeless, truncated link row for URLs that aren't media.
pub(crate) fn link_row(url: &str) -> AnyElement {
    let target = url.to_string();
    let openable = web_url(&target);
    div()
        .id(seg_id("link", url))
        .cursor_pointer()
        .text_size(px(theme::T_BODY))
        .text_color(rgb(theme::muted()))
        .underline()
        .hover(|s| s.text_color(rgb(theme::vermilion())))
        .on_click(move |_, _, cx| {
            if openable {
                cx.open_url(&target);
            }
        })
        .child(display_url(url))
        .into_any_element()
}

/// The link-preview card (D73): the page's og: metadata as a bordered row
/// under the note body — thumbnail left (when the page offers one and it
/// has landed in the ordinary image cache), site + title + description
/// right. Everything on it is attacker-written, so the sizes are capped at
/// the source (core) and the layout clamps what it shows. The whole card
/// is the click target: it opens what the link row above names (the M2
/// web_url gate). The strip happened at extraction: the card's target
/// carries no tracking params.
fn og_card(
    link: &str,
    preview: &std::sync::Arc<satori_core::media::LinkPreview>,
    ctx: &Body,
) -> AnyElement {
    let target = link.to_string();
    let openable = web_url(&target);
    let image = preview.image.as_deref().and_then(|img| ctx.media.png(img));
    let card = div()
        .id(seg_id("og", link))
        .cursor_pointer()
        .w_full()
        .flex()
        .gap_2()
        .overflow_hidden()
        .rounded(px(theme::R_EMBED))
        .border_1()
        .border_color(rgb(theme::hairline()))
        .bg(rgb(theme::panel()))
        .hover(|s| s.border_color(rgb(theme::vermilion())))
        .on_click(move |_, _, cx| {
            cx.stop_propagation();
            if openable {
                cx.open_url(&target);
            }
        });
    // The thumbnail: a fixed 96px column, cover-fitted; without a landed
    // image the text column takes the whole card (the image pops in via
    // the image fetch's own notify).
    let card = if let Some(png) = image {
        card.child(
            div()
                .w(px(96.0))
                .h(px(72.0))
                .flex_none()
                .overflow_hidden()
                .child(img(png).size_full().object_fit(ObjectFit::Cover)),
        )
    } else {
        card
    };
    let mut text = div().w_full().flex().flex_col().gap_0p5().py_1().pr_2();
    if !preview.site.is_empty() {
        text = text.child(
            div()
                .text_size(px(theme::T_SMALL))
                .text_color(rgb(theme::muted()))
                .text_ellipsis()
                .overflow_hidden()
                .child(preview.site.to_uppercase()),
        );
    }
    text = text.child(
        div()
            .text_size(px(theme::T_UI))
            .font_weight(FontWeight::SEMIBOLD)
            .text_color(rgb(theme::ink()))
            .text_ellipsis()
            .overflow_hidden()
            .child(preview.title.clone()),
    );
    if let Some(desc) = &preview.description {
        text = text.child(
            div()
                .text_size(px(theme::T_SMALL))
                .text_color(rgb(theme::muted()))
                .line_clamp(2)
                .overflow_hidden()
                .child(desc.clone()),
        );
    }
    card.child(text).into_any_element()
}

/// Video tile: a poster frame wearing a play mark when the cache has one
/// (NIP-92 `image`, YouTube thumbnail), a quiet play-row while it loads or
/// when there's nothing to show. Phase 3: when the inline player is live
/// for this URL the tile renders the player element and its control row
/// (⏸/▶, ✕, ↗ browser) instead; the tap opens the player when the URL is
/// inline-able (video.rs gates — strict Tor and YouTube stay browser
/// links), else the browser.
fn video_tile(
    url: &str,
    poster: Option<&str>,
    blurhash: Option<&str>,
    mime: Option<&str>,
    w: Option<f32>,
    h: f32,
    ctx: &Body,
) -> AnyElement {
    let url_for_open = url.to_string();
    let mime_for_open = mime.map(str::to_string);

    // The inline player is live for this URL: the element paints the frame
    // (the crate aspect-fits inside the box it's given), the row below is
    // its controls — all sealed against the tile's own click.
    if let Some(v) = crate::video::active(url) {
        let max_w = w.unwrap_or(COL_W - 32.0);
        let ar = v.aspect_ratio();
        let box_h = if ar > 0.0 {
            (max_w / ar).clamp(80.0, 560.0)
        } else {
            h
        };
        let paused_now = v.paused();
        let browser_target = url.to_string();
        return div()
            .id(seg_id("video-player", url))
            .flex_none()
            .overflow_hidden()
            .rounded(px(theme::R_EMBED))
            .border_1()
            .border_color(rgb(theme::hairline()))
            .bg(rgb(0x000000))
            .map(|d| match w {
                Some(w) => d.w(px(w)),
                None => d.w_full(),
            })
            .flex()
            .flex_col()
            .child(
                div()
                    .flex()
                    .items_center()
                    .justify_center()
                    .h(px(box_h))
                    .child(crate::video::element(&v, max_w, box_h)),
            )
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_3()
                    .px_2()
                    .py_1()
                    .bg(rgb(theme::panel()))
                    .child(
                        div()
                            .id(seg_id("vp-toggle", url))
                            .cursor_pointer()
                            .text_size(px(theme::T_UI))
                            .text_color(rgb(theme::ink()))
                            .on_click(|_, _, cx| {
                                cx.stop_propagation();
                                crate::video::toggle(cx);
                            })
                            .child(if paused_now { "▶" } else { "⏸" }),
                    )
                    .child(
                        div()
                            .id(seg_id("vp-close", url))
                            .cursor_pointer()
                            .text_size(px(theme::T_UI))
                            .text_color(rgb(theme::muted()))
                            .hover(|s| s.text_color(rgb(theme::ink())))
                            .on_click(|_, _, cx| {
                                cx.stop_propagation();
                                crate::video::close(cx);
                            })
                            .child("✕"),
                    )
                    .child(
                        div()
                            .id(seg_id("vp-browser", url))
                            .cursor_pointer()
                            .text_size(px(theme::T_UI))
                            .text_color(rgb(theme::muted()))
                            .hover(|s| s.text_color(rgb(theme::ink())))
                            .on_click(move |_, _, cx| {
                                cx.stop_propagation();
                                if crate::views::content::web_url(&browser_target) {
                                    cx.open_url(&browser_target);
                                }
                            })
                            .child("↗"),
                    ),
            )
            .into_any_element();
    }

    // Opening: the pipeline is building (Video::new can take seconds). The
    // tile stays exactly what it was, but the play mark breathes — the tap
    // acknowledged without a spinner widget, honoring the motion pref like
    // the zap bolt does (sumi-e: one living mark, no chrome).
    let opening_now = crate::video::opening(url);
    let reduced = crate::desktop::reduced_motion();
    let play_mark = |size: f32| -> gpui::AnyElement {
        let mark = div()
            .text_size(px(size))
            .text_color(rgb(theme::vermilion()))
            .child("▶");
        if !opening_now {
            mark.into_any_element()
        } else if reduced {
            div().opacity(0.6).child(mark).into_any_element()
        } else {
            mark.with_animation(
                seg_id("video-opening", url),
                gpui::Animation::new(std::time::Duration::from_millis(1400)).repeat(),
                |el, delta| el.opacity(0.65 - 0.3 * (2.0 * delta - 1.0).abs()),
            )
            .into_any_element()
        }
    };

    // D38: the preview panel is a fixed 16:9 — posters mostly are, and a
    // uniform shape reads cleaner than every video its own. The player
    // above keeps the video's true aspect; this is just the poster box.
    let panel_w = w.unwrap_or(COL_W - 32.0);
    let panel_h = panel_w * 9.0 / 16.0;

    let frame = div()
        .id(seg_id("video-tile", url))
        .cursor_pointer()
        .flex_none()
        .overflow_hidden()
        .rounded(px(theme::R_EMBED))
        .border_1()
        .border_color(rgb(theme::hairline()))
        .bg(rgb(theme::panel()))
        .map(|d| match w {
            Some(w) => d.w(px(w)),
            None => d.w_full(),
        })
        .h(px(panel_h))
        .on_click(move |_, _, cx| {
            cx.stop_propagation();
            crate::video::open(url_for_open.clone(), mime_for_open.clone(), cx);
        });
    // The preview ladder (D32, reordered D72): the publisher's poster (now
    // OUR uploads embed one — D38's grab at attach time), then a locally
    // sniffed first frame — a real frame beats an impression — and the
    // blurhash gradient LAST: the local filler that paints while the sniff
    // runs or when it fails. Any hit paints under the centered play mark;
    // none means the quiet 16:9 panel, mark only (the filename row is gone
    // — nobody read it).
    let shown = poster
        .and_then(|p| ctx.media.png(p))
        .or_else(|| ctx.media.png(&crate::poster::poster_key(url)))
        .or_else(|| blurhash.and_then(|b| ctx.media.png(&crate::poster::blurhash_key(b))));
    match shown {
        Some(png) => frame
            .child(
                div()
                    .relative()
                    .size_full()
                    // Cover: the panel is the shape now — a non-16:9 poster
                    // crops (Contain's letterbox bars read as breakage).
                    .child(img(png).w_full().h_full().object_fit(ObjectFit::Cover))
                    .child(
                        div()
                            .absolute()
                            .inset_0()
                            .flex()
                            .items_center()
                            .justify_center()
                            .text_size(px(30.0))
                            .child(play_mark(30.0)),
                    ),
            )
            .into_any_element(),
        None => frame
            .child(
                div()
                    .size_full()
                    .flex()
                    .items_center()
                    .justify_center()
                    .child(play_mark(24.0)),
            )
            .into_any_element(),
    }
}

/// The NIP-A0 voice row (#52): waveform bars, the duration, and the play
/// controls — all theme chrome (audio paints no frames, so there is no
/// element swap like the video tile's; the row is the control). The bars
/// ride the author's imeta waveform when it rode along, else a
/// deterministic pattern hashed from the URL (the seg_id discipline: same
/// URL, same shape every frame). The whole row is the toggle; ✕ and ↗ are
/// sealed against it like the video controls.
fn audio_row(url: &str, duration: Option<f64>, waveform: Option<&[u32]>) -> AnyElement {
    let playing_now = crate::audio::playing(url);
    let bar_color = if playing_now {
        theme::vermilion()
    } else {
        theme::muted()
    };

    // The bars: the author's amplitudes, downsampled to at most 40 (the
    // NIP says <100 values is plenty — 40 stays legible at row height),
    // 2-18px on the 0-100 amplitude. The fallback hashes the URL into the
    // same shape (a voice note whose imeta never arrived still reads as
    // audio, not as a dead link).
    let bars: Vec<f32> = match waveform {
        Some(w) if !w.is_empty() => {
            let step = w.len().div_ceil(40);
            (0..w.len())
                .step_by(step)
                .map(|i| 2.0 + (w[i].min(100) as f32 / 100.0) * 16.0)
                .collect()
        }
        _ => {
            let mut h: u32 = 0x811c9dc5;
            for b in url.as_bytes() {
                h = h.wrapping_mul(0x01000193).wrapping_add(*b as u32);
            }
            (0..32)
                .map(|i| {
                    h = h
                        .wrapping_mul(0x01000193)
                        .wrapping_add(0x9e37_79b9 + i as u32);
                    2.0 + (h % 100) as f32 / 100.0 * 16.0
                })
                .collect()
        }
    };

    // The duration label: m:ss from the imeta seconds (absent = no label;
    // the browser link still answers "how long").
    let label = duration.map(|d| {
        let d = d.round() as u64;
        format!("{}:{:02}", d / 60, d % 60)
    });

    let row_url = url.to_string();
    let browser_url = url.to_string();
    let mut row =
        div()
            .id(seg_id("audio-row", url))
            .cursor_pointer()
            .w_full()
            .flex()
            .items_center()
            .gap_3()
            .px_3()
            .py_2()
            .rounded(px(theme::R_EMBED))
            .border_1()
            .border_color(rgb(theme::hairline()))
            .bg(rgb(theme::panel()))
            .on_click(move |_, _, cx| {
                cx.stop_propagation();
                crate::audio::open(row_url.clone(), cx);
            })
            .child(div().flex().items_end().gap(px(2.0)).h(px(18.0)).children(
                bars.into_iter().map(|h| {
                    div()
                        .w(px(3.0))
                        .h(px(h))
                        .rounded(px(1.5))
                        .bg(rgb(bar_color))
                }),
            ))
            .when_some(label, |d, l| {
                d.child(
                    div()
                        .text_size(px(theme::T_SMALL))
                        .text_color(rgb(theme::muted()))
                        .child(l),
                )
            });
    if crate::audio::active(url) {
        // The live row's extras: pause-and-listen stays, the ✕ hands back
        // the quiet waveform (the video controls' shape).
        row = row.child(
            div()
                .id(seg_id("audio-close", url))
                .cursor_pointer()
                .text_size(px(theme::T_UI))
                .text_color(rgb(theme::muted()))
                .hover(|s| s.text_color(rgb(theme::ink())))
                .on_click(|_, _, cx| {
                    cx.stop_propagation();
                    crate::audio::close(cx);
                })
                .child("✕"),
        );
    }
    row = row.child(
        div()
            .id(seg_id("audio-browser", url))
            .cursor_pointer()
            .text_size(px(theme::T_UI))
            .text_color(rgb(theme::muted()))
            .hover(|s| s.text_color(rgb(theme::ink())))
            .on_click(move |_, _, cx| {
                cx.stop_propagation();
                if web_url(&browser_url) {
                    cx.open_url(&browser_url);
                }
            })
            .child("↗"),
    );
    row.into_any_element()
}

/// The gallery section: single image sized by its dim aspect (media_picture:
/// height = width·h/w clamped to 560), several images as a horizontal strip
/// (cards.rs gallery), every tile opening the lightbox.
pub(crate) fn media_section<V: EventEmitter<Nav> + 'static>(
    assets: &[MediaAsset],
    dims: &HashMap<String, Option<(u32, u32)>>,
    alts: &HashMap<String, String>,
    ctx: &Body,
    handle: &Entity<V>,
) -> Option<AnyElement> {
    // Pictures vanish when their fetch failed (media.rs remembers); videos
    // never do — a failed poster degrades to the quiet play-row.
    let visible: Vec<MediaAsset> = assets
        .iter()
        .filter(|a| match a {
            MediaAsset::Picture { url } => !ctx.media.not_media(url),
            MediaAsset::Video { .. } => true,
            MediaAsset::Audio { .. } => true,
        })
        .cloned()
        .collect();
    if visible.is_empty() {
        return None;
    }

    // The lightbox walks pictures only.
    let pictures: Vec<String> = visible
        .iter()
        .filter_map(|a| match a {
            MediaAsset::Picture { url } => Some(url.clone()),
            MediaAsset::Video { .. } | MediaAsset::Audio { .. } => None,
        })
        .collect();

    if visible.len() == 1 {
        // Height from the item's true aspect at full card width (~COL_W
        // minus card padding): imeta dim when the author sent one, otherwise
        // the decoded size once the fetch lands. Only an item we've never
        // seen wears the provisional box (ObjectFit::Contain letterboxes it
        // until the aspect arrives with the bytes).
        let width = COL_W - 32.0;
        let height = |url: &str, poster: Option<&str>, provisional: f32| {
            // The imeta dim (describes the video) first, then the poster's
            // landed size, then the sniffed frame's (same key the tile
            // paints) — the provisional box wears otherwise.
            let aspect = dims
                .get(url)
                .copied()
                .flatten()
                .filter(|(w, _)| *w > 0)
                .or_else(|| poster.and_then(|p| ctx.media.size(p)))
                .or_else(|| ctx.media.size(&crate::poster::poster_key(url)));
            aspect.map_or(provisional, |(w, h)| {
                if w > 0 {
                    (width * h as f32 / w as f32).clamp(80.0, 560.0)
                } else {
                    provisional
                }
            })
        };
        return Some(match &visible[0] {
            MediaAsset::Picture { url } => media_tile(
                url,
                None,
                height(url, None, 360.0),
                pictures,
                0,
                alts.get(url).map(|s| s.as_str()),
                ctx,
                handle,
            )
            .into_any_element(),
            MediaAsset::Video {
                url,
                poster,
                blurhash,
                mime,
            } => video_tile(
                url,
                poster.as_deref(),
                blurhash.as_deref(),
                mime.as_deref(),
                None,
                height(url, poster.as_deref(), 360.0),
                ctx,
            )
            .into_any_element(),
            MediaAsset::Audio {
                url,
                duration,
                waveform,
                ..
            } => audio_row(url, *duration, waveform.as_deref()).into_any_element(),
        });
    }

    // Multi-image (NIP-68 multi-imeta): a carousel, not a strip — one
    // image at a time with ‹ › arrows and position dots (dark-wisp
    // MediaCarousel; the strip hid every picture after the first). The
    // selection is a STATE CHANGE, not an animation (§3) — reduced motion
    // is honored by construction, there is nothing to reduce. Keyboard:
    // a click/Enter on the image opens the lightbox, whose arrow keys
    // walk the same set.
    let pictures_only = visible
        .iter()
        .all(|a| matches!(a, MediaAsset::Picture { .. }));
    if pictures_only && visible.len() > 1 {
        let urls: Vec<String> = visible
            .iter()
            .filter_map(|a| match a {
                MediaAsset::Picture { url } => Some(url.clone()),
                _ => None,
            })
            .collect();
        return Some(carousel(&urls, alts, pictures, ctx, handle).into_any_element());
    }

    let id = seg_id(
        "strip",
        &visible
            .iter()
            .map(|a| a.url())
            .collect::<Vec<_>>()
            .join("|"),
    );
    let mut strip = div().id(id).w_full().overflow_x_scroll().flex().gap_2();
    let mut pic_idx = 0;
    for asset in visible {
        match asset {
            MediaAsset::Picture { url } => {
                let aspect = dim_or(ctx.media, &url, dims.get(&url).copied().flatten());
                let height = aspect.map_or(480.0, |(w, h)| {
                    if w > 0 {
                        (560.0 * h as f32 / w as f32).clamp(240.0, 480.0)
                    } else {
                        480.0
                    }
                });
                strip = strip.child(media_tile(
                    &url,
                    Some(560.0),
                    height,
                    pictures.clone(),
                    pic_idx,
                    alts.get(&url).map(|s| s.as_str()),
                    ctx,
                    handle,
                ));
                pic_idx += 1;
            }
            MediaAsset::Video {
                url,
                poster,
                blurhash,
                mime,
            } => {
                // The imeta dim describes the video itself; the poster
                // (when there is one) shares its aspect, as does the
                // sniffed frame.
                let aspect = dims
                    .get(&url)
                    .copied()
                    .flatten()
                    .filter(|d| d.0 > 0)
                    .or_else(|| poster.as_deref().and_then(|p| ctx.media.size(p)))
                    .or_else(|| ctx.media.size(&crate::poster::poster_key(&url)));
                let height = aspect.map_or(480.0, |(w, h)| {
                    if w > 0 {
                        (560.0 * h as f32 / w as f32).clamp(240.0, 480.0)
                    } else {
                        480.0
                    }
                });
                strip = strip.child(video_tile(
                    &url,
                    poster.as_deref(),
                    blurhash.as_deref(),
                    mime.as_deref(),
                    Some(560.0),
                    height,
                    ctx,
                ));
            }
            MediaAsset::Audio {
                url,
                duration,
                waveform,
                ..
            } => {
                strip = strip.child(audio_row(&url, duration, waveform.as_deref()));
            }
        }
    }
    Some(strip.into_any_element())
}

/// The frame aspect for a media url: the author's imeta dim first, the
/// decoded size once the bytes land, else nothing yet.
fn dim_or(media: &media::Snapshot, url: &str, dim: Option<(u32, u32)>) -> Option<(u32, u32)> {
    match dim {
        Some(d) if d.0 > 0 => Some(d),
        _ => media.size(url).filter(|d| d.0 > 0),
    }
}

/// One gallery tile: the picture when the shared cache has it, a quiet
/// loading frame otherwise; click opens the lightbox at this index. `w`:
/// `None` fills the column, `Some(px)` fixes a strip-tile width. `alt`:
/// the NIP-68 imeta alt — an "ALT" badge rides the frame's corner
/// (dark-wisp AltTextBadge; quiet, on hairline, never a vermilion seal).
#[allow(clippy::too_many_arguments)]
fn media_tile<V: EventEmitter<Nav> + 'static>(
    url: &str,
    w: Option<f32>,
    h: f32,
    lightbox: Vec<String>,
    idx: usize,
    alt: Option<&str>,
    ctx: &Body,
    handle: &Entity<V>,
) -> AnyElement {
    let handle = handle.clone();
    let frame = div()
        .id(seg_id("media", url))
        .cursor_pointer()
        .flex_none()
        .overflow_hidden()
        .rounded(px(theme::R_EMBED))
        .border_1()
        .border_color(rgb(theme::hairline()))
        .bg(rgb(theme::panel()))
        .map(|d| match w {
            Some(w) => d.w(px(w)),
            None => d.w_full(),
        })
        .h(px(h))
        .on_click(move |_, _, cx| {
            cx.stop_propagation();
            handle.update(cx, |_, cx| {
                cx.emit(Nav::OpenLightbox(lightbox.clone(), idx))
            });
        });
    let frame = match ctx.media.png(url) {
        // Contain, not Cover: the whole picture shows (the quiet panel frame
        // letterboxes); full size is the lightbox's job.
        Some(png) => frame.child(img(png).w_full().h_full().object_fit(ObjectFit::Contain)),
        None => frame.child(
            div()
                .size_full()
                .flex()
                .items_center()
                .justify_center()
                .text_size(px(theme::T_SMALL))
                .text_color(rgb(theme::muted()))
                .child("…"),
        ),
    };
    match alt {
        Some(_) => frame
            .child(
                div()
                    .absolute()
                    .left_2()
                    .bottom_2()
                    .px_1()
                    .rounded(px(theme::R_EMBED))
                    .bg(rgb(theme::washi()))
                    .border_1()
                    .border_color(rgb(theme::hairline()))
                    .text_size(px(theme::T_SMALL))
                    .text_color(rgb(theme::muted()))
                    .child("ALT"),
            )
            .into_any_element(),
        None => frame.into_any_element(),
    }
}

// --- the multi-image carousel (dark-wisp MediaCarousel) ---------------------

/// Per-carousel selection, keyed by the carousel's seg id — a cx-less
/// static map (the theme.rs/timefmt.rs split, media_urls_cached's bound):
/// the state IS the map. The wake-up rides the host entity's notify (the
/// handle media_section already carries), so no view needs to observe a
/// global and feed.rs stays untouched. Bounded, oldest-dropped.
fn sel_map() -> &'static std::sync::Mutex<HashMap<String, usize>> {
    static SEL: std::sync::OnceLock<std::sync::Mutex<HashMap<String, usize>>> =
        std::sync::OnceLock::new();
    SEL.get_or_init(|| std::sync::Mutex::new(HashMap::new()))
}

fn carousel_sel(id: &str, n: usize) -> usize {
    let map = sel_map().lock().unwrap();
    map.get(id).copied().unwrap_or(0).min(n.saturating_sub(1))
}

fn carousel_step<V: 'static>(
    id: &str,
    n: usize,
    delta: i64,
    handle: &Entity<V>,
    cx: &mut gpui::App,
) {
    {
        let mut map = sel_map().lock().unwrap();
        if map.len() >= 4096 && !map.contains_key(id) {
            let oldest = map.keys().next().cloned();
            if let Some(k) = oldest {
                map.remove(&k);
            }
        }
        let cur = map.get(id).copied().unwrap_or(0).min(n.saturating_sub(1)) as i64;
        // Wrap-around: past the last image, the first — a carousel, not a list.
        let next = ((cur + delta).rem_euclid(n as i64)) as usize;
        map.insert(id.to_string(), next);
    }
    handle.update(cx, |_, cx| cx.notify());
}

/// Keyboard path for the carousel (the feed's ←/→, via the shell's key
/// handler → feed.rs carousel_nav): the cursor row's multi-image
/// selection steps exactly as its ‹ › arrows do. The seg id is
/// re-derived the way media_section paints the carousel (media_assets →
/// the not_media screen → the joined picture urls), so the keys hit the
/// live selection; a row without a carousel answers false and the shell
/// ignores the key. No wake-up here — the caller owns the entity and
/// notifies it (it IS the view being updated).
pub fn carousel_key_step(ev: &Event, media: &media::Snapshot, delta: i64) -> bool {
    let urls: Vec<String> = media_assets(ev)
        .iter()
        .filter_map(|a| match a {
            MediaAsset::Picture { url } if !media.not_media(url) => Some(url.clone()),
            _ => None,
        })
        .collect();
    if urls.len() < 2 {
        return false;
    }
    let n = urls.len();
    let key = seg_id("car", &urls.join("|"));
    let mut map = sel_map().lock().unwrap();
    let cur = map.get(key.as_ref()).copied().unwrap_or(0).min(n - 1) as i64;
    // Same wrap-around as carousel_step: past the last image, the first.
    let next = ((cur + delta).rem_euclid(n as i64)) as usize;
    map.insert(key.to_string(), next);
    true
}

/// The carousel frame: one image at a time (full column width, the
/// single-tile aspect math), ‹ › arrows, position dots. Pure state —
/// no slide, no fade (§3: a state appears; it does not travel).
fn carousel<V: EventEmitter<Nav> + 'static>(
    urls: &[String],
    alts: &HashMap<String, String>,
    lightbox: Vec<String>,
    ctx: &Body,
    handle: &Entity<V>,
) -> AnyElement {
    let n = urls.len();
    let key = seg_id("car", &urls.join("|"));
    let idx = carousel_sel(&key, n);
    let url = &urls[idx];
    let width = COL_W - 32.0;
    // The visible image keeps the single-tile aspect discipline.
    let aspect = dim_or(ctx.media, url, None);
    let height = aspect.map_or(480.0, |(w, h)| {
        if w > 0 {
            (width * h as f32 / w as f32).clamp(240.0, 480.0)
        } else {
            480.0
        }
    });
    let handle_cl = handle.clone();
    let mk_arrow = |which: &str, label: &'static str, delta: i64| {
        let key = key.clone();
        let handle = handle_cl.clone();
        div()
            .id(SharedString::from(format!("{key}-{which}")))
            .cursor_pointer()
            .px_2()
            .rounded(px(theme::R_EMBED))
            .border_1()
            .border_color(rgb(theme::hairline()))
            .text_size(px(theme::T_UI))
            .text_color(rgb(theme::muted()))
            .hover(|s| s.text_color(rgb(theme::ink())))
            .on_click(move |_, _, cx| {
                // The feed wraps the whole note body in click-to-open-thread;
                // the arrows are their own affordance (media_tile's discipline).
                cx.stop_propagation();
                carousel_step(&key, n, delta, &handle, cx)
            })
            .child(label)
    };
    div()
        .w_full()
        .flex()
        .flex_col()
        .gap_1()
        .child(media_tile(
            url,
            None,
            height,
            lightbox,
            idx,
            alts.get(url).map(|s| s.as_str()),
            ctx,
            handle,
        ))
        .child(
            div()
                .w_full()
                .flex()
                .items_center()
                .justify_center()
                .gap_2()
                .child(mk_arrow("prev", "‹", -1))
                .child(
                    div()
                        .flex()
                        .gap_1()
                        .items_center()
                        .children(urls.iter().enumerate().map(|(i, _)| {
                            let key = key.clone();
                            let handle = handle_cl.clone();
                            div()
                                .id(SharedString::from(format!("{key}-dot-{i}")))
                                .cursor_pointer()
                                .size(px(6.))
                                .rounded_full()
                                .bg(rgb(if i == idx {
                                    theme::ink()
                                } else {
                                    theme::hairline()
                                }))
                                .on_click(move |_, _, cx| {
                                    cx.stop_propagation();
                                    carousel_step(&key, n, i as i64 - idx as i64, &handle, cx)
                                })
                        })),
                )
                .child(mk_arrow("next", "›", 1)),
        )
        .into_any_element()
}

/// Compact embed card for quotes: left rule, name + time + clamped text
/// (embed_card; the GTK thumbnail is skipped — the text carries it in P2).
fn embed_card<V: EventEmitter<Nav> + 'static>(
    bech: &str,
    e: &Embed,
    handle: Entity<V>,
) -> AnyElement {
    let id = e.event.id;
    // The preview reads as text only — URLs never do (a raw blossom link
    // used to leak into the serif line as “https//…” noise; core's
    // plain_snippet drops them the way the whisper does).
    let text = satori_core::manager::plain_snippet(&e.event.content, 160);
    div()
        .id(seg_id("embed", bech))
        .cursor_pointer()
        .w_full()
        .flex()
        .flex_col()
        .gap_1()
        .pl_3()
        .py_1()
        .border_l_2()
        .border_color(rgb(theme::hairline()))
        .hover(|s| s.border_color(rgb(theme::vermilion())))
        .on_click(move |_, _, cx| {
            cx.stop_propagation();
            handle.update(cx, |_, cx| cx.emit(Nav::OpenThread(id)))
        })
        .child(
            div()
                .flex()
                .items_baseline()
                .gap_2()
                .child(
                    div()
                        .text_size(px(theme::T_SMALL))
                        .font_weight(FontWeight::SEMIBOLD)
                        .text_color(rgb(theme::ink()))
                        .child(e.name.clone()),
                )
                .child(
                    div()
                        .text_size(px(theme::T_SMALL))
                        .text_color(rgb(theme::muted()))
                        // Mode-aware without a cx (no bridge on embed
                        // paths): date mode shows dates, block keeps
                        // relative.
                        .child(crate::timefmt::stamp_text(e.event.created_at.as_secs())),
                ),
        )
        .child(
            div()
                .font_family(theme::SERIF)
                .text_size(px(theme::T_BODY))
                .text_color(rgb(theme::muted()))
                .child(text),
        )
        .into_any_element()
}

/// Compact note card shared by the notifications and search panes: avatar,
/// name, time, word-flow body; the author row opens the profile, the body
/// opens the thread (the GTK panes re-use the full note card — the desktop
/// keeps them lighter: no action glyphs on secondary surfaces).
#[allow(clippy::too_many_arguments)]
pub(crate) fn compact_card<V: EventEmitter<Nav> + 'static>(
    idx: usize,
    tag: &str,
    ev: &Event,
    profiles: &HashMap<String, Profile>,
    media: &media::Snapshot,
    quotes: &Quotes,
    time: String,
    handle: Entity<V>,
) -> AnyElement {
    let key = ev.pubkey.to_string();
    let name = display_name(profiles.get(&key), &key);
    let picture = profiles
        .get(&key)
        .map(|p| p.picture.clone())
        .unwrap_or_default();
    let ev_for_open = ev.clone();
    let ev_for_profile = ev.clone();
    let handle_open = handle.clone();
    let handle_profile = handle.clone();
    let ctx = Body {
        media,
        quotes,
        profiles,
        emoji: body_parse(ev).emoji.clone(),
    };

    div()
        .w_full()
        .flex()
        .flex_col()
        .gap_2()
        .px_4()
        .py_3()
        .child(
            div()
                .flex()
                .items_center()
                .gap_2()
                .child(media::avatar(media, &picture, &name, 28.0))
                .child(
                    div()
                        .id(SharedString::from(format!("{tag}-author-{idx}")))
                        .cursor_pointer()
                        .flex_1()
                        .text_size(px(theme::T_UI))
                        .font_weight(FontWeight::SEMIBOLD)
                        .text_color(rgb(theme::ink()))
                        .on_click(move |_, _, cx| {
                            let ev = ev_for_profile.clone();
                            handle_profile.update(cx, |_, cx| cx.emit(Nav::OpenProfile(ev.pubkey)));
                        })
                        .child(name),
                )
                .child(
                    div()
                        .flex()
                        .items_center()
                        .gap_1()
                        .child(copy_seal(
                            &format!("{tag}-{idx}"),
                            satori_core::nip::nip19::uri(ev),
                        ))
                        // The timestamp is the third mode toggle (timefmt.rs):
                        // tap cycles relative → date → block height.
                        .child(time_toggle(
                            SharedString::from(format!("{tag}-time-{idx}")),
                            time,
                        )),
                ),
        )
        .child(
            div()
                .id(SharedString::from(format!("{tag}-open-{idx}")))
                .cursor_pointer()
                .on_click(move |_, _, cx| {
                    let ev = ev_for_open.clone();
                    handle_open.update(cx, |_, cx| {
                        // A NIP-22 comment notifies about someone else's
                        // note — the interesting thread is the parent's
                        // (comment.rs parse_refs: lowercase e = parent).
                        let target = if u16::from(ev.kind) == 1111 {
                            match satori_core::nip::comment::parse_refs(&ev).parent {
                                Some(satori_core::nip::comment::Ref::Event(id)) => id,
                                _ => ev.id,
                            }
                        } else {
                            ev.id
                        };
                        cx.emit(Nav::OpenThread(target));
                    });
                })
                .child(body(ev, &ctx, handle)),
        )
        .into_any_element()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An extension-less blossom URL alone on a line classifies as a
    /// picture (the byte-sniff fallback path), so the gallery section
    /// claims it instead of the text flow.
    #[test]
    fn standalone_blossom_link_classifies_as_picture() {
        let keys = Keys::generate();
        let unsigned = UnsignedEvent::new(
            keys.public_key(),
            Timestamp::from_secs(1),
            Kind::TextNote,
            [],
            "nostr:npub1fa05cayzx9xze32d2nhxnp7vhf42mkvpf9zr8xa9keq35tlrps5q7k0z97\nhttps://logen.btcforplebs.com/584dbd0e64cf17d19e4838c10ec22482495e61b52705029a263b8f85168f9048",
        );
        let ev = keys.sign_event(unsigned).unwrap();
        let assets = media_assets(&ev);
        let urls: Vec<&str> = assets.iter().map(|a| a.url()).collect();
        assert_eq!(
            urls,
            vec![
                "https://logen.btcforplebs.com/584dbd0e64cf17d19e4838c10ec22482495e61b52705029a263b8f85168f9048"
            ]
        );
        assert!(matches!(assets[0], MediaAsset::Picture { .. }));
    }

    /// Fixture gate (D59) for the voice rider (#52): a NIP-A0 root voice
    /// message the way the NIP's own example publishes it — kind 1222,
    /// content the audio URL, one imeta with `waveform` (space-separated
    /// ints) and `duration`, and NO `m` attribute inside a video-shaped
    /// .mp4 extension. The kind decides: the asset is Audio with the
    /// metadata parsed, never a video tile.
    #[test]
    fn voice_note_fixture_classifies_as_audio() {
        let keys = Keys::generate();
        let unsigned = UnsignedEvent::new(
            keys.public_key(),
            Timestamp::from_secs(1_752_501_052),
            Kind::Custom(1222),
            [Tag::custom(
                "imeta",
                [
                    "url https://blossom.primal.net/5fe7df0e46ee6b14b5a8b8b92939e84e3ca5e3950eb630299742325d5ed9891b.mp4",
                    "waveform 0 7 35 8 100 100 49 8 4 16 8 10 7 2 20 10 100 100 100 100",
                    "duration 8",
                ],
            )],
            "https://blossom.primal.net/5fe7df0e46ee6b14b5a8b8b92939e84e3ca5e3950eb630299742325d5ed9891b.mp4",
        );
        let ev = keys.sign_event(unsigned).unwrap();
        let assets = media_assets(&ev);
        assert_eq!(assets.len(), 1, "the content URL folds into one row");
        let MediaAsset::Audio {
            duration, waveform, ..
        } = &assets[0]
        else {
            panic!("a 1222 must classify as audio");
        };
        assert_eq!(duration.map(|d| d.round() as u64), Some(8));
        assert_eq!(waveform.as_deref().map(|w| w.len()), Some(20));
        assert_eq!(waveform.as_deref().unwrap()[2], 35);

        // The same payload without ANY imeta: the content URL still
        // renders as audio (the fallback rule).
        let bare_keys = Keys::generate();
        let bare = bare_keys
            .sign_event(UnsignedEvent::new(
                bare_keys.public_key(),
                Timestamp::from_secs(1),
                Kind::Custom(1222),
                [],
                "https://cdn.example.com/voice.m4a",
            ))
            .unwrap();
        let assets = media_assets(&bare);
        assert!(matches!(assets[0], MediaAsset::Audio { .. }));

        // A non-voice note with the same .mp4 imeta stays VIDEO (the ext
        // decides when the kind does not).
        let video_keys = Keys::generate();
        let video = video_keys
            .sign_event(UnsignedEvent::new(
                video_keys.public_key(),
                Timestamp::from_secs(1),
                Kind::Custom(20),
                [Tag::custom(
                    "imeta",
                    ["url https://cdn.example.com/clip.mp4", "m video/mp4"],
                )],
                "caption",
            ))
            .unwrap();
        assert!(matches!(media_assets(&video)[0], MediaAsset::Video { .. }));

        // A plain note's standalone audio link (an .ogg) renders the voice
        // row too — attachments beyond the NIP-A0 kinds.
        let ogg_keys = Keys::generate();
        let ogg = ogg_keys
            .sign_event(UnsignedEvent::new(
                ogg_keys.public_key(),
                Timestamp::from_secs(1),
                Kind::TextNote,
                [],
                "https://cdn.example.com/song.ogg",
            ))
            .unwrap();
        assert!(matches!(media_assets(&ogg)[0], MediaAsset::Audio { .. }));
    }

    #[test]
    fn emoji_shortcode_is_bare_colon_wrapped() {
        assert_eq!(emoji_shortcode(":sox:"), Some("sox".into()));
        assert_eq!(emoji_shortcode(":sox"), None);
        assert_eq!(emoji_shortcode("sox:"), None);
        assert_eq!(emoji_shortcode("::"), None);
        assert_eq!(
            emoji_shortcode(":a:b:"),
            None,
            "inner colon is not one code"
        );
        assert_eq!(emoji_shortcode(":so x:"), None);
        // Mid-text tokens arrive word-split, so punctuation hugs fail the
        // bare shape (NIP-30 shortcodes are whitespace-delimited).
        assert_eq!(emoji_shortcode("(:sox:)"), None);
    }

    #[test]
    fn emoji_urls_ride_the_fetch_list_but_not_the_gallery() {
        let keys = Keys::generate();
        let unsigned = UnsignedEvent::new(
            keys.public_key(),
            Timestamp::from_secs(1),
            Kind::TextNote,
            [Tag::custom(
                "emoji",
                ["sox".to_string(), "https://a/sox.png".to_string()],
            )],
            "hi :sox:",
        );
        let ev = keys.sign_event(unsigned).unwrap();
        // The sweep fetches it...
        assert!(media_urls(&ev).contains(&"https://a/sox.png".to_string()));
        // ...the gallery never tiles it...
        assert!(media_assets(&ev).is_empty());
        // ...and the body's map resolves the code.
        assert_eq!(
            emoji_map(&ev).get("sox").map(String::as_str),
            Some("https://a/sox.png")
        );
    }
}

#[cfg(test)]
mod og_tests {
    use super::*;

    fn ev_with(content: &str) -> Event {
        let keys = Keys::generate();
        let unsigned = UnsignedEvent::new(
            keys.public_key(),
            Timestamp::from_secs(1),
            Kind::TextNote,
            [],
            content,
        );
        keys.sign_event(unsigned).unwrap()
    }

    #[test]
    fn candidate_is_first_plain_link_stripped() {
        let ev = ev_with("look at https://ex.com/p?utm_source=x&id=9 and prose");
        assert_eq!(
            og_candidate(&ev, &[]).as_deref(),
            Some("https://ex.com/p?id=9")
        );

        // First link wins; later links never shadow it.
        let ev = ev_with("https://a.ex/one https://b.ex/two");
        assert_eq!(og_candidate(&ev, &[]).as_deref(), Some("https://a.ex/one"));
    }

    #[test]
    fn candidate_skips_media_links_and_youtube() {
        // An imeta picture URL is a tile already — not a card.
        let ev = ev_with("https://img.ex/pic.jpg");
        assert_eq!(og_candidate(&ev, &["https://img.ex/pic.jpg".into()]), None);

        // YouTube links: the deterministic thumbnail tile covers them; a
        // page fetch is a Google contact the facade never makes.
        let ev = ev_with("https://www.youtube.com/watch?v=dQw4w9WgXcQ");
        assert_eq!(og_candidate(&ev, &[]), None);
    }

    #[test]
    fn candidate_skips_non_web_urls() {
        // web_url gate: anything beyond http(s) never becomes a card
        // (the M2 allow-list).
        assert_eq!(
            og_candidate(&ev_with("file:///etc/passwd"), &[]),
            None,
            "non-http(s) is not even a candidate"
        );
    }

    /// The owner's failing note (nevent 501aac5f…): prose line, then the
    /// URL alone on the next line.
    #[test]
    fn candidate_littles_law_note() {
        let ev = ev_with(
            "I'm going to apply Little's Law to ephemeral storage. \nhttps://en.wikipedia.org/wiki/Little%27s_law",
        );
        assert_eq!(
            og_candidate(&ev, &[]).as_deref(),
            Some("https://en.wikipedia.org/wiki/Little%27s_law")
        );
    }

    /// Content that embeds serialized-event JSON: the URL token carries
    /// mid-token garbage (`","m`, `","created_at":…`). A quote is illegal
    /// in a URL, so the candidate ends at the first one — and an imeta
    /// picture inside that JSON now matches the media-link skip instead
    /// of becoming a broken card.
    #[test]
    fn candidate_cuts_json_embedded_tokens() {
        let (core, punct) = split_trailing("https://blossom.primal.net/3fbe956e.jpg\",\"m");
        assert_eq!(core, "https://blossom.primal.net/3fbe956e.jpg");
        assert_eq!(punct, "");
        assert_eq!(
            split_trailing("https://kuroshio.monster/\",\"created_at\":1794723232").0,
            "https://kuroshio.monster/"
        );
        assert_eq!(
            split_trailing("https://ex.com/a?utm_source=x\"}").0,
            "https://ex.com/a?utm_source=x"
        );
    }

    /// End to end: a JSON-embedded note (broken client) whose picture URL
    /// now matches the media-link skip after the cut, with a real link
    /// after it still winning the card.
    #[test]
    fn candidate_json_embedded_note_skips_media_finds_link() {
        let ev = ev_with(
            "{\"imeta\":[\"url https://blossom.primal.net/3fbe956e.jpg\",\"m image/jpeg\"]} https://real.example/page",
        );
        let media = vec!["https://blossom.primal.net/3fbe956e.jpg".to_string()];
        assert_eq!(
            og_candidate(&ev, &media).as_deref(),
            Some("https://real.example/page")
        );
    }

    /// The owner's reported note (92fa6a05…): an App Store link alone on
    /// its last line. Extension-less paths (`/app/centimeters/id6832626453`)
    /// are WEB PAGES, not blob bytes — they must never be claimed as
    /// picture tiles (which suppressed the card).
    #[test]
    fn candidate_app_store_link_is_not_a_picture() {
        let ev = ev_with("scan your room\n\nhttps://apps.apple.com/app/centimeters/id6832626453");
        let assets = media_assets(&ev);
        assert!(
            assets.is_empty(),
            "an app-store page is not a media tile: {assets:?}"
        );
        assert_eq!(
            og_candidate(&ev, &[]).as_deref(),
            Some("https://apps.apple.com/app/centimeters/id6832626453")
        );
    }

    /// Same shape: a wiki slug (Little%27s_law) is a page, not bytes.
    #[test]
    fn candidate_wiki_slug_is_not_a_picture() {
        let ev = ev_with("https://en.wikipedia.org/wiki/Little%27s_law");
        assert!(media_assets(&ev).is_empty());
        assert_eq!(
            og_candidate(&ev, &[]).as_deref(),
            Some("https://en.wikipedia.org/wiki/Little%27s_law")
        );
    }

    /// The blossom shape still rides the byte-sniff fallback: a 64-hex
    /// path segment IS a blob address.
    #[test]
    fn blossom_blob_url_still_classifies_as_picture() {
        let ev = ev_with(
            "https://logen.btcforplebs.com/584dbd0e64cf17d19e4838c10ec22482495e61b52705029a263b8f85168f9048",
        );
        let assets = media_assets(&ev);
        assert!(matches!(assets[0], MediaAsset::Picture { .. }));
        // And a blob never becomes an og candidate: the real path hands
        // the candidate pass the media links it came from, and it's in
        // there (the skip list is what protects it).
        let media: Vec<String> = assets.iter().map(|a| a.url().to_string()).collect();
        assert_eq!(og_candidate(&ev, &media), None);
    }

    /// Direct media files inline in prose: no og card is possible (no
    /// HTML, no metadata) — the candidate pass refuses them instead of
    /// burning a NotMedia round trip.
    #[test]
    fn candidate_skips_direct_media_extensions() {
        let ev = ev_with("look https://ex.com/photo.png and https://ex.com/clip.mp4");
        assert_eq!(og_candidate(&ev, &[]), None);
    }
}
