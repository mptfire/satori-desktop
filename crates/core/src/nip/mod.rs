//! Thin NIP implementations not covered by the rust-nostr workspace
//! (DESIGN.md §6.2). Mostly tag/parse/render semantics — no protocol risk.
//!
//! | module | NIP |
//! |---|---|
//! | `article` | 23 — long-form metadata |
//! | `comment` | 22 — generic comments (kind 1111) |
//! | `imeta` | 68/71/92 — media metadata |
//! | `poll` | 88 — poll options + tally |
//! | `calendar` | 52 — calendar events + RSVP addressing |
//! | `highlight` | 84 — highlight quotes |
//! | `classified` | 99 — classified listings |
//! | `podcast` | F4 — podcast episodes |
//! | `wiki` | 54 — wiki topics (AsciiDoc subset) |
//! | `repo` | 34 — git repositories |
//! | `nip78` | 78 — app data (encrypted prefs sync) |
//! | `nip19` | 19 — bech32 entities (the shareable nevent/naddr) |
//!
//! NIP-96 stays rejected; Blossom only (matches the web app).

pub mod article;
pub mod calendar;
pub mod classified;
pub mod comment;
pub mod fields;
pub mod goal;
pub mod highlight;
pub mod imeta;
pub mod nip10;
pub mod nip19;
pub mod nip78;
pub mod podcast;
pub mod poll;
pub mod repo;
pub mod wiki;
