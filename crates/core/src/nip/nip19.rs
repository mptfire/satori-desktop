//! NIP-19 entity encoding — the shareable bech32 id of an event.
//!
//! The copy affordance on a note's timestamp (and anywhere else a note id
//! is worth handing off) needs the entity OTHER clients can open: nevent1
//! for regular events, naddr1 for addressable ones (the d-tag is part of
//! the coordinate), with the seen-on relays and the author riding along
//! as fetch hints (NIP-19 §Encrypted Payloads — receivers use them to
//! fetch the note without a full blast).

use nostr::prelude::*;

use crate::seen_event;

/// The note's NIP-21 URI (`nostr:nevent1…` / `nostr:naddr1…`) — the form
/// a paste lands as a clickable reference everywhere.
pub fn uri(ev: &Event) -> String {
    format!("nostr:{}", entity(ev))
}

/// The bare bech32 entity for `ev`: naddr for addressable kinds (the
/// coordinate is the identity — the d-tag, not the id), nevent otherwise.
/// Fallback to the raw hex if bech32 ever fails (it can't in practice;
/// the honest string beats a panic on the render path).
pub fn entity(ev: &Event) -> String {
    let relays: Vec<RelayUrl> = seen_event::for_event(&ev.id)
        .iter()
        .filter_map(|r| r.parse().ok())
        .collect();
    let bech = if ev.kind.is_addressable() || ev.kind.is_replaceable() {
        Nip19::Coordinate(Nip19Coordinate {
            coordinate: Coordinate {
                kind: ev.kind,
                public_key: ev.pubkey,
                identifier: ev.tags.identifier().unwrap_or_default(),
            },
            relays,
        })
        .to_bech32()
    } else {
        Nip19::Event(Nip19Event {
            event_id: ev.id,
            author: Some(ev.pubkey),
            kind: Some(ev.kind),
            relays,
        })
        .to_bech32()
    };
    bech.unwrap_or_else(|_| ev.id.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_env::EnvGuard;

    fn note() -> Event {
        let keys = Keys::generate();
        EventBuilder::new(Kind::TextNote, "the body")
            .finalize(&keys)
            .unwrap()
    }

    #[test]
    fn regular_note_encodes_as_nevent() {
        let _env = EnvGuard::new("nip19-nevent");
        let ev = note();
        let u = uri(&ev);
        assert!(u.starts_with("nostr:nevent1"), "{u}");
        // Round-trip: the entity decodes back to the same event id + author.
        let Nip19::Event(e) = Nip19::from_bech32(u.strip_prefix("nostr:").unwrap()).unwrap() else {
            panic!("not an nevent");
        };
        assert_eq!(e.event_id, ev.id);
        assert_eq!(e.author, Some(ev.pubkey));
    }

    #[test]
    fn article_encodes_as_naddr() {
        let _env = EnvGuard::new("nip19-naddr");
        let keys = Keys::generate();
        let ev = EventBuilder::new(Kind::LongFormTextNote, "the article")
            .tag(Tag::identifier("the-slug"))
            .finalize(&keys)
            .unwrap();
        let u = uri(&ev);
        assert!(u.starts_with("nostr:naddr1"), "{u}");
        let Nip19::Coordinate(c) = Nip19::from_bech32(u.strip_prefix("nostr:").unwrap()).unwrap()
        else {
            panic!("not an naddr");
        };
        assert_eq!(c.coordinate.identifier, "the-slug");
        assert_eq!(c.coordinate.public_key, ev.pubkey);
    }
}
