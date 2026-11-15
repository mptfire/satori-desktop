//! Read-only NIP-65 and notification provenance inspection.
//! Run with Satori stopped. Prints relay URLs and event/tag relationships,
//! not note contents, signer secrets, or credentials.

use std::collections::{HashMap, HashSet};

use nostr::prelude::*;
use nostr_database::NostrDatabase;
use nostr_lmdb::NostrLmdb;
use satori_core::config;
use satori_core::nip::{comment, nip10};
use satori_core::outbox;

#[tokio::main]
async fn main() {
    let session: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(config::state_file(config::files::SESSION))
            .expect("read local session"),
    )
    .expect("parse local session");
    let me = PublicKey::parse(session["pubkey"].as_str().expect("public session key"))
        .expect("valid session key");
    let db = NostrLmdb::open(config::events_dir())
        .await
        .expect("open read-only inspection");

    let relays = db
        .query(Filter::new().kind(Kind::RelayList).author(me).limit(1))
        .await
        .expect("read NIP-65")
        .into_iter()
        .collect::<Vec<_>>();
    if relays.is_empty() {
        println!("NIP-65: no latest list in the local store");
    } else {
        let list = outbox::parse_relay_list(&relays[0]);
        println!("NIP-65 event: {}", relays[0].id);
        println!("Read relays ({}):", list.read.len());
        for relay in &list.read {
            println!("  {relay}");
        }
        println!("Write relays ({}):", list.write.len());
        for relay in &list.write {
            println!("  {relay}");
        }
        for candidate in [
            "umbrel",
            "umbrel.local",
            "192.168.8.179",
            "4848",
            "100.78.120.44",
        ] {
            println!(
                "Local-relay candidate '{candidate}': read={} write={}",
                list.read.iter().any(|u| u.contains(candidate)),
                list.write.iter().any(|u| u.contains(candidate))
            );
        }
    }

    // This deliberately samples, not a full notification/archive dump.
    let own_notes: Vec<Event> = db
        .query(Filter::new().authors([me]).limit(500))
        .await
        .expect("query own notes")
        .into_iter()
        .collect();
    let own_ids: HashSet<EventId> = own_notes.iter().map(|e| e.id).collect();
    let mentioned: Vec<Event> = db
        .query(
            Filter::new()
                .kinds([Kind::TextNote, Kind::Custom(1111)])
                .pubkeys([me])
                .limit(150),
        )
        .await
        .expect("query #p mentioning events")
        .into_iter()
        .collect();
    let candidates: Vec<Event> = mentioned.into_iter().filter(|e| e.pubkey != me).collect();
    println!(
        "\nForeign notification candidates sampled: {}",
        candidates.len()
    );

    let mut referenced_ids: HashSet<EventId> = HashSet::new();
    for event in &candidates {
        reference(event).map(|(id, _)| referenced_ids.insert(id));
        nip10::reply_root(event)
            .and_then(|(id, _)| EventId::from_hex(&id).ok())
            .map(|id| referenced_ids.insert(id));
    }
    let mut parents: HashMap<EventId, PublicKey> = HashMap::new();
    for id in referenced_ids {
        if let Some(ev) = db
            .query(Filter::new().id(id))
            .await
            .expect("query referenced event")
            .first()
            .cloned()
        {
            parents.insert(id, ev.pubkey);
        }
    }

    let mut counts = HashMap::new();
    for event in &candidates {
        let kind = u16::from(event.kind);
        let relative = |key: &str, p: PublicKey| {
            if p == me {
                format!("{key}=self")
            } else {
                format!("{key}=other")
            }
        };
        let parent = reference(event)
            .map(|(id, _)| {
                parents
                    .get(&id)
                    .map(|a| relative("parent", *a))
                    .unwrap_or_else(|| "parent=not_cached".to_string())
            })
            .unwrap_or_else(|| "none".to_string());
        let root = nip10::reply_root(event)
            .and_then(|(id, _)| EventId::from_hex(&id).ok())
            .map(|id| {
                parents
                    .get(&id)
                    .map(|a| relative("root", *a))
                    .unwrap_or_else(|| "root=not_cached".to_string())
            })
            .unwrap_or_else(|| "root=none".to_string());
        let own_direct = match kind {
            1 => reference(event).is_some_and(|(id, _)| own_ids.contains(&id)),
            1111 => reference(event).is_some_and(|(id, _)| own_ids.contains(&id)),
            _ => false,
        };
        let direct = reference(event).and_then(|(id, _)| parents.get(&id).copied());
        let classification = if own_direct {
            "direct-id=own"
        } else if direct == Some(me) {
            "parent-author=self (own note outside last-500-id set)"
        } else if reference(event).is_some() {
            "ancestor-or-thread reference, not direct to own note"
        } else {
            "mention without event parent"
        };
        *counts
            .entry(format!("kind={kind}, {parent}, {root}, {classification}"))
            .or_insert(0usize) += 1;
        println!(
            "event={} kind={} {classification} {parent} {root} own_last500={}",
            &event.id.to_string()[..16],
            kind,
            own_ids.contains(&event.id)
        );
    }
    println!("\nProvenance summary (no note content):");
    for (key, n) in counts {
        println!("  {n} {key}");
    }
}

fn reference(event: &Event) -> Option<(EventId, String)> {
    if u16::from(event.kind) == 1111 {
        match comment::parse_refs(event).parent {
            Some(comment::Ref::Event(id)) => Some((id, "NIP-22-e".into())),
            Some(comment::Ref::Address { .. }) => None,
            Some(comment::Ref::Url(_)) => None,
            None => None,
        }
    } else {
        nip10::reply_parent(event)
            .and_then(|(hex, _)| EventId::from_hex(&hex).ok())
            .map(|id| (id, "NIP-10-parent".into()))
    }
}
