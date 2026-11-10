//! Relay capability memory (NIP-11 Relay Information Documents): what each
//! relay ADVERTISES it can do, fetched with `Accept: application/nostr+json`
//! and cached in a sidecar so capability-dependent surfaces can whisper
//! "this relay can't do X" honestly (0.2-research deficiency 9 — search.rs's
//! NIP-50 note generalized; the retired webapp's relay-info.ts).
//!
//! Honesty rules: absence of a document (never fetched, fetch failed, or a
//! non-NIP-11 answer) is UNKNOWN (`Option::None`), never "unsupported" — a
//! relay that doesn't describe itself is not accused of anything. Only
//! advertised limitations are stored, and only what we actually consume
//! today: `limitation.search` (NIP-50). Persisted (0600 temp+rename, the
//! D33 sidecar discipline — capabilities are static, so the write is
//! write-through on each fetch, rare by construction: TTL-gated sweeps).

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

/// A capability document outlives a session (relay metadata changes in
/// human time); the refresher re-asks after a week.
const TTL_SECS: u64 = 7 * 24 * 3600;
/// Per-relay fetch budget: a relay that doesn't answer its own HTTP
/// description is treated as unknown, not dead (its websocket health is
/// relay_latency.rs's business, not ours).
const FETCH_BUDGET: std::time::Duration = std::time::Duration::from_secs(8);

/// One relay's remembered capabilities. `search: None` = unknown.
#[derive(Debug, Clone)]
pub struct RelayCaps {
    pub url: String,
    /// NIP-11 `limitation.search` — the relay says it serves NIP-50
    /// `search` filters.
    pub search: Option<bool>,
    /// When the document was fetched (epoch secs; 0 = pre-sidecar entry).
    pub at: u64,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
struct Entry {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    search: Option<bool>,
    #[serde(default)]
    at: u64,
}

static MAP: OnceLock<Mutex<HashMap<String, Entry>>> = OnceLock::new();

fn map() -> &'static Mutex<HashMap<String, Entry>> {
    MAP.get_or_init(|| {
        let raw = std::fs::read_to_string(crate::config::state_file(crate::config::files::RELAY_INFO))
            .unwrap_or_default();
        let parsed: HashMap<String, Entry> = serde_json::from_str(&raw).unwrap_or_default();
        Mutex::new(parsed)
    })
}

fn write_disk(map: &HashMap<String, Entry>) {
    let path = crate::config::state_file(crate::config::files::RELAY_INFO);
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    let tmp = path.with_extension(format!("tmp-{}-{nanos}", std::process::id()));
    let body = match serde_json::to_string(map) {
        Ok(b) => b,
        Err(_) => return,
    };
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt;
    let Ok(mut f) = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)
    else {
        return;
    };
    if f.write_all(body.as_bytes()).is_ok() {
        drop(f);
        let _ = std::fs::rename(&tmp, &path);
    } else {
        let _ = std::fs::remove_file(&tmp);
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Snapshot of every remembered relay, unordered (the manager's free
/// accessor hands it to capability-dependent surfaces).
pub fn snapshot() -> Vec<RelayCaps> {
    let held = map().lock().unwrap();
    held.iter()
        .map(|(url, e)| RelayCaps { url: url.clone(), search: e.search, at: e.at })
        .collect()
}

/// The advertised NIP-50 search support for one relay (None = unknown).
pub fn search(relay: &str) -> Option<bool> {
    let held = map().lock().unwrap();
    held.get(&crate::outbox::relay_key(relay)).and_then(|e| e.search)
}

/// Fetch one relay's document and remember `limitation.search`. Any
/// failure (no answer, non-JSON, hostile size) leaves the entry unknown —
/// a relay that won't describe itself is not described by us. Returns
/// whether a fresh document landed.
pub async fn refresh(relay: &str) -> bool {
    // wss://host/path → https://host/path (NIP-11 is plain HTTPS).
    let url = if let Some(rest) = relay.strip_prefix("wss://") {
        format!("https://{rest}")
    } else if let Some(rest) = relay.strip_prefix("ws://") {
        format!("http://{rest}")
    } else {
        return false;
    };
    let url = url.trim_end_matches('/').to_string();
    // media::client() rides the guarded fetch (SafeResolver, redirect
    // re-validation). Its longer connect/total timeouts never come into
    // play: the outer FETCH_BUDGET still bounds the whole request at 8s.
    let req = crate::media::client()
        .get(&url)
        .header("Accept", "application/nostr+json");
    let res = match tokio::time::timeout(FETCH_BUDGET, req.send()).await {
        Ok(Ok(res)) => res,
        _ => return false,
    };
    if !res.status().is_success() {
        return false;
    }
    // Relay documents are small; refuse to read more than a sane body.
    // read_capped STREAMS the cap: a declared-length lie dies up-front,
    // and a chunked (undeclared) response is cut mid-stream instead of
    // being read whole and measured after.
    const CAP: usize = 256 * 1024;
    let body = match crate::media::read_capped(res, CAP).await {
        Ok(b) => b,
        Err(_) => return false,
    };
    let doc: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(d) => d,
        Err(_) => return false,
    };
    let search = doc
        .get("limitation")
        .and_then(|l| l.get("search"))
        .and_then(|v| v.as_bool());
    let key = crate::outbox::relay_key(relay);
    let mut held = map().lock().unwrap();
    held.insert(key, Entry { search, at: now_secs() });
    write_disk(&held);
    true
}

/// TTL-gated sweep over a whole relay set (the read set connects → the
/// manager spawns this): relays fetched inside the TTL are skipped, the
/// rest are asked concurrently. A relay that answers keeps its new
/// document; one that doesn't keeps the old (until the next sweep).
pub async fn refresh_stale(relays: &[String]) {
    let now = now_secs();
    let stale: Vec<String> = {
        let held = map().lock().unwrap();
        relays
            .iter()
            .filter(|u| {
                held.get(&crate::outbox::relay_key(u))
                    .is_none_or(|e| now.saturating_sub(e.at) > TTL_SECS)
            })
            .cloned()
            .collect()
    };
    if stale.is_empty() {
        return;
    }
    let sweeps = stale.iter().map(|u| refresh(u));
    let _ = futures_util::future::join_all(sweeps).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_env::EnvGuard;

    #[test]
    fn unknown_stays_unknown_and_snapshot_roundtrips() {
        let _env = EnvGuard::new("nip11-caps");
        // Never fetched: unknown, not unsupported.
        assert_eq!(search("wss://quiet.example"), None);
        // A stored entry round-trips through snapshot().
        let key = crate::outbox::relay_key("wss://r.example");
        map().lock().unwrap().insert(
            key,
            Entry { search: Some(true), at: now_secs() },
        );
        assert_eq!(search("wss://r.example"), Some(true));
        let snap = snapshot();
        let hit = snap.iter().find(|c| c.url == "wss://r.example").unwrap();
        assert_eq!(hit.search, Some(true));
        assert!(hit.at > 0);
    }

    #[test]
    fn refresh_rejects_non_ws_urls_without_network() {
        let _env = EnvGuard::new("nip11-refresh");
        // Not a websocket url → no document, no entry, no panic.
        assert!(!tokio::runtime::Runtime::new().unwrap().block_on(refresh("https://x.example")));
        assert_eq!(search("https://x.example"), None);
    }
}
