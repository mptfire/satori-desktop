//! The shared dial guard — one IP authority for every pipeline that
//! resolves and dials (M5: "no byte is fetched by any pipeline we don't
//! pin").
//!
//! Today three surfaces resolve untrusted names: reqwest fetches
//! (media.rs/upload.rs/nip11.rs — all via [`SafeResolver`]), the wss
//! relay pool (socks.rs routes nostr-sdk through the screening SOCKS5
//! server), and — until the range-proxy lands — GStreamer's playbin.
//! The classification rules below are THE rules: one function, so the
//! screens cannot drift apart the way media's `is_global_ip` and
//! outbox's `is_public_ip` had (outbox lacked the documentation,
//! benchmark and 192.0.0.0/24 ranges; the unified ruleset takes the
//! stricter union).
//!
//! Strictness policy (unchanged from media.rs's resolver, Nov 2026):
//! fail closed — a name that resolves to ANY non-public address yields
//! no connectable address, so a public/private mix never dials the
//! private leg.
//!
//! User-entered relays are exempt BY NAME, not by address: the relay
//! allowlist (`allow_direct_relay` / [`user_chosen_relay`]) holds the
//! hosts the user typed into Settings or signed into their own NIP-65
//! — those dial direct (today's behavior, LAN relays included), every
//! other host rides the screening path. Remote kind:10002 lists and
//! learned hints can never join that set.

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::OnceLock;
use std::sync::RwLock;

/// The resolver's address screen: global-reachability, std's `is_global`
/// being feature-gated. Strict side — a block is asserted only when the
/// address is demonstrably NOT global-unreachable (private, loopback,
/// link-local, shared/CGNAT, this-network, benchmark, documentation,
/// reserved/multicast, unspecified; v6: ULA, link-local, multicast,
/// everything outside 2000::/3). A v4-mapped v6 screens through the v4
/// rules (dual-stack dials the embedded v4).
pub fn is_public_unicast_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_multicast()
                || v4.is_unspecified()
                || v4.is_documentation()
                || o[0] == 0 // this-network (0.0.0.0/8)
                || o[0] == 100 // shared address space (CGNAT, 100.64/10)
                || (o[0] == 192 && o[1] == 0 && o[2] == 0) // 192.0.0.0/24
                || (o[0] == 198 && (o[1] == 18 || o[1] == 19)) // 198.18/15 benchmark
                || o[0] >= 240) // reserved + broadcast
        }
        IpAddr::V6(v6) => {
            if v6.is_multicast() || v6.is_loopback() || v6.is_unspecified() {
                return false;
            }
            let s = v6.segments();
            // ::ffff:0:0/96 (v4-mapped) dials the embedded v4 on a
            // dual-stack host — screen THAT address.
            if s[..5] == [0, 0, 0, 0, 0] && s[5] == 0xffff {
                return is_public_unicast_ip(IpAddr::V4(std::net::Ipv4Addr::new(
                    (s[6] >> 8) as u8,
                    s[6] as u8,
                    (s[7] >> 8) as u8,
                    s[7] as u8,
                )));
            }
            // Global unicast lives in 2000::/3; ULA (fc00::/7),
            // link-local (fe80::/10) and everything experimental dies.
            // Transition mechanisms embed IPv4 INSIDE 2000::/3 — screen
            // the embedded leg too, or 64:ff9b::192.0.2.9-style answers
            // ride a NAT64 gateway onto the internal network:
            // - 64:ff9b::/96 (well-known NAT64): v4 in segments 6+7
            // - 2002::/16 (6to4): v4 in segment 1 (hi) + 2 (lo)
            // - 2001::/32 (Teredo): server v4 in segments 2+3, client
            //   v4 obfuscated (XOR 0xffff) in segments 6+7 — screen BOTH
            if s[0] == 0x0064 && s[1] == 0xff9b && s[2] == 0 && s[3] == 0 && s[4] == 0 && s[5] == 0
            {
                return is_public_unicast_ip(IpAddr::V4(std::net::Ipv4Addr::new(
                    (s[6] >> 8) as u8,
                    s[6] as u8,
                    (s[7] >> 8) as u8,
                    s[7] as u8,
                )));
            }
            if s[0] == 0x2002 {
                return is_public_unicast_ip(IpAddr::V4(std::net::Ipv4Addr::new(
                    (s[1] >> 8) as u8,
                    s[1] as u8,
                    (s[2] >> 8) as u8,
                    s[2] as u8,
                )));
            }
            if s[0] == 0x2001 && s[1] == 0 {
                let server = is_public_unicast_ip(IpAddr::V4(std::net::Ipv4Addr::new(
                    (s[2] >> 8) as u8,
                    s[2] as u8,
                    (s[3] >> 8) as u8,
                    s[3] as u8,
                )));
                let client = is_public_unicast_ip(IpAddr::V4(std::net::Ipv4Addr::new(
                    !(s[6] >> 8) as u8,
                    !(s[6] as u8),
                    !(s[7] >> 8) as u8,
                    !(s[7] as u8),
                )));
                return server && client;
            }
            (s[0] & 0xe000) == 0x2000 && !(s[0] == 0x2001 && s[1] == 0x0db8)
        }
    }
}

/// The DNS-rebinding-safe resolver (issue #3 WS4). The URL guard checks
/// HOST STRINGS — `evil.example.com` resolving to 127.0.0.1 sailed past
/// it. reqwest dials WHATEVER its resolver returns, so the check moves
/// to the address list: a name that resolves anywhere non-global yields
/// NO connectable address (fail closed — a public and private mix fails
/// the whole resolution, so no leg of it leaks onto the internal
/// network). Every connection this client opens — first party, every
/// redirect hop, every retry — re-walks here, so a rebinding rotation
/// between hops re-runs the check. TOCTOU-free by construction: the
/// addresses that passed the filter are the addresses hyper dials.
#[derive(Debug)]
pub struct SafeResolver;

impl reqwest::dns::Resolve for SafeResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let host = name.as_str().to_string();
        Box::pin(async move {
            // Port 0: reqwest replaces it with the scheme's conventional
            // port (the trait contract).
            let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host.as_str(), 0))
                .await
                .map_err(std::io::Error::other)?
                .filter(|a| is_public_unicast_ip(a.ip()))
                .collect();
            if addrs.is_empty() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    format!("{host} resolved to no public addresses"),
                )
                .into());
            }
            Ok(Box::new(addrs.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

/// Resolve `(host, port)` and hand back ONLY public-unicast addresses.
/// The relay-pool dial path's front door (socks.rs): same fail-closed
/// mix rule as the resolver — one internal answer poisons the name.
pub async fn resolve_pinned_public(
    host: &str,
    port: u16,
) -> Result<Vec<SocketAddr>, NetGuardError> {
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, port))
        .await
        .map_err(|_| NetGuardError::Resolve(host.to_string()))?
        .collect();
    if addrs.is_empty() {
        return Err(NetGuardError::Resolve(host.to_string()));
    }
    if !addrs.iter().all(|a| is_public_unicast_ip(a.ip())) {
        // Fail closed on the WHOLE name: no partial dials.
        return Err(NetGuardError::NonPublic(host.to_string()));
    }
    Ok(addrs)
}

/// Why a name was refused. `Resolve` is weather (DNS down, no answers);
/// `NonPublic` is the guard speaking (an internal address answered).
#[derive(Debug, PartialEq)]
pub enum NetGuardError {
    Resolve(String),
    NonPublic(String),
}

impl std::fmt::Display for NetGuardError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Resolve(host) => write!(f, "{host}: no answer"),
            Self::NonPublic(host) => {
                write!(f, "{host}: resolved to a non-public address")
            }
        }
    }
}

// --- the user-relay exemption --------------------------------------------

/// Hosts the USER chose (Settings entries, the session's own NIP-65,
/// login-time bunker/wallet relays): dial direct, no screening — the
/// user may deliberately point at a LAN relay (`wss://umbrel.local`,
/// `ws://192.168.1.10:7777`). Remote data (kind:10002s, hints) can
/// never join this set; its members ride the screening path.
fn direct_hosts() -> &'static RwLock<HashSet<String>> {
    static SET: OnceLock<RwLock<HashSet<String>>> = OnceLock::new();
    SET.get_or_init(|| RwLock::new(HashSet::new()))
}

/// Exempt a relay host from the screening path (lowercase host, no
/// port, no trailing dot — `relay_key`-adjacent normalization).
pub fn allow_direct_relay(host: &str) {
    let host = normalize_host(host);
    if host.is_empty() {
        return;
    }
    direct_hosts().write().unwrap().insert(host);
}

/// Drop an exemption (relay retired from the session's lists).
pub fn disallow_direct_relay(host: &str) {
    direct_hosts()
        .write()
        .unwrap()
        .remove(&normalize_host(host));
}

/// Does this relay URL belong to the user-chosen set (direct dial)?
/// Anything NOT in the set must ride the screening transport.
pub fn user_chosen_relay(url: &str) -> bool {
    let Ok(parsed) = url::Url::parse(url) else {
        return false;
    };
    match parsed.host_str() {
        Some(host) => direct_hosts()
            .read()
            .unwrap()
            .contains(&normalize_host(host)),
        None => false,
    }
}

fn normalize_host(host: &str) -> String {
    host.trim()
        .trim_end_matches('.')
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v4_screen() {
        // Public unicast passes.
        assert!(is_public_unicast_ip("8.8.8.8".parse().unwrap()));
        assert!(is_public_unicast_ip("1.1.1.1".parse().unwrap()));
        // Everything the guard exists for dies.
        for bad in [
            "127.0.0.1",       // loopback
            "10.0.0.1",        // RFC1918
            "192.168.1.1",     // RFC1918
            "172.16.0.1",      // RFC1918
            "169.254.169.254", // cloud metadata
            "100.64.0.1",      // CGNAT
            "0.0.0.0",         // this-network
            "192.0.2.1",       // documentation
            "198.18.0.1",      // benchmark
            "224.0.0.1",       // multicast
            "240.0.0.1",       // reserved
            "255.255.255.255", // broadcast
        ] {
            assert!(
                !is_public_unicast_ip(bad.parse().unwrap()),
                "{bad} must be refused"
            );
        }
    }

    #[test]
    fn v6_screen() {
        assert!(is_public_unicast_ip("2606:4700::1111".parse().unwrap()));
        for bad in [
            "::1",              // loopback
            "fe80::1",          // link-local
            "fc00::1",          // ULA
            "ff02::1",          // multicast
            "::ffff:127.0.0.1", // v4-mapped loopback
            "2001:db8::1",      // documentation
            // Transition mechanisms with embedded INTERNAL v4:
            "64:ff9b::192.0.2.9", // NAT64 → TEST-NET-1
            "64:ff9b::127.0.0.1", // NAT64 → loopback
            "2002:7f00:1::1",     // 6to4 → loopback
            "2002:c0a8:101::1",   // 6to4 → 192.168.1.1
            "2001:0:c0a8:101::1", // Teredo server 192.168.1.1
        ] {
            assert!(
                !is_public_unicast_ip(bad.parse().unwrap()),
                "{bad} must be refused"
            );
        }
        // Teredo with an internal CLIENT v4 (obfuscated) also dies —
        // 192.168.1.1 XOR 0xffff = c6:57 → segments 6/7 = 0x39a7,0xfe9f.
        assert!(!is_public_unicast_ip(
            "2001:0:6464:6464:0:0:39a7:fe9f".parse().unwrap()
        ));
        // Transition mechanisms with PUBLIC embedded v4 still pass.
        assert!(is_public_unicast_ip("64:ff9b::8.8.8.8".parse().unwrap()));
        assert!(is_public_unicast_ip("2002:0808:0808::1".parse().unwrap()));
    }

    #[test]
    fn pinned_resolution_fails_closed() {
        // localhost never resolves to a public address — the name is
        // refused outright, whatever the answer list looks like.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let res = resolve_pinned_public("localhost", 8080).await;
            assert!(matches!(
                res,
                Err(NetGuardError::NonPublic(_)) | Err(NetGuardError::Resolve(_))
            ));
        });
    }

    #[test]
    fn user_relay_exemption_roundtrip() {
        let url = "wss://umbrel.local:7777";
        assert!(!user_chosen_relay(url));
        allow_direct_relay("UMBREL.local");
        assert!(user_chosen_relay(url), "normalization folds case");
        disallow_direct_relay("umbrel.local");
        assert!(!user_chosen_relay(url));
        // Garbage URLs are never "user chosen".
        assert!(!user_chosen_relay("not a url"));
    }
}
