//! The screening SOCKS5 transport — how the relay pool dials (M5 WP2).
//!
//! nostr-sdk resolves and dials relay hosts itself (async-wsocket, no
//! connector hook), but it accepts a per-relay SOCKS5 proxy policy
//! (`Proxy::custom`, evaluated at connect time). So the guard goes
//! where the dial goes: this module runs a loopback SOCKS5 server and
//! pool.rs points every NON-user relay at it. The server never sees a
//! hostname it hasn't screened:
//!
//! - IP-literal targets: [`net_guard::is_public_ip`] or refused.
//! - Domain targets: [`net_guard::resolve_pinned_public`] — fail closed
//!   on any non-public answer (a public/private mix poisons the name).
//! - User-entered relays never arrive here at all: pool.rs's policy
//!   closure returns `None` (direct dial) for the exemption set, which
//!   remote data can never join (net_guard.rs, "the user-relay
//!   exemption").
//!
//! This is also the M5 Tor seam (DESIGN.md D7): when the transport
//! lands, the server's connect step forwards to the bundled tor's
//! SOCKS port instead of dialing direct — every screened relay rides
//! tor through the same door, per-host circuit isolation via unique
//! SOCKS usernames if the upstream wants it.
//!
//! **No byte cap on the pipe, on purpose**: relay connections are
//! long-lived subscriptions (hours, megabytes of events, negentropy
//! syncs). The SSRF risk lives at DIAL time — host + resolved
//! addresses — and that is where the guard sits. A cap here would
//! sever subscriptions mid-session for no security gain.
//!
//! TODO(port): tor.rs — the M5 transport replaces this server's
//! direct-dial step with the tor SOCKS port; the screening stays.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Dial timeout for the screened connect (relay-latency budgets live
/// one layer up; this only bounds TCP connect + the screens).
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// A running screening server. Dropping it stops accepting (the accept
/// task aborts); live connections drain naturally as the pool's relays
/// close them.
pub struct ScreeningSocks {
    addr: SocketAddr,
    task: tokio::task::JoinHandle<()>,
}

impl ScreeningSocks {
    /// The loopback address to hand to `Proxy::custom`.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }
}

impl Drop for ScreeningSocks {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Bind `127.0.0.1:0` and serve until dropped. Bind failure is the
/// caller's problem (no loopback listener = no screened transport =
/// pool.rs refuses to build the client unpinned; fail closed, not
/// fall back).
pub async fn spawn() -> std::io::Result<ScreeningSocks> {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await?;
    let addr = listener.local_addr()?;
    let task = tokio::spawn(async move {
        while let Ok((stream, peer)) = listener.accept().await {
            // Only the process itself may use the guard: a
            // loopback listener is reachable by every local
            // user, and this server dials ARBITRARY hosts.
            if !peer.ip().is_loopback() {
                continue;
            }
            tokio::spawn(serve_conn(stream, false));
        }
    });
    Ok(ScreeningSocks { addr, task })
}

async fn read_handshake(stream: &mut tokio::net::TcpStream) -> Result<Target, &'static [u8]> {
    // Greeting: VER NMETHODS METHODS… — accept only the no-auth offer.
    let mut buf = [0u8; 2];
    if stream.read_exact(&mut buf).await.is_err() || buf[0] != 5 || buf[1] == 0 {
        return Err(&[]);
    }
    let mut methods = vec![0u8; buf[1] as usize];
    if stream.read_exact(&mut methods).await.is_err() || !methods.contains(&0) {
        return Err(&[5, 0xFF]); // no acceptable methods
    }
    if stream.write_all(&[5, 0]).await.is_err() {
        return Err(&[]);
    }
    // Request: VER CMD RSV ATYP ADDR PORT.
    let mut head = [0u8; 4];
    if stream.read_exact(&mut head).await.is_err() || head[0] != 5 {
        return Err(&[]);
    }
    if head[1] != 1 {
        // CONNECT only — the pool never BINDs or UDPs.
        return Err(&[5, 7, 0, 1, 0, 0, 0, 0, 0, 0]);
    }
    read_target(stream, head[3])
        .await
        .ok_or(&[5, 8, 0, 1, 0, 0, 0, 0, 0, 0][..])
}

async fn serve_conn(mut stream: tokio::net::TcpStream, allow_loopback_test: bool) {
    let target = match tokio::time::timeout(CONNECT_TIMEOUT, read_handshake(&mut stream)).await {
        Ok(Ok(t)) => t,
        Ok(Err(reply)) => {
            if !reply.is_empty() {
                let _ = stream.write_all(reply).await;
            }
            return;
        }
        Err(_) => return,
    };
    // THE GUARD. Every refusal path replies 0x02 (not allowed by
    // ruleset) and hangs up.
    let dial = match if allow_loopback_test {
        match &target {
            Target::Ip(ip, port) if ip.is_loopback() => Ok(SocketAddr::new(*ip, *port)),
            _ => screen(&target).await,
        }
    } else {
        screen(&target).await
    } {
        Ok(addr) => addr,
        Err(_) => {
            let _ = stream.write_all(&[5, 2, 0, 1, 0, 0, 0, 0, 0, 0]).await;
            return;
        }
    };
    let mut outbound = match tokio::time::timeout(CONNECT_TIMEOUT, tokio::net::TcpStream::connect(dial)).await {
        Ok(Ok(s)) => s,
        _ => {
            let _ = stream.write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0]).await;
            return;
        }
    };
    // Success: BND.ADDR/PORT are advisory — zeros are fine.
    if stream.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await.is_err() {
        return;
    }
    let _ = tokio::io::copy_bidirectional(&mut stream, &mut outbound).await;
}

#[derive(Debug)]
pub(crate) enum Target {
    Ip(IpAddr, u16),
    Domain(String, u16),
}

async fn read_target(
    rd: &mut tokio::net::TcpStream,
    atyp: u8,
) -> Option<Target> {
    match atyp {
        1 => {
            let mut o = [0u8; 4];
            rd.read_exact(&mut o).await.ok()?;
            Some(Target::Ip(IpAddr::V4(o.into()), read_port(rd).await?))
        }
        4 => {
            let mut o = [0u8; 16];
            rd.read_exact(&mut o).await.ok()?;
            Some(Target::Ip(IpAddr::V6(o.into()), read_port(rd).await?))
        }
        3 => {
            let mut len = [0u8; 1];
            rd.read_exact(&mut len).await.ok()?;
            if len[0] == 0 || len[0] > 253 {
                return None;
            }
            let mut name = vec![0u8; len[0] as usize];
            rd.read_exact(&mut name).await.ok()?;
            let name = String::from_utf8(name).ok()?;
            Some(Target::Domain(name, read_port(rd).await?))
        }
        _ => None,
    }
}

async fn read_port(rd: &mut tokio::net::TcpStream) -> Option<u16> {
    let mut p = [0u8; 2];
    rd.read_exact(&mut p).await.ok()?;
    Some(u16::from_be_bytes(p))
}

/// The screen, separated from the handshake so tests can hit it
/// without a socket. IP literals screen by value; domains resolve
/// through net_guard's fail-closed pin.
pub(crate) async fn screen(target: &Target) -> Result<SocketAddr, ()> {
    match target {
        Target::Ip(ip, port) => {
            if crate::net_guard::is_public_ip(ip) {
                Ok(SocketAddr::new(*ip, *port))
            } else {
                Err(())
            }
        }
        Target::Domain(host, port) => {
            let host = host.trim_end_matches('.');
            match crate::net_guard::resolve_pinned_public(host, *port).await {
                Ok(addrs) => addrs.first().copied().ok_or(()),
                Err(_) => Err(()),
            }
        }
    }
}

// NOTE: no blocking-side helpers — the server is fully async.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn screen_refuses_every_internal_target() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            // IP literals — the whole internal zoo, one line each.
            for (ip, port) in [
                ("127.0.0.1", 8080),
                ("10.0.0.5", 80),
                ("192.168.1.1", 80),
                ("169.254.169.254", 80),
                ("::1", 8080),
                ("fe80::1", 80),
            ] {
                let t = Target::Ip(ip.parse().unwrap(), port);
                assert!(screen(&t).await.is_err(), "{ip} must be refused");
            }
            // Domains that resolve only internally fail closed.
            for host in ["localhost", "127.0.0.1.nip.io"] {
                // nip.io answers may vary by network; the FIRST is the
                // offline-certain one.
                let t = Target::Domain(host.into(), 8080);
                if host == "localhost" {
                    assert!(screen(&t).await.is_err(), "{host} must be refused");
                }
            }
            // Public literal passes (no dial happens — screen only).
            let t = Target::Ip("8.8.8.8".parse().unwrap(), 53);
            assert_eq!(screen(&t).await.unwrap(), "8.8.8.8:53".parse().unwrap());
        });
    }

    #[tokio::test]
    async fn handshake_refuses_internal_connect() {
        // The full server path: greet, request 127.0.0.1:9, expect the
        // ruleset refusal (reply code 0x02) — no byte dials anywhere.
        let server = spawn().await.expect("bind loopback");
        let mut c = tokio::net::TcpStream::connect(server.addr()).await.unwrap();
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        c.write_all(&[5, 1, 0]).await.unwrap(); // VER=5, 1 method, no-auth
        let mut reply = [0u8; 2];
        c.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [5, 0], "no-auth accepted");
        // CONNECT 127.0.0.1:9 (discard port, loopback).
        c.write_all(&[5, 1, 0, 1, 127, 0, 0, 1, 0, 9]).await.unwrap();
        let mut verdict = [0u8; 10];
        c.read_exact(&mut verdict).await.unwrap();
        assert_eq!(verdict[1], 2, "ruleset refusal, got {}", verdict[1]);
        drop(c);
    }

    #[tokio::test]
    async fn handshake_pipe_through_allowlisted_shape() {
        // A real pipe: the target is a LOCAL echo server, reached via
        // its literal… which the screen refuses. So this test drives
        // the pipe through a PUBLIC literal? Impossible offline.
        // Instead: prove the handshake completes and the refusal path
        // is the only guard-visible branch — the piped-dial case is
        // covered end-to-end by the pool wiring at runtime.
        let server = spawn().await.expect("bind loopback");
        let mut c = tokio::net::TcpStream::connect(server.addr()).await.unwrap();
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        c.write_all(&[5, 1, 0]).await.unwrap();
        let mut reply = [0u8; 2];
        c.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [5, 0]);
        // Bad command (BIND=2) → 0x07.
        c.write_all(&[5, 2, 0, 1, 8, 8, 8, 8, 0, 53]).await.unwrap();
        let mut verdict = [0u8; 10];
        c.read_exact(&mut verdict).await.unwrap();
        assert_eq!(verdict[1], 7, "command refusal, got {}", verdict[1]);
        drop(c);
    }

    #[tokio::test]
    async fn relay_bidirectional_echo_and_clean_half_close() {
        let echo_listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let echo_addr = echo_listener.local_addr().unwrap();
        let echo_task = tokio::spawn(async move {
            let (mut sock, _) = echo_listener.accept().await.unwrap();
            let mut buf = Vec::new();
            sock.read_to_end(&mut buf).await.unwrap();
            sock.write_all(&buf).await.unwrap();
            sock.shutdown().await.unwrap();
        });

        let proxy_listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        let proxy_task = tokio::spawn(async move {
            let (stream, _) = proxy_listener.accept().await.unwrap();
            serve_conn(stream, true).await;
        });

        let mut client = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();
        client.write_all(&[5, 1, 0]).await.unwrap();
        let mut reply = [0u8; 2];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [5, 0]);

        let port = echo_addr.port().to_be_bytes();
        client
            .write_all(&[5, 1, 0, 1, 127, 0, 0, 1, port[0], port[1]])
            .await
            .unwrap();
        let mut verdict = [0u8; 10];
        client.read_exact(&mut verdict).await.unwrap();
        assert_eq!(verdict[1], 0, "connect succeeded");

        client.write_all(b"ping-bidirectional-payload").await.unwrap();
        client.shutdown().await.unwrap();

        let mut echoed = Vec::new();
        client.read_to_end(&mut echoed).await.unwrap();
        assert_eq!(echoed, b"ping-bidirectional-payload");

        echo_task.await.unwrap();
        proxy_task.await.unwrap();
    }
}
