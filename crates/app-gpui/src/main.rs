//! Satori's GPUI front-end (D13). One window, sumi-e ink on washi, driven by
//! the untouched `crates/core`.
//!
//! NOTE: shares the LMDB store with the GTK app — run one at a time until P4.

mod audio;
mod desktop;
mod emoji;
mod icons;
mod input;
mod markdown;
mod media;
mod media_guard;
mod og;
mod poster;
mod prefs;
mod theme;
mod timefmt;
mod uris;
mod video;
mod views;

use std::sync::Arc;

use gpui::{
    App, Application, Bounds, Context, Entity, Render, WindowBounds, WindowOptions, div,
    prelude::*, px, size,
};
use satori_core::manager::{Core, FeedEvent};

use crate::{
    input::bind_input_keys,
    uris::{Instance, UriTarget, uri_target},
    views::{
        composer::bind_composer_keys,
        login::{Login, LoginView},
        shell::{Shell, ShellEvent},
    },
};

/// The window root: the login doors until a session exists, then the shell.
/// The swap happens on Login::Approved — the shell focuses itself on first
/// render (shell.rs focused_once).
struct Root {
    core: Arc<Core>,
    login: Option<Entity<LoginView>>,
    shell: Option<Entity<Shell>>,
    /// A `nostr:` URI that arrived before there was a shell to open it in
    /// (pre-login click-through, or argv on a fresh machine) — parked here
    /// until Approved, then routed (NIP-21 seam).
    pending: Option<UriTarget>,
}

impl Root {
    fn new(
        core: Arc<Core>,
        session: bool,
        resume_error: Option<String>,
        argv_uri: Option<String>,
        uri_rx: Option<tokio::sync::mpsc::UnboundedReceiver<String>>,
        cx: &mut Context<Self>,
    ) -> Self {
        let (login, shell) = match session {
            true => {
                let shell = cx.new(|cx| Shell::new(core.clone(), cx));
                Self::watch_shell(shell.clone(), cx);
                (None, Some(shell))
            }
            false => {
                // Resume failures surface on the doors — the user must know
                // why they're back here (login.rs set_resume_error).
                (
                    Some(cx.new(|cx| LoginView::new(core.clone(), resume_error, cx))),
                    None,
                )
            }
        };
        if let Some(login) = login.clone() {
            Self::watch_login(&login, cx);
        }
        // The single-instance socket pump: forwarded URIs (and bare
        // "activate" pings) arrive here on a tokio channel and route into
        // whatever the window is showing.
        if let Some(mut rx) = uri_rx {
            cx.spawn(async move |this, cx| {
                while let Some(uri) = rx.recv().await {
                    let _ = this.update(cx, |root, cx| root.route(&uri, cx));
                    // A URI arriving from outside should raise the window.
                    cx.update(|app| app.activate(true));
                }
            })
            .detach();
        }
        let mut root = Self {
            core,
            login,
            shell,
            pending: None,
        };
        // argv on a resumed session routes immediately; pre-login it parks.
        if let Some(uri) = argv_uri {
            root.route(&uri, cx);
        }
        root
    }

    /// A `nostr:` URI arrived (socket or argv): parse and route.
    fn route(&mut self, uri: &str, cx: &mut Context<Self>) {
        match uri_target(uri) {
            Some(t) => self.route_target(t, cx),
            None => eprintln!("[satori-gpui] ignored unhandled URI: {uri:.80}"),
        }
    }

    fn route_target(&mut self, target: UriTarget, cx: &mut Context<Self>) {
        let Some(shell) = self.shell.clone() else {
            self.pending = Some(target);
            return;
        };
        match target {
            UriTarget::Thread(id) => shell.update(cx, |s, cx| s.open_thread(id, cx)),
            UriTarget::Profile(who) => shell.update(cx, |s, cx| s.open_profile(who, cx)),
            UriTarget::Article {
                kind,
                author,
                identifier,
            } => {
                // naddr: resolve against relays first (newest wins, NIP-01
                // addressable semantics), then open what came back — an
                // article for 30023, the thread containing it for anything
                // else that resolved.
                let mut rx = self.core.event_by_address(kind, author, identifier);
                let shell2 = shell.clone();
                cx.spawn(async move |_, cx| {
                    let Some(FeedEvent::One(Some(ev), _)) = rx.recv().await else {
                        return;
                    };
                    if u16::from(ev.kind) == 30023 {
                        shell2.update(cx, |s, cx| s.open_article(ev, cx));
                    } else {
                        shell2.update(cx, |s, cx| s.open_thread(ev.id, cx));
                    }
                })
                .detach();
            }
        }
    }

    /// Login-to-root subscription: the approved login swaps the window to
    /// the shell. Attached per login view — sign-out builds a new one, so
    /// the attachment must be born with it (a startup-only subscribe is
    /// what stranded every post-sign-out login on the doors).
    fn watch_login(login: &Entity<LoginView>, cx: &mut Context<Self>) {
        cx.subscribe(login, |this, _, _: &Login, cx| {
            // Stand down any sibling handshake (bunker paste while the QR
            // flow ran): a no-op for the flow that won — pending was cleared
            // via ptr-eq on resolve — and a shutdown for the one that lost,
            // instead of a zombie socket subscribed to 24133 forever.
            this.core.cancel_login();
            this.login = None;
            let shell = cx.new(|cx| Shell::new(this.core.clone(), cx));
            Self::watch_shell(shell.clone(), cx);
            this.shell = Some(shell);
            // A URI clicked while the doors were up opens right after
            // sign-in — same behavior as the session-resume path.
            if let Some(t) = this.pending.take() {
                this.route_target(t, cx);
            }
            cx.notify();
        })
        .detach();
    }

    /// Shell-to-root subscription: sign-out clears the core (done by the
    /// shell before it emits) and the window returns to the login doors.
    fn watch_shell(shell: Entity<Shell>, cx: &mut Context<Self>) {
        cx.subscribe(&shell, |this, _, ev: &ShellEvent, cx| match ev {
            ShellEvent::SignedOut => {
                this.shell = None;
                let login = cx.new(|cx| LoginView::new(this.core.clone(), None, cx));
                // The new doors need their own subscription: without it the
                // next Approved is emitted with no listener and the window
                // sits on the login page forever (the "frozen doors" bug —
                // every login after a sign-out, on any build).
                Self::watch_login(&login, cx);
                this.login = Some(login);
                cx.notify();
            }
        })
        .detach();
    }
}

impl Render for Root {
    fn render(&mut self, _window: &mut gpui::Window, _cx: &mut Context<Self>) -> impl IntoElement {
        if let Some(login) = self.login.clone() {
            login.into_any_element()
        } else if let Some(shell) = self.shell.clone() {
            shell.into_any_element()
        } else {
            div().into_any_element()
        }
    }
}

/// Allocator: mimalloc owns every Rust-side allocation (nostr-sdk serde
/// churn, event deserialization, gpui element trees). glibc's per-thread
/// arenas were the multi-GB RSS source: 37 arenas x ~50MB of freed-but-
/// retained churn after an evening of feed use (audit Nov 2026) — mimalloc
/// keeps per-thread pages compact and hands them back to the OS eagerly.
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

fn main() {
    // The vacuum door (WS3, issue #23): an offline store rebuild, run
    // INSTEAD of the app — two writers on one LMDB is corruption. The
    // rebuild copies every surviving event into a fresh env, verifies
    // the counts, and swaps the directories (details in store::vacuum).
    if std::env::args().any(|arg| arg == "--vacuum") {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("vacuum runtime");
        match rt.block_on(satori_core::store::vacuum()) {
            Ok(report) => {
                println!(
                    "vacuum: {} events rebuilt, data.mdb {:.1} MB -> {:.1} MB",
                    report.events,
                    report.bytes_before as f64 / 1048576.0,
                    report.bytes_after as f64 / 1048576.0
                );
                println!(
                    "the previous store is parked at events.prev; boot Satori once to clear it"
                );
            }
            Err(err) => {
                eprintln!("vacuum failed (the live store is untouched): {err}");
                std::process::exit(1);
            }
        }
        return;
    }
    // The C side (glib, gstreamer, lmdb) keeps glibc malloc: cap its arena
    // count so its retention stays bounded too (default 8x ncores = 96
    // possible 64MB arenas). The malloc_trim loop below keeps cycling it.
    // glibc-only knobs: musl's mallocng hands pages back eagerly and has
    // no arena tunables (the alpine/musl build, issue #23).
    #[cfg(target_env = "gnu")]
    unsafe {
        let _ = libc::mallopt(libc::M_ARENA_MAX, 4);
    }
    // D35/P5: the snapshot moved the platform out of Application::new();
    // the Linux platform (wgpu renderer) comes from gpui_linux.
    Application::with_platform(gpui_linux::current_platform(false)).run(|cx: &mut App| {
        // Return glibc arena heap to the OS on a slow clock. gpui's image
        // work allocates/frees large blocks on many threads; glibc retains
        // the freed arenas (RSS stays at the high-water mark otherwise).
        // malloc_trim(0) walks the arenas and gives the untouched pages
        // back — cheap every 5 minutes, invisible otherwise.
        #[cfg(target_env = "gnu")]
        cx.spawn(async move |cx| {
            loop {
                cx.background_executor()
                    .timer(std::time::Duration::from_secs(300))
                    .await;
                unsafe {
                    libc::malloc_trim(0);
                }
            }
        })
        .detach();
        bind_input_keys(cx);
        bind_composer_keys(cx);
        // Shared decoded-image cache (media.rs) — avatars, tiles and the
        // lightbox all key off it.
        cx.default_global::<media::Cache>();
        // The nsec tripwire's shared alert (input.rs): off until a paste
        // in a tripwired field finds a key.
        cx.set_global(input::NsecWarn(false));
        // The desktop's appearance (portal): the system scheme the `dark:
        // None` pref follows, and the reduced-motion flag the login
        // screen's breathing ensō honors. One blocking round trip, before
        // the first frame.
        let desktop = crate::desktop::probe();
        // Palette before the first frame: the pref wins; unset follows the
        // desktop's color-scheme (falls back to the night paper).
        if let Some(false) = crate::prefs::load().dark.or(desktop.dark) {
            crate::theme::select(crate::theme::LIGHT)
        }
        cx.set_global(desktop);
        let core = Arc::new(Core::new());
        // The suspend watchdog (DESIGN.md §3.4): after sleep/hibernate,
        // reconnect the relays in seconds instead of the SDK's backoff.
        core.spawn_suspend_watchdog();
        // Store retention: prune past-retention events shortly after
        // launch, then daily.
        core.spawn_store_prune();
        // Relay-list refresher: hourly, refetch the follows' stale
        // kind:10002 lists so routed reads heal themselves.
        core.spawn_list_refresher();
        // The blocktime bridge (timefmt.rs): the core handle + ask dedup
        // behind every tappable timestamp, before any window renders.
        crate::timefmt::init(core.clone(), cx);
        let (session, err) = core.init();
        if err.is_some() {
            eprintln!("[satori-gpui] resume error (surfaced on the login doors)");
        }
        // NIP-21 (D25 follow-up): the .desktop handler passes a nostr: URI
        // as argv. Own the single-instance socket first — if another Satori
        // is live, forward the URI to it and exit; never a second window.
        let argv = std::env::args().nth(1).filter(|a| uri_target(a).is_some());
        match uris::acquire(argv.as_deref()) {
            Instance::Forwarded => std::process::exit(0),
            Instance::Primary(uri_rx) => {
                // TODO(port): crates/app/src/shell.rs window geometry + state — P1.
                let bounds = Bounds::centered(None, size(px(460.), px(760.)), cx);
                cx.open_window(
                    WindowOptions {
                        window_bounds: Some(WindowBounds::Windowed(bounds)),
                        titlebar: Some(gpui::TitlebarOptions {
                            title: Some("Satori".into()),
                            ..Default::default()
                        }),
                        // The window's Wayland app_id — byte-identical to the
                        // .desktop file's ID so GNOME matches dash icon, grouping,
                        // and startup notification to this window (D12).
                        app_id: Some(satori_core::config::APP_ID.into()),
                        ..Default::default()
                    },
                    |_window, cx| {
                        let session_ok = session.is_some();
                        cx.new(|cx| Root::new(core, session_ok, err, argv, uri_rx, cx))
                    },
                )
                .expect("failed to open Satori window");
                cx.activate(true);
            }
        }
    });
}
