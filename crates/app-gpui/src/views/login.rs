//! Login — port of crates/app/src/login.rs (the /login page, minus NIP-07),
//! re-doored per D17: the app never handles the master key. Two doors —
//! bunker:// (paste the URI your signer shows) and nostrconnect:// (the app
//! advertises a QR; the signer scans and approves). The waiting state
//! breathes the ensō at the web app's 3.4s period — or shows the QR when a
//! nostrconnect handshake is live. Success swaps the window root to the
//! shell (main.rs Root).

use std::sync::Arc;

use gpui::{
    Animation, AnimationExt, App, Context, Entity, EventEmitter, FocusHandle, Focusable, Image,
    ImageFormat, KeyDownEvent, Render, TextAlign, Window, div, img, prelude::*, px, rgb,
};
use satori_core::dlog;
use satori_core::manager::{ConnectEvent, ConnectRx, Core};
use std::time::Duration;

use crate::{desktop, icons, input::Input, theme};

/// Login outcome — the root drops the login view and mounts the shell.
pub enum Login {
    Approved,
}

pub struct LoginView {
    core: Arc<Core>,
    bunker: Entity<Input>,
    focus: FocusHandle,
    /// Form, or the waiting page with its status + hint.
    waiting: Option<(String, String)>,
    /// Live nostrconnect handshake: the advertised URI + its QR (rendered
    /// once at Uri, not per frame).
    qr_uri: Option<String>,
    qr: Option<Arc<Image>>,
    /// Click-the-URI-to-copy feedback (brief "Copied" swap).
    copied: bool,
    /// NIP-46 out-of-band approval link (login.rs AuthUrl — GTK printed it
    /// to stderr behind a TODO; here it's a clickable chip).
    auth_url: Option<String>,
    error: String,
    /// The banner's severity: the startup resume notice is a state (amber),
    /// a runtime handshake failure is an error (red). on_event flips this.
    error_is_notice: bool,
    /// Each connect run invalidates the previous pump (same seam as search).
    generation: u64,
    /// A handshake is in flight. Gates the URI strip's click-to-re-arm:
    /// re-arming while a handshake runs bumps the generation, which
    /// silently discards the completed login (session saved core-side
    /// before the UI ever saw Approved) — the quit-and-restart bug.
    connecting: bool,
    autofocused: bool,
}

impl EventEmitter<Login> for LoginView {}

impl Focusable for LoginView {
    fn focus_handle(&self, _cx: &App) -> FocusHandle {
        self.focus.clone()
    }
}

impl LoginView {
    pub fn new(core: Arc<Core>, resume_error: Option<String>, cx: &mut Context<Self>) -> Self {
        crate::theme::watch(cx); // repaint on theme change
        let bunker = cx.new(|cx| {
            let mut i = Input::new(cx);
            i.multiline = false; // Enter submits, no newline
            i.placeholder("bunker://…")
        });
        let focus = bunker.read(cx).focus_handle(cx);
        let resume_notice = resume_error.is_some();
        let mut view = Self {
            core,
            bunker,
            focus,
            waiting: None,
            qr_uri: None,
            qr: None,
            copied: false,
            auth_url: None,
            error: resume_error.unwrap_or_default(),
            error_is_notice: resume_notice,
            generation: 0,
            connecting: false,
            autofocused: false,
        };
        view.start_nostrconnect(cx);
        view
    }

    /// The nostrconnect handshake runs from the moment the doors show —
    /// the QR is form furniture, not a flow you start. A fresh URI per
    /// LoginView (each resume/reject regenerates one).
    fn start_nostrconnect(&mut self, cx: &mut Context<Self>) {
        self.generation += 1;
        let generation = self.generation;
        self.qr_uri = None;
        self.qr = None;
        self.connecting = true;
        let rx = self
            .core
            .connect_nostrconnect("wss://relay.primal.net".into());
        let mut rx = rx;
        dlog!("[login] nostrconnect pump armed (generation {generation})");
        cx.spawn(async move |this, cx| {
            while let Some(ev) = rx.recv().await {
                let again = this
                    .update(cx, |this, cx| this.on_event(ev, generation, cx))
                    .is_ok_and(|more| more);
                if !again {
                    break;
                }
            }
            // Terminal exit (approved, failed, superseded): lift the gate —
            // but only if this pump still owns the handshake.
            let _ = this.update(cx, |this, cx| {
                if this.generation == generation {
                    this.connecting = false;
                    cx.notify();
                }
            });
            dlog!("[login] nostrconnect pump exited (generation {generation})");
        })
        .detach();
    }

    fn begin(&mut self, status: &str, hint: &str, rx: ConnectRx, cx: &mut Context<Self>) {
        self.generation += 1;
        let generation = self.generation;
        self.error.clear();
        self.auth_url = None;
        self.qr_uri = None;
        self.qr = None;
        self.waiting = Some((status.into(), hint.into()));
        self.connecting = true;
        let mut rx = rx;
        cx.spawn(async move |this, cx| {
            while let Some(ev) = rx.recv().await {
                let again = this
                    .update(cx, |this, cx| this.on_event(ev, generation, cx))
                    .is_ok_and(|more| more);
                if !again {
                    break;
                }
            }
            let _ = this.update(cx, |this, cx| {
                if this.generation == generation {
                    this.connecting = false;
                    cx.notify();
                }
            });
            dlog!("[login] bunker pump exited (generation {generation})");
        })
        .detach();
        cx.notify();
    }

    /// Returns false when the flow is over (approved, failed or superseded).
    fn on_event(&mut self, ev: ConnectEvent, generation: u64, cx: &mut Context<Self>) -> bool {
        if generation != self.generation {
            dlog!(
                "[login] event {ev:?} arrived stale (gen {generation} vs {})",
                self.generation
            );
            return false; // superseded by a newer attempt or a cancel
        }
        match ev {
            ConnectEvent::Waiting => {}
            ConnectEvent::AuthUrl(url) => self.auth_url = Some(url),
            ConnectEvent::Uri(uri) => {
                dlog!("[login] uri event, QR refreshed");
                self.qr = qr_image(&uri);
                self.qr_uri = Some(uri);
            }
            ConnectEvent::Approved(_) => {
                dlog!("[login] approved, swapping to the shell");
                cx.emit(Login::Approved);
                return false;
            }
            ConnectEvent::Failed(msg) => {
                dlog!("[login] failed: {msg}");
                self.error = msg;
                self.error_is_notice = false; // a real failure — red banner
                self.waiting = None;
                self.connecting = false;
                // A dead handshake leaves a stale QR on the doors — drop it;
                // the URI strip now reads "generating…" and re-arms on click.
                self.qr_uri = None;
                self.qr = None;
                self.core.cancel_login();
                return false;
            }
        }
        cx.notify();
        true
    }

    fn connect_bunker(&mut self, cx: &mut Context<Self>) {
        let uri = self.bunker.read(cx).content.trim().to_string();
        if uri.is_empty() {
            return;
        }
        let rx = self.core.connect_bunker(uri);
        self.begin(
            "Waiting for approval…",
            "Approve the request in your bunker app.",
            rx,
            cx,
        );
    }

    fn cancel(&mut self, cx: &mut Context<Self>) {
        self.generation += 1; // invalidate the pump: failures stay quiet
        self.core.cancel_login();
        self.connecting = false;
        self.waiting = None;
        self.auth_url = None;
        cx.notify();
    }
}

impl Render for LoginView {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        if !self.autofocused {
            self.autofocused = true;
            window.focus(&self.focus, cx);
        }
        let error = self.error.clone();
        let err_color = if self.error_is_notice {
            theme::warn()
        } else {
            theme::err()
        };
        let waiting = self.waiting.clone();
        let auth_url = self.auth_url.clone();
        let bunker = self.bunker.clone();
        let qr = self.qr.clone();
        let qr_uri = self.qr_uri.clone();

        div()
            .id("login")
            .track_focus(&self.focus)
            .on_key_down(cx.listener(|this, ev: &KeyDownEvent, _window, cx| {
                // Enter submits whichever door is focused (single-line Inputs
                // don't bind enter, so it bubbles here).
                if ev.keystroke.key == "enter" {
                    this.connect_bunker(cx);
                }
                // Esc backs out of a running flow — the waiting page's
                // keyboard Cancel (matches the shell's Esc-to-back).
                if ev.keystroke.key == "escape" && this.waiting.is_some() {
                    this.cancel(cx);
                }
            }))
            // Window root, not a pane: a definite size, so the doors center.
            .size_full()
            .overflow_hidden()
            .bg(rgb(theme::washi()))
            .text_color(rgb(theme::ink()))
            .font_family(theme::SANS)
            .flex()
            .justify_center()
            .items_center()
            .child(
                div()
                    .flex()
                    .flex_col()
                    .gap_3()
                    .w_full()
                    .max_w(px(420.))
                    .px_6()
                    .items_center()
                    .children(if let Some((status, hint)) = waiting {
                        // The waiting page: breathing ensō + status + cancel.
                        vec![
                            // nostrconnect: the QR is the waiting mark. Bunker:
                            // the breathing ensō (the breath animates the
                            // wrapper's opacity — canvas glyphs aren't
                            // styleable directly).
                            if let Some(code) = qr.clone() {
                                let open = qr_uri.clone();
                                div()
                                    .id("waiting-qr-open")
                                    .cursor_pointer()
                                    .rounded(px(theme::R_EMBED))
                                    .border_1()
                                    .border_color(rgb(theme::hairline()))
                                    .hover(|s| s.border_color(rgb(theme::muted())))
                                    .on_click(move |_, _, cx| {
                                        // Same contract as the doors QR: click
                                        // opens the system's nostrconnect handler.
                                        if let Some(uri) = open.clone() {
                                            cx.open_url(&uri);
                                        }
                                    })
                                    .child(img(code).size(px(280.0)).rounded(px(theme::R_EMBED)))
                                    .into_any_element()
                            } else {
                                // Reduced motion (the portal's
                                // prefers-reduced-motion): the ensō sits
                                // still — one mark, no breath.
                                let enso = icons::enso_icon(theme::ink(), 120.0);
                                if desktop::Desktop::get(cx).reduced_motion {
                                    div().child(enso).into_any_element()
                                } else {
                                    div().child(enso).with_animation(
                                        "enso-breath",
                                        Animation::new(Duration::from_millis(3_400)).repeat(),
                                        |enso, t| {
                                            // 0.4→1.0 opacity, one breath per cycle
                                            // (the web app's enso-breath, login.rs).
                                            let phase =
                                                0.5 + 0.5 * (t * std::f32::consts::TAU).sin();
                                            enso.opacity(0.4 + 0.6 * phase)
                                        },
                                    )
                                    .into_any_element()
                                }
                                    .into_any_element()
                            },
                            div()
                                .font_family(theme::SERIF)
                                .text_size(px(16.0))
                                .child(status)
                                .into_any_element(),
                            div()
                                .text_size(px(theme::T_SMALL))
                                .text_color(rgb(theme::muted()))
                                .child(hint)
                                .into_any_element(),
                            // The URI in the clear, for signers that can't
                            // scan (typed by hand into the signer app).
                            qr_uri
                                .map(|uri| {
                                    div()
                                        .id("qr-uri")
                                        .text_size(px(theme::T_SMALL))
                                        .text_color(rgb(theme::muted()))
                                        .overflow_x_scroll()
                                        .max_w(px(360.))
                                        .child(uri)
                                        .into_any_element()
                                })
                                .unwrap_or_else(|| div().into_any_element()),
                            auth_url
                                .map(|url| {
                                    let open = url.clone();
                                    div()
                                        .id("login-auth-url")
                                        .cursor_pointer()
                                        .text_size(px(theme::T_SMALL))
                                        .text_color(rgb(theme::live()))
                                        .overflow_x_scroll()
                                        .max_w(px(360.))
                                        .on_click(move |_, _, cx| cx.open_url(&open))
                                        .child(url)
                                        .into_any_element()
                                })
                                .unwrap_or_else(|| div().into_any_element()),
                            div()
                                .id("login-cancel")
                                .cursor_pointer()
                                .p_1()
                                .px_2()
                                .text_size(px(theme::T_UI))
                                .text_color(rgb(theme::muted()))
                                .on_click(cx.listener(|this, _, _, cx| this.cancel(cx)))
                                .child("Cancel")
                                .into_any_element(),
                        ]
                    } else {
                        // The form: two doors (login.rs form page).
                        vec![
                            div()
                                .font_family(theme::SERIF)
                                .text_size(px(28.0))
                                .child("Satori")
                                .into_any_element(),
                            div()
                                .w_full()
                                .text_size(px(theme::T_SMALL))
                                .text_color(rgb(theme::muted()))
                                .text_align(TextAlign::Center)
                                .child("A quiet Nostr client. Your key never has to touch it.")
                                .into_any_element(),
                            div()
                                .w_full()
                                .h(px(1.))
                                .bg(rgb(theme::hairline()))
                                .into_any_element(),
                            div()
                                .when(!error.is_empty(), |d| {
                                    d.child(
                                        div()
                                            .text_size(px(theme::T_SMALL))
                                            .text_color(rgb(err_color))
                                            .text_align(TextAlign::Center)
                                            .child(error),
                                    )
                                })
                                .into_any_element(),
                            div()
                                .w_full()
                                .flex()
                                .items_center()
                                .gap_2()
                                .child(field(bunker))
                                .child(
                                    div()
                                        .id("connect-bunker")
                                        .cursor_pointer()
                                        .p_1()
                                        .px_2()
                                        .text_size(px(theme::T_UI))
                                        .text_color(rgb(theme::vermilion()))
                                        .on_click(cx.listener(|this, _, _, cx| {
                                            this.connect_bunker(cx)
                                        }))
                                        .child("Connect"),
                                )
                                .into_any_element(),
                            div()
                                .w_full()
                                .text_size(px(theme::T_SMALL))
                                .text_color(rgb(theme::muted()))
                                .text_align(TextAlign::Center)
                                .child(
                                    "Sign in with a remote signer (NIP-46). The app holds \
                                     only a transport secret.",
                                )
                                .into_any_element(),
                            div()
                                .w_full()
                                .h(px(1.))
                                .bg(rgb(theme::hairline()))
                                .into_any_element(),
                            // The nostrconnect door, always on: the QR is
                            // generated the moment the doors show — click the
                            // code to open the system signer; the URI row
                            // below copies it for signers that can't.
                            div()
                                .w_full()
                                .flex()
                                .flex_col()
                                .items_center()
                                .gap_2()
                                .child(
                                    div()
                                        .font_family(theme::SERIF)
                                        .text_size(px(theme::T_READER))
                                        .child("Scan with your signer"),
                                )
                                .child(
                                    match &qr {
                                        Some(code) => div()
                                            .id("qr-open")
                                            .cursor_pointer()
                                            .rounded(px(theme::R_EMBED))
                                            .border_1()
                                            .border_color(rgb(theme::hairline()))
                                            .hover(|s| {
                                                s.border_color(rgb(theme::muted()))
                                            })
                                            .child(
                                                img(code.clone())
                                                    .size(px(240.0))
                                                    .rounded(px(theme::R_EMBED)),
                                            )
                                            // The desktop's nostrconnect:// handler
                                            // (kumaOS: the built-in signer panel) pops
                                            // on click; signers without a scheme
                                            // handler fall back to the copy row below.
                                            .on_click(cx.listener(|this, _, _, cx| {
                                                if let Some(uri) = this.qr_uri.clone() {
                                                    cx.open_url(&uri);
                                                }
                                            }))
                                            .into_any_element(),
                                        None => {
                                            let enso = icons::enso_icon(theme::muted(), 60.0);

                                            if desktop::Desktop::get(cx)
                                                .reduced_motion
                                            {
                                                div().child(enso).into_any_element()
                                            } else {
                                                div().child(enso).with_animation(
                                                    "qr-breath",
                                                    Animation::new(Duration::from_millis(
                                                        3_400,
                                                    ))
                                                    .repeat(),
                                                    |enso, t| {
                                                        let phase = 0.5
                                                            + 0.5
                                                                * (t * std::f32::consts::TAU)
                                                                    .sin();
                                                        enso.opacity(0.4 + 0.6 * phase)
                                                    },
                                                )
                                                .into_any_element()
                                            }
                                        }
                                    },
                                )
                                .child(
                                    div()
                                        .id("qr-uri-copy")
                                        .cursor_pointer()
                                        .p_1()
                                        .px_2()
                                        .rounded(px(theme::R_EMBED))
                                        .border_1()
                                        .border_color(rgb(theme::hairline()))
                                        .hover(|s| s.border_color(rgb(theme::muted())))
                                        .text_size(px(theme::T_SMALL))
                                        .text_color(rgb(theme::muted()))
                                        .on_click(cx.listener(|this, _, _, cx| {
                                            // Handshake dead (timeout, relay loss)?
                                            // The click re-arms it — but NEVER
                                            // while a handshake is live: the
                                            // re-arm bumps the generation, and
                                            // the completed login would be
                                            // dropped on the floor (the core
                                            // saved the session; the UI never
                                            // heard Approved).
                                            if this.qr_uri.is_none() && !this.connecting {
                                                dlog!("[login] uri strip click: re-arming nostrconnect");
                                                this.start_nostrconnect(cx);
                                                return;
                                            }
                                            let Some(uri) = this.qr_uri.clone() else {
                                                return;
                                            };
                                            cx.write_to_clipboard(
                                                gpui::ClipboardItem::new_string(uri),
                                            );
                                            this.copied = true;
                                            cx.notify();
                                            let reset = cx.spawn(async move |this, cx| {
                                                cx.background_executor()
                                                    .timer(Duration::from_millis(2_500))
                                                    .await;
                                                let _ = this.update(cx, |this, cx| {
                                                    this.copied = false;
                                                    cx.notify();
                                                });
                                            });
                                            reset.detach();
                                        }))
                                        .child(match (&qr_uri, self.copied) {
                                            (_, true) => {
                                                "Copied, paste it in your signer".to_string()
                                            }
                                            (Some(uri), _) => {
                                                format!("{} · click to copy", uri_brief(uri))
                                            }
                                            (None, _) => "generating…".to_string(),
                                        }),
                                )
                                .into_any_element(),
                            div()
                                .w_full()
                                .text_size(px(theme::T_SMALL))
                                .text_color(rgb(theme::muted()))
                                .text_align(TextAlign::Center)
                                .child(
                                    "Click to open your signer, the key never \
                                     touches Satori.",
                                )
                                .into_any_element(),
                        ]
                    }),
            )
    }
}

/// A door's field: the Input in the quiet panel skin (search.rs row). The
/// height is definite — the Input element fills its parent (relative 1.0),
/// which collapses in the login's content-sized chain.
fn field(input: Entity<Input>) -> impl IntoElement {
    div()
        .flex_1()
        .min_w_0()
        .overflow_hidden()
        .h(px(34.))
        .px_2()
        .pt_1()
        .rounded(px(theme::R_EMBED))
        .bg(rgb(theme::panel()))
        .border_1()
        .border_color(rgb(theme::hairline()))
        .child(input)
}

/// One-line display form of the (long) handshake URI: scheme + leading id,
/// then an ellipsis. The full URI still rides the clipboard on click —
/// the brief form is only ever shown, never transmitted.
fn uri_brief(uri: &str) -> String {
    const KEEP: usize = 26;
    if uri.chars().count() <= KEEP {
        return uri.to_string();
    }
    format!("{}…", uri.chars().take(KEEP).collect::<String>())
}

/// The nostrconnect URI as a QR image — PNG bytes at 4px/module with the
/// spec's 4-module quiet zone, handed straight to gpui's image pipeline
/// (media.rs's Image::from_bytes path).
fn qr_image(uri: &str) -> Option<Arc<Image>> {
    let code = qrcode::QrCode::new(uri.as_bytes()).ok()?;
    let n = code.width();
    let colors = code.to_colors();
    let scale = 4usize;
    let quiet = 4usize;
    let dim = (n + quiet * 2) * scale;
    let mut buf = vec![255u8; dim * dim];
    for y in 0..n {
        for x in 0..n {
            if colors[y * n + x] == qrcode::Color::Dark {
                for dy in 0..scale {
                    for dx in 0..scale {
                        let py = (y + quiet) * scale + dy;
                        let px = (x + quiet) * scale + dx;
                        buf[py * dim + px] = 0;
                    }
                }
            }
        }
    }
    let luma = image::GrayImage::from_raw(dim as u32, dim as u32, buf)?;
    let mut png = std::io::Cursor::new(Vec::new());
    image::DynamicImage::ImageLuma8(luma)
        .write_to(&mut png, image::ImageFormat::Png)
        .ok()?;
    Some(Arc::new(Image::from_bytes(
        ImageFormat::Png,
        png.into_inner(),
    )))
}

#[cfg(test)]
mod scratch {
    use super::*;

    #[test]
    fn uri_and_qr_generate() {
        let keys = nostr::prelude::Keys::generate();
        use nostr::prelude::*;
        let uri = NostrConnectUri::client(
            keys.public_key(),
            [RelayUrl::parse("wss://relay.primal.net").unwrap()],
            "Satori",
        );
        let s = uri.to_string();
        println!("uri len={} starts={}", s.len(), &s[..40]);
        let code = qrcode::QrCode::new(s.as_bytes());
        match code {
            Ok(c) => println!("qr ok, width={}", c.width()),
            Err(e) => println!("QR ERR: {e}"),
        }
        assert!(qr_image(&s).is_some(), "qr_image returned None");
    }
}
