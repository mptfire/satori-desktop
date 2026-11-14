//! WP3 playback smoke: real GStreamer playback through the guarded range-proxy.
//!
//! Run from the development container, with network access enabled:
//!   DISPLAY=:0 cargo run --example playback_smoke --locked --offline
//!
//! Does not log into Nostr or publish anything. Default origin is the official
//! GStreamer Basic Tutorial 1 fixture (HTTPS, supports byte ranges).

use std::sync::{Arc, Mutex};
use std::time::Duration;

use gpui::prelude::*;
use gpui::{App, Context, Render, Window, WindowOptions, div, px};
use gpui_video_player::{Video, video};
use url::Url;

const ORIGIN: &str = "https://gstreamer.freedesktop.org/data/media/sintel_trailer-480p.webm";

struct Player {
    video: Video,
}

impl Render for Player {
    fn render(&mut self, _: &mut Window, _: &mut Context<Self>) -> impl IntoElement {
        div()
            .w(px(640.0))
            .h(px(270.0))
            .child(video(self.video.clone()).id("playback-smoke").buffer_capacity(30))
    }
}

fn main() {
    let origin = std::env::args().nth(1).unwrap_or_else(|| ORIGIN.to_string());
    let parsed = Url::parse(&origin).expect("origin must be a valid URL");
    assert_eq!(parsed.scheme(), "https", "smoke origin must be HTTPS");
    let proxy = satori_core::video_proxy::spawn(origin).expect("bind range-proxy loopback");
    let proxied = Url::parse(&proxy.uri()).expect("proxy URI must parse");
    println!("SMOKE: origin {parsed}");
    println!("SMOKE: playbin receives guarded {}", proxy.uri());

    gpui::Application::with_platform(gpui_linux::current_platform(false)).run(move |cx: &mut App| {
        let slot: Arc<Mutex<Option<Video>>> = Arc::new(Mutex::new(None));
        let slot_init = Arc::clone(&slot);
        let proxied_init = proxied.clone();
        cx.open_window(WindowOptions::default(), move |_, cx| {
            let video = match Video::new(&proxied_init) {
                Ok(video) => video,
                Err(e) => {
                    eprintln!("SMOKE FAIL: Video::new through proxy: {e}");
                    std::process::exit(1);
                }
            };
            video.set_volume(0.0);
            slot_init.lock().expect("video slot").replace(video.clone());
            cx.new(|_| Player { video })
        })
        .expect("SMOKE FAIL: open player window");
        cx.activate(true);

        let video = slot.lock().expect("video slot").clone().expect("video initialized");
        std::thread::spawn(move || {
            for _ in 0..45 {
                std::thread::sleep(Duration::from_secs(1));
                let frame = video.current_frame_data();
                let position = video.position();
                println!(
                    "SMOKE: position={}ms frame={}",
                    position.as_millis(),
                    frame
                        .as_ref()
                        .map(|(_, w, h)| format!("{w}x{h}"))
                        .unwrap_or_else(|| "pending".into())
                );
                if let Some((bytes, width, height)) = frame
                    && !bytes.is_empty()
                    && width > 0
                    && height > 0
                    && !position.is_zero()
                {
                    println!(
                        "SMOKE PASS: proxy + GStreamer decoded a {}x{} NV12 frame ({} bytes), position {}ms, {} fps, duration {}ms",
                        width,
                        height,
                        bytes.len(),
                        position.as_millis(),
                        video.framerate(),
                        video.duration().as_millis()
                    );
                    std::process::exit(0);
                }
            }
            eprintln!("SMOKE FAIL: no decoded frame and advancing playhead within 45 seconds");
            std::process::exit(1);
        });
    });
}
