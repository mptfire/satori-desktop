//! Stroke-drawn icons: glyphs painted as raw paths at render time.
//!
//! TODO(port): crates/app/assets/icons/scalable/actions/satori-*-symbolic.svg —
//! P0 (three of ~34 ported; add glyphs as views need them). The GTK symbolic
//! SVG pipeline dies with D13; in GPUI the 24-unit grid coordinates become
//! `PathBuilder` ops, stroked at paint time and crisp at every scale. Same
//! iconography, zero asset toolchain.

use gpui::{IntoElement, PathBuilder, Pixels, Point, canvas, prelude::*, px, rgb};

/// Maps 24-unit glyph coordinates onto the element's pixel bounds.
pub(crate) struct Grid {
    origin: Point<Pixels>,
    scale: f32,
}

impl Grid {
    fn p(&self, x: f32, y: f32) -> Point<Pixels> {
        gpui::point(
            self.origin.x + px(x * self.scale),
            self.origin.y + px(y * self.scale),
        )
    }
}

type Glyph = fn(&mut PathBuilder, &Grid);

// satori-like-symbolic.svg
fn heart(b: &mut PathBuilder, g: &Grid) {
    b.move_to(g.p(12.0, 20.3));
    b.curve_to(g.p(3.8, 12.8), g.p(8.0, 16.5));
    b.curve_to(g.p(2.6, 8.6), g.p(2.6, 10.8));
    b.curve_to(g.p(6.2, 4.0), g.p(2.6, 4.6));
    b.curve_to(g.p(12.0, 7.0), g.p(9.6, 3.6));
    b.curve_to(g.p(17.8, 4.0), g.p(14.4, 3.6));
    b.curve_to(g.p(21.4, 8.6), g.p(21.4, 4.6));
    b.curve_to(g.p(20.2, 12.8), g.p(21.4, 10.8));
    b.curve_to(g.p(12.0, 20.3), g.p(16.0, 16.5));
}

// satori-comment-symbolic.svg
fn bubble(b: &mut PathBuilder, g: &Grid) {
    b.move_to(g.p(20.5, 14.5));
    b.curve_to(g.p(18.5, 16.5), g.p(20.5, 15.6));
    b.line_to(g.p(8.0, 16.5));
    b.line_to(g.p(4.0, 20.0));
    b.line_to(g.p(4.0, 5.8));
    b.curve_to(g.p(5.9, 3.5), g.p(4.0, 4.4));
    b.line_to(g.p(18.1, 3.5));
    b.curve_to(g.p(20.5, 5.8), g.p(19.9, 3.5));
    b.close();
}

// satori-bookmark-symbolic.svg
fn bookmark(b: &mut PathBuilder, g: &Grid) {
    b.move_to(g.p(19.0, 21.0));
    b.line_to(g.p(12.0, 16.0));
    b.line_to(g.p(5.0, 21.0));
    b.line_to(g.p(5.0, 5.8));
    b.curve_to(g.p(6.9, 3.5), g.p(5.0, 4.4));
    b.line_to(g.p(17.1, 3.5));
    b.curve_to(g.p(19.0, 5.8), g.p(19.0, 4.4));
    b.close();
}

// NIP-18: the repost cycle — two arrows chasing each other (feather repeat,
// arcs straightened for the stroke grid).
fn repost(b: &mut PathBuilder, g: &Grid) {
    // top arrowhead, right-pointing
    b.move_to(g.p(17.0, 1.5));
    b.line_to(g.p(21.0, 5.5));
    b.line_to(g.p(17.0, 9.5));
    // top path: from the left rail, over the shoulder, out to the arrow
    b.move_to(g.p(3.0, 11.5));
    b.line_to(g.p(3.0, 9.5));
    b.curve_to(g.p(7.0, 5.5), g.p(3.0, 7.2));
    b.line_to(g.p(21.0, 5.5));
    // bottom arrowhead, left-pointing
    b.move_to(g.p(7.0, 22.5));
    b.line_to(g.p(3.0, 18.5));
    b.line_to(g.p(7.0, 14.5));
    // bottom path: mirror
    b.move_to(g.p(21.0, 12.5));
    b.line_to(g.p(21.0, 14.5));
    b.curve_to(g.p(17.0, 18.5), g.p(21.0, 16.8));
    b.line_to(g.p(3.0, 18.5));
}

// The mention — an `a` in the ring (feather at-sign): the bowl, the
// ring sweeping around open at the right, the tail hooking out.
fn at_sign(b: &mut PathBuilder, g: &Grid) {
    circle(b, g, 12.0, 12.5, 3.2);
    b.move_to(g.p(16.0, 10.0));
    b.curve_to(g.p(16.0, 6.5), g.p(12.0, 5.0));
    b.curve_to(g.p(6.0, 5.5), g.p(4.5, 10.0));
    b.curve_to(g.p(3.5, 14.5), g.p(7.0, 18.5));
    b.curve_to(g.p(10.0, 20.5), g.p(15.0, 19.5));
    b.move_to(g.p(16.0, 10.0));
    b.line_to(g.p(16.0, 14.0));
    b.curve_to(g.p(16.0, 17.0), g.p(20.5, 17.0));
    b.line_to(g.p(20.5, 12.0));
}

// The poll vote — a check (feather check, on the stroke grid).
fn check(b: &mut PathBuilder, g: &Grid) {
    b.move_to(g.p(19.5, 6.5));
    b.line_to(g.p(9.5, 17.0));
    b.line_to(g.p(4.5, 11.5));
}

// The timeframe clock: a face + hands (feather clock) — the notifications
// strip's window dropdown marks that its scope is TIME.
fn clock(b: &mut PathBuilder, g: &Grid) {
    circle(b, g, 12.0, 12.0, 9.0);
    b.move_to(g.p(12.0, 6.5));
    b.line_to(g.p(12.0, 12.0));
    b.line_to(g.p(15.5, 14.0));
}

// NIP-18: the quote — a doubled quotation mark, bowl and tail, outline.
fn quote(b: &mut PathBuilder, g: &Grid) {
    // left mark: bowl (three sides) + tail sweeping down-left
    b.move_to(g.p(9.5, 6.5));
    b.line_to(g.p(4.5, 6.5));
    b.line_to(g.p(4.5, 11.5));
    b.line_to(g.p(9.0, 11.5));
    b.curve_to(g.p(8.8, 14.5), g.p(7.5, 16.3));
    b.line_to(g.p(4.5, 17.5));
    // right mark: shifted +9
    b.move_to(g.p(18.5, 6.5));
    b.line_to(g.p(13.5, 6.5));
    b.line_to(g.p(13.5, 11.5));
    b.line_to(g.p(18.0, 11.5));
    b.curve_to(g.p(17.8, 14.5), g.p(16.5, 16.3));
    b.line_to(g.p(13.5, 17.5));
}

// NIP-57: the bolt — feather zap, straight lines on the stroke grid.
fn bolt(b: &mut PathBuilder, g: &Grid) {
    b.move_to(g.p(13.0, 2.0));
    b.line_to(g.p(3.0, 14.0));
    b.line_to(g.p(12.0, 14.0));
    b.line_to(g.p(11.0, 22.0));
    b.line_to(g.p(21.0, 10.0));
    b.line_to(g.p(12.0, 10.0));
    b.close();
}

/// A stroke-drawn glyph on the 24-unit grid — the GPUI twin of a symbolic SVG.
/// All outline, no fill, per the icon rule.
pub fn icon(glyph: Glyph, color: u32, size_px: f32) -> impl IntoElement {
    canvas(
        |_, _, _| {},
        move |bounds, _, window, _| {
            let scale = bounds.size.width.min(bounds.size.height) / 24.0;
            let g = Grid {
                origin: bounds.origin,
                scale: f32::from(scale),
            };
            let mut b = PathBuilder::stroke(px(1.9 * g.scale));
            glyph(&mut b, &g);
            if let Ok(path) = b.build() {
                window.paint_path(path, rgb(color));
            }
        },
    )
    .size(px(size_px))
}

pub fn heart_icon(color: u32) -> impl IntoElement {
    icon(heart, color, 17.0)
}

pub fn bubble_icon(color: u32) -> impl IntoElement {
    icon(bubble, color, 17.0)
}

pub fn bookmark_icon(color: u32) -> impl IntoElement {
    icon(bookmark, color, 17.0)
}

pub fn repost_icon(color: u32) -> impl IntoElement {
    icon(repost, color, 17.0)
}

pub fn quote_icon(color: u32) -> impl IntoElement {
    icon(quote, color, 17.0)
}

/// The zap bolt (NIP-57) — action-row size.
pub fn bolt_icon(color: u32) -> impl IntoElement {
    icon(bolt, color, 17.0)
}

/// Notification-header glyphs (the glyph slot leading an actor header).
pub fn at_icon(color: u32) -> impl IntoElement {
    icon(at_sign, color, 18.0)
}

/// The copy-the-id seal (timestamp row): two stacked sheets, small.
pub fn copy_icon(color: u32) -> impl IntoElement {
    icon(copy, color, 14.0)
}

pub fn check_icon(color: u32) -> impl IntoElement {
    icon(check, color, 18.0)
}

/// The timeframe clock (the notifications strip's window dropdown).
pub fn clock_icon(color: u32) -> impl IntoElement {
    icon(clock, color, 14.0)
}

/// Rail glyphs at rail size (icons.rs rail pass — the sidebar icons).
pub fn stream_icon(color: u32) -> impl IntoElement {
    icon(stream, color, 20.0)
}

pub fn search_icon(color: u32) -> impl IntoElement {
    icon(magnifier, color, 20.0)
}

pub fn bell_icon(color: u32) -> impl IntoElement {
    icon(bell, color, 20.0)
}

pub fn pen_icon(color: u32) -> impl IntoElement {
    icon(pen, color, 20.0)
}

pub fn gear_icon(color: u32) -> impl IntoElement {
    icon(gear, color, 20.0)
}

pub fn article_icon(color: u32) -> impl IntoElement {
    icon(article, color, 20.0)
}

pub fn book_icon(color: u32) -> impl IntoElement {
    icon(book, color, 17.0)
}

pub fn arrow_up_icon(color: u32) -> impl IntoElement {
    icon(arrow_up, color, 16.0)
}

pub fn columns_icon(color: u32) -> impl IntoElement {
    icon(columns, color, 20.0)
}

pub fn hash_icon(color: u32) -> impl IntoElement {
    icon(hash, color, 20.0)
}

/// The live wire (D68's relay column): a dot with broadcast waves on
/// both sides — distinct from the stream glyph (a timeline) and the
/// hash (a tag).
pub fn wire_icon(color: u32) -> impl IntoElement {
    icon(wire, color, 20.0)
}

/// The add-column button (rail slot in columns mode).
pub fn plus_icon(color: u32) -> impl IntoElement {
    icon(plus, color, 20.0)
}

// The ensō — the brush circle with a gap, drawn as a slightly spiralling
// arc that tapers toward the tail (the brush lifting off). It opens every
// session: the waiting mark of the login flow.
fn enso_glyph(b: &mut PathBuilder, g: &Grid) {
    let start = 60.0_f32.to_radians();
    let sweep = 320.0_f32.to_radians();
    let n = 80;
    for i in 0..=n {
        let t = i as f32 / n as f32;
        let a = start + sweep * t;
        // Radius tapers inward toward the tail.
        let r = 9.2 - 1.1 * t;
        let pt = g.p(12.0 + r * a.cos(), 12.0 + r * a.sin());
        if i == 0 {
            b.move_to(pt);
        } else {
            b.line_to(pt);
        }
    }
}

/// A sampled circle stroke (the magnifier's lens, the gear's hub).
fn circle(b: &mut PathBuilder, g: &Grid, cx: f32, cy: f32, r: f32) {
    let n = 48;
    for i in 0..=n {
        let a = (i as f32 / n as f32) * std::f32::consts::TAU;
        let pt = g.p(cx + r * a.cos(), cy + r * a.sin());
        if i == 0 {
            b.move_to(pt);
        } else {
            b.line_to(pt);
        }
    }
}

// The rail's feed mark: three lines of text with the current-position dot —
// the quietest possible "stream".
fn stream(b: &mut PathBuilder, g: &Grid) {
    b.move_to(g.p(10.0, 6.5));
    b.line_to(g.p(19.5, 6.5));
    b.move_to(g.p(10.0, 12.0));
    b.line_to(g.p(19.5, 12.0));
    b.move_to(g.p(10.0, 17.5));
    b.line_to(g.p(19.5, 17.5));
    // The dot: a hairline segment, too short to read as a line.
    b.move_to(g.p(4.8, 6.5));
    b.line_to(g.p(5.2, 6.5));
    b.move_to(g.p(4.8, 12.0));
    b.line_to(g.p(5.2, 12.0));
    b.move_to(g.p(4.8, 17.5));
    b.line_to(g.p(5.2, 17.5));
}

// satori-search-symbolic.svg — lens + handle.
fn magnifier(b: &mut PathBuilder, g: &Grid) {
    circle(b, g, 10.5, 10.5, 6.2);
    b.move_to(g.p(15.2, 15.2));
    b.line_to(g.p(20.2, 20.2));
}

/// A stroke rectangle with softly cut corners (the copy glyph's sheets).
fn sheet(b: &mut PathBuilder, g: &Grid, x0: f32, y0: f32, x1: f32, y1: f32) {
    let r = 2.0;
    b.move_to(g.p(x0 + r, y0));
    b.line_to(g.p(x1 - r, y0));
    b.line_to(g.p(x1, y0 + r));
    b.line_to(g.p(x1, y1 - r));
    b.line_to(g.p(x1 - r, y1));
    b.line_to(g.p(x0 + r, y1));
    b.line_to(g.p(x0, y1 - r));
    b.line_to(g.p(x0, y0 + r));
    b.close();
}

// The copy glyph: two stacked sheets (the copy-the-id seal).
fn copy(b: &mut PathBuilder, g: &Grid) {
    sheet(b, g, 8.5, 8.5, 21.0, 21.0);
    sheet(b, g, 3.0, 3.0, 15.5, 15.5);
}

// The bell: dome with a smile-arc clapper.
fn bell(b: &mut PathBuilder, g: &Grid) {
    b.move_to(g.p(12.0, 4.0));
    b.curve_to(g.p(6.0, 4.6), g.p(6.0, 12.0));
    b.line_to(g.p(6.0, 15.5));
    b.line_to(g.p(18.0, 15.5));
    b.line_to(g.p(18.0, 12.0));
    b.curve_to(g.p(18.0, 4.6), g.p(12.0, 4.0));
    b.move_to(g.p(10.0, 18.6));
    b.curve_to(g.p(12.0, 20.0), g.p(14.0, 18.6));
}

// The compose pen: pencil outline with the tip cross-line (feather edit-2).
fn pen(b: &mut PathBuilder, g: &Grid) {
    b.move_to(g.p(5.0, 19.0));
    b.line_to(g.p(5.9, 15.7));
    b.line_to(g.p(17.0, 4.6));
    b.line_to(g.p(19.4, 7.0));
    b.line_to(g.p(8.8, 18.6));
    b.line_to(g.p(5.0, 19.0));
    b.move_to(g.p(15.4, 6.2));
    b.line_to(g.p(18.3, 9.1));
}

// Settings: a proper cog — toothed silhouette (alternating radii) around a
// hub circle. The sunburst experiment didn't read as "settings".
fn gear(b: &mut PathBuilder, g: &Grid) {
    let n = 8;
    for i in 0..n {
        let a0 = (i as f32) * std::f32::consts::FRAC_PI_4;
        // valley -> tip -> tip -> valley per tooth; consecutive teeth's
        // valleys connect as the cog's outer valleys.
        for (da, r) in [(-0.16, 6.6), (-0.09, 8.6), (0.09, 8.6), (0.16, 6.6)] {
            let a = a0 + da;
            let pt = g.p(12.0 + r * a.cos(), 12.0 + r * a.sin());
            if i == 0 && da == -0.16 {
                b.move_to(pt);
            } else {
                b.line_to(pt);
            }
        }
    }
    b.close();
    circle(b, g, 12.0, 12.0, 3.4);
}

// The articles mark: a page outline carrying text lines.
fn article(b: &mut PathBuilder, g: &Grid) {
    b.move_to(g.p(6.0, 3.5));
    b.line_to(g.p(18.0, 3.5));
    b.line_to(g.p(18.0, 20.5));
    b.line_to(g.p(6.0, 20.5));
    b.close();
    b.move_to(g.p(8.8, 8.0));
    b.line_to(g.p(15.2, 8.0));
    b.move_to(g.p(8.8, 12.0));
    b.line_to(g.p(15.2, 12.0));
    b.move_to(g.p(8.8, 16.0));
    b.line_to(g.p(13.0, 16.0));
}

// The Library (D38): a closed book — cover, spine, two title lines.
fn book(b: &mut PathBuilder, g: &Grid) {
    b.move_to(g.p(5.0, 4.0));
    b.line_to(g.p(19.0, 4.0));
    b.line_to(g.p(19.0, 20.0));
    b.line_to(g.p(5.0, 20.0));
    b.close();
    b.move_to(g.p(8.5, 4.0));
    b.line_to(g.p(8.5, 20.0));
    b.move_to(g.p(11.5, 9.0));
    b.line_to(g.p(16.0, 9.0));
    b.move_to(g.p(11.5, 13.0));
    b.line_to(g.p(16.0, 13.0));
}

// Back-to-top: shaft + head.
fn arrow_up(b: &mut PathBuilder, g: &Grid) {
    b.move_to(g.p(12.0, 19.0));
    b.line_to(g.p(12.0, 5.5));
    b.move_to(g.p(6.5, 11.0));
    b.line_to(g.p(12.0, 5.5));
    b.line_to(g.p(17.5, 11.0));
}

/// The add-column button (D68's rail slot): a plain plus.
fn plus(b: &mut PathBuilder, g: &Grid) {
    b.move_to(g.p(12.0, 5.0));
    b.line_to(g.p(12.0, 19.0));
    b.move_to(g.p(5.0, 12.0));
    b.line_to(g.p(19.0, 12.0));
}

/// The columns workspace (D68): a triptych — three pane strokes.
fn columns(b: &mut PathBuilder, g: &Grid) {
    for x in [5.0, 12.0, 19.0] {
        b.move_to(g.p(x, 5.0));
        b.line_to(g.p(x, 19.0));
    }
}

/// The hashtag column mark (D68 phase 2): the hash.
fn hash(b: &mut PathBuilder, g: &Grid) {
    for x in [9.0, 15.0] {
        b.move_to(g.p(x, 4.5));
        b.line_to(g.p(x, 19.5));
    }
    for y in [8.0, 16.0] {
        b.move_to(g.p(4.5, y));
        b.line_to(g.p(19.5, y));
    }
}

/// The live wire: a source dot, broadcast waves arcing out on both
/// sides (stroke-only, the icon rule). Quadratic curves: endpoint +
/// one control (gpui's curve_to).
fn wire(b: &mut PathBuilder, g: &Grid) {
    // The dot: a hairline circle, four quad arcs.
    b.move_to(g.p(13.2, 12.0));
    b.curve_to(g.p(12.0, 13.2), g.p(13.2, 13.2));
    b.curve_to(g.p(10.8, 12.0), g.p(12.0, 13.2));
    b.curve_to(g.p(12.0, 10.8), g.p(10.8, 12.0));
    b.curve_to(g.p(13.2, 12.0), g.p(12.0, 10.8));
    // The inner waves.
    b.move_to(g.p(8.5, 9.5));
    b.curve_to(g.p(8.5, 14.5), g.p(5.6, 12.0));
    b.move_to(g.p(15.5, 9.5));
    b.curve_to(g.p(15.5, 14.5), g.p(18.4, 12.0));
    // The outer waves.
    b.move_to(g.p(6.3, 7.0));
    b.curve_to(g.p(6.3, 17.0), g.p(2.2, 12.0));
    b.move_to(g.p(17.7, 7.0));
    b.curve_to(g.p(17.7, 17.0), g.p(21.8, 12.0));
}

/// The ensō at display size — a brush circle, so the stroke runs heavier
/// than the hairline glyphs.
pub fn enso_icon(color: u32, size_px: f32) -> impl IntoElement {
    canvas(
        |_, _, _| {},
        move |bounds, _, window, _| {
            let scale = bounds.size.width.min(bounds.size.height) / 24.0;
            let g = Grid {
                origin: bounds.origin,
                scale: f32::from(scale),
            };
            let mut b = PathBuilder::stroke(px(2.4 * g.scale));
            enso_glyph(&mut b, &g);
            if let Ok(path) = b.build() {
                window.paint_path(path, rgb(color));
            }
        },
    )
    .size(px(size_px))
}
