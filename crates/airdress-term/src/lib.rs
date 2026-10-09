// cspell:ignore DECCKM DECKPAM DECTCEM ARGB argb renderable zerowidth
//! A terminal screen model for shell clients.
//!
//! The bytes a session's program writes arrive at a client as `out` and
//! `snapshot` messages. This crate turns them into a grid of cells a
//! painter can draw without knowing any VT: every cell comes out with its
//! code point, its resolved foreground and background colors (bold as
//! bright, dim, inverse and hidden already applied) and a few style bits.
//!
//! The emulator is `alacritty_terminal`. The Android app reaches this crate
//! through the C ABI in [`ffi`], the same way it reaches the protocol crate;
//! nothing here does I/O.
//!
//! **Replies.** Some sequences ask the terminal a question (device
//! attributes, the cursor position, a color). A local terminal answers on
//! the program's input; here the answers are collected and handed out by
//! [`Screen::take_replies`], and only the typist sends them on, as `in`.
// `src/` only, by amendment: tests under `tests/` are test crates already.
#![warn(clippy::tests_outside_test_module)]
// Every unsafe operation (all of it in `ffi`) is spelled out and justified
// where it happens, and every unsafe fn says what its caller owes (rust
// guide R-UNS-2).
#![deny(unsafe_op_in_unsafe_fn)]
#![deny(clippy::undocumented_unsafe_blocks, clippy::missing_safety_doc)]

use std::sync::{Arc, Mutex};

use alacritty_terminal::event::{Event, EventListener, WindowSize};
use alacritty_terminal::grid::{Dimensions, Scroll};
use alacritty_terminal::term::cell::Flags;
use alacritty_terminal::term::color::Colors;
use alacritty_terminal::term::{Config, Osc52, Term, TermMode};
use alacritty_terminal::vte::ansi::{Color, CursorShape, NamedColor, Processor, Rgb};

pub mod ffi;

/// The model's version, for a client to refuse a library it does not know.
pub const VERSION: u32 = 1;

/// The `u32`s per cell in a snapshot: code point, foreground, background,
/// style.
pub const WORDS_PER_CELL: usize = 4;

/// The largest grid accepted, per side.
pub const MAX_SIDE: u16 = 1000;

/// The most scrollback a screen keeps.
pub const MAX_SCROLLBACK: u32 = 100_000;

/// Style bits in a cell's fourth word. Stable: the painter depends on them,
/// not on the emulator's own flags.
pub mod style {
    /// Bold.
    pub const BOLD: u32 = 1 << 0;
    /// Italic.
    pub const ITALIC: u32 = 1 << 1;
    /// Any underline.
    pub const UNDERLINE: u32 = 1 << 2;
    /// Strike-through.
    pub const STRIKEOUT: u32 = 1 << 3;
    /// The first half of a double-width character: paint it two cells wide.
    pub const WIDE: u32 = 1 << 4;
    /// The second half of a double-width character: paint nothing.
    pub const SPACER: u32 = 1 << 5;
    /// The cell carries combining characters: its text is more than its
    /// code point (read it with `airdress_term_cell_text`).
    pub const COMBINING: u32 = 1 << 6;
    /// The cell is under the cursor (a block cursor is painted by the
    /// caller; the colors are not swapped here).
    pub const CURSOR: u32 = 1 << 7;
}

/// Mode bits in [`State::modes`]. Stable, like [`style`].
pub mod mode {
    /// DECCKM: arrows send `ESC O x` instead of `ESC [ x`.
    pub const APP_CURSOR: u32 = 1 << 0;
    /// DECKPAM: the keypad sends application sequences.
    pub const APP_KEYPAD: u32 = 1 << 1;
    /// Bracketed paste: pasted text is wrapped in `ESC [200~` / `ESC [201~`.
    pub const BRACKETED_PASTE: u32 = 1 << 2;
    /// The alternate screen (a full-screen program) is showing.
    pub const ALT_SCREEN: u32 = 1 << 3;
    /// The program asked for mouse reports.
    pub const MOUSE: u32 = 1 << 4;
    /// SGR mouse encoding.
    pub const SGR_MOUSE: u32 = 1 << 5;
    /// Focus in/out reports.
    pub const FOCUS: u32 = 1 << 6;
    /// The cursor is shown (DECTCEM).
    pub const SHOW_CURSOR: u32 = 1 << 7;
}

/// Cursor shapes in [`State::cursor_shape`].
pub mod cursor {
    /// A block.
    pub const BLOCK: u8 = 0;
    /// An underline.
    pub const UNDERLINE: u8 = 1;
    /// A vertical bar.
    pub const BEAM: u8 = 2;
    /// A hollow block.
    pub const HOLLOW: u8 = 3;
    /// Not shown.
    pub const HIDDEN: u8 = 4;
}

/// What a painter needs besides the cells.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct State {
    /// Columns.
    pub cols: u16,
    /// Rows.
    pub rows: u16,
    /// The cursor's column.
    pub cursor_col: u16,
    /// The cursor's row in the viewport, or -1 when scrolled off it.
    pub cursor_row: i32,
    /// One of [`cursor`].
    pub cursor_shape: u8,
    /// [`mode`] bits.
    pub modes: u32,
    /// Lines scrolled back from the bottom.
    pub display_offset: u32,
    /// Lines of scrollback held.
    pub history: u32,
    /// Bells rung since the screen was made.
    pub bells: u32,
    /// Increments on every change a painter must redraw for.
    pub generation: u64,
    /// The default background, ARGB.
    pub default_bg: u32,
}

#[derive(Debug, Default)]
struct Inbox {
    events: Vec<Event>,
    bells: u32,
}

#[derive(Debug, Clone, Default)]
struct Listener(Arc<Mutex<Inbox>>);

impl EventListener for Listener {
    fn send_event(&self, event: Event) {
        let Ok(mut inbox) = self.0.lock() else {
            return;
        };
        match event {
            Event::Bell => inbox.bells = inbox.bells.saturating_add(1),
            e @ (Event::PtyWrite(_) | Event::ColorRequest(..) | Event::TextAreaSizeRequest(_)) => {
                inbox.events.push(e)
            }
            // Titles, the clipboard and the rest are a desktop terminal's
            // business. OSC 52 is off (see `Screen::new`), so a remote
            // program cannot read or write the phone's clipboard.
            _ => {}
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct Size {
    cols: usize,
    rows: usize,
}

impl Dimensions for Size {
    fn total_lines(&self) -> usize {
        self.rows
    }
    fn screen_lines(&self) -> usize {
        self.rows
    }
    fn columns(&self) -> usize {
        self.cols
    }
}

/// Errors from [`Screen`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TermError {
    /// A size of zero or above [`MAX_SIDE`].
    BadSize,
    /// A buffer too small for the grid.
    BufferTooSmall,
    /// A cell outside the grid.
    OutOfRange,
}

/// One terminal screen.
pub struct Screen {
    term: Term<Listener>,
    parser: Processor,
    listener: Listener,
    scrollback: usize,
    fg: Rgb,
    bg: Rgb,
    generation: u64,
    replies: Vec<u8>,
}

impl std::fmt::Debug for Screen {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Screen")
            .field("cols", &self.term.columns())
            .field("rows", &self.term.screen_lines())
            .finish_non_exhaustive()
    }
}

fn check(cols: u16, rows: u16) -> Result<Size, TermError> {
    if cols == 0 || rows == 0 || cols > MAX_SIDE || rows > MAX_SIDE {
        return Err(TermError::BadSize);
    }
    Ok(Size {
        cols: cols.into(),
        rows: rows.into(),
    })
}

const fn rgb(v: u32) -> Rgb {
    Rgb {
        r: (v >> 16) as u8,
        g: (v >> 8) as u8,
        b: v as u8,
    }
}

const fn argb(c: Rgb) -> u32 {
    0xFF00_0000 | (c.r as u32) << 16 | (c.g as u32) << 8 | c.b as u32
}

/// The sixteen ANSI colors (xterm's defaults, slightly softened).
const ANSI: [u32; 16] = [
    0x000000, 0xCD3131, 0x0DBC79, 0xE5E510, 0x2472C8, 0xBC3FBC, 0x11A8CD, 0xE5E5E5, 0x666666,
    0xF14C4C, 0x23D18B, 0xF5F543, 0x3B8EEA, 0xD670D6, 0x29B8DB, 0xFFFFFF,
];

/// The 256-color palette entry `i` before any program changed it.
fn palette(i: usize) -> Rgb {
    match i {
        0..=15 => rgb(ANSI[i]),
        16..=231 => {
            let i = i - 16;
            let level = |v: usize| if v == 0 { 0 } else { (55 + v * 40) as u8 };
            Rgb {
                r: level(i / 36),
                g: level((i / 6) % 6),
                b: level(i % 6),
            }
        }
        _ => {
            let v = (8 + (i.min(255) - 232) * 10) as u8;
            Rgb { r: v, g: v, b: v }
        }
    }
}

fn dim(c: Rgb) -> Rgb {
    Rgb {
        r: (c.r as u16 * 2 / 3) as u8,
        g: (c.g as u16 * 2 / 3) as u8,
        b: (c.b as u16 * 2 / 3) as u8,
    }
}

impl Screen {
    /// A `cols`×`rows` screen keeping up to `scrollback` lines.
    pub fn new(cols: u16, rows: u16, scrollback: u32) -> Result<Self, TermError> {
        let size = check(cols, rows)?;
        let scrollback = scrollback.min(MAX_SCROLLBACK) as usize;
        let listener = Listener::default();
        let term = Term::new(Self::config(scrollback), &size, listener.clone());
        Ok(Self {
            term,
            parser: Processor::new(),
            listener,
            scrollback,
            fg: rgb(0xE5E5E5),
            bg: rgb(0x1E1E1E),
            generation: 0,
            replies: Vec::new(),
        })
    }

    fn config(scrollback: usize) -> Config {
        Config {
            scrolling_history: scrollback,
            // A remote program must not read or write this device's
            // clipboard.
            osc52: Osc52::Disabled,
            ..Config::default()
        }
    }

    /// Start over at `cols`×`rows`: what a `snapshot` is written into.
    pub fn reset(&mut self, cols: u16, rows: u16) -> Result<(), TermError> {
        let size = check(cols, rows)?;
        self.term = Term::new(Self::config(self.scrollback), &size, self.listener.clone());
        self.parser = Processor::new();
        self.replies.clear();
        self.generation += 1;
        Ok(())
    }

    /// The colors a cell without its own color is drawn in (ARGB; the
    /// alpha is ignored).
    pub fn set_default_colors(&mut self, fg: u32, bg: u32) {
        self.fg = rgb(fg);
        self.bg = rgb(bg);
        self.generation += 1;
    }

    /// Feed program output.
    pub fn feed(&mut self, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        self.parser.advance(&mut self.term, bytes);
        self.generation += 1;
        self.collect_replies();
    }

    fn collect_replies(&mut self) {
        let events = match self.listener.0.lock() {
            Ok(mut inbox) => std::mem::take(&mut inbox.events),
            Err(_) => return,
        };
        for e in events {
            match e {
                Event::PtyWrite(s) => self.replies.extend_from_slice(s.as_bytes()),
                Event::ColorRequest(i, f) => {
                    let c = self.color_index(i);
                    self.replies.extend_from_slice(f(c).as_bytes());
                }
                Event::TextAreaSizeRequest(f) => {
                    let s = WindowSize {
                        num_lines: self.term.screen_lines() as u16,
                        num_cols: self.term.columns() as u16,
                        cell_width: 0,
                        cell_height: 0,
                    };
                    self.replies.extend_from_slice(f(s).as_bytes());
                }
                _ => {}
            }
        }
    }

    /// Answers the program asked for since the last call (see the module
    /// note). Only the typist sends them on.
    pub fn take_replies(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.replies)
    }

    /// Change the size; the scrollback reflows.
    pub fn resize(&mut self, cols: u16, rows: u16) -> Result<(), TermError> {
        let size = check(cols, rows)?;
        self.term.resize(size);
        self.generation += 1;
        Ok(())
    }

    /// Scroll the view by `lines` (positive is back into history).
    pub fn scroll(&mut self, lines: i32) {
        self.term.scroll_display(Scroll::Delta(lines));
        self.generation += 1;
    }

    /// Follow the bottom again.
    pub fn scroll_to_bottom(&mut self) {
        self.term.scroll_display(Scroll::Bottom);
        self.generation += 1;
    }

    fn color_index(&self, i: usize) -> Rgb {
        if let Some(c) = self.term.colors()[i] {
            return c;
        }
        match i {
            0..=255 => palette(i),
            x if x == NamedColor::Foreground as usize => self.fg,
            x if x == NamedColor::Background as usize => self.bg,
            x if x == NamedColor::Cursor as usize => self.fg,
            x if x == NamedColor::BrightForeground as usize => self.fg,
            x if x == NamedColor::DimForeground as usize => dim(self.fg),
            x if (NamedColor::DimBlack as usize..=NamedColor::DimWhite as usize).contains(&x) => {
                dim(palette(x - NamedColor::DimBlack as usize))
            }
            _ => self.fg,
        }
    }

    fn resolve(&self, c: Color, colors: &Colors, flags: Flags) -> Rgb {
        match c {
            Color::Spec(rgb) => rgb,
            Color::Indexed(i) => {
                let mut i = i as usize;
                if flags.contains(Flags::BOLD) && i < 8 {
                    i += 8;
                }
                colors[i].unwrap_or_else(|| palette(i))
            }
            Color::Named(n) => {
                let mut i = n as usize;
                if flags.contains(Flags::BOLD) && i < 8 {
                    i += 8;
                }
                colors[i].unwrap_or_else(|| self.color_index(i))
            }
        }
    }

    /// The state a painter needs besides the cells.
    pub fn state(&self) -> State {
        let content = self.term.renderable_content();
        let offset = content.display_offset;
        let row = content.cursor.point.line.0 + offset as i32;
        let rows = self.term.screen_lines() as i32;
        let m = content.mode;
        let mut modes = 0;
        for (have, bit) in [
            (TermMode::APP_CURSOR, mode::APP_CURSOR),
            (TermMode::APP_KEYPAD, mode::APP_KEYPAD),
            (TermMode::BRACKETED_PASTE, mode::BRACKETED_PASTE),
            (TermMode::ALT_SCREEN, mode::ALT_SCREEN),
            (TermMode::MOUSE_MODE, mode::MOUSE),
            (TermMode::SGR_MOUSE, mode::SGR_MOUSE),
            (TermMode::FOCUS_IN_OUT, mode::FOCUS),
            (TermMode::SHOW_CURSOR, mode::SHOW_CURSOR),
        ] {
            if m.intersects(have) {
                modes |= bit;
            }
        }
        let shape = match content.cursor.shape {
            CursorShape::Block => cursor::BLOCK,
            CursorShape::Underline => cursor::UNDERLINE,
            CursorShape::Beam => cursor::BEAM,
            CursorShape::HollowBlock => cursor::HOLLOW,
            CursorShape::Hidden => cursor::HIDDEN,
        };
        let bells = self.listener.0.lock().map(|i| i.bells).unwrap_or(0);
        State {
            cols: self.term.columns() as u16,
            rows: rows as u16,
            cursor_col: content.cursor.point.column.0 as u16,
            cursor_row: if (0..rows).contains(&row) { row } else { -1 },
            cursor_shape: shape,
            modes,
            display_offset: offset as u32,
            history: self.term.grid().history_size() as u32,
            bells,
            generation: self.generation,
            default_bg: argb(self.bg),
        }
    }

    /// The viewport's cells, row by row, [`WORDS_PER_CELL`] words each:
    /// code point (0 for a blank or a spacer), foreground ARGB, background
    /// ARGB, [`style`] bits.
    pub fn snapshot(&self, out: &mut [u32]) -> Result<usize, TermError> {
        let cols = self.term.columns();
        let rows = self.term.screen_lines();
        let need = cols * rows * WORDS_PER_CELL;
        if out.len() < need {
            return Err(TermError::BufferTooSmall);
        }
        out[..need].fill(0);
        let content = self.term.renderable_content();
        let offset = content.display_offset as i32;
        let colors = content.colors;
        let cursor = content.cursor;
        let blank_bg = argb(self.bg);
        let blank_fg = argb(self.fg);
        // Cells the grid never wrote stay at zero; paint them blank.
        for cell in out[..need].as_chunks_mut::<WORDS_PER_CELL>().0 {
            cell[1] = blank_fg;
            cell[2] = blank_bg;
        }
        for indexed in content.display_iter {
            let row = indexed.point.line.0 + offset;
            if row < 0 || row as usize >= rows {
                continue;
            }
            let col = indexed.point.column.0;
            if col >= cols {
                continue;
            }
            let c = indexed.cell;
            let flags = c.flags;
            let mut fg = self.resolve(c.fg, colors, flags);
            let mut bg = self.resolve(c.bg, colors, flags & !Flags::BOLD);
            if flags.contains(Flags::DIM) {
                fg = dim(fg);
            }
            if flags.contains(Flags::INVERSE) {
                std::mem::swap(&mut fg, &mut bg);
            }
            if flags.contains(Flags::HIDDEN) {
                fg = bg;
            }
            let mut st = 0;
            for (have, bit) in [
                (Flags::BOLD, style::BOLD),
                (Flags::ITALIC, style::ITALIC),
                (Flags::ALL_UNDERLINES, style::UNDERLINE),
                (Flags::STRIKEOUT, style::STRIKEOUT),
                (Flags::WIDE_CHAR, style::WIDE),
            ] {
                if flags.intersects(have) {
                    st |= bit;
                }
            }
            let spacer =
                flags.intersects(Flags::WIDE_CHAR_SPACER | Flags::LEADING_WIDE_CHAR_SPACER);
            if spacer {
                st |= style::SPACER;
            }
            if c.zerowidth().is_some_and(|z| !z.is_empty()) {
                st |= style::COMBINING;
            }
            if cursor.point == indexed.point {
                st |= style::CURSOR;
            }
            let cp = if spacer || c.c == ' ' { 0 } else { c.c as u32 };
            let i = (row as usize * cols + col) * WORDS_PER_CELL;
            out[i] = cp;
            out[i + 1] = argb(fg);
            out[i + 2] = argb(bg);
            out[i + 3] = st;
        }
        Ok(need)
    }

    /// A cell's whole text: its character and any combining characters.
    pub fn cell_text(&self, row: u16, col: u16) -> Result<String, TermError> {
        let rows = self.term.screen_lines();
        let cols = self.term.columns();
        if row as usize >= rows || col as usize >= cols {
            return Err(TermError::OutOfRange);
        }
        let offset = self.term.grid().display_offset() as i32;
        let point = alacritty_terminal::index::Point::new(
            alacritty_terminal::index::Line(row as i32 - offset),
            alacritty_terminal::index::Column(col as usize),
        );
        let cell = &self.term.grid()[point];
        let mut s = String::new();
        s.push(cell.c);
        if let Some(z) = cell.zerowidth() {
            s.extend(z.iter());
        }
        Ok(s)
    }

    /// The viewport as text, rows joined with `\n`, trailing blanks
    /// trimmed. For copying, and for tests.
    pub fn screen_text(&self) -> String {
        let cols = self.term.columns();
        let rows = self.term.screen_lines();
        let mut lines = vec![String::new(); rows];
        let mut cells = vec![' '; cols * rows];
        let content = self.term.renderable_content();
        let offset = content.display_offset as i32;
        for indexed in content.display_iter {
            let row = indexed.point.line.0 + offset;
            if row < 0 || row as usize >= rows || indexed.point.column.0 >= cols {
                continue;
            }
            let c = indexed.cell;
            if c.flags
                .intersects(Flags::WIDE_CHAR_SPACER | Flags::LEADING_WIDE_CHAR_SPACER)
            {
                cells[row as usize * cols + indexed.point.column.0] = '\0';
                continue;
            }
            cells[row as usize * cols + indexed.point.column.0] = c.c;
        }
        for (r, line) in lines.iter_mut().enumerate() {
            line.extend(
                cells[r * cols..(r + 1) * cols]
                    .iter()
                    .filter(|c| **c != '\0'),
            );
            let trimmed = line.trim_end().len();
            line.truncate(trimmed);
        }
        lines.join("\n")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cells(s: &Screen) -> Vec<u32> {
        let st = s.state();
        let mut v = vec![0u32; st.cols as usize * st.rows as usize * WORDS_PER_CELL];
        s.snapshot(&mut v).unwrap();
        v
    }

    fn at(v: &[u32], cols: usize, row: usize, col: usize) -> [u32; 4] {
        let i = (row * cols + col) * WORDS_PER_CELL;
        [v[i], v[i + 1], v[i + 2], v[i + 3]]
    }

    #[test]
    fn text_lands_in_cells_and_colors_resolve() {
        let mut s = Screen::new(10, 3, 100).unwrap();
        s.feed(b"a\x1b[31mb\x1b[0m\x1b[1;32mc\x1b[0m\x1b[38;2;1;2;3;48;5;21md");
        let v = cells(&s);
        assert_eq!(at(&v, 10, 0, 0)[0], 'a' as u32);
        assert_eq!(at(&v, 10, 0, 1)[1], 0xFF00_0000 | 0xCD3131);
        // Bold green is bright green.
        assert_eq!(at(&v, 10, 0, 2)[1], 0xFF00_0000 | 0x23D18B);
        assert_eq!(at(&v, 10, 0, 2)[3] & style::BOLD, style::BOLD);
        assert_eq!(at(&v, 10, 0, 3)[1], 0xFF01_0203);
        // Index 21 of the cube: r0 g0 b5 (255).
        assert_eq!(at(&v, 10, 0, 3)[2], 0xFF00_00FF);
        assert_eq!(s.screen_text(), "abcd\n\n");
    }

    #[test]
    fn umlauts_wide_characters_and_combining_marks() {
        let mut s = Screen::new(10, 2, 0).unwrap();
        s.feed("grüße 日e\u{301}".as_bytes());
        let v = cells(&s);
        assert_eq!(at(&v, 10, 0, 2)[0], 'ü' as u32);
        assert_eq!(at(&v, 10, 0, 3)[0], 'ß' as u32);
        assert_eq!(at(&v, 10, 0, 6)[3] & style::WIDE, style::WIDE);
        assert_eq!(at(&v, 10, 0, 7)[3] & style::SPACER, style::SPACER);
        assert_eq!(at(&v, 10, 0, 8)[3] & style::COMBINING, style::COMBINING);
        assert_eq!(s.cell_text(0, 8).unwrap(), "e\u{301}");
        assert_eq!(s.screen_text().lines().next(), Some("grüße 日e"));
    }

    #[test]
    fn inverse_and_cursor_and_modes() {
        let mut s = Screen::new(5, 2, 0).unwrap();
        s.set_default_colors(0xFFFFFF, 0x000000);
        s.feed(b"\x1b[7mx\x1b[0m\x1b[?1h\x1b[?2004h\x1b[?1049h");
        let st = s.state();
        assert_ne!(st.modes & mode::APP_CURSOR, 0);
        assert_ne!(st.modes & mode::BRACKETED_PASTE, 0);
        assert_ne!(st.modes & mode::ALT_SCREEN, 0);
        s.feed(b"\x1b[?1049l");
        let v = cells(&s);
        assert_eq!(at(&v, 5, 0, 0)[1], 0xFF00_0000);
        assert_eq!(at(&v, 5, 0, 0)[2], 0xFFFF_FFFF);
        let st = s.state();
        assert_eq!((st.cursor_row, st.cursor_col), (0, 1));
        assert_ne!(at(&v, 5, 0, 1)[3] & style::CURSOR, 0);
    }

    #[test]
    fn questions_are_answered_through_replies() {
        let mut s = Screen::new(20, 5, 0).unwrap();
        s.feed(b"ab\x1b[6n");
        assert_eq!(s.take_replies(), b"\x1b[1;3R");
        assert!(s.take_replies().is_empty());
        s.feed(b"\x1b[c");
        assert!(s.take_replies().starts_with(b"\x1b[?"));
    }

    #[test]
    fn scrollback_scrolls_and_the_cursor_leaves_the_view() {
        let mut s = Screen::new(5, 2, 100).unwrap();
        for i in 0..10 {
            s.feed(format!("{i}\r\n").as_bytes());
        }
        assert_eq!(s.state().history, 9);
        s.scroll(3);
        let st = s.state();
        assert_eq!(st.display_offset, 3);
        assert_eq!(st.cursor_row, -1);
        assert_eq!(s.screen_text(), "6\n7");
        s.scroll_to_bottom();
        assert_eq!(s.screen_text(), "9\n");
    }

    #[test]
    fn reset_and_resize() {
        let mut s = Screen::new(5, 2, 0).unwrap();
        s.feed(b"hello");
        let g = s.state().generation;
        s.reset(8, 3).unwrap();
        assert!(s.state().generation > g);
        assert_eq!((s.state().cols, s.state().rows), (8, 3));
        assert_eq!(s.screen_text(), "\n\n");
        s.resize(4, 4).unwrap();
        assert_eq!(s.state().cols, 4);
        assert_eq!(s.resize(0, 4), Err(TermError::BadSize));
        assert_eq!(Screen::new(1001, 1, 0).err(), Some(TermError::BadSize));
        let mut small = [0u32; 3];
        assert_eq!(s.snapshot(&mut small), Err(TermError::BufferTooSmall));
    }

    #[test]
    fn the_clipboard_is_out_of_reach() {
        let mut s = Screen::new(10, 2, 0).unwrap();
        // OSC 52 query: a remote program asking for the clipboard.
        s.feed(b"\x1b]52;c;?\x07");
        assert!(s.take_replies().is_empty());
    }
}
