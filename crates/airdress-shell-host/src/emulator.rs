//! The session's terminal emulator: what a snapshot is drawn from (design
//! §7.1, §7.3, task C.2; the choice is argued in `docs/terminal-emulator.md`).
//!
//! Every byte the PTY writes is fed here as well as to the journal. When a
//! client attaches, or falls too far behind, it gets a **snapshot** instead
//! of the backlog: a VT byte sequence that, written into a fresh terminal of
//! the same size, reproduces the screen, the cursor, the modes a program
//! set, and as much scrollback as fits.
//!
//! The emulator is `vt100` (MIT). Its callbacks also tell the session when
//! the program rang the bell, which is the terminal tier's only attention
//! signal (D-20).

/// The callbacks the emulator reports.
#[derive(Debug, Default)]
pub struct Signals {
    /// Bells since the last [`Emulator::take_bells`].
    pub bells: u32,
}

impl vt100::Callbacks for Signals {
    fn audible_bell(&mut self, _: &mut vt100::Screen) {
        self.bells = self.bells.saturating_add(1);
    }
}

/// One session's emulator.
pub struct Emulator {
    parser: vt100::Parser<Signals>,
    scrollback: usize,
}

impl std::fmt::Debug for Emulator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (rows, cols) = self.parser.screen().size();
        f.debug_struct("Emulator")
            .field("rows", &rows)
            .field("cols", &cols)
            .finish_non_exhaustive()
    }
}

impl Emulator {
    /// A `cols`×`rows` screen keeping up to `scrollback` lines.
    pub fn new(cols: u16, rows: u16, scrollback: usize) -> Self {
        Self {
            parser: vt100::Parser::new_with_callbacks(
                rows.max(1),
                cols.max(1),
                scrollback,
                Signals::default(),
            ),
            scrollback,
        }
    }

    /// Feed PTY output.
    pub fn process(&mut self, bytes: &[u8]) {
        self.parser.process(bytes);
    }

    /// The typist changed the size.
    ///
    /// **A shorter screen keeps its bottom, not its top.** `vt100` cuts the
    /// rows below the new height, which is the part a person is looking
    /// at: the prompt, the cursor and the last lines written. A terminal
    /// does the opposite — the top lines scroll into the scrollback and the
    /// cursor's line stays — and the program, which is told the new size by
    /// `SIGWINCH`, assumes it did. So when the cursor would fall off, the
    /// screen is first scrolled up by as many lines, and the cursor put back
    /// on the line it was on. Without this, a session resized from a tall
    /// phone to a laptop sent every later attach a snapshot without its
    /// visible screen (found live on a test operator, 2026-10-04: the CLI drew the
    /// scrollback and a fresh prompt, and none of the lines the phone
    /// showed).
    ///
    /// The alternate screen has no scrollback and its program redraws on
    /// `SIGWINCH`; it is resized as it is.
    pub fn resize(&mut self, cols: u16, rows: u16) {
        let (cols, rows) = (cols.max(1), rows.max(1));
        let screen = self.parser.screen();
        let (old_rows, _) = screen.size();
        let (row, col) = screen.cursor_position();
        if rows < old_rows && row >= rows && !screen.alternate_screen() {
            let lift = row + 1 - rows;
            // The last row, then one line feed per line to lift: each scrolls
            // the top line into the scrollback, as a terminal's own shrink
            // does. Neither sequence touches the program's attributes.
            let mut seq = format!("\x1b[{old_rows};1H").into_bytes();
            seq.extend(std::iter::repeat_n(b'\n', usize::from(lift)));
            self.parser.process(&seq);
            self.parser.screen_mut().set_size(rows, cols);
            self.parser
                .process(format!("\x1b[{};{}H", row - lift + 1, col + 1).as_bytes());
            return;
        }
        self.parser.screen_mut().set_size(rows, cols);
    }

    /// `(cols, rows)`.
    pub fn size(&self) -> (u16, u16) {
        let (rows, cols) = self.parser.screen().size();
        (cols, rows)
    }

    /// How many bells rang since the last call.
    pub fn take_bells(&mut self) -> u32 {
        std::mem::take(&mut self.parser.callbacks_mut().bells)
    }

    /// The screen as plain text, for tests and the raw tier.
    pub fn text(&self) -> String {
        self.parser.screen().contents()
    }

    /// The cursor, `(row, col)`.
    pub fn cursor(&self) -> (u16, u16) {
        self.parser.screen().cursor_position()
    }

    /// Every scrollback line, oldest first, each as a formatted row and
    /// whether the terminal wrapped it into the row after (the next
    /// scrollback row, or for the newest one the screen's first row).
    fn scrollback_rows(&mut self) -> Vec<(Vec<u8>, bool)> {
        let screen = self.parser.screen_mut();
        let (rows, cols) = screen.size();
        screen.set_scrollback(usize::MAX);
        let total = screen.scrollback();
        let mut out = Vec::with_capacity(total);
        // The view at offset `o` shows scrollback lines `total - o …`; take
        // its first row, one offset at a time, from the oldest down.
        let mut offset = total;
        while offset > 0 {
            screen.set_scrollback(offset);
            let take = offset.min(rows as usize);
            for (i, row) in screen.rows_formatted(0, cols).take(take).enumerate() {
                // `take <= rows`, so the index fits the screen's row type.
                let wrapped = screen.row_wrapped(u16::try_from(i).unwrap_or(u16::MAX));
                out.push((row, wrapped));
            }
            offset -= take;
        }
        screen.set_scrollback(0);
        out
    }

    /// A snapshot no larger than `budget` bytes: the most recent scrollback
    /// lines that fit, pushed out of view, then the screen and its modes.
    ///
    /// Written into a fresh terminal of the same size, the visible screen,
    /// the cursor and the input modes come out as they are here.
    pub fn snapshot(&mut self, budget: usize) -> Vec<u8> {
        let screen = self.parser.screen().state_formatted();
        let (_, rows) = self.size();
        // Reset, home, clear below. Not `ESC [2J`: alacritty (the phone's
        // emulator) answers a whole-screen erase by scrolling the screen into
        // its scrollback, and on a just-reset screen that pushes one blank
        // row above the oldest line.
        let mut out: Vec<u8> = b"\x1bc\x1b[0m\x1b[H\x1b[J".to_vec();
        let room = budget.saturating_sub(screen.len() + out.len() + rows as usize * 2 + 16);
        if self.scrollback > 0 && room > 0 {
            let lines = self.scrollback_rows();
            let mut picked: Vec<&(Vec<u8>, bool)> = Vec::new();
            let mut used = 0usize;
            for l in lines.iter().rev() {
                let cost = l.0.len() + 6;
                if used + cost > room {
                    break;
                }
                used += cost;
                picked.push(l);
            }
            // Lines are separated, not terminated: a newline after the last
            // one would leave the cursor on a blank row, and the push below
            // would scroll that blank row into the client's scrollback too,
            // between the last history line and the screen.
            //
            // **A row the terminal wrapped gets no separator.** Its next row
            // is the same logical line, and the client must hold it as one:
            // writing on past the last column wraps there too, and marks the
            // row wrapped, as the program's own output did. A `\r\n` would
            // break the line in two, and a wider view would no longer rejoin
            // it.
            let mut wrapped = false;
            for (i, (l, w)) in picked.iter().rev().enumerate() {
                if i > 0 && !wrapped {
                    out.extend_from_slice(b"\r\n");
                }
                out.extend_from_slice(b"\x1b[0m");
                out.extend_from_slice(l);
                wrapped = *w;
            }
            if !picked.is_empty() {
                // Push every written line off the visible screen and into the
                // client's own scrollback before the screen is drawn: from the
                // last written row, `rows` newlines scroll exactly the written
                // rows out.
                let mut push = rows;
                if wrapped {
                    // The newest history line wraps into the screen's first
                    // row (found on a test operator, 2026-10-05: the top row's `te +%T)`
                    // of `echo seg0-line $(date +%T)` was gone after a
                    // reattach). One blank written past the last column
                    // wraps the client's row as well, and moves the cursor
                    // to the row the continuation will occupy; one newline
                    // fewer then pushes the same rows out, and that row is
                    // the screen's first, which the screen below redraws.
                    out.extend_from_slice(b"\x1b[0m \r\x1b[K");
                    push -= 1;
                }
                for _ in 0..push {
                    out.extend_from_slice(b"\r\n");
                }
            }
        }
        out.extend_from_slice(&screen);
        out
    }

    /// The screen with every escape removed, line by line: the raw tier
    /// (design §9.5).
    pub fn plain_rows(&self) -> Vec<String> {
        let (_, cols) = self.parser.screen().size();
        self.parser.screen().rows(0, cols).collect()
    }

    /// The bytes one session's emulator holds, roughly: its grid and its
    /// scrollback, at the size of a cell. For the comparison in
    /// `docs/terminal-emulator.md`.
    pub fn approx_bytes(&self) -> usize {
        let (rows, cols) = self.parser.screen().size();
        (rows as usize + self.scrollback) * cols as usize * std::mem::size_of::<vt100::Cell>()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn replay(src: &mut Emulator) -> Emulator {
        let (cols, rows) = src.size();
        let snap = src.snapshot(1 << 20);
        let mut dst = Emulator::new(cols, rows, 100);
        dst.process(&snap);
        dst
    }

    #[test]
    fn a_snapshot_redraws_the_screen_cursor_and_colors() {
        let mut e = Emulator::new(40, 10, 100);
        e.process(b"hello \x1b[1;31mred\x1b[0m world\r\nline two\x1b[5;7H*");
        let d = replay(&mut e);
        assert_eq!(d.text(), e.text());
        assert_eq!(d.cursor(), e.cursor());
        assert_eq!(
            d.parser.screen().contents_formatted(),
            e.parser.screen().contents_formatted()
        );
    }

    #[test]
    fn a_full_screen_program_comes_back_on_the_alternate_screen() {
        let mut e = Emulator::new(80, 24, 100);
        e.process(b"$ vim\r\n\x1b[?1049h\x1b[?1h\x1b=\x1b[H\x1b[2J~\r\n~\r\n\x1b[24;1H\"x\" 0L");
        let d = replay(&mut e);
        assert!(d.parser.screen().alternate_screen() || d.text() == e.text());
        assert_eq!(d.text(), e.text());
        assert_eq!(
            d.parser.screen().application_cursor(),
            e.parser.screen().application_cursor()
        );
    }

    #[test]
    fn scrollback_comes_along_within_the_budget() {
        let mut e = Emulator::new(20, 5, 1000);
        for i in 0..50 {
            e.process(format!("line {i}\r\n").as_bytes());
        }
        let snap = e.snapshot(1 << 20);
        let s = String::from_utf8_lossy(&snap);
        assert!(s.contains("line 0"), "the oldest line is in");
        let small = e.snapshot(400);
        assert!(small.len() <= 400, "{}", small.len());
        let s = String::from_utf8_lossy(&small);
        assert!(!s.contains("line 0\r"), "the oldest lines go first");
        let d = {
            let mut d = Emulator::new(20, 5, 1000);
            d.process(&small);
            d
        };
        assert_eq!(d.text(), e.text(), "the screen survives a tight budget");
    }

    /// A client that reattaches gets a snapshot and then the live stream.
    /// What it shows must be what a client that never left shows, history
    /// included: a taller view (or scrolling back) reveals the lines the
    /// snapshot pushed into scrollback, and no blank row may sit between
    /// them and the screen. One did, between the last scrollback line and
    /// the first screen row, on a phone (2026-10-04).
    #[test]
    fn a_reattached_client_shows_what_one_that_never_left_shows() {
        for (lines, rows) in [(12, 5), (3, 5), (5, 5), (4, 5), (40, 24)] {
            let mut host = Emulator::new(20, rows, 1000);
            let mut stayed = airdress_term::Screen::new(20, rows, 1000).unwrap();
            let mut before = Vec::new();
            for i in 1..=lines {
                before.extend_from_slice(format!("L{i}\r\n").as_bytes());
            }
            host.process(&before);
            stayed.feed(&before);

            let mut back = airdress_term::Screen::new(80, 24, 1000).unwrap();
            back.reset(20, rows).unwrap();
            let snap = host.snapshot(1 << 20);
            back.feed(&snap);

            let live = format!("L{}\r\n$ ", lines + 1);
            host.process(live.as_bytes());
            stayed.feed(live.as_bytes());
            back.feed(live.as_bytes());
            assert_eq!(back.screen_text(), stayed.screen_text(), "{lines}/{rows}");
            assert_eq!(
                back.state().history,
                stayed.state().history,
                "{lines}/{rows}"
            );

            // A taller view pulls history down into sight.
            stayed.resize(20, rows + 30).unwrap();
            back.resize(20, rows + 30).unwrap();
            assert_eq!(back.screen_text(), stayed.screen_text(), "{lines}/{rows}");
        }
    }

    /// A line the terminal wrapped, split across the history/screen
    /// boundary: its start is the last scrollback row, its continuation the
    /// first screen row. A reattached client must show the continuation and
    /// keep the two rows one logical line. On a test operator (2026-10-05) a phone's
    /// top row lost `te +%T)` of `echo seg0-line $(date +%T)` this way.
    #[test]
    fn a_line_wrapped_across_the_history_boundary_comes_back_whole() {
        let cmd = "$ echo seg0-line $(date +%T)";
        for (cols, rows) in [(20u16, 5u16), (19, 5), (12, 4), (20, 24)] {
            // Every split position of the long line against the top of the
            // screen, including the one that puts its continuation first.
            for after in 0..=rows + 2 {
                let mut host = Emulator::new(cols, rows, 1000);
                let mut stayed = airdress_term::Screen::new(cols, rows, 1000).unwrap();
                let mut before = Vec::new();
                for i in 1..=rows + 3 {
                    before.extend_from_slice(format!("L{i}\r\n").as_bytes());
                }
                before.extend_from_slice(format!("{cmd}\r\n").as_bytes());
                for i in 0..after {
                    before.extend_from_slice(format!("seg0-line {i}\r\n").as_bytes());
                }
                before.extend_from_slice(b"$ ");
                host.process(&before);
                stayed.feed(&before);

                let mut back = airdress_term::Screen::new(80, 24, 1000).unwrap();
                back.reset(cols, rows).unwrap();
                back.feed(&host.snapshot(1 << 20));
                let case = format!("{cols}x{rows} after={after}");
                assert_eq!(back.screen_text(), stayed.screen_text(), "{case}");
                assert_eq!(back.state().history, stayed.state().history, "{case}");
                assert_eq!(back.state().cursor_row, stayed.state().cursor_row, "{case}");

                // Live output after the snapshot lands where it would have.
                let live = b"date\r\n00:31:58\r\n$ ";
                host.process(live);
                stayed.feed(live);
                back.feed(live);
                assert_eq!(back.screen_text(), stayed.screen_text(), "{case} live");

                // A wider view rejoins the wrapped line from both halves:
                // the continuation is still one line with its start.
                stayed.resize(cols + 40, rows + 30).unwrap();
                back.resize(cols + 40, rows + 30).unwrap();
                assert_eq!(back.screen_text(), stayed.screen_text(), "{case} reflow");
            }
        }
    }

    #[test]
    fn a_shorter_screen_keeps_the_lines_by_the_cursor() {
        // A phone's tall screen, full, then the typist moves to a laptop's
        // shorter one: what is by the prompt is what must survive.
        let mut e = Emulator::new(46, 40, 1000);
        for i in 1..=60 {
            e.process(format!("L{i}\r\n").as_bytes());
        }
        e.process(b"$ echo reattached\r\nreattached\r\n$ from-tablet\r\n$ from-s23\r\n$ ");
        e.resize(120, 24);
        let text = e.text();
        for line in ["reattached", "from-tablet", "from-s23"] {
            assert!(text.contains(line), "{line} is on the screen:\n{text}");
        }
        assert_eq!(e.cursor(), (23, 2), "the cursor stays on the prompt");
        assert!(text.trim_end().ends_with('$'), "{text}");
        // The lines lifted off the top went to the scrollback, so a
        // snapshot still carries them, and the screen after them.
        let snap = String::from_utf8_lossy(&e.snapshot(1 << 20)).into_owned();
        assert!(snap.contains("L1\r") && snap.contains("L40"), "{snap}");
        assert!(snap.contains("from-s23"));
        let d = replay(&mut e);
        assert_eq!(d.text(), e.text());
        assert_eq!(d.cursor(), e.cursor());
    }

    /// The test-operator case end to end, in the style of the reattach test above: a
    /// typist on a tall phone, the session moved to a shorter terminal, then
    /// a client attaches. What it draws from the snapshot must be what a
    /// terminal that saw the whole stream and was resized the same way
    /// shows: the visible screen by the prompt, and the history above it.
    #[test]
    fn an_attach_after_the_typist_shrank_the_screen_shows_the_visible_screen() {
        let (cols, tall, short) = (46u16, 40u16, 24u16);
        let mut host = Emulator::new(cols, tall, 1000);
        let mut stayed = airdress_term::Screen::new(cols, tall, 1000).unwrap();
        let mut stream = Vec::new();
        for i in 1..=60 {
            stream.extend_from_slice(format!("L{i}\r\n").as_bytes());
        }
        stream.extend_from_slice(
            b"$ echo reattached\r\nreattached\r\n$ from-tablet\r\n$ from-s23\r\n$ ",
        );
        host.process(&stream);
        stayed.feed(&stream);
        host.resize(cols, short);
        stayed.resize(cols, short).unwrap();

        let mut back = airdress_term::Screen::new(80, 24, 1000).unwrap();
        back.reset(cols, short).unwrap();
        back.feed(&host.snapshot(1 << 20));
        let live = b"echo after\r\nafter\r\n$ ";
        host.process(live);
        stayed.feed(live);
        back.feed(live);
        assert_eq!(back.screen_text(), stayed.screen_text());
        assert!(
            back.screen_text().contains("from-s23"),
            "{}",
            back.screen_text()
        );
        assert_eq!(back.state().history, stayed.state().history);
        assert_eq!(back.state().cursor_row, stayed.state().cursor_row);
    }

    #[test]
    fn a_shorter_screen_with_the_cursor_on_it_is_cut_at_the_bottom() {
        // The cursor at the top (a cleared screen): nothing is lifted.
        let mut e = Emulator::new(40, 30, 100);
        e.process(
            b"\x1b[H\x1b[2J\
            top line\r\n$ ",
        );
        e.resize(40, 10);
        assert_eq!(e.cursor(), (1, 2));
        assert!(e.text().starts_with("top line"));
    }

    #[test]
    fn the_bell_is_counted() {
        let mut e = Emulator::new(10, 2, 0);
        e.process(b"a\x07b\x07");
        // A BEL that ends an OSC title is not a bell.
        e.process(b"\x1b]2;title\x07");
        assert_eq!(e.take_bells(), 2);
        assert_eq!(e.take_bells(), 0);
    }
}
