# The snapshot emulator: `vt100`

The host keeps a terminal emulator per session for one purpose: to draw a
**snapshot** — a VT byte sequence that reproduces the screen, the cursor,
the modes the program set, and some scrollback — for a device that attaches,
or that fell too far behind to be sent the backlog (design §7.1, §7.3,
FR-S3, FR-S9). The device renders with its own terminal; the host's
emulator is never shown to anyone.

Decision: **`vt100` 0.16** (MIT). Choice made 2026-10-04 (task C.2).

## The candidates

| | `vt100` 0.16.2 | `alacritty_terminal` 0.26 | `termwiz` 0.23 |
|---|---|---|---|
| Licence | MIT | Apache-2.0 | MIT |
| What it is | a parser and screen model, nothing else | the terminal core of a GPU terminal | a toolkit: parser, surface, widgets, input, terminal I/O |
| Snapshot API | `state_formatted()` (screen, modes, cursor), `rows_formatted()` per row, scrollback by offset | none; walk the grid and re-encode every cell's attributes yourself | `Surface::screen_chars_to_string()` / changes; a surface, not a VT model of a pty |
| Bell, title callbacks | `Callbacks` trait | event listener | yes |
| Dependencies added | 3 small crates | the event loop, `parking_lot`, `polling`, `vte`, … | many (`terminfo`, `phf`, `wezterm-*`) |
| API stability | small and stable | follows the alacritty app; breaks between minors | follows wezterm |

## Measured on the host, 2026-10-04

Each program was run on a real 120×40 PTY through `pty::spawn`, its output
fed to the emulator, the snapshot taken under a 60 KiB budget and replayed
into a fresh emulator of the same size
(`cargo run --example emulator_measure -- <program>`):

| Program | Snapshot | Screen text equal | Cursor equal |
|---|---|---|---|
| `htop` | 7,110 B | yes | yes |
| `top` | 4,740 B | yes | yes |
| `less /etc/services` | 1,683 B | yes | yes |
| `vi -u NONE /etc/services` | 1,359 B | yes | yes |
| `nano /etc/services` | 2,113 B | yes | yes |

The unit tests hold the same round trip for colors, the alternate screen
and application-cursor mode (`emulator.rs`).

**Memory per 120×40 session** (release build, ten emulators, resident set
difference): about **159 KiB** empty, about **7.6 MiB** with all 2,000
lines of scrollback full of 120-column lines (`--example emulator_measure
-- --memory`). That sits inside NFR-3's "≤ 8 MiB per idle session plus its
journal", with little room: `[host] scrollback_lines` is the lever.

**Not measured:** a `vttest` score for any of the three (it is interactive
and was not scripted here), and the other two candidates' memory and
fidelity; their columns above are from their documentation and manifests.
A harness TUI was not available on this machine; `htop` stands in for a
full-screen program that redraws continuously.

## Why `vt100`

- The snapshot is the whole job, and `vt100` already produces one
  (`state_formatted`), plus formatted scrollback rows. With
  `alacritty_terminal` the host would write and maintain its own grid
  re-encoder, which is the part most likely to be subtly wrong.
- It is small, dependency-light and stable, in a process the person runs
  on their own machine and that must stay cheap (NFR-3).
- The fidelity measured on real full-screen programs is exact for what a
  device needs: the screen, the cursor and the modes.

## Its limits, and what the host does about them

- It answers no terminal queries (device attributes, cursor position). With
  no device attached, a program that waits for an answer waits; the device
  that attaches answers from its own terminal.
- Scrollback in a snapshot is limited by the operator's frame ceiling (64
  KiB a record): the newest lines that fit are sent, the screen always is.
