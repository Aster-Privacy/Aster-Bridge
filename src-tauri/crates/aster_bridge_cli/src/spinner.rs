//
// Aster Communications Inc.
//
// Copyright (c) 2026 Aster Communications Inc.
//
// This file is part of this project.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.
//
use std::future::Future;
use std::io::Write;
use std::time::Duration;

use crate::output::{terminal_width, truncate_visible, visible_len, Output, Tone};

pub const FRAME_INTERVAL: Duration = Duration::from_millis(100);

const UNICODE_FRAMES: [&str; 10] = [
    "\u{280b}", "\u{2819}", "\u{2839}", "\u{2838}", "\u{283c}", "\u{2834}", "\u{2826}", "\u{2827}",
    "\u{2807}", "\u{280f}",
];
const ASCII_FRAMES: [&str; 4] = ["|", "/", "-", "\\"];

pub struct Spinner {
    out: Output,
    label: String,
    detail: String,
    frame: usize,
    drawn: usize,
    painted: String,
    cursor_hidden: bool,
}

impl Spinner {
    pub fn start(out: &Output, label: impl Into<String>) -> Self {
        let mut spinner = Self {
            out: *out,
            label: label.into(),
            detail: String::new(),
            frame: 0,
            drawn: 0,
            painted: String::new(),
            cursor_hidden: false,
        };
        if spinner.out.animates() {
            spinner.draw();
        } else if !spinner.out.json {
            spinner.out.line(&spinner.label);
        }
        spinner
    }

    pub fn set_detail(&mut self, detail: impl Into<String>) {
        self.detail = detail.into();
    }

    pub fn tick(&mut self) {
        if !self.out.animates() {
            return;
        }
        self.frame = self.frame.wrapping_add(1);
        self.draw();
    }

    pub fn clear(&mut self) {
        self.painted.clear();
        if self.drawn == 0 {
            self.show_cursor();
            return;
        }
        let mut frame = String::with_capacity(self.drawn + 8);
        if self.out.ansi() {
            frame.push_str("\r\x1b[2K");
        } else {
            frame.push('\r');
            frame.push_str(&" ".repeat(self.drawn));
            frame.push('\r');
        }
        self.drawn = 0;
        self.write(&frame);
        self.show_cursor();
    }

    fn write(&self, frame: &str) {
        let mut stdout = std::io::stdout().lock();
        let _ = stdout.write_all(frame.as_bytes());
        let _ = stdout.flush();
    }

    fn hide_cursor(&mut self) {
        if self.cursor_hidden || !self.out.ansi() {
            return;
        }
        self.cursor_hidden = true;
        self.write("\x1b[?25l");
    }

    fn show_cursor(&mut self) {
        if !self.cursor_hidden {
            return;
        }
        self.cursor_hidden = false;
        self.write("\x1b[?25h");
    }

    pub fn finish(&mut self, tone: Tone, text: impl AsRef<str>) {
        self.clear();
        if self.out.json {
            return;
        }
        self.out
            .line(format!("{} {}", self.out.mark(tone), text.as_ref()));
    }

    fn draw(&mut self) {
        if !viewport_follows_cursor() {
            return;
        }
        if let Some(frame) = self.compose(terminal_width()) {
            self.hide_cursor();
            self.write(&frame);
        }
    }

    fn compose(&mut self, width: Option<usize>) -> Option<String> {
        let frames = self.frames();
        let glyph = frames[self.frame % frames.len()];
        let mut rendered = format!(
            "{} {}",
            self.out.tone(glyph, Tone::Accent),
            self.out.sweep(&self.label, self.frame)
        );
        if !self.detail.is_empty() {
            rendered.push_str(&format!("  {}", self.out.dim(&self.detail)));
        }
        if let Some(width) = width {
            let room = width.saturating_sub(1);
            if room == 0 {
                return None;
            }
            rendered = truncate_visible(&rendered, room);
        }
        if rendered == self.painted {
            return None;
        }
        let visible = visible_len(&rendered);
        let mut frame = String::with_capacity(rendered.len() + 16);
        frame.push('\r');
        if self.out.ansi() {
            frame.push_str("\x1b[2K");
            frame.push_str(&rendered);
        } else {
            frame.push_str(&rendered);
            if self.drawn > visible {
                frame.push_str(&" ".repeat(self.drawn - visible));
                frame.push('\r');
                frame.push_str(&rendered);
            }
        }
        self.drawn = visible;
        self.painted = rendered;
        Some(frame)
    }

    fn frames(&self) -> &'static [&'static str] {
        if self.out.unicode() {
            &UNICODE_FRAMES
        } else {
            &ASCII_FRAMES
        }
    }
}

#[cfg(windows)]
fn viewport_follows_cursor() -> bool {
    use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows_sys::Win32::System::Console::{
        GetConsoleScreenBufferInfo, GetStdHandle, CONSOLE_SCREEN_BUFFER_INFO, STD_OUTPUT_HANDLE,
    };
    unsafe {
        let handle = GetStdHandle(STD_OUTPUT_HANDLE);
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            return true;
        }
        let mut info: CONSOLE_SCREEN_BUFFER_INFO = std::mem::zeroed();
        if GetConsoleScreenBufferInfo(handle, &mut info) == 0 {
            return true;
        }
        info.dwCursorPosition.Y >= info.srWindow.Top
            && info.dwCursorPosition.Y <= info.srWindow.Bottom
    }
}

#[cfg(not(windows))]
fn viewport_follows_cursor() -> bool {
    true
}

pub async fn while_working<F, T>(out: &Output, quiet: bool, label: &str, work: F) -> T
where
    F: Future<Output = T>,
{
    if quiet {
        return work.await;
    }
    let mut spinner = Spinner::start(out, label);
    tokio::pin!(work);
    let mut ticker = tokio::time::interval(FRAME_INTERVAL);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            value = &mut work => {
                spinner.clear();
                return value;
            }
            _ = ticker.tick() => spinner.tick(),
        }
    }
}

impl Drop for Spinner {
    fn drop(&mut self) {
        self.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::{ColorChoice, ThemeChoice};

    fn plain() -> Output {
        Output::build(false, ColorChoice::Never, ThemeChoice::Dark, false, false)
    }

    fn animating() -> Output {
        Output::assemble(
            false,
            ColorChoice::Always,
            ThemeChoice::Dark,
            true,
            true,
            true,
            true,
        )
    }

    #[test]
    fn a_frame_is_one_write_that_starts_by_clearing_the_line() {
        let out = animating();
        let mut spinner = Spinner::start(&out, "Listening for your email app");
        spinner.painted.clear();
        let frame = spinner.compose(Some(120)).expect("first frame");
        assert!(frame.starts_with("\r\x1b[2K"));
        assert_eq!(frame.matches('\r').count(), 1);
        assert_eq!(frame.matches("\x1b[2K").count(), 1);
        assert!(frame.ends_with("\x1b[0m"));
    }

    #[test]
    fn an_unchanged_frame_is_not_written_again() {
        let out = animating();
        let mut spinner = Spinner::start(&out, "Working");
        spinner.painted.clear();
        assert!(spinner.compose(Some(120)).is_some());
        assert!(spinner.compose(Some(120)).is_none());
        spinner.frame += 1;
        assert!(spinner.compose(Some(120)).is_some());
    }

    #[test]
    fn a_frame_never_outgrows_the_terminal() {
        let out = animating();
        let mut spinner = Spinner::start(&out, "Listening for your email app");
        spinner.set_detail("up 3m 20s  \u{b7}  Press Control-C to stop.");
        for width in [8usize, 20, 40, 64] {
            spinner.painted.clear();
            spinner.frame += 1;
            let frame = spinner.compose(Some(width)).expect("frame");
            let body = frame.trim_start_matches('\r').trim_start_matches("\x1b[2K");
            assert!(
                visible_len(body) < width,
                "width {} produced {} columns",
                width,
                visible_len(body)
            );
        }
        spinner.painted.clear();
        assert!(spinner.compose(Some(1)).is_none());
    }

    #[test]
    fn the_label_animates_across_frames() {
        let out = animating();
        let mut spinner = Spinner::start(&out, "Listening for your email app");
        let mut seen = std::collections::HashSet::new();
        for _ in 0..12 {
            spinner.frame += 1;
            spinner.painted.clear();
            seen.insert(spinner.compose(Some(120)).expect("frame"));
        }
        assert_eq!(seen.len(), 12);
    }

    #[test]
    fn clearing_restores_the_cursor_and_forgets_the_frame() {
        let out = animating();
        let mut spinner = Spinner::start(&out, "Working");
        spinner.painted.clear();
        let _ = spinner.compose(Some(120));
        assert!(!spinner.painted.is_empty());
        spinner.clear();
        assert_eq!(spinner.drawn, 0);
        assert!(spinner.painted.is_empty());
        assert!(!spinner.cursor_hidden);
    }

    #[test]
    fn a_non_animating_output_never_spins() {
        let out = plain();
        let mut spinner = Spinner::start(&out, "Waiting");
        spinner.tick();
        spinner.tick();
        assert_eq!(spinner.drawn, 0);
    }

    #[test]
    fn json_output_writes_no_spinner_text() {
        let out = Output::build(true, ColorChoice::Always, ThemeChoice::Dark, true, true);
        let mut spinner = Spinner::start(&out, "Waiting");
        spinner.tick();
        spinner.finish(Tone::Good, "done");
        assert_eq!(spinner.drawn, 0);
    }

    #[test]
    fn an_animating_output_draws_and_clears() {
        let out = Output::assemble(
            false,
            ColorChoice::Always,
            ThemeChoice::Dark,
            true,
            true,
            true,
            true,
        );
        let mut spinner = Spinner::start(&out, "Waiting for you to enter the code");
        spinner.set_detail("expires in 9:12");
        spinner.tick();
        assert!(spinner.drawn > 0);
        spinner.clear();
        assert_eq!(spinner.drawn, 0);
    }
}
