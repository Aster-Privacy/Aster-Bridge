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

use crate::output::{visible_len, Output, Tone};

pub const FRAME_INTERVAL: Duration = Duration::from_millis(90);

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
}

impl Spinner {
    pub fn start(out: &Output, label: impl Into<String>) -> Self {
        let mut spinner = Self {
            out: *out,
            label: label.into(),
            detail: String::new(),
            frame: 0,
            drawn: 0,
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
        if self.drawn == 0 {
            return;
        }
        if self.out.ansi() {
            print!("\r\x1b[2K");
        } else {
            print!("\r{}\r", " ".repeat(self.drawn));
        }
        let _ = std::io::stdout().flush();
        self.drawn = 0;
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
        let frames = self.frames();
        let glyph = frames[self.frame % frames.len()];
        let painted_glyph = self.out.tone(glyph, Tone::Accent);
        let painted_label = self.out.gradient_from(&self.label, self.frame / 2);
        let mut rendered = format!("{} {}", painted_glyph, painted_label);
        if !self.detail.is_empty() {
            rendered.push_str(&format!("  {}", self.out.dim(&self.detail)));
        }
        self.clear();
        print!("{}", rendered);
        let _ = std::io::stdout().flush();
        self.drawn = visible_len(&rendered);
    }

    fn frames(&self) -> &'static [&'static str] {
        if self.out.unicode() {
            &UNICODE_FRAMES
        } else {
            &ASCII_FRAMES
        }
    }
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
