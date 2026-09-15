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
use std::io::{IsTerminal, Write};

use serde_json::{Map, Value};

use crate::cli::{ColorChoice, GlobalArgs, ThemeChoice};
use crate::exit::CliError;
use crate::theme::{self, ColorDepth, Palette, Role};

pub const SCHEMA_VERSION: u64 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tone {
    Good,
    Warn,
    Bad,
    Muted,
    Accent,
}

impl Tone {
    fn role(self) -> Role {
        match self {
            Tone::Good => Role::Good,
            Tone::Warn => Role::Warn,
            Tone::Bad => Role::Bad,
            Tone::Muted => Role::Muted,
            Tone::Accent => Role::Accent,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Output {
    pub json: bool,
    palette: Palette,
    err_palette: Palette,
    animate: bool,
    unicode: bool,
}

impl Output {
    pub fn new(global: &GlobalArgs) -> Self {
        Self::build(
            global.json,
            global.color,
            global.theme,
            std::io::stdout().is_terminal(),
            std::io::stderr().is_terminal(),
        )
    }

    pub fn build(
        json: bool,
        color: ColorChoice,
        theme_choice: ThemeChoice,
        stdout_tty: bool,
        stderr_tty: bool,
    ) -> Self {
        Self::assemble(
            json,
            color,
            theme_choice,
            stdout_tty,
            stderr_tty,
            vt_ready(false, stdout_tty),
            vt_ready(true, stderr_tty),
        )
    }

    pub fn assemble(
        json: bool,
        color: ColorChoice,
        theme_choice: ThemeChoice,
        stdout_tty: bool,
        stderr_tty: bool,
        stdout_vt: bool,
        stderr_vt: bool,
    ) -> Self {
        let appearance = theme::detect_appearance(theme_choice);
        let choice = if json { ColorChoice::Never } else { color };
        let depth = theme::detect_depth(choice, stdout_tty, stdout_vt);
        let err_depth = theme::detect_depth(choice, stderr_tty, stderr_vt);
        Self {
            json,
            palette: Palette::new(appearance, depth),
            err_palette: Palette::new(appearance, err_depth),
            animate: !json && stdout_tty && depth != ColorDepth::None,
            unicode: unicode_ready(),
        }
    }

    pub fn ansi(&self) -> bool {
        self.palette.depth != ColorDepth::None
    }

    pub fn animates(&self) -> bool {
        self.animate
    }

    pub fn unicode(&self) -> bool {
        self.unicode
    }

    pub fn stdout_is_terminal(&self) -> bool {
        !self.json && std::io::stdout().is_terminal()
    }

    pub fn json(&self, value: Value) {
        println!("{}", envelope(value));
        let _ = std::io::stdout().flush();
    }

    pub fn line(&self, text: impl AsRef<str>) {
        println!("{}", text.as_ref());
    }

    pub fn blank(&self) {
        println!();
    }

    pub fn bold(&self, text: &str) -> String {
        if !self.ansi() {
            return text.to_string();
        }
        self.wrap(text, "1".to_string())
    }

    pub fn dim(&self, text: &str) -> String {
        self.wrap(text, self.palette.sequence(Role::Muted))
    }

    pub fn tone(&self, text: &str, tone: Tone) -> String {
        self.wrap(text, self.palette.sequence(tone.role()))
    }

    pub fn accent(&self, text: &str) -> String {
        self.wrap(text, self.palette.sequence(Role::Accent))
    }

    pub fn strong_accent(&self, text: &str) -> String {
        let sequence = self.palette.sequence(Role::Accent);
        if sequence.is_empty() {
            return text.to_string();
        }
        self.wrap(text, format!("1;{}", sequence))
    }

    pub fn gradient(&self, text: &str) -> String {
        self.gradient_from(text, 0)
    }

    pub fn gradient_from(&self, text: &str, offset: usize) -> String {
        if !self.ansi() {
            return text.to_string();
        }
        if self.palette.depth == ColorDepth::Ansi16 {
            return self.accent(text);
        }
        let chars: Vec<char> = text.chars().collect();
        let span = chars.len().max(2);
        let mut painted = String::with_capacity(text.len() * 12);
        for (index, character) in chars.iter().enumerate() {
            let position = (index + offset) % span;
            let wave = if position * 2 <= span {
                position * 2
            } else {
                span * 2 - position * 2
            };
            let color = self
                .palette
                .gradient(Role::AccentDeep, Role::AccentSoft, span, wave.min(span));
            painted.push_str(&format!(
                "\x1b[{}m{}",
                self.palette.rgb_sequence(color, Role::Accent),
                character
            ));
        }
        painted.push_str("\x1b[0m");
        painted
    }

    pub fn heading(&self, text: &str) -> String {
        if !self.ansi() {
            return text.to_string();
        }
        format!("\x1b[1m{}", self.gradient(text))
    }

    pub fn dot(&self, tone: Tone) -> String {
        self.tone(if self.unicode { "\u{25CF}" } else { "*" }, tone)
    }

    pub fn mark(&self, tone: Tone) -> String {
        let glyph = match (tone, self.unicode) {
            (Tone::Good, true) => "\u{2713}",
            (Tone::Good, false) => "+",
            (Tone::Bad, true) => "\u{2717}",
            (Tone::Bad, false) => "x",
            (Tone::Warn, _) => "!",
            (Tone::Muted, true) | (Tone::Accent, true) => "\u{2022}",
            (Tone::Muted, false) | (Tone::Accent, false) => "-",
        };
        self.tone(glyph, tone)
    }

    fn wrap(&self, text: &str, code: String) -> String {
        if code.is_empty() {
            text.to_string()
        } else {
            format!("\x1b[{}m{}\x1b[0m", code, text)
        }
    }

    pub fn banner(&self, tone: Tone, title: &str) {
        let title = if tone == Tone::Good || tone == Tone::Accent {
            self.heading(title)
        } else {
            self.bold(title)
        };
        println!("{} {}", self.mark(tone), title);
    }

    pub fn fields(&self, rows: &[(&str, String)]) {
        let width = rows
            .iter()
            .map(|(label, _)| visible_len(label))
            .max()
            .unwrap_or(0);
        for (label, value) in rows {
            println!("  {}  {}", self.dim(&pad(label, width)), value);
        }
    }

    pub fn steps(&self, rows: &[(String, String)]) {
        let width = rows
            .iter()
            .map(|(text, _)| visible_len(text))
            .max()
            .unwrap_or(0);
        for (index, (text, command)) in rows.iter().enumerate() {
            println!(
                "  {} {}  {}",
                self.accent(&format!("{}.", index + 1)),
                pad(text, width),
                self.strong_accent(command)
            );
        }
    }

    pub fn table(&self, headers: &[&str], rows: &[Vec<String>]) {
        let mut widths: Vec<usize> = headers.iter().map(|h| visible_len(h)).collect();
        for row in rows {
            for (i, cell) in row.iter().enumerate() {
                if i < widths.len() {
                    widths[i] = widths[i].max(visible_len(cell));
                }
            }
        }
        let header = headers
            .iter()
            .enumerate()
            .map(|(i, h)| pad(h, widths[i]))
            .collect::<Vec<_>>()
            .join("  ");
        println!("  {}", self.dim(header.trim_end()));
        for row in rows {
            let line = row
                .iter()
                .enumerate()
                .map(|(i, cell)| pad(cell, widths.get(i).copied().unwrap_or(0)))
                .collect::<Vec<_>>()
                .join("  ");
            println!("  {}", line.trim_end());
        }
    }

    pub fn warn(&self, text: impl AsRef<str>) {
        if self.json {
            return;
        }
        let sequence = self.err_palette.sequence(Role::Warn);
        let label = if sequence.is_empty() {
            "warning:".to_string()
        } else {
            format!("\x1b[1;{}mwarning:\x1b[0m", sequence)
        };
        eprintln!("{} {}", label, text.as_ref());
    }

    pub fn error(&self, err: &CliError) {
        if self.json {
            let mut map = Map::new();
            map.insert("error".to_string(), err.to_json());
            self.json(Value::Object(map));
            return;
        }
        let sequence = self.err_palette.sequence(Role::Bad);
        let label = if sequence.is_empty() {
            "error:".to_string()
        } else {
            format!("\x1b[1;{}merror:\x1b[0m", sequence)
        };
        eprintln!("{} {}", label, err.message);
        for (name, value) in error_details(err) {
            eprintln!("  {}  {}", self.err_dim(&pad(name, 9)), value);
        }
    }

    fn err_dim(&self, text: &str) -> String {
        let sequence = self.err_palette.sequence(Role::Muted);
        if sequence.is_empty() {
            return text.to_string();
        }
        format!("\x1b[{}m{}\x1b[0m", sequence, text)
    }
}

pub fn error_details(err: &CliError) -> Vec<(&'static str, String)> {
    let mut rows = Vec::new();
    match err.reference() {
        Some(reference) => rows.push(("reference", format!("{} ({})", reference, err.code))),
        None => rows.push(("reference", err.code.clone())),
    }
    if let Some(hint) = &err.hint {
        rows.push(("next step", hint.clone()));
    }
    if let Some(reference) = err.reference() {
        rows.push(("help", format!("aster-bridge errors {}", reference)));
    }
    rows
}

fn unicode_ready() -> bool {
    if !cfg!(windows) {
        return true;
    }
    std::env::var_os("WT_SESSION").is_some()
        || std::env::var_os("TERM").is_some()
        || std::env::var_os("TERM_PROGRAM").is_some()
}

fn vt_ready(stderr: bool, is_terminal: bool) -> bool {
    if !is_terminal {
        return true;
    }
    enable_ansi(stderr)
}

#[cfg(windows)]
fn enable_ansi(stderr: bool) -> bool {
    use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows_sys::Win32::System::Console::{
        GetConsoleMode, GetStdHandle, SetConsoleMode, ENABLE_VIRTUAL_TERMINAL_PROCESSING,
        STD_ERROR_HANDLE, STD_OUTPUT_HANDLE,
    };
    unsafe {
        let handle = GetStdHandle(if stderr { STD_ERROR_HANDLE } else { STD_OUTPUT_HANDLE });
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            return false;
        }
        let mut mode = 0;
        if GetConsoleMode(handle, &mut mode) == 0 {
            return false;
        }
        if mode & ENABLE_VIRTUAL_TERMINAL_PROCESSING != 0 {
            return true;
        }
        SetConsoleMode(handle, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING) != 0
    }
}

#[cfg(not(windows))]
fn enable_ansi(_stderr: bool) -> bool {
    true
}

pub fn envelope(value: Value) -> String {
    let mut map = Map::new();
    map.insert("schema".to_string(), Value::from(SCHEMA_VERSION));
    match value {
        Value::Object(object) => {
            for (key, item) in object {
                if key != "schema" {
                    map.insert(key, item);
                }
            }
        }
        Value::Null => {}
        other => {
            map.insert("data".to_string(), other);
        }
    }
    Value::Object(map).to_string()
}

pub fn visible_len(text: &str) -> usize {
    let mut count = 0;
    let mut in_escape = false;
    for c in text.chars() {
        if in_escape {
            if c == 'm' {
                in_escape = false;
            }
        } else if c == '\x1b' {
            in_escape = true;
        } else {
            count += 1;
        }
    }
    count
}

fn pad(text: &str, width: usize) -> String {
    let len = visible_len(text);
    if len >= width {
        text.to_string()
    } else {
        format!("{}{}", text, " ".repeat(width - len))
    }
}

pub fn format_timestamp(unix: i64) -> String {
    use chrono::TimeZone;
    match chrono::Local.timestamp_opt(unix, 0).single() {
        Some(t) => t.format("%Y-%m-%d %H:%M").to_string(),
        None => "-".to_string(),
    }
}

pub fn format_elapsed(seconds: i64) -> String {
    let seconds = seconds.max(0);
    if seconds < 60 {
        return format!("{} seconds", seconds);
    }
    let minutes = seconds / 60;
    if minutes < 60 {
        return plural_unit(minutes, "minute");
    }
    let hours = minutes / 60;
    if hours < 24 {
        return plural_unit(hours, "hour");
    }
    plural_unit(hours / 24, "day")
}

pub fn format_relative(unix: i64, now: i64) -> String {
    let difference = now - unix;
    if difference < 0 {
        return format_timestamp(unix);
    }
    if difference < 45 {
        return "just now".to_string();
    }
    format!("{} ago", format_elapsed(difference))
}

fn plural_unit(count: i64, unit: &str) -> String {
    if count == 1 {
        format!("1 {}", unit)
    } else {
        format!("{} {}s", count, unit)
    }
}

pub fn title_case(text: &str) -> String {
    let mut chars = text.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
        None => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn painted(theme_choice: ThemeChoice) -> Output {
        Output::assemble(
            false,
            ColorChoice::Always,
            theme_choice,
            true,
            true,
            true,
            true,
        )
    }

    fn plain() -> Output {
        Output::build(false, ColorChoice::Never, ThemeChoice::Dark, true, true)
    }

    #[test]
    fn envelope_always_carries_schema() {
        let text = envelope(serde_json::json!({"running": true, "schema": 99}));
        let parsed: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(parsed["schema"], 1);
        assert_eq!(parsed["running"], true);
    }

    #[test]
    fn visible_len_ignores_color_codes() {
        assert_eq!(visible_len("\x1b[32mok\x1b[0m"), 2);
        assert_eq!(pad("\x1b[1mab\x1b[0m", 4), "\x1b[1mab\x1b[0m  ");
    }

    #[test]
    fn json_mode_never_colors_or_animates() {
        let out = Output::build(true, ColorChoice::Always, ThemeChoice::Dark, true, true);
        assert!(!out.animates());
        assert_eq!(out.accent("hi"), "hi");
        assert_eq!(out.gradient("hi"), "hi");
        assert_eq!(out.dim("hi"), "hi");
        assert_eq!(out.bold("hi"), "hi");
    }

    #[test]
    fn color_never_leaves_the_text_bare() {
        let out = plain();
        assert_eq!(out.accent("hi"), "hi");
        assert_eq!(out.tone("hi", Tone::Good), "hi");
        assert_eq!(out.heading("hi"), "hi");
        assert!(!out.animates());
        assert!(!out.dot(Tone::Good).contains('\x1b'));
    }

    #[test]
    fn a_pipe_gets_no_color_by_default() {
        let out = Output::build(false, ColorChoice::Auto, ThemeChoice::Dark, false, false);
        assert!(!out.ansi());
        assert!(!out.animates());
        assert_eq!(out.accent("hi"), "hi");
        assert_eq!(out.bold("hi"), "hi");
    }

    #[test]
    fn a_muted_banner_writes_no_escapes_to_a_pipe() {
        let out = Output::build(false, ColorChoice::Auto, ThemeChoice::Dark, false, false);
        assert!(!out.bold("No app passwords").contains('\x1b'));
        assert!(!out.mark(Tone::Muted).contains('\x1b'));
    }

    #[test]
    fn light_and_dark_use_different_blues() {
        let dark = painted(ThemeChoice::Dark).accent("aster");
        let light = painted(ThemeChoice::Light).accent("aster");
        assert!(dark.contains('\x1b'));
        assert!(light.contains('\x1b'));
        assert_ne!(dark, light);
    }

    #[test]
    fn gradient_paints_every_character_and_resets() {
        let out = painted(ThemeChoice::Dark);
        let text = out.gradient("aster");
        assert_eq!(visible_len(&text), 5);
        assert!(text.ends_with("\x1b[0m"));
    }

    #[test]
    fn marks_carry_meaning_without_color() {
        let out = plain();
        assert_ne!(out.mark(Tone::Good), out.mark(Tone::Bad));
        assert_ne!(out.mark(Tone::Warn), out.mark(Tone::Good));
    }

    #[test]
    fn elapsed_and_relative_read_as_sentences() {
        assert_eq!(format_elapsed(5), "5 seconds");
        assert_eq!(format_elapsed(60), "1 minute");
        assert_eq!(format_elapsed(7200), "2 hours");
        assert_eq!(format_elapsed(172_800), "2 days");
        assert_eq!(format_relative(100, 110), "just now");
        assert_eq!(format_relative(0, 120), "2 minutes ago");
    }
}
