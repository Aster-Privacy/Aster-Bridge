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

const SWEEP_TAIL: usize = 6;

fn sweep_period(width: usize) -> usize {
    width.saturating_sub(1).max(1) * 2
}

fn sweep_levels(width: usize, frame: usize) -> Vec<usize> {
    if width == 0 {
        return Vec::new();
    }
    let travel = width - 1;
    let period = sweep_period(width);
    let step = frame % period;
    let head = if step <= travel { step } else { period - step };
    (0..width)
        .map(|index| SWEEP_TAIL - index.abs_diff(head).min(SWEEP_TAIL))
        .collect()
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

    pub fn sweep(&self, text: &str, frame: usize) -> String {
        if !self.ansi() {
            return text.to_string();
        }
        if self.palette.depth == ColorDepth::Ansi16 {
            return self.accent(text);
        }
        let chars: Vec<char> = text.chars().collect();
        if chars.is_empty() {
            return String::new();
        }
        let levels = sweep_levels(chars.len(), frame);
        let mut painted = String::with_capacity(text.len() * 4);
        let mut previous = usize::MAX;
        for (character, level) in chars.iter().zip(levels) {
            if level != previous {
                let color =
                    self.palette
                        .gradient(Role::AccentDeep, Role::AccentSoft, SWEEP_TAIL, level);
                painted.push_str(&format!(
                    "\x1b[{}m",
                    self.palette.rgb_sequence(color, Role::Accent)
                ));
                previous = level;
            }
            painted.push(*character);
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
        let lively = tone == Tone::Good || tone == Tone::Accent;
        let glyph = if lively {
            self.dot(tone)
        } else {
            self.mark(tone)
        };
        let title = if lively {
            self.heading(title)
        } else {
            self.bold(title)
        };
        println!("{} {}", glyph, title);
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

pub fn terminal_width() -> Option<usize> {
    if let Some(columns) = std::env::var("COLUMNS")
        .ok()
        .and_then(|value| value.trim().parse::<usize>().ok())
    {
        if columns > 0 {
            return Some(columns);
        }
    }
    console_width()
}

#[cfg(windows)]
fn console_width() -> Option<usize> {
    use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows_sys::Win32::System::Console::{
        GetConsoleScreenBufferInfo, GetStdHandle, CONSOLE_SCREEN_BUFFER_INFO, STD_OUTPUT_HANDLE,
    };
    unsafe {
        let handle = GetStdHandle(STD_OUTPUT_HANDLE);
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            return None;
        }
        let mut info: CONSOLE_SCREEN_BUFFER_INFO = std::mem::zeroed();
        if GetConsoleScreenBufferInfo(handle, &mut info) == 0 {
            return None;
        }
        let width = i32::from(info.srWindow.Right) - i32::from(info.srWindow.Left) + 1;
        usize::try_from(width).ok().filter(|width| *width > 0)
    }
}

#[cfg(not(windows))]
fn console_width() -> Option<usize> {
    None
}

pub fn truncate_visible(text: &str, width: usize) -> String {
    if visible_len(text) <= width {
        return text.to_string();
    }
    let mut kept = String::with_capacity(text.len());
    let mut visible = 0usize;
    let mut inside = false;
    let mut colored = false;
    for character in text.chars() {
        if character == '\x1b' {
            inside = true;
            colored = true;
            kept.push(character);
            continue;
        }
        if inside {
            kept.push(character);
            if character == 'm' {
                inside = false;
            }
            continue;
        }
        if visible + 1 >= width {
            kept.push('\u{2026}');
            break;
        }
        kept.push(character);
        visible += 1;
    }
    if colored {
        kept.push_str("\x1b[0m");
    }
    kept
}

#[cfg(windows)]
fn unicode_ready() -> bool {
    use windows_sys::Win32::System::Console::{GetConsoleOutputCP, SetConsoleOutputCP};
    if std::env::var_os("WT_SESSION").is_some()
        || std::env::var_os("TERM").is_some()
        || std::env::var_os("TERM_PROGRAM").is_some()
    {
        return true;
    }
    unsafe {
        const CP_UTF8: u32 = 65001;
        if GetConsoleOutputCP() == CP_UTF8 {
            return true;
        }
        SetConsoleOutputCP(CP_UTF8) != 0
    }
}

#[cfg(not(windows))]
fn unicode_ready() -> bool {
    true
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

    fn band_center(levels: &[usize]) -> Option<usize> {
        let peak = *levels.iter().max()?;
        if peak == 0 {
            return None;
        }
        let mut hits = levels
            .iter()
            .enumerate()
            .filter(|(_, level)| **level == peak);
        let first = hits.next()?.0;
        if hits.next().is_some() {
            return None;
        }
        Some(first)
    }

    #[test]
    fn sweep_moves_one_column_per_frame_and_turns_around() {
        let width = 28usize;
        let period = sweep_period(width);
        let centers: Vec<Option<usize>> = (0..period)
            .map(|frame| band_center(&sweep_levels(width, frame)))
            .collect();
        let mut previous: Option<usize> = None;
        for center in &centers {
            let center = center.expect("the band is always on screen");
            if let Some(last) = previous {
                assert!(
                    center.abs_diff(last) <= 1,
                    "band jumped from {} to {}",
                    last,
                    center
                );
            }
            previous = Some(center);
        }
        assert!(centers.iter().flatten().any(|center| *center == 0));
        assert!(centers.iter().flatten().any(|center| *center == width - 1));
        assert_eq!(sweep_levels(width, 0), sweep_levels(width, period));
        assert_ne!(sweep_levels(width, 0), sweep_levels(width, 1));
    }

    #[test]
    fn a_short_line_is_left_alone_and_a_long_one_is_cut_with_an_ellipsis() {
        assert_eq!(truncate_visible("hello", 10), "hello");
        assert_eq!(truncate_visible("hello", 5), "hello");
        assert_eq!(truncate_visible("hello", 4), "hel\u{2026}");
        assert_eq!(visible_len(&truncate_visible("hello world", 6)), 6);
        assert_eq!(truncate_visible("hello", 0), "\u{2026}");
    }

    #[test]
    fn truncating_keeps_color_codes_and_always_resets() {
        let out = Output::assemble(
            false,
            ColorChoice::Always,
            ThemeChoice::Dark,
            true,
            true,
            true,
            true,
        );
        let painted = out.sweep("Listening for your email app", 4);
        let cut = truncate_visible(&painted, 10);
        assert_eq!(visible_len(&cut), 10);
        assert!(cut.ends_with("\x1b[0m"));
        assert!(!truncate_visible("plain text here", 6).contains('\x1b'));
    }

    #[test]
    fn sweep_levels_stay_within_the_tail() {
        for frame in 0..200 {
            let levels = sweep_levels(28, frame);
            assert_eq!(levels.len(), 28);
            assert!(levels.iter().all(|level| *level <= SWEEP_TAIL));
            for pair in levels.windows(2) {
                assert!(pair[1].abs_diff(pair[0]) <= 1);
            }
        }
        assert!(sweep_levels(0, 5).is_empty());
    }

    #[test]
    fn sweep_frames_differ_so_the_line_animates() {
        let out = Output::assemble(
            false,
            ColorChoice::Always,
            ThemeChoice::Dark,
            true,
            true,
            true,
            true,
        );
        let text = "Listening for your email app";
        let first = out.sweep(text, 10);
        assert_ne!(first, out.sweep(text, 11));
        assert_eq!(
            first,
            out.sweep(text, 10 + sweep_period(text.chars().count()))
        );
    }

    #[test]
    fn sweep_keeps_every_character_and_resets_color() {
        let out = Output::assemble(
            false,
            ColorChoice::Always,
            ThemeChoice::Dark,
            true,
            true,
            true,
            true,
        );
        let text = "Listening for your email app";
        for frame in 0..40 {
            let painted = out.sweep(text, frame);
            let stripped: String = strip_ansi(&painted);
            assert_eq!(stripped, text);
            assert!(painted.ends_with("\x1b[0m"));
        }
    }

    #[test]
    fn sweep_without_color_returns_the_plain_text() {
        let out = Output::build(false, ColorChoice::Never, ThemeChoice::Dark, false, false);
        assert_eq!(out.sweep("Working", 3), "Working");
        assert_eq!(out.sweep("", 0), "");
    }

    fn strip_ansi(text: &str) -> String {
        let mut plain = String::new();
        let mut inside = false;
        for character in text.chars() {
            if character == '\x1b' {
                inside = true;
                continue;
            }
            if inside {
                if character == 'm' {
                    inside = false;
                }
                continue;
            }
            plain.push(character);
        }
        plain
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
