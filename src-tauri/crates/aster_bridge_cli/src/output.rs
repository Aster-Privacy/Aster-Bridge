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

use crate::exit::CliError;

pub const SCHEMA_VERSION: u64 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tone {
    Good,
    Warn,
    Bad,
    Muted,
}

#[derive(Debug, Clone, Copy)]
pub struct Output {
    pub json: bool,
    color: bool,
    err_color: bool,
}

impl Output {
    pub fn new(json: bool) -> Self {
        let no_color = std::env::var_os("NO_COLOR").is_some_and(|v| !v.is_empty());
        Self {
            json,
            color: !no_color && std::io::stdout().is_terminal() && enable_ansi(false),
            err_color: !no_color && std::io::stderr().is_terminal() && enable_ansi(true),
        }
    }

    pub fn ansi(&self) -> bool {
        self.color
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
        self.paint(text, "1")
    }

    pub fn dim(&self, text: &str) -> String {
        self.paint(text, "2")
    }

    pub fn tone(&self, text: &str, tone: Tone) -> String {
        match tone {
            Tone::Good => self.paint(text, "32"),
            Tone::Warn => self.paint(text, "33"),
            Tone::Bad => self.paint(text, "31"),
            Tone::Muted => self.paint(text, "2"),
        }
    }

    pub fn dot(&self, tone: Tone) -> String {
        self.tone("\u{25CF}", tone)
    }

    fn paint(&self, text: &str, code: &str) -> String {
        if self.color {
            format!("\x1b[{}m{}\x1b[0m", code, text)
        } else {
            text.to_string()
        }
    }

    pub fn fields(&self, rows: &[(&str, String)]) {
        let width = rows.iter().map(|(label, _)| visible_len(label)).max().unwrap_or(0);
        for (label, value) in rows {
            println!("  {}  {}", self.dim(&pad(label, width)), value);
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
        let label = if self.err_color {
            "\x1b[1;33mwarning:\x1b[0m"
        } else {
            "warning:"
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
        let label = if self.err_color {
            "\x1b[1;31merror:\x1b[0m"
        } else {
            "error:"
        };
        eprintln!("{} {}", label, err.message);
        if let Some(hint) = &err.hint {
            eprintln!("{}", hint);
        }
    }
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
}
