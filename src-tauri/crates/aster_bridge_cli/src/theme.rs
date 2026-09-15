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
use crate::cli::{ColorChoice, ThemeChoice};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColorDepth {
    None,
    Ansi16,
    Ansi256,
    TrueColor,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Appearance {
    Dark,
    Light,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rgb(pub u8, pub u8, pub u8);

impl Rgb {
    pub fn mix(self, other: Rgb, amount: f32) -> Rgb {
        let amount = amount.clamp(0.0, 1.0);
        let blend = |a: u8, b: u8| {
            (f32::from(a) + (f32::from(b) - f32::from(a)) * amount)
                .round()
                .clamp(0.0, 255.0) as u8
        };
        Rgb(
            blend(self.0, other.0),
            blend(self.1, other.1),
            blend(self.2, other.2),
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Accent,
    AccentSoft,
    AccentDeep,
    Good,
    Warn,
    Bad,
    Muted,
}

#[derive(Debug, Clone, Copy)]
pub struct Palette {
    pub appearance: Appearance,
    pub depth: ColorDepth,
}

const ASTER_BLUE: Rgb = Rgb(0x3b, 0x82, 0xf6);
const ASTER_BLUE_LIFT: Rgb = Rgb(0x60, 0xa5, 0xfa);
const ASTER_BLUE_PALE: Rgb = Rgb(0x9f, 0xc0, 0xe8);
const ASTER_BLUE_PRESS: Rgb = Rgb(0x25, 0x63, 0xeb);
const ASTER_BLUE_INK: Rgb = Rgb(0x1d, 0x4e, 0xd8);

impl Palette {
    pub fn new(appearance: Appearance, depth: ColorDepth) -> Self {
        Self { appearance, depth }
    }

    pub fn rgb(&self, role: Role) -> Rgb {
        match (self.appearance, role) {
            (Appearance::Dark, Role::Accent) => ASTER_BLUE_LIFT,
            (Appearance::Dark, Role::AccentSoft) => ASTER_BLUE_PALE,
            (Appearance::Dark, Role::AccentDeep) => ASTER_BLUE,
            (Appearance::Dark, Role::Good) => Rgb(0x4a, 0xde, 0x80),
            (Appearance::Dark, Role::Warn) => Rgb(0xfb, 0xbf, 0x24),
            (Appearance::Dark, Role::Bad) => Rgb(0xf8, 0x71, 0x71),
            (Appearance::Dark, Role::Muted) => Rgb(0x9a, 0xa1, 0xad),
            (Appearance::Light, Role::Accent) => ASTER_BLUE_PRESS,
            (Appearance::Light, Role::AccentSoft) => ASTER_BLUE,
            (Appearance::Light, Role::AccentDeep) => ASTER_BLUE_INK,
            (Appearance::Light, Role::Good) => Rgb(0x15, 0x80, 0x3d),
            (Appearance::Light, Role::Warn) => Rgb(0xb4, 0x53, 0x09),
            (Appearance::Light, Role::Bad) => Rgb(0xb9, 0x1c, 0x1c),
            (Appearance::Light, Role::Muted) => Rgb(0x6b, 0x72, 0x80),
        }
    }

    pub fn sequence(&self, role: Role) -> String {
        self.rgb_sequence(self.rgb(role), role)
    }

    pub fn rgb_sequence(&self, color: Rgb, role: Role) -> String {
        match self.depth {
            ColorDepth::None => String::new(),
            ColorDepth::TrueColor => format!("38;2;{};{};{}", color.0, color.1, color.2),
            ColorDepth::Ansi256 => format!("38;5;{}", to_ansi256(color)),
            ColorDepth::Ansi16 => basic_code(self.appearance, role).to_string(),
        }
    }

    pub fn gradient(&self, from: Role, to: Role, steps: usize, index: usize) -> Rgb {
        if steps <= 1 {
            return self.rgb(from);
        }
        let amount = index.min(steps - 1) as f32 / (steps - 1) as f32;
        self.rgb(from).mix(self.rgb(to), amount)
    }
}

fn basic_code(appearance: Appearance, role: Role) -> &'static str {
    match role {
        Role::Accent | Role::AccentSoft => {
            if appearance == Appearance::Light {
                "34"
            } else {
                "94"
            }
        }
        Role::AccentDeep => "34",
        Role::Good => "32",
        Role::Warn => "33",
        Role::Bad => "31",
        Role::Muted => "90",
    }
}

pub fn to_ansi256(color: Rgb) -> u8 {
    let level = |value: u8| -> u8 {
        match value {
            0..=47 => 0,
            48..=114 => 1,
            115..=154 => 2,
            155..=194 => 3,
            195..=234 => 4,
            _ => 5,
        }
    };
    let red_green = i32::from(color.0) - i32::from(color.1);
    let green_blue = i32::from(color.1) - i32::from(color.2);
    if red_green.abs() < 8 && green_blue.abs() < 8 {
        let average = (u16::from(color.0) + u16::from(color.1) + u16::from(color.2)) / 3;
        if average < 8 {
            return 16;
        }
        if average > 248 {
            return 231;
        }
        return 232 + ((average - 8) * 24 / 247) as u8;
    }
    16 + 36 * level(color.0) + 6 * level(color.1) + level(color.2)
}

pub fn detect_depth(choice: ColorChoice, is_terminal: bool, vt_ready: bool) -> ColorDepth {
    if choice == ColorChoice::Never {
        return ColorDepth::None;
    }
    if no_color_set() && choice != ColorChoice::Always {
        return ColorDepth::None;
    }
    if !vt_ready {
        return ColorDepth::None;
    }
    if choice == ColorChoice::Auto && !is_terminal {
        return ColorDepth::None;
    }
    let depth = depth_from_env(|name| std::env::var(name).ok());
    if depth == ColorDepth::None && choice == ColorChoice::Always {
        return ColorDepth::Ansi16;
    }
    depth
}

pub fn depth_from_env(read: impl Fn(&str) -> Option<String>) -> ColorDepth {
    let term = read("TERM").unwrap_or_default().to_ascii_lowercase();
    if term == "dumb" {
        return ColorDepth::None;
    }
    let color_term = read("COLORTERM").unwrap_or_default().to_ascii_lowercase();
    if color_term.contains("truecolor") || color_term.contains("24bit") {
        return ColorDepth::TrueColor;
    }
    if read("WT_SESSION").is_some() {
        return ColorDepth::TrueColor;
    }
    let program = read("TERM_PROGRAM").unwrap_or_default();
    if matches!(
        program.as_str(),
        "iTerm.app" | "WezTerm" | "vscode" | "ghostty" | "Hyper" | "rio"
    ) {
        return ColorDepth::TrueColor;
    }
    if term.contains("kitty") || term.contains("direct") {
        return ColorDepth::TrueColor;
    }
    if term.contains("256color") {
        return ColorDepth::Ansi256;
    }
    if term.is_empty() && cfg!(windows) {
        return ColorDepth::TrueColor;
    }
    ColorDepth::Ansi16
}

pub fn no_color_set() -> bool {
    std::env::var_os("NO_COLOR").is_some_and(|value| !value.is_empty())
}

pub fn detect_appearance(choice: ThemeChoice) -> Appearance {
    match choice {
        ThemeChoice::Dark => Appearance::Dark,
        ThemeChoice::Light => Appearance::Light,
        ThemeChoice::Auto => appearance_from_env(|name| std::env::var(name).ok()),
    }
}

pub fn appearance_from_env(read: impl Fn(&str) -> Option<String>) -> Appearance {
    match read("COLORFGBG").and_then(|value| appearance_from_colorfgbg(&value)) {
        Some(appearance) => appearance,
        None => Appearance::Dark,
    }
}

pub fn appearance_from_colorfgbg(value: &str) -> Option<Appearance> {
    let background = value
        .split(';')
        .rfind(|part| !part.trim().is_empty())?
        .trim()
        .parse::<u16>()
        .ok()?;
    match background {
        0..=6 | 8 => Some(Appearance::Dark),
        7 | 9..=15 => Some(Appearance::Light),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(pairs: &'static [(&'static str, &'static str)]) -> impl Fn(&str) -> Option<String> {
        move |name| {
            pairs
                .iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| (*value).to_string())
        }
    }

    #[test]
    fn colorfgbg_picks_the_background_field() {
        assert_eq!(appearance_from_colorfgbg("15;0"), Some(Appearance::Dark));
        assert_eq!(appearance_from_colorfgbg("0;15"), Some(Appearance::Light));
        assert_eq!(
            appearance_from_colorfgbg("15;default;0"),
            Some(Appearance::Dark)
        );
        assert_eq!(appearance_from_colorfgbg("7"), Some(Appearance::Light));
        assert_eq!(appearance_from_colorfgbg("default"), None);
    }

    #[test]
    fn a_light_terminal_is_detected_from_the_environment() {
        assert_eq!(
            appearance_from_env(env(&[("COLORFGBG", "0;15")])),
            Appearance::Light
        );
        assert_eq!(
            appearance_from_env(env(&[("COLORFGBG", "15;0")])),
            Appearance::Dark
        );
        assert_eq!(appearance_from_env(env(&[])), Appearance::Dark);
    }

    #[test]
    fn an_explicit_theme_wins_over_detection() {
        assert_eq!(detect_appearance(ThemeChoice::Light), Appearance::Light);
        assert_eq!(detect_appearance(ThemeChoice::Dark), Appearance::Dark);
    }

    #[test]
    fn light_terminals_get_a_darker_blue() {
        let light = Palette::new(Appearance::Light, ColorDepth::TrueColor);
        let dark = Palette::new(Appearance::Dark, ColorDepth::TrueColor);
        assert_eq!(light.rgb(Role::Accent), ASTER_BLUE_PRESS);
        assert_eq!(dark.rgb(Role::Accent), ASTER_BLUE_LIFT);
        assert_eq!(light.rgb(Role::AccentSoft), ASTER_BLUE);
        assert_eq!(dark.rgb(Role::AccentDeep), ASTER_BLUE);
    }

    #[test]
    fn depth_degrades_by_terminal_capability() {
        assert_eq!(
            depth_from_env(env(&[("COLORTERM", "truecolor")])),
            ColorDepth::TrueColor
        );
        assert_eq!(
            depth_from_env(env(&[("WT_SESSION", "abc"), ("TERM", "")])),
            ColorDepth::TrueColor
        );
        assert_eq!(
            depth_from_env(env(&[("TERM", "xterm-256color")])),
            ColorDepth::Ansi256
        );
        assert_eq!(depth_from_env(env(&[("TERM", "xterm")])), ColorDepth::Ansi16);
        assert_eq!(depth_from_env(env(&[("TERM", "dumb")])), ColorDepth::None);
    }

    #[test]
    fn color_is_off_without_a_terminal_or_vt_support() {
        assert_eq!(
            detect_depth(ColorChoice::Auto, false, true),
            ColorDepth::None
        );
        assert_eq!(
            detect_depth(ColorChoice::Always, true, false),
            ColorDepth::None
        );
        assert_eq!(
            detect_depth(ColorChoice::Never, true, true),
            ColorDepth::None
        );
    }

    #[test]
    fn sequences_match_the_depth() {
        let color = Rgb(0x60, 0xa5, 0xfa);
        assert_eq!(
            Palette::new(Appearance::Dark, ColorDepth::TrueColor).rgb_sequence(color, Role::Accent),
            "38;2;96;165;250"
        );
        assert!(Palette::new(Appearance::Dark, ColorDepth::Ansi256)
            .rgb_sequence(color, Role::Accent)
            .starts_with("38;5;"));
        assert_eq!(
            Palette::new(Appearance::Dark, ColorDepth::Ansi16).rgb_sequence(color, Role::Accent),
            "94"
        );
        assert_eq!(
            Palette::new(Appearance::Light, ColorDepth::Ansi16).rgb_sequence(color, Role::Accent),
            "34"
        );
        assert!(Palette::new(Appearance::Dark, ColorDepth::None)
            .sequence(Role::Accent)
            .is_empty());
    }

    #[test]
    fn greys_map_into_the_ansi256_ramp() {
        assert_eq!(to_ansi256(Rgb(0, 0, 0)), 16);
        assert_eq!(to_ansi256(Rgb(255, 255, 255)), 231);
        assert_eq!(to_ansi256(Rgb(0x3b, 0x82, 0xf6)), 16 + 36 + 6 * 2 + 5);
    }

    #[test]
    fn gradient_walks_from_one_role_to_the_other() {
        let palette = Palette::new(Appearance::Dark, ColorDepth::TrueColor);
        assert_eq!(
            palette.gradient(Role::AccentDeep, Role::AccentSoft, 4, 0),
            ASTER_BLUE
        );
        assert_eq!(
            palette.gradient(Role::AccentDeep, Role::AccentSoft, 4, 3),
            ASTER_BLUE_PALE
        );
        assert_eq!(
            palette.gradient(Role::AccentDeep, Role::AccentSoft, 1, 0),
            ASTER_BLUE
        );
    }
}
