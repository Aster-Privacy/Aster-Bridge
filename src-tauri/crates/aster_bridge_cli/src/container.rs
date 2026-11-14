//
// Aster Communications Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
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
use std::borrow::Cow;
use std::sync::OnceLock;

pub const IN_CONTAINER_ENV: &str = "ASTER_BRIDGE_IN_CONTAINER";

const PROGRAM: &str = "aster-bridge";
const SERVICE: &str = "aster-bridge";

const SUBCOMMANDS: &[&str] = &[
    "login",
    "logout",
    "serve",
    "status",
    "stop",
    "app-password",
    "outbox",
    "sync",
    "tls",
    "secret-key",
    "config",
    "repair-cache",
    "recipient-key",
    "tags",
    "service",
    "errors",
    "version",
    "healthcheck",
];

pub fn in_container() -> bool {
    static FLAG: OnceLock<bool> = OnceLock::new();
    *FLAG.get_or_init(|| {
        std::env::var(IN_CONTAINER_ENV)
            .map(|value| value.trim() == "1")
            .unwrap_or(false)
    })
}

pub fn localize(text: &str) -> Cow<'_, str> {
    if in_container() && text.contains(PROGRAM) {
        Cow::Owned(container_commands(text))
    } else {
        Cow::Borrowed(text)
    }
}

pub fn container_commands(text: &str) -> String {
    let mut result = String::with_capacity(text.len() + 64);
    let mut rest = text;
    while let Some(index) = rest.find(PROGRAM) {
        let (before, from) = rest.split_at(index);
        result.push_str(before);
        let after = &from[PROGRAM.len()..];
        match command_at(&result, after) {
            Some((replacement, consumed)) => {
                result.push_str(&replacement);
                rest = &after[consumed..];
            }
            None => {
                result.push_str(PROGRAM);
                rest = after;
            }
        }
    }
    result.push_str(rest);
    result
}

fn command_at(before: &str, after: &str) -> Option<(String, usize)> {
    let line = before.rsplit('\n').next().unwrap_or(before);
    if !starts_a_word(before) || line.contains("docker ") {
        return None;
    }
    let tail = after.strip_prefix(' ')?;
    let length = tail
        .find(|c: char| !(c.is_ascii_lowercase() || c == '-'))
        .unwrap_or(tail.len());
    let word = &tail[..length];
    if !SUBCOMMANDS.contains(&word) {
        return None;
    }
    let consumed = 1 + length;
    match word {
        "serve" => {
            let extra = if tail[length..].starts_with(" --service") {
                " --service".len()
            } else {
                0
            };
            Some((format!("docker compose restart {}", SERVICE), consumed + extra))
        }
        "secret-key" => Some((
            format!("docker compose run --rm {} {}", SERVICE, word),
            consumed,
        )),
        _ => Some((
            format!("docker compose exec {} {} {}", SERVICE, PROGRAM, word),
            consumed,
        )),
    }
}

fn starts_a_word(before: &str) -> bool {
    let Some(previous) = before.chars().last() else {
        return true;
    };
    if previous == 'm' && ends_with_color_code(before) {
        return true;
    }
    !(previous.is_alphanumeric() || matches!(previous, '/' | '\\' | '-' | '_' | '.'))
}

fn ends_with_color_code(before: &str) -> bool {
    let Some(code) = before.strip_suffix('m') else {
        return false;
    };
    let Some(start) = code.rfind("\x1b[") else {
        return false;
    };
    code[start + 2..].chars().all(|c| c.is_ascii_digit() || c == ';')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hints_name_the_docker_command() {
        assert_eq!(
            container_commands("To link this device to your account, run: aster-bridge login"),
            "To link this device to your account, run: docker compose exec aster-bridge aster-bridge login"
        );
        assert_eq!(
            container_commands("help       aster-bridge errors ASTER-6001"),
            "help       docker compose exec aster-bridge aster-bridge errors ASTER-6001"
        );
        assert_eq!(
            container_commands("To create the key file, run: aster-bridge secret-key create"),
            "To create the key file, run: docker compose run --rm aster-bridge secret-key create"
        );
        assert_eq!(
            container_commands("Stop it, then start it again with: aster-bridge serve"),
            "Stop it, then start it again with: docker compose restart aster-bridge"
        );
        assert_eq!(
            container_commands("process manager: aster-bridge serve --service"),
            "process manager: docker compose restart aster-bridge"
        );
    }

    #[test]
    fn colored_commands_keep_their_color() {
        assert_eq!(
            container_commands("run: \x1b[1;36master-bridge login\x1b[0m"),
            "run: \x1b[1;36mdocker compose exec aster-bridge aster-bridge login\x1b[0m"
        );
    }

    #[test]
    fn other_mentions_stay_unchanged() {
        for text in [
            "aster-bridge stopped: You're not signed in.",
            "aster-bridge is waiting for you to sign in",
            "/usr/local/bin/aster-bridge status",
            "aster-bridge-cli login",
            "docker compose exec aster-bridge aster-bridge login",
            "docker compose run --rm aster-bridge secret-key create",
            "aster-bridge",
        ] {
            assert_eq!(container_commands(text), text);
        }
    }
}
