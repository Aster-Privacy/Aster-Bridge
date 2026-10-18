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
use std::borrow::Cow;

pub fn response_text(text: &str) -> Cow<'_, str> {
    if !text.chars().any(char::is_control) {
        return Cow::Borrowed(text);
    }
    Cow::Owned(
        text.chars()
            .map(|c| if c.is_control() { ' ' } else { c })
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_text_is_borrowed_unchanged() {
        assert!(matches!(response_text("APPEND completed"), Cow::Borrowed("APPEND completed")));
    }

    #[test]
    fn line_breaks_and_controls_become_spaces() {
        assert_eq!(
            response_text("bad\r\na2 OK done\n\0\t\u{1b}[x\u{85}y"),
            "bad  a2 OK done    [x y"
        );
    }

    #[test]
    fn non_ascii_text_is_kept() {
        assert_eq!(response_text("r\u{e9}sum\u{e9}.pdf"), "r\u{e9}sum\u{e9}.pdf");
    }
}
