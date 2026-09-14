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
use std::process::Command;

#[cfg(not(feature = "test-support"))]
#[test]
fn release_binary_has_no_test_hooks() {
    let bytes = std::fs::read(env!("CARGO_BIN_EXE_aster-bridge")).unwrap();
    let needle = concat!("ASTER_BRIDGE_", "TEST_").as_bytes();
    assert!(
        !bytes.windows(needle.len()).any(|window| window == needle),
        "the release binary contains test-only environment hooks"
    );
}

#[test]
fn cli_does_not_depend_on_the_desktop_toolkit() {
    let output = Command::new(env!("CARGO"))
        .args([
            "tree",
            "-p",
            "aster-bridge-cli",
            "-e",
            "normal",
            "--prefix",
            "none",
            "--target",
            "all",
        ])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "cargo tree failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let tree = String::from_utf8_lossy(&output.stdout);
    let banned = ["wry", "tao", "webkit2gtk", "gtk", "javascriptcore-rs", "webview2-com"];
    for line in tree.lines() {
        let name = line.split_whitespace().next().unwrap_or_default();
        assert!(
            !name.starts_with("tauri") && !banned.contains(&name),
            "aster-bridge-cli depends on {}",
            name
        );
    }
}

#[test]
fn help_and_version_work_without_a_data_folder() {
    let binary = env!("CARGO_BIN_EXE_aster-bridge");
    let help = Command::new(binary).arg("--help").output().unwrap();
    assert!(help.status.success());
    assert!(String::from_utf8_lossy(&help.stdout).contains("serve"));
    let version = Command::new(binary)
        .args(["--json", "version"])
        .env("ASTER_BRIDGE_DATA_DIR", tempfile::tempdir().unwrap().path())
        .output()
        .unwrap();
    assert!(version.status.success());
    let body: serde_json::Value = serde_json::from_slice(&version.stdout).unwrap();
    assert_eq!(body["schema"], 1);
    assert_eq!(body["version"], env!("CARGO_PKG_VERSION"));
}
