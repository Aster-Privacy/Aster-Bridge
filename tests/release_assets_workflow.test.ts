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

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";

const TAG = "v9.9.9";

const REQUIRED = [
  "Aster-Bridge-x64-setup.exe",
  "Aster-Bridge-x64.msi",
  "Aster-Bridge-x86_64.AppImage",
  "Aster-Bridge-amd64.deb",
  "Aster-Bridge-x86_64.rpm",
  "Aster-Bridge-universal.dmg",
];

const CLI_FILES = [
  "aster-bridge-cli-x86_64-unknown-linux-gnu.tar.gz",
  "aster-bridge-cli-aarch64-unknown-linux-gnu.tar.gz",
  "aster-bridge-cli-universal-apple-darwin.tar.gz",
  "aster-bridge-cli-x86_64-pc-windows-msvc.zip",
].flatMap((archive) => [archive, `${archive}.sha256`]);

const FAKE_GH = `#!/usr/bin/env bash
state="$FAKE_GH_STATE"
case "$1 $2" in
  "release list")
    [ -n "\${FAIL_LIST:-}" ] && exit 1
    printf '%s\\n' "$TAG" v1.0.0
    ;;
  "release view")
    if [ "$3" = "$TAG" ]; then cat "$state/current"; else cat "$state/previous"; fi
    ;;
  "release download")
    [ -n "\${FAIL_DOWNLOAD:-}" ] && exit 1
    shift 3
    dir=""
    patterns=()
    while [ $# -gt 0 ]; do
      case "$1" in
        --pattern) patterns+=("$2"); shift 2 ;;
        --dir) dir="$2"; shift 2 ;;
        *) shift ;;
      esac
    done
    for p in "\${patterns[@]}"; do echo data > "$dir/$p"; done
    ;;
  "release upload")
    [ -n "\${FAIL_UPLOAD:-}" ] && exit 1
    shift 3
    for a in "$@"; do
      [ -f "$a" ] && basename "$a" >> "$state/current"
    done
    ;;
  *)
    exit 2
    ;;
esac
exit 0
`;

function workflow_script(): string {
  const lines = readFileSync(new URL("../.github/workflows/verify_release_assets.yml", import.meta.url), "utf8")
    .replace(/\r\n/g, "\n")
    .split("\n");
  const start = lines.findIndex((line) => line.trim() === "run: |");
  assert.ok(start >= 0, "the workflow has no run block");
  const body: string[] = [];
  for (const line of lines.slice(start + 1)) {
    if (line.trim() !== "" && !line.startsWith("          ")) break;
    body.push(line.slice(10));
  }
  return body.join("\n");
}

function find_modern_bash(): string | undefined {
  const candidates = [process.env.ASTER_TEST_BASH, "/opt/homebrew/bin/bash", "/usr/local/bin/bash", "/bin/bash", "bash"];
  for (const candidate of candidates) {
    if (!candidate) continue;
    const probe = spawnSync(candidate, ["-c", "echo \"${BASH_VERSINFO[0]}\""], { encoding: "utf8" });
    if (probe.status === 0 && Number(probe.stdout.trim()) >= 4) return candidate;
  }
  return undefined;
}

const MODERN_BASH = find_modern_bash();

const NEEDS_BASH = { skip: MODERN_BASH ? false : "bash 4 or later is needed to run the release asset workflow" };

interface Run {
  status: number | null;
  output: string;
  current: string[];
}

function run_workflow(current: string[], previous: string[], failures: Record<string, string>): Run {
  const root = mkdtempSync(join(tmpdir(), "aster_release_assets_"));
  try {
    const bin = join(root, "bin");
    const state = join(root, "state");
    mkdirSync(bin, { recursive: true });
    mkdirSync(state, { recursive: true });
    writeFileSync(join(bin, "gh"), FAKE_GH);
    chmodSync(join(bin, "gh"), 0o755);
    writeFileSync(join(state, "current"), current.map((name) => `${name}\n`).join(""));
    writeFileSync(join(state, "previous"), previous.map((name) => `${name}\n`).join(""));
    const result = spawnSync(MODERN_BASH as string, ["-c", workflow_script()], {
      encoding: "utf8",
      env: {
        ...process.env,
        ...failures,
        PATH: `${bin}${delimiter}${process.env.PATH ?? ""}`,
        TAG,
        REPO: "example/bridge",
        GH_TOKEN: "unused",
        FAKE_GH_STATE: state,
      },
    });
    return {
      status: result.status,
      output: `${result.stdout}${result.stderr}`,
      current: readFileSync(join(state, "current"), "utf8").split("\n").filter(Boolean),
    };
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

test("missing command line archives are carried over from an earlier release", NEEDS_BASH, () => {
  const run = run_workflow(REQUIRED, [...REQUIRED, ...CLI_FILES], {});
  assert.equal(run.status, 0, run.output);
  for (const name of CLI_FILES) assert.ok(run.current.includes(name), `${name} was not carried over\n${run.output}`);
});

test("a failed download while carrying over assets fails the check with an error", NEEDS_BASH, () => {
  const run = run_workflow(REQUIRED, [...REQUIRED, ...CLI_FILES], { FAIL_DOWNLOAD: "1" });
  assert.notEqual(run.status, 0, run.output);
  assert.match(run.output, /::error::could not download aster-bridge-cli-/);
});

test("a failed upload while carrying over assets fails the check with an error", NEEDS_BASH, () => {
  const run = run_workflow(REQUIRED, [...REQUIRED, ...CLI_FILES], { FAIL_UPLOAD: "1" });
  assert.notEqual(run.status, 0, run.output);
  assert.match(run.output, /::error::could not upload aster-bridge-cli-/);
});

test("an unreadable release list fails the check with an error", NEEDS_BASH, () => {
  const run = run_workflow(REQUIRED, [...REQUIRED, ...CLI_FILES], { FAIL_LIST: "1" });
  assert.notEqual(run.status, 0, run.output);
  assert.match(run.output, /::error::could not list earlier releases/);
});

test("a failed upload while renaming a versioned asset is reported by name", NEEDS_BASH, () => {
  const current = [...REQUIRED.filter((name) => name !== "Aster-Bridge-x64.msi"), "Aster.Bridge_9.9.9_x64_en-US.msi", ...CLI_FILES];
  const run = run_workflow(current, current, { FAIL_UPLOAD: "1" });
  assert.notEqual(run.status, 0, run.output);
  assert.match(run.output, /::error::could not upload Aster-Bridge-x64\.msi to v9\.9\.9/);
});
