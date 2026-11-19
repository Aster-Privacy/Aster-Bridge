//
// Aster Communications Inc.
//
// Copyright (c) 2026 Aster Communications Inc.
//
// This file is part of this project.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the AGPLv3 as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// AGPLv3 for more details.
//
// You should have received a copy of the AGPLv3
// along with this program. If not, see <https://www.gnu.org/licenses/>.

import { test } from "node:test";
import assert from "node:assert/strict";
import * as flow from "../src/lib/provision_flow.ts";
import { request_provision_bundle } from "../src/lib/provision_flow.ts";

const sample_bundle = {
  password_id: "pw_1",
  email: "user@example.com",
  app_password: "abcd-efgh-ijkl-mnop",
  label: "",
  imap_host: "127.0.0.1",
  imap_port: 1143,
  smtp_host: "127.0.0.1",
  smtp_port: 1025,
  jmap_host: "127.0.0.1",
  jmap_port: 1080,
  jmap_url: "http://127.0.0.1:1080",
  jmap_enabled: false,
  carddav_port: 1180,
  carddav_url: "http://127.0.0.1:1180",
  carddav_enabled: false,
};

function make_deps() {
  const copied: string[] = [];
  const deleted: string[] = [];
  const deps = {
    provision_bundle: async (label: string) => ({ ...sample_bundle, label }),
    copy_text: async (value: string) => {
      copied.push(value);
    },
    delete_app_password: async (id: string) => {
      deleted.push(id);
    },
    clear_clipboard_if_unchanged: (_value: string) => {},
  };
  return { copied, deleted, deps };
}

test("provisioned settings never reach the clipboard", async () => {
  const { copied, deps } = make_deps();
  const result = await request_provision_bundle("Phone", deps);
  assert.deepEqual(copied, [], "provisioned settings were written to the clipboard");
  assert.equal(result.app_password, sample_bundle.app_password);
  assert.equal(result.label, "Phone");
});

test("the provisioned password stays revocable from the result", async () => {
  const { deleted, deps } = make_deps();
  const result = await request_provision_bundle("Laptop", deps);
  assert.equal(result.password_id, sample_bundle.password_id);
  assert.deepEqual(deleted, []);
});

const FALLBACK = "New device";

function parse(payload: string): string | null {
  assert.equal(typeof flow.parse_provision_link, "function", "the deep link parser is not exported from provision_flow");
  return flow.parse_provision_link(payload, FALLBACK);
}

function link(label: string): string {
  return `aster-mail://provision?label=${encodeURIComponent(label)}`;
}

test("a deep link for another scheme, host, or a malformed payload is ignored", () => {
  assert.equal(parse("https://provision/?label=Phone"), null);
  assert.equal(parse("aster-mail://settings?label=Phone"), null);
  assert.equal(parse("aster-mail://provisioning?label=Phone"), null);
  assert.equal(parse("not a link"), null);
  assert.equal(parse(""), null);
});

test("a provision deep link yields its trimmed label", () => {
  assert.equal(parse(link("  Work Phone  ")), "Work Phone");
  assert.equal(parse("aster-mail:/provision?label=Laptop"), "Laptop");
});

test("control and direction characters are removed from the label", () => {
  const hidden = [0x00, 0x07, 0x1b, 0x7f, 0x85, 0xad, 0x61c, 0x200b, 0x200e, 0x2028, 0x202e, 0x2066, 0x2069, 0xfeff]
    .map((code) => String.fromCharCode(code));
  const label = `Pay${hidden.join("")}lapyap`;
  assert.equal(parse(link(label)), "Paylapyap");
  assert.equal(parse(link(`${String.fromCharCode(0x202e)}gpj.exe`)), "gpj.exe");
});

test("a label of only hidden characters or no label falls back to the default", () => {
  assert.equal(parse(link(`${String.fromCharCode(0x200b)}${String.fromCharCode(0x202e)} `)), FALLBACK);
  assert.equal(parse("aster-mail://provision"), FALLBACK);
  assert.equal(parse("aster-mail://provision?label="), FALLBACK);
});

test("the label is capped at 64 characters without splitting a character", () => {
  const long = parse(link("a".repeat(200)));
  assert.equal(long, "a".repeat(64));
  const face = String.fromCodePoint(0x1f600);
  const emoji = parse(link(face.repeat(70)));
  assert.equal(emoji, face.repeat(64));
  assert.equal(parse(link(`${"b".repeat(63)} c`)), "b".repeat(63));
});
