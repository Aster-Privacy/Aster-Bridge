// SPDX-License-Identifier: AGPL-3.0-or-later
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

import { afterEach, describe, expect, it, vi } from "vitest";

import { check_for_update, is_desktop_runtime, updates_managed_externally, updates_supported } from "./updater";

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("updates_supported", () => {
  it("is off outside the desktop app", () => {
    vi.stubGlobal("window", {});
    expect(is_desktop_runtime()).toBe(false);
    expect(updates_supported()).toBe(false);
  });

  it("is on in the desktop app by default", () => {
    vi.stubGlobal("window", { __TAURI_INTERNALS__: {} });
    expect(updates_managed_externally()).toBe(false);
    expect(updates_supported()).toBe(true);
  });

  it("is off when a package manager handles updates", async () => {
    vi.stubGlobal("window", { __TAURI_INTERNALS__: {}, __ASTER_UPDATES_MANAGED__: true });
    expect(is_desktop_runtime()).toBe(true);
    expect(updates_managed_externally()).toBe(true);
    expect(updates_supported()).toBe(false);
    await expect(check_for_update()).resolves.toBeNull();
  });
});
