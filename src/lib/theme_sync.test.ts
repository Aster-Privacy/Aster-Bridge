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
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  accent_foreground_for,
  apply_preferences,
  contrast_ratio,
  default_resolved_preferences,
  is_dark_only_color_theme,
  resolve_appearance_is_dark,
  type ResolvedPreferences,
} from "./theme_sync";

function make_root() {
  const classes = new Set<string>();
  const props = new Map<string, string>();
  return {
    classList: {
      add: (c: string) => { classes.add(c); },
      remove: (c: string) => { classes.delete(c); },
      contains: (c: string) => classes.has(c),
      toggle: (c: string, on?: boolean) => {
        const next = on ?? !classes.has(c);
        if (next) classes.add(c); else classes.delete(c);
        return next;
      },
      [Symbol.iterator]: () => classes.values(),
    },
    style: {
      setProperty: (k: string, v: string) => { props.set(k, v); },
      removeProperty: (k: string) => { props.delete(k); return ""; },
      getPropertyValue: (k: string) => props.get(k) ?? "",
    },
    setAttribute: () => {},
    removeAttribute: () => {},
    dataset: {} as Record<string, string>,
    classes,
    props,
  };
}

let root: ReturnType<typeof make_root>;

function prefs(over: Partial<ResolvedPreferences>): ResolvedPreferences {
  return { ...default_resolved_preferences(), ...over };
}

beforeEach(() => {
  root = make_root();
  vi.stubGlobal("document", { documentElement: root, body: root, dispatchEvent: () => true });
  vi.stubGlobal("window", { matchMedia: () => ({ matches: false }), dispatchEvent: () => true });
  vi.stubGlobal("getComputedStyle", () => ({ getPropertyValue: () => "" }));
  vi.stubGlobal("localStorage", { getItem: () => null, setItem: () => {}, removeItem: () => {} });
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("contrast helpers", () => {
  it("measures black on white at 21", () => {
    expect(contrast_ratio("#000000", "#ffffff")).toBeCloseTo(21, 0);
  });

  it("uses dark text on a light accent", () => {
    expect(accent_foreground_for("#a3e635")).toBe("#111827");
  });

  it("keeps white text on a dark accent", () => {
    expect(accent_foreground_for("#1d4ed8")).toBe("#ffffff");
  });
});

describe("apply_preferences", () => {
  it("forces dark mode for a named dark-only theme", () => {
    const resolved = prefs({ theme: "light", color_theme: "purple" });
    expect(is_dark_only_color_theme("purple")).toBe(true);
    expect(resolve_appearance_is_dark(resolved)).toBe(true);
    apply_preferences(resolved);
    expect(root.classes.has("dark")).toBe(true);
    expect(root.classes.has("light")).toBe(false);
    expect(root.classes.has("theme-purple")).toBe(true);
    expect(root.props.has("--accent-color")).toBe(false);
  });

  it("applies the accent and its foreground for the default theme", () => {
    apply_preferences(prefs({ theme: "light", accent_color: "#a3e635", accent_color_hover: "#84cc16" }));
    expect(root.classes.has("light")).toBe(true);
    expect(root.props.get("--accent-color")).toBe("#a3e635");
    expect(root.props.get("--accent-fg")).toBe("#111827");
  });

  it("removes the old theme class when switching back to default", () => {
    apply_preferences(prefs({ theme: "dark", color_theme: "purple" }));
    apply_preferences(prefs({ theme: "light", color_theme: "default" }));
    expect(root.classes.has("theme-purple")).toBe(false);
    expect(root.classes.has("dark")).toBe(false);
  });

  it("sets surface tokens for a custom theme and clears them afterward", () => {
    apply_preferences(prefs({ theme: "dark", color_theme: "custom", custom_theme_seed: "#7c3aed" }));
    const custom_keys = Array.from(root.props.keys()).filter((k) => k.startsWith("--bg-") || k.startsWith("--text-"));
    expect(custom_keys.length).toBeGreaterThan(3);
    apply_preferences(prefs({ theme: "dark", color_theme: "default" }));
    const left = Array.from(root.props.keys()).filter((k) => k.startsWith("--bg-") || k.startsWith("--text-"));
    expect(left).toEqual([]);
  });

  it("never writes an inline page background", () => {
    root.props.set("background", "#000");
    apply_preferences(prefs({ theme: "dark" }));
    expect(root.props.has("background")).toBe(false);
  });
});
