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
import type { UserPreferences } from "../api";
import {
  ACCENT_DERIVED_KEYS,
  apply_custom_theme,
  clear_material_theme,
  derive_accent_vars,
  is_valid_hex_color,
  type CustomThemeOverrides,
} from "./material_theme";
import { FONT_SIZE_DEFAULT, get_font_stack, normalize_font_size_scale } from "./font_stacks";

const DEFAULT_ACCENT = "#3b82f6";
const DEFAULT_ACCENT_HOVER = "#2563eb";
const DEFAULT_CUSTOM_SEED = "#3b82f6";

const CACHE_KEY = "aster_bridge_theme_cache";

const TOAST_POSITIONS = [
  "top",
  "bottom",
  "top-right",
  "top-left",
  "bottom-right",
  "bottom-left",
];

export type ThemePreference = "light" | "dark" | "system";

export interface ResolvedPreferences {
  theme: ThemePreference;
  color_theme: string;
  accent_color: string;
  accent_color_hover: string;
  custom_theme_seed: string;
  custom_theme_overrides: CustomThemeOverrides;
  font_choice: string;
  font_size_scale: number;
  reduce_motion: boolean;
  compact_mode: boolean;
  high_contrast: boolean;
  reduce_transparency: boolean;
  link_underlines: boolean;
  dyslexia_font: boolean;
  text_spacing: boolean;
  toast_position: string;
}

let sync_generation = 0;

export function invalidate_preferences_sync(): void {
  sync_generation++;
}

export function current_sync_generation(): number {
  return sync_generation;
}

let current_toast_position = "bottom";
const toast_position_listeners: (() => void)[] = [];

export function get_toast_position(): string {
  return current_toast_position;
}

export function on_toast_position_change(listener: () => void): () => void {
  toast_position_listeners.push(listener);
  return () => {
    const i = toast_position_listeners.indexOf(listener);
    if (i >= 0) toast_position_listeners.splice(i, 1);
  };
}

function set_toast_position(position: string): void {
  const next = TOAST_POSITIONS.includes(position) ? position : "bottom";
  if (next === current_toast_position) return;
  current_toast_position = next;
  toast_position_listeners.forEach((l) => l());
}

export function system_is_dark(): boolean {
  return (
    typeof window !== "undefined" &&
    !!window.matchMedia &&
    window.matchMedia("(prefers-color-scheme: dark)").matches
  );
}

export function default_resolved_preferences(): ResolvedPreferences {
  return {
    theme: "system",
    color_theme: "default",
    accent_color: DEFAULT_ACCENT,
    accent_color_hover: DEFAULT_ACCENT_HOVER,
    custom_theme_seed: DEFAULT_CUSTOM_SEED,
    custom_theme_overrides: {},
    font_choice: "default",
    font_size_scale: FONT_SIZE_DEFAULT,
    reduce_motion: false,
    compact_mode: false,
    high_contrast: false,
    reduce_transparency: false,
    link_underlines: false,
    dyslexia_font: false,
    text_spacing: false,
    toast_position: "bottom",
  };
}

export function normalize_preferences(raw: UserPreferences | null): ResolvedPreferences | null {
  if (!raw) return null;

  const nothing_set =
    !raw.theme &&
    !raw.color_theme &&
    !raw.accent_color &&
    !raw.custom_theme_seed &&
    !raw.font_choice &&
    raw.font_size_scale == null &&
    raw.reduce_motion == null &&
    raw.compact_mode == null &&
    raw.high_contrast == null &&
    raw.reduce_transparency == null &&
    raw.link_underlines == null &&
    raw.dyslexia_font == null &&
    raw.text_spacing == null &&
    !raw.toast_position;
  if (nothing_set) return null;

  const pref = raw.theme;
  const theme: ThemePreference =
    pref === "light" || pref === "dark" || pref === "system" ? pref : "system";

  return {
    theme,
    color_theme: raw.color_theme || "default",
    accent_color: raw.accent_color || DEFAULT_ACCENT,
    accent_color_hover: raw.accent_color_hover || DEFAULT_ACCENT_HOVER,
    custom_theme_seed: raw.custom_theme_seed || DEFAULT_CUSTOM_SEED,
    custom_theme_overrides: (raw.custom_theme_overrides || {}) as CustomThemeOverrides,
    font_choice: raw.font_choice || "default",
    font_size_scale: normalize_font_size_scale(raw.font_size_scale),
    reduce_motion: raw.reduce_motion === true,
    compact_mode: raw.compact_mode === true,
    high_contrast: raw.high_contrast === true,
    reduce_transparency: raw.reduce_transparency === true,
    link_underlines: raw.link_underlines === true,
    dyslexia_font: raw.dyslexia_font === true,
    text_spacing: raw.text_spacing === true,
    toast_position: raw.toast_position || "bottom",
  };
}

function resolve_is_dark(theme: ThemePreference): boolean {
  return theme === "system" ? system_is_dark() : theme === "dark";
}

function apply_color_theme(resolved: ResolvedPreferences, is_dark: boolean): void {
  const root = document.documentElement;

  root.style.removeProperty("--bg-secondary");
  root.style.removeProperty("--border-secondary");
  root.style.removeProperty("--text-tertiary");

  for (const cls of Array.from(root.classList)) {
    if (cls.startsWith("theme-")) root.classList.remove(cls);
  }

  const set_inline_accent = () => {
    root.style.setProperty("--accent-color", resolved.accent_color);
    root.style.setProperty("--accent-color-hover", resolved.accent_color_hover);

    if (is_valid_hex_color(resolved.accent_color)) {
      for (const [key, value] of Object.entries(derive_accent_vars(resolved.accent_color))) {
        root.style.setProperty(key, value);
      }
    }
  };

  if (resolved.color_theme === "custom") {
    if (is_valid_hex_color(resolved.custom_theme_seed)) {
      apply_custom_theme(resolved.custom_theme_seed, is_dark, resolved.custom_theme_overrides);
    } else {
      clear_material_theme();
      set_inline_accent();
    }
  } else {
    clear_material_theme();

    if (resolved.color_theme !== "default") {
      root.classList.add(`theme-${resolved.color_theme}`);
      root.style.removeProperty("--accent-color");
      root.style.removeProperty("--accent-color-hover");

      for (const key of ACCENT_DERIVED_KEYS) {
        root.style.removeProperty(key);
      }
    } else {
      set_inline_accent();
    }
  }
}

function apply_accessibility(resolved: ResolvedPreferences): void {
  const root = document.documentElement;

  root.style.setProperty(
    "--font-scale",
    String(normalize_font_size_scale(resolved.font_size_scale) / FONT_SIZE_DEFAULT),
  );
  root.style.setProperty("--font-sans", get_font_stack(resolved.font_choice));

  root.classList.toggle("reduce-motion", resolved.reduce_motion);
  root.classList.toggle("compact-mode", resolved.compact_mode);
  root.classList.toggle("high-contrast", resolved.high_contrast);
  root.classList.toggle("reduce-transparency", resolved.reduce_transparency);
  root.classList.toggle("link-underlines", resolved.link_underlines);
  root.classList.toggle("dyslexia-font", resolved.dyslexia_font);
  root.classList.toggle("text-spacing", resolved.text_spacing);
}

export function apply_preferences(resolved: ResolvedPreferences): void {
  if (typeof document === "undefined") return;

  const is_dark = resolve_is_dark(resolved.theme);
  document.documentElement.classList.toggle("dark", is_dark);
  apply_color_theme(resolved, is_dark);
  apply_accessibility(resolved);
  set_toast_position(resolved.toast_position);
}

export function read_cached_preferences(): ResolvedPreferences | null {
  try {
    const raw = localStorage.getItem(CACHE_KEY);
    if (!raw) return null;

    const parsed = JSON.parse(raw) as Partial<UserPreferences>;
    if (!parsed || typeof parsed !== "object") return null;

    return normalize_preferences({
      theme: parsed.theme ?? null,
      color_theme: parsed.color_theme ?? null,
      accent_color: parsed.accent_color ?? null,
      accent_color_hover: parsed.accent_color_hover ?? null,
      custom_theme_seed: parsed.custom_theme_seed ?? null,
      custom_theme_overrides: parsed.custom_theme_overrides ?? {},
      font_choice: parsed.font_choice ?? null,
      font_size_scale: parsed.font_size_scale ?? null,
      reduce_motion: parsed.reduce_motion ?? null,
      compact_mode: parsed.compact_mode ?? null,
      high_contrast: parsed.high_contrast ?? null,
      reduce_transparency: parsed.reduce_transparency ?? null,
      link_underlines: parsed.link_underlines ?? null,
      dyslexia_font: parsed.dyslexia_font ?? null,
      text_spacing: parsed.text_spacing ?? null,
      color_vision_mode: parsed.color_vision_mode ?? null,
      toast_position: parsed.toast_position ?? null,
    });
  } catch {
    return null;
  }
}

export function write_cached_preferences(resolved: ResolvedPreferences): void {
  try {
    localStorage.setItem(CACHE_KEY, JSON.stringify(resolved));
  } catch {}
}

export function clear_cached_preferences(): void {
  try {
    localStorage.removeItem(CACHE_KEY);
  } catch {}
}
