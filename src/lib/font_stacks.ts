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
const DEFAULT_FONT_ID = "default";

const FONT_STACKS: Record<string, string> = {
  default: "'Google Sans Flex', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif",
  system: "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif",
  inter: "'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif",
  roboto: "'Roboto', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif",
  nunito: "'Nunito', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif",
  merriweather: "'Merriweather', Georgia, serif",
  lora: "'Lora', Georgia, serif",
  jetbrains_mono: "'JetBrains Mono', 'Courier New', Courier, monospace",
  poppins: "'Poppins', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif",
  montserrat: "'Montserrat', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif",
  work_sans: "'Work Sans', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif",
  ibm_plex_sans: "'IBM Plex Sans', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif",
  ibm_plex_mono: "'IBM Plex Mono', 'Courier New', Courier, monospace",
  space_mono: "'Space Mono', 'Courier New', Courier, monospace",
  playfair_display: "'Playfair Display', Georgia, serif",
  libre_baskerville: "'Libre Baskerville', Georgia, serif",
  pt_serif: "'PT Serif', Georgia, serif",
  raleway: "'Raleway', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif",
};

export function get_font_stack(id: string | undefined | null): string {
  return FONT_STACKS[id ?? DEFAULT_FONT_ID] ?? FONT_STACKS[DEFAULT_FONT_ID];
}

const LEGACY_FONT_SIZE_MAP: Record<string, number> = {
  small: 14,
  default: 15,
  large: 17,
  extra_large: 19,
};

export const FONT_SIZE_DEFAULT = 15;

export function normalize_font_size_scale(value: unknown): number {
  if (typeof value === "number" && Number.isFinite(value)) {
    return Math.max(1, Math.round(value));
  }
  if (typeof value === "string" && value in LEGACY_FONT_SIZE_MAP) {
    return LEGACY_FONT_SIZE_MAP[value];
  }

  return FONT_SIZE_DEFAULT;
}
