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

export const HEX_COLOR = /^#[0-9a-f]{6}$/i;

export const DEFAULT_PROFILE_COLOR = "#6366f1";

export const NEUTRAL_PROFILE_COLOR = "#6b7280";

export const PROFILE_GRADIENTS: Record<string, { top_left: string; bottom_right: string }> = {
  "#6366f1": { top_left: "#6366f1", bottom_right: "#312e81" },
  "#3b82f6": { top_left: "#3b82f6", bottom_right: "#312e81" },
  "#8b5cf6": { top_left: "#7c3aed", bottom_right: "#1e3a5f" },
  "#ec4899": { top_left: "#ec4899", bottom_right: "#581c87" },
  "#ef4444": { top_left: "#d97706", bottom_right: "#7f1d1d" },
  "#f97316": { top_left: "#eab308", bottom_right: "#78350f" },
  "#22c55e": { top_left: "#4ade80", bottom_right: "#064e3b" },
  "#14b8a6": { top_left: "#2dd4bf", bottom_right: "#134e4a" },
  "#6b7280": { top_left: "#9ca3af", bottom_right: "#111827" },
};

export function profile_gradient_background(color: string): string {
  const fallback = HEX_COLOR.test(color) ? color : NEUTRAL_PROFILE_COLOR;
  const config = PROFILE_GRADIENTS[color] || { top_left: fallback, bottom_right: fallback };
  return `linear-gradient(135deg, ${config.top_left} 0%, ${config.bottom_right} 100%)`;
}
