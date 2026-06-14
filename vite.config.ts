// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Aster Communications Inc.

import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import tsconfig_paths from "vite-tsconfig-paths";

export default defineConfig({
  plugins: [react(), tailwindcss(), tsconfig_paths()],
  server: {
    port: 5174,
    strictPort: true,
  },
  build: {
    target: process.env.TAURI_ENV_PLATFORM === "windows" ? "chrome105" : "safari14.1",
  },
  clearScreen: false,
});
