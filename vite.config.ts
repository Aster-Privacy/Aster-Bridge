// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Aster Communications Inc.

import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import tsconfig_paths from "vite-tsconfig-paths";
import path from "node:path";

const dep = (p: string) => path.resolve(process.cwd(), "node_modules", p);

export default defineConfig({
  plugins: [react(), tailwindcss(), tsconfig_paths()],
  server: {
    port: 5174,
    strictPort: true,
    fs: { allow: [".."] },
  },
  resolve: {
    dedupe: ["react", "react-dom"],
    alias: {
      "@radix-ui/react-slot": dep("@radix-ui/react-slot"),
      "@radix-ui/react-tooltip": dep("@radix-ui/react-tooltip"),
      "class-variance-authority": dep("class-variance-authority"),
      "framer-motion": dep("framer-motion"),
    },
  },
  optimizeDeps: {
    include: [
      "react",
      "react-dom",
      "react-dom/client",
      "react/jsx-runtime",
      "react/jsx-dev-runtime",
      "@radix-ui/react-slot",
      "@radix-ui/react-tooltip",
      "class-variance-authority",
      "framer-motion",
      "i18next",
      "react-i18next",
    ],
    esbuildOptions: { target: "es2022" },
  },
  build: {
    target: process.env.TAURI_ENV_PLATFORM === "windows" ? "chrome105" : "safari14.1",
  },
  clearScreen: false,
});
