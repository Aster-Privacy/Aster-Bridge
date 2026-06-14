// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Aster Communications Inc.

import React from "react";
import ReactDOM from "react-dom/client";
import App from "@/App";
import "@/i18n";
import "@aster/ui/styles";
import "@fontsource/google-sans-flex";
import "@/styles/global.css";

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
