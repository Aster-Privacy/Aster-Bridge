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
const MISSING_DIST: &str = concat!(
    "Aster Bridge: the web interface has not been built yet, so the app would start with an ",
    "empty window.\n\n",
    "Build it first, from the repository root:\n",
    "    npm install\n",
    "    npm run build\n\n",
    "Then run the build again. To build the desktop app in one step, run `npm run tauri:build` ",
    "instead of a bare cargo command."
);

const DEV_SERVER_BUILD: &str = concat!(
    "cargo:warning=Aster Bridge is being built without the `custom-protocol` feature, so it ",
    "loads its interface from the Vite dev server on http://localhost:5174 instead of from the ",
    "binary. This is only correct for `npm run tauri:dev`."
);

fn main() {
    if std::env::var_os("CARGO_FEATURE_CUSTOM_PROTOCOL").is_some() {
        if !std::path::Path::new("../dist/index.html").exists() {
            panic!("{MISSING_DIST}");
        }
    } else {
        println!("{DEV_SERVER_BUILD}");
    }
    tauri_build::build()
}
