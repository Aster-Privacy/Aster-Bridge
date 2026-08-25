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
use objc2::{AnyThread, MainThreadMarker};
use objc2_app_kit::{NSApplication, NSImage};
use objc2_foundation::NSData;
use tauri::Theme;

const LIGHT_ICON: &[u8] = include_bytes!("../icons/icon_macos.png");
const DARK_ICON: &[u8] = include_bytes!("../icons/icon_macos_dark.png");

pub fn apply(theme: Theme) {
    let Some(main_thread) = MainThreadMarker::new() else {
        return;
    };
    let bytes = match theme {
        Theme::Dark => DARK_ICON,
        _ => LIGHT_ICON,
    };
    let data = NSData::with_bytes(bytes);
    let Some(image) = NSImage::initWithData(NSImage::alloc(), &data) else {
        return;
    };
    unsafe {
        NSApplication::sharedApplication(main_thread).setApplicationIconImage(Some(&image));
    }
}
