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
pub async fn ctrl_c() {
    if tokio::signal::ctrl_c().await.is_err() {
        std::future::pending::<()>().await;
    }
}

#[cfg(unix)]
pub async fn shutdown() {
    use tokio::signal::unix::{signal, SignalKind};
    let (Ok(mut terminate), Ok(mut interrupt)) =
        (signal(SignalKind::terminate()), signal(SignalKind::interrupt()))
    else {
        ctrl_c().await;
        return;
    };
    tokio::select! {
        _ = terminate.recv() => {}
        _ = interrupt.recv() => {}
    }
}

#[cfg(windows)]
pub async fn shutdown() {
    use tokio::signal::windows;
    let mut ctrl_c = windows::ctrl_c().ok();
    let mut ctrl_break = windows::ctrl_break().ok();
    let mut close = windows::ctrl_close().ok();
    let mut shutdown = windows::ctrl_shutdown().ok();
    let mut logoff = windows::ctrl_logoff().ok();
    tokio::select! {
        _ = async { match ctrl_c.as_mut() { Some(s) => s.recv().await, None => std::future::pending().await } } => {}
        _ = async { match ctrl_break.as_mut() { Some(s) => s.recv().await, None => std::future::pending().await } } => {}
        _ = async { match close.as_mut() { Some(s) => s.recv().await, None => std::future::pending().await } } => {}
        _ = async { match shutdown.as_mut() { Some(s) => s.recv().await, None => std::future::pending().await } } => {}
        _ = async { match logoff.as_mut() { Some(s) => s.recv().await, None => std::future::pending().await } } => {}
    }
}

#[cfg(not(any(unix, windows)))]
pub async fn shutdown() {
    ctrl_c().await;
}
