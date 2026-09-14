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
pub mod accept;
pub mod account_state;
pub mod api_client;
pub mod auth;
pub mod config;
pub mod conn_limit;
pub mod crypto;
pub mod dav;
pub mod db;
pub mod diagnostics;
pub mod error;
pub mod events;
pub mod imap;
pub mod jmap;
pub mod message_render;
pub mod ops;
pub mod outbox;
pub mod pop3;
pub mod port_picker;
#[cfg(test)]
mod protocol_harness;
pub mod runtime;
pub mod secrets;
pub mod smtp;
pub mod sync;
pub mod tls;
pub mod tls_pinning;
