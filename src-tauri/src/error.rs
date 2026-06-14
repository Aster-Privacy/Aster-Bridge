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

#[derive(Debug, thiserror::Error)]
#[allow(dead_code)]
pub enum BridgeError {
    #[error("authentication failed: {0}")]
    Auth(String),

    #[error("API error: {0}")]
    Api(String),

    #[error("crypto error: {0}")]
    Crypto(String),

    #[error("database error: {0}")]
    Database(String),

    #[error("IMAP protocol error: {0}")]
    Imap(String),

    #[error("SMTP protocol error: {0}")]
    Smtp(String),

    #[error("configuration error: {0}")]
    Config(String),

    #[error("network error: {0}")]
    Network(#[from] reqwest::Error),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("plan limit exceeded: {0}")]
    PlanLimit(String),

    #[error("plan_upgrade_required: {0}")]
    PlanUpgradeRequired(String),
}

pub type Result<T> = std::result::Result<T, BridgeError>;
