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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_includes_variant_label_and_message() {
        assert_eq!(
            BridgeError::Auth("bad token".to_string()).to_string(),
            "authentication failed: bad token"
        );
        assert_eq!(
            BridgeError::Crypto("nonce".to_string()).to_string(),
            "crypto error: nonce"
        );
        assert_eq!(
            BridgeError::Config("missing".to_string()).to_string(),
            "configuration error: missing"
        );
        assert_eq!(
            BridgeError::PlanUpgradeRequired("pro".to_string()).to_string(),
            "plan_upgrade_required: pro"
        );
    }

    #[test]
    fn from_io_error_maps_to_io_variant() {
        let io = std::io::Error::new(std::io::ErrorKind::NotFound, "nope");
        let err: BridgeError = io.into();
        assert!(matches!(err, BridgeError::Io(_)));
        assert!(err.to_string().starts_with("IO error:"));
    }

    #[test]
    fn from_io_error_propagates_through_result() {
        fn fails() -> Result<()> {
            std::fs::read_to_string("/nonexistent/aster/bridge/path")?;
            Ok(())
        }
        let err = fails().unwrap_err();
        assert!(matches!(err, BridgeError::Io(_)));
    }

    #[test]
    fn debug_is_distinct_from_display() {
        let err = BridgeError::Api("rate limited".to_string());
        let debug = format!("{:?}", err);
        let display = err.to_string();
        assert!(debug.contains("Api"));
        assert_eq!(display, "API error: rate limited");
    }
}
