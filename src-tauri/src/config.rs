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
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeConfig {
    pub imap_port: u16,
    pub smtp_port: u16,
    #[serde(default = "default_jmap_port")]
    pub jmap_port: u16,
    #[serde(default = "default_jmap_enabled")]
    pub jmap_enabled: bool,
    #[serde(default)]
    pub service_mode: bool,
    #[serde(default)]
    pub autostart: bool,
    #[serde(default = "default_tls_enabled")]
    pub tls_enabled: bool,
    #[serde(default = "default_imap_implicit_tls_port")]
    pub imap_implicit_tls_port: u16,
    #[serde(default = "default_smtp_implicit_tls_port")]
    pub smtp_implicit_tls_port: u16,
    #[serde(default = "default_jmap_https_enabled")]
    pub jmap_https_enabled: bool,
    #[serde(default = "default_pop3_port")]
    pub pop3_port: u16,
    #[serde(default = "default_pop3s_port")]
    pub pop3s_port: u16,
    pub poll_interval_secs: u64,
    #[serde(skip)]
    pub data_dir: PathBuf,
}

fn default_jmap_port() -> u16 {
    1080
}

fn default_jmap_enabled() -> bool {
    true
}

fn default_tls_enabled() -> bool {
    true
}

fn default_imap_implicit_tls_port() -> u16 {
    1993
}

fn default_smtp_implicit_tls_port() -> u16 {
    1465
}

fn default_jmap_https_enabled() -> bool {
    true
}

fn default_pop3_port() -> u16 {
    1110
}

fn default_pop3s_port() -> u16 {
    1995
}

impl Default for BridgeConfig {
    fn default() -> Self {
        Self {
            imap_port: 1143,
            smtp_port: 1025,
            jmap_port: default_jmap_port(),
            jmap_enabled: default_jmap_enabled(),
            service_mode: false,
            autostart: false,
            tls_enabled: default_tls_enabled(),
            imap_implicit_tls_port: default_imap_implicit_tls_port(),
            smtp_implicit_tls_port: default_smtp_implicit_tls_port(),
            jmap_https_enabled: default_jmap_https_enabled(),
            pop3_port: default_pop3_port(),
            pop3s_port: default_pop3s_port(),
            poll_interval_secs: 30,
            data_dir: PathBuf::new(),
        }
    }
}

pub fn data_dir() -> Result<PathBuf, String> {
    let base = dirs::data_local_dir()
        .ok_or_else(|| "cannot resolve local data directory".to_string())?;
    let dir = base.join("com.astermail.bridge");
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    Ok(dir)
}

pub fn load_config() -> Result<BridgeConfig, String> {
    let dir = data_dir()?;
    let config_path = dir.join("config.toml");

    let mut config = if config_path.exists() {
        let contents = std::fs::read_to_string(&config_path).map_err(|e| e.to_string())?;
        toml::from_str::<BridgeConfig>(&contents).map_err(|e| e.to_string())?
    } else {
        let default = BridgeConfig::default();
        let contents = toml::to_string_pretty(&default).map_err(|e| e.to_string())?;
        std::fs::write(&config_path, contents).map_err(|e| e.to_string())?;
        default
    };

    config.data_dir = dir;
    if let Err(e) = validate_ports(&config) {
        eprintln!(
            "invalid port configuration ({}); resetting imap/smtp ports to defaults",
            e
        );
        let defaults = BridgeConfig::default();
        config.imap_port = defaults.imap_port;
        config.smtp_port = defaults.smtp_port;
        validate_ports(&config)?;
        save_config(&config)?;
    }

    const MIN_POLL_INTERVAL_SECS: u64 = 5;
    const MAX_POLL_INTERVAL_SECS: u64 = 86_400;
    if config.poll_interval_secs < MIN_POLL_INTERVAL_SECS {
        tracing::warn!(
            "poll_interval_secs {} below minimum, clamping to {}",
            config.poll_interval_secs,
            MIN_POLL_INTERVAL_SECS
        );
        config.poll_interval_secs = MIN_POLL_INTERVAL_SECS;
    } else if config.poll_interval_secs > MAX_POLL_INTERVAL_SECS {
        config.poll_interval_secs = MAX_POLL_INTERVAL_SECS;
    }

    Ok(config)
}

pub(crate) fn validate_ports(c: &BridgeConfig) -> Result<(), String> {
    for (name, port) in [
        ("imap_port", c.imap_port),
        ("imap_implicit_tls_port", c.imap_implicit_tls_port),
        ("smtp_port", c.smtp_port),
        ("smtp_implicit_tls_port", c.smtp_implicit_tls_port),
        ("jmap_port", c.jmap_port),
        ("pop3_port", c.pop3_port),
        ("pop3s_port", c.pop3s_port),
    ] {
        if port < 1024 {
            return Err(format!("{} must be >= 1024 (got {})", name, port));
        }
    }
    let mut ports = [
        c.imap_port, c.imap_implicit_tls_port, c.smtp_port, c.smtp_implicit_tls_port,
        c.jmap_port, c.pop3_port, c.pop3s_port,
    ];
    ports.sort();
    for i in 0..ports.len() - 1 {
        if ports[i] == ports[i + 1] {
            return Err(format!("port {} is assigned to multiple protocols", ports[i]));
        }
    }
    Ok(())
}

pub fn save_config(config: &BridgeConfig) -> Result<(), String> {
    let config_path = config.data_dir.join("config.toml");
    let contents = toml::to_string_pretty(config).map_err(|e| e.to_string())?;
    std::fs::write(&config_path, contents).map_err(|e| e.to_string())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_sensible_and_distinct() {
        let c = BridgeConfig::default();
        assert_eq!(c.imap_port, 1143);
        assert_eq!(c.smtp_port, 1025);
        assert_eq!(c.jmap_port, 1080);
        assert_eq!(c.poll_interval_secs, 30);
        assert!(c.jmap_enabled);
        assert!(c.tls_enabled);
        assert!(!c.service_mode);
        validate_ports(&c).expect("default ports must validate");
    }

    #[test]
    fn validate_ports_rejects_privileged_port() {
        let mut c = BridgeConfig::default();
        c.imap_port = 143;
        let err = validate_ports(&c).unwrap_err();
        assert!(err.contains("imap_port"));
    }

    #[test]
    fn validate_ports_rejects_duplicate_ports() {
        let mut c = BridgeConfig::default();
        c.smtp_port = c.imap_port;
        let err = validate_ports(&c).unwrap_err();
        assert!(err.contains("multiple protocols"));
    }

    #[test]
    fn validate_ports_rejects_collision_with_reserved_port() {
        let mut c = BridgeConfig::default();
        c.imap_port = c.imap_implicit_tls_port;
        let err = validate_ports(&c).unwrap_err();
        assert!(err.contains("multiple protocols"));

        let mut c = BridgeConfig::default();
        c.smtp_port = c.pop3s_port;
        let err = validate_ports(&c).unwrap_err();
        assert!(err.contains("multiple protocols"));
    }

    #[test]
    fn toml_round_trip_preserves_fields() {
        let c = BridgeConfig::default();
        let serialized = toml::to_string_pretty(&c).unwrap();
        let parsed: BridgeConfig = toml::from_str(&serialized).unwrap();
        assert_eq!(parsed.imap_port, c.imap_port);
        assert_eq!(parsed.pop3s_port, c.pop3s_port);
        assert_eq!(parsed.poll_interval_secs, c.poll_interval_secs);
    }

    #[test]
    fn missing_optional_fields_fall_back_to_defaults() {
        let minimal = "imap_port = 1143\nsmtp_port = 1025\npoll_interval_secs = 30\n";
        let parsed: BridgeConfig = toml::from_str(minimal).unwrap();
        assert_eq!(parsed.jmap_port, default_jmap_port());
        assert!(parsed.jmap_enabled);
        assert_eq!(parsed.pop3_port, default_pop3_port());
        assert!(!parsed.service_mode);
    }

    #[test]
    fn save_config_writes_toml_that_reloads() {
        let dir = tempfile::tempdir().unwrap();
        let mut c = BridgeConfig::default();
        c.data_dir = dir.path().to_path_buf();
        c.smtp_port = 2025;
        save_config(&c).unwrap();

        let contents = std::fs::read_to_string(dir.path().join("config.toml")).unwrap();
        let parsed: BridgeConfig = toml::from_str(&contents).unwrap();
        assert_eq!(parsed.smtp_port, 2025);
    }

    #[test]
    fn data_dir_is_not_serialized() {
        let c = BridgeConfig::default();
        let serialized = toml::to_string_pretty(&c).unwrap();
        assert!(!serialized.contains("data_dir"));
    }
}
