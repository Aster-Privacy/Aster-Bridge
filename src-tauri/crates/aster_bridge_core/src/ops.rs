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
use std::path::Path;

use crate::api_client::{ApiClient, DeviceCodeRequest};
use crate::auth::device_identity::{self, DeviceIdentity};
use crate::auth::session::{self, Session};
use crate::error::{BridgeError, Result};
use crate::runtime::ClientProfile;

pub const DEVICE_TYPE: &str = "bridge";
pub const RESERVED_SERVICE_PORTS: [u16; 4] = [3306, 5432, 6379, 27017];

pub fn machine_name(profile: ClientProfile) -> String {
    let name = whoami::devicename();
    let name = name.trim();
    let name = if name.is_empty() { "Aster Bridge" } else { name };
    match profile {
        ClientProfile::Desktop => name.to_string(),
        ClientProfile::Cli => format!("{} (CLI)", name),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceCode {
    pub code: String,
    pub normalized: String,
    pub expires_in: u64,
}

pub fn normalize_code(code: &str) -> String {
    code.chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .collect()
}

pub async fn request_device_code(
    client: &ApiClient,
    identity: &DeviceIdentity,
    profile: ClientProfile,
) -> Result<DeviceCode> {
    let (ed25519_pk, mlkem_pk, x25519_pk) = device_identity::get_pubkeys(identity);
    let response = client
        .generate_device_code(&DeviceCodeRequest {
            ed25519_pk,
            mlkem_pk,
            x25519_pk,
            machine_name: machine_name(profile),
            device_type: DEVICE_TYPE.to_string(),
        })
        .await?;
    Ok(DeviceCode {
        normalized: normalize_code(&response.code),
        code: response.code,
        expires_in: response.expires_in,
    })
}

pub enum SignInPoll {
    Pending(String),
    Expired,
    Confirmed(Box<Session>),
}

pub async fn poll_device_sign_in(
    client: &ApiClient,
    identity: &mut DeviceIdentity,
    data_dir: &Path,
    normalized_code: &str,
) -> Result<SignInPoll> {
    let status = client.poll_device_code_status(normalized_code).await?;
    match status.status.as_str() {
        "confirmed" => {
            let device_id = status
                .device_id
                .ok_or_else(|| BridgeError::Auth("no device_id in confirmation".to_string()))?;
            let sealed_envelope = status
                .sealed_envelope
                .ok_or_else(|| BridgeError::Auth("no sealed envelope in confirmation".to_string()))?;
            let passphrase = device_identity::unseal_vault_envelope(identity, &sealed_envelope)
                .map_err(BridgeError::Crypto)?;
            device_identity::set_device_id(data_dir, device_id).map_err(BridgeError::Auth)?;
            device_identity::store_passphrase(data_dir, &passphrase).map_err(BridgeError::Auth)?;
            identity.device_id = Some(device_id);
            let session =
                session::login_with_passphrase(identity, device_id, passphrase, client).await?;
            Ok(SignInPoll::Confirmed(Box::new(session)))
        }
        "expired" => Ok(SignInPoll::Expired),
        other => Ok(SignInPoll::Pending(other.to_string())),
    }
}

pub fn validate_port(port: u16) -> std::result::Result<(), &'static str> {
    if port < 1024 {
        return Err("port must be >= 1024");
    }
    if RESERVED_SERVICE_PORTS.contains(&port) {
        return Err("well-known service port not allowed");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_machine_name_is_suffixed() {
        let desktop = machine_name(ClientProfile::Desktop);
        let cli = machine_name(ClientProfile::Cli);
        assert!(!desktop.is_empty());
        assert_eq!(cli, format!("{} (CLI)", desktop));
    }

    #[test]
    fn normalize_code_strips_dashes_and_spaces() {
        assert_eq!(normalize_code("AB12-CD34"), "AB12CD34");
        assert_eq!(normalize_code(" AB12 - CD34 "), "AB12CD34");
    }

    #[test]
    fn validate_port_rejects_privileged_and_reserved() {
        assert!(validate_port(80).is_err());
        assert!(validate_port(1023).is_err());
        assert!(validate_port(5432).is_err());
        assert!(validate_port(27017).is_err());
        assert!(validate_port(1024).is_ok());
        assert!(validate_port(1143).is_ok());
    }
}
