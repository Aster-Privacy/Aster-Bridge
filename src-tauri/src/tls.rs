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
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;

pub type TlsResult<T> = std::result::Result<T, String>;

pub fn cert_pem_path(data_dir: &Path) -> PathBuf {
    data_dir.join("tls.crt")
}

pub fn key_pem_path(data_dir: &Path) -> PathBuf {
    data_dir.join("tls.key")
}

pub fn ensure_cert(
    data_dir: &Path,
) -> TlsResult<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let cert_path = cert_pem_path(data_dir);
    let key_path = key_pem_path(data_dir);

    if cert_path.exists() && key_path.exists() {
        let should_renew = cert_older_than_days(&cert_path, 700);
        if let Ok((certs, key)) = load_existing(&cert_path, &key_path) {
            if !should_renew {
                return Ok((certs, key));
            }
            tracing::info!("TLS cert is older than 700 days; regenerating");
        } else {
            tracing::warn!("existing TLS material failed to parse; regenerating");
        }
    }

    generate_and_persist(&cert_path, &key_path)
}

fn load_existing(
    cert_path: &Path,
    key_path: &Path,
) -> TlsResult<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let cert_bytes = std::fs::read(cert_path).map_err(|e| e.to_string())?;
    let key_bytes = std::fs::read(key_path).map_err(|e| e.to_string())?;

    let mut cert_reader = std::io::BufReader::new(&cert_bytes[..]);
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_reader)
        .collect::<std::io::Result<Vec<_>>>()
        .map_err(|e| e.to_string())?;
    if certs.is_empty() {
        return Err("no certificates parsed from tls.crt".to_string());
    }

    let mut key_reader = std::io::BufReader::new(&key_bytes[..]);
    let key = rustls_pemfile::private_key(&mut key_reader)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "no private key parsed from tls.key".to_string())?;

    Ok((certs, key))
}

fn generate_and_persist(
    cert_path: &Path,
    key_path: &Path,
) -> TlsResult<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, SanType};
    use time::OffsetDateTime;

    let mut params = CertificateParams::new(vec![
        "127.0.0.1".to_string(),
        "localhost".to_string(),
        "bridge.local".to_string(),
    ])
    .map_err(|e| e.to_string())?;

    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "Aster Bridge");
    dn.push(DnType::OrganizationName, "Aster Communications Inc.");
    params.distinguished_name = dn;

    params.subject_alt_names = vec![
        SanType::IpAddress(std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1))),
        SanType::IpAddress(std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)),
        SanType::DnsName("localhost".to_string().try_into().map_err(|e: rcgen::Error| e.to_string())?),
        SanType::DnsName("bridge.local".to_string().try_into().map_err(|e: rcgen::Error| e.to_string())?),
    ];

    let now = OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::days(1);
    params.not_after = now + time::Duration::days(365 * 2);

    let key_pair = KeyPair::generate().map_err(|e| e.to_string())?;
    let cert = params.self_signed(&key_pair).map_err(|e| e.to_string())?;

    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();

    if let Some(parent) = cert_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    std::fs::write(cert_path, cert_pem.as_bytes()).map_err(|e| e.to_string())?;
    write_key_restricted(key_path, key_pem.as_bytes())?;

    let cert_der: CertificateDer<'static> = cert.der().clone();
    let key_der: PrivateKeyDer<'static> = PrivateKeyDer::try_from(key_pair.serialize_der())
        .map_err(|e| e.to_string())?;

    Ok((vec![cert_der], key_der))
}

#[cfg(unix)]
fn write_key_restricted(path: &Path, bytes: &[u8]) -> TlsResult<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| e.to_string())?;
    use std::io::Write;
    f.write_all(bytes).map_err(|e| e.to_string())?;
    Ok(())
}

#[cfg(windows)]
fn write_key_restricted(path: &Path, bytes: &[u8]) -> TlsResult<()> {
    use std::io::Write;
    use std::os::windows::process::CommandExt;
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)
        .map_err(|e| e.to_string())?;

    let p = path.to_string_lossy();
    let user = whoami::fallible::username().unwrap_or_else(|_| {
        std::env::var("USERNAME").unwrap_or_else(|_| "SYSTEM".to_string())
    });
    let acl_ok = match std::process::Command::new("icacls")
        .args([p.as_ref(), "/inheritance:r", "/grant:r", &format!("{}:(F)", user)])
        .creation_flags(0x0800_0000)
        .output()
    {
        Ok(out) if out.status.success() => true,
        Ok(out) => {
            tracing::warn!(
                "icacls failed to restrict TLS key permissions: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            );
            false
        }
        Err(e) => {
            tracing::warn!("icacls invocation failed for TLS key: {}", e);
            false
        }
    };
    if !acl_ok {
        tracing::warn!("TLS private key {} may be readable under inherited ACLs", p);
    }

    f.write_all(bytes).map_err(|e| e.to_string())?;
    f.flush().map_err(|e| e.to_string())?;
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn write_key_restricted(path: &Path, bytes: &[u8]) -> TlsResult<()> {
    std::fs::write(path, bytes).map_err(|e| e.to_string())
}

pub fn server_config(
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> TlsResult<Arc<ServerConfig>> {
    let provider = rustls::crypto::ring::default_provider();
    let config = ServerConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| e.to_string())?;
    Ok(Arc::new(config))
}

pub fn install_default_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

fn cert_older_than_days(cert_path: &Path, days: u64) -> bool {
    let Ok(metadata) = std::fs::metadata(cert_path) else { return true };
    let Ok(modified) = metadata.modified() else { return true };
    let Ok(age) = modified.elapsed() else { return true };
    age > std::time::Duration::from_secs(days * 86400)
}

pub fn cert_fingerprint_sha256(data_dir: &Path) -> Option<String> {
    let path = cert_pem_path(data_dir);
    let bytes = std::fs::read(&path).ok()?;
    let mut reader = std::io::BufReader::new(&bytes[..]);
    let certs: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut reader).collect::<std::io::Result<Vec<_>>>().ok()?;
    let first = certs.into_iter().next()?;
    Some(fingerprint_hex_colon(first.as_ref()))
}

fn fingerprint_hex_colon(der: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(der);
    let digest = h.finalize();
    digest
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join(":")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ensure_cert_generates_and_reuses() {
        let dir = tempfile::tempdir().unwrap();
        let (certs1, _key1) = ensure_cert(dir.path()).unwrap();
        assert!(!certs1.is_empty());
        assert!(cert_pem_path(dir.path()).exists());
        assert!(key_pem_path(dir.path()).exists());

        let (certs2, _key2) = ensure_cert(dir.path()).unwrap();
        assert_eq!(certs1[0].as_ref(), certs2[0].as_ref());
    }

    #[test]
    fn fingerprint_format_is_colon_hex_uppercase() {
        let dir = tempfile::tempdir().unwrap();
        let _ = ensure_cert(dir.path()).unwrap();
        let fp = cert_fingerprint_sha256(dir.path()).unwrap();
        let parts: Vec<&str> = fp.split(':').collect();
        assert_eq!(parts.len(), 32);
        for p in parts {
            assert_eq!(p.len(), 2);
            assert!(p.chars().all(|c| c.is_ascii_hexdigit() && (!c.is_alphabetic() || c.is_uppercase())));
        }
    }
}
