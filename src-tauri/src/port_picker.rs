//
// Aster Communications Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//
use std::net::SocketAddr;

const MAX_PROBE_STEPS: u16 = 20;

pub fn pick_available_port(host: &str, preferred: u16) -> Result<u16, String> {
    let host_ip: std::net::IpAddr = host
        .parse()
        .map_err(|_| format!("invalid bind host: {}", host))?;
    if !host_ip.is_loopback() {
        return Err(format!("refusing to bind mail listener to non-loopback host {}", host));
    }
    for offset in 0..=MAX_PROBE_STEPS {
        let candidate = match preferred.checked_add(offset) {
            Some(p) if p >= 1024 => p,
            _ => continue,
        };
        let addr_str = format!("{}:{}", host, candidate);
        let parsed: SocketAddr = match addr_str.parse() {
            Ok(a) => a,
            Err(_) => continue,
        };
        match std::net::TcpListener::bind(parsed) {
            Ok(listener) => {
                drop(listener);
                if offset > 0 {
                    tracing::warn!(
                        "port {} in use, picked {} instead",
                        preferred,
                        candidate
                    );
                }
                return Ok(candidate);
            }
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
                continue;
            }
            Err(e) => {
                return Err(format!("bind probe failed on {}: {}", addr_str, e));
            }
        }
    }
    Err(format!(
        "no free port within {} of {}",
        MAX_PROBE_STEPS, preferred
    ))
}

#[cfg(test)]
pub(crate) static TEST_SERVER_START: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
