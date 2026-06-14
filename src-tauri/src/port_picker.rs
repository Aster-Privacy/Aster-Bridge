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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn picks_preferred_port_when_free() {
        let probe = TcpListener::bind("127.0.0.1:0").unwrap();
        let free = probe.local_addr().unwrap().port();
        drop(probe);
        let picked = pick_available_port("127.0.0.1", free).unwrap();
        assert_eq!(picked, free);
    }

    #[test]
    fn picked_port_is_actually_bindable() {
        let picked = pick_available_port("127.0.0.1", 23456).unwrap();
        let listener = TcpListener::bind(format!("127.0.0.1:{}", picked));
        assert!(listener.is_ok());
    }

    #[test]
    fn skips_busy_preferred_and_picks_next() {
        let held = TcpListener::bind("127.0.0.1:0").unwrap();
        let busy = held.local_addr().unwrap().port();
        if busy >= u16::MAX - MAX_PROBE_STEPS {
            return;
        }
        let picked = pick_available_port("127.0.0.1", busy).unwrap();
        assert_ne!(picked, busy);
        assert!(picked > busy);
    }

    #[test]
    fn rejects_non_loopback_host() {
        let err = pick_available_port("8.8.8.8", 30000).unwrap_err();
        assert!(err.contains("non-loopback"));
    }

    #[test]
    fn rejects_invalid_host() {
        let err = pick_available_port("not-an-ip", 30000).unwrap_err();
        assert!(err.contains("invalid bind host"));
    }
}
