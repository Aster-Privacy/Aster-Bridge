//
// Aster Communications Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//
use std::net::SocketAddr;

const MAX_PROBE_STEPS: u16 = 20;

const OCCUPANT_CONNECT_TIMEOUT_MS: u64 = 500;
const OCCUPANT_READ_TIMEOUT_MS: u64 = 1000;
const OCCUPANT_RECHECKS: u32 = 3;
const OCCUPANT_RECHECK_DELAY_MS: u64 = 150;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Occupant {
    Free,
    AsterBridge,
    Unidentified,
    Unreachable,
}

pub fn probe_occupant(host: &str, port: u16) -> Occupant {
    use std::io::Read;

    let addr: SocketAddr = match format!("{}:{}", host, port).parse() {
        Ok(a) => a,
        Err(_) => return Occupant::Unreachable,
    };
    if let Ok(listener) = std::net::TcpListener::bind(addr) {
        drop(listener);
        return Occupant::Free;
    }
    let mut stream = match std::net::TcpStream::connect_timeout(
        &addr,
        std::time::Duration::from_millis(OCCUPANT_CONNECT_TIMEOUT_MS),
    ) {
        Ok(s) => s,
        Err(_) => return Occupant::Unreachable,
    };
    if stream
        .set_read_timeout(Some(std::time::Duration::from_millis(
            OCCUPANT_READ_TIMEOUT_MS,
        )))
        .is_err()
    {
        return Occupant::Unidentified;
    }
    let mut buf = [0u8; 256];
    match stream.read(&mut buf) {
        Ok(n) if n > 0 => {
            if String::from_utf8_lossy(&buf[..n]).contains("Aster Bridge") {
                Occupant::AsterBridge
            } else {
                Occupant::Unidentified
            }
        }
        _ => Occupant::Unidentified,
    }
}

fn pick_startup_port_for(preferred: u16, occupant: Occupant) -> Result<u16, String> {
    match occupant {
        Occupant::AsterBridge => {
            tracing::error!(
                "port {} is already served by another Aster Bridge; refusing to move to a different port",
                preferred
            );
            Err(format!(
                "Port {} is already in use by another copy of Aster Bridge. Quit the other copy, then start Aster Bridge again.",
                preferred
            ))
        }
        _ => {
            tracing::error!(
                "port {} is held by a program that did not identify itself; refusing to move to a different port",
                preferred
            );
            Err(format!(
                "Port {} is already in use by another program. Quit that program, or choose a different port in Settings, then start Aster Bridge again.",
                preferred
            ))
        }
    }
}

pub fn pick_startup_port(host: &str, preferred: u16) -> Result<u16, String> {
    match probe_occupant(host, preferred) {
        Occupant::Free => pick_available_port(host, preferred),
        Occupant::Unreachable => {
            for _ in 0..OCCUPANT_RECHECKS {
                std::thread::sleep(std::time::Duration::from_millis(OCCUPANT_RECHECK_DELAY_MS));
                match probe_occupant(host, preferred) {
                    Occupant::Free => return pick_available_port(host, preferred),
                    Occupant::Unreachable => continue,
                    other => return pick_startup_port_for(preferred, other),
                }
            }
            pick_startup_port_for(preferred, Occupant::Unreachable)
        }
        other => pick_startup_port_for(preferred, other),
    }
}

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

const BIND_RETRIES: u32 = 5;

pub async fn bind_loopback_listener(addr: &str) -> std::io::Result<tokio::net::TcpListener> {
    let sock_addr: SocketAddr = addr
        .parse()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    if !sock_addr.ip().is_loopback() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "refusing to bind mail listener to non-loopback host {}",
                sock_addr.ip()
            ),
        ));
    }
    let mut attempt = 0u32;
    loop {
        let socket = tokio::net::TcpSocket::new_v4()?;
        #[cfg(not(windows))]
        socket.set_reuseaddr(true).ok();
        match socket.bind(sock_addr) {
            Ok(()) => return socket.listen(1024),
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse && attempt < BIND_RETRIES => {
                attempt += 1;
                tracing::warn!("{} still in use, retrying bind ({})", addr, attempt);
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            }
            Err(e) => return Err(e),
        }
    }
}

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

    fn serve_greeting(greeting: &'static str) -> (u16, std::thread::JoinHandle<()>) {
        use std::io::Write;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let _ = stream.write_all(greeting.as_bytes());
                let _ = stream.flush();
                std::thread::sleep(std::time::Duration::from_millis(200));
            }
        });
        (port, handle)
    }

    #[test]
    fn an_unused_port_reads_as_free() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        assert_eq!(probe_occupant("127.0.0.1", port), Occupant::Free);
    }

    #[test]
    fn a_listener_that_greets_as_aster_bridge_is_recognized() {
        let (port, handle) = serve_greeting(
            "* OK [CAPABILITY IMAP4rev1 AUTH=PLAIN] Aster Bridge ready\r\n",
        );
        assert_eq!(probe_occupant("127.0.0.1", port), Occupant::AsterBridge);
        handle.join().unwrap();
    }

    #[test]
    fn a_foreign_listener_is_not_mistaken_for_aster_bridge() {
        let (port, handle) = serve_greeting("* OK Some Other Server ready\r\n");
        assert_eq!(probe_occupant("127.0.0.1", port), Occupant::Unidentified);
        handle.join().unwrap();
    }

    #[test]
    fn startup_refuses_to_move_off_a_port_held_by_another_bridge() {
        let (port, handle) = serve_greeting(
            "* OK [CAPABILITY IMAP4rev1 AUTH=PLAIN] Aster Bridge ready\r\n",
        );
        let err = pick_startup_port("127.0.0.1", port).unwrap_err();
        assert!(
            err.contains("another copy of Aster Bridge"),
            "unexpected error: {}",
            err
        );
        handle.join().unwrap();
    }

    #[test]
    fn startup_reports_a_foreign_listener_instead_of_stranding_configured_clients() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let picked = pick_startup_port("127.0.0.1", port);
        let message = picked.expect_err("moving to another port leaves every configured mail client refused");
        assert!(
            message.contains(&port.to_string()),
            "the message must name the port the user has to free: {}",
            message
        );
        drop(listener);
    }

    #[test]
    fn a_silent_program_holding_the_port_stops_startup_instead_of_moving_the_port() {
        let held = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = held.local_addr().unwrap().port();
        assert_eq!(probe_occupant("127.0.0.1", port), Occupant::Unidentified);
        let picked = pick_startup_port("127.0.0.1", port);
        assert!(
            picked.is_err(),
            "moving to {:?} would leave every configured mail client refused on port {}",
            picked,
            port
        );
        drop(held);
    }

    #[test]
    fn a_free_port_is_used_as_configured() {
        let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = probe.local_addr().unwrap().port();
        drop(probe);
        assert_eq!(probe_occupant("127.0.0.1", port), Occupant::Free);
        assert_eq!(pick_startup_port("127.0.0.1", port), Ok(port));
    }
}
