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
use std::os::unix::net::UnixStream;
use std::sync::mpsc;
use std::time::Duration;

const LOOKUP_TIMEOUT: Duration = Duration::from_secs(2);

fn lookup_session_address() -> Option<String> {
    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        let address = zbus::blocking::Connection::session().ok().and_then(|connection| {
            connection
                .call_method(
                    Some("org.a11y.Bus"),
                    "/org/a11y/bus",
                    Some("org.a11y.Bus"),
                    "GetAddress",
                    &(),
                )
                .ok()
                .and_then(|reply| reply.body().deserialize::<String>().ok())
        });
        let _ = sender.send(address);
    });
    receiver
        .recv_timeout(LOOKUP_TIMEOUT)
        .ok()
        .flatten()
        .map(|address| address.trim().to_string())
        .filter(|address| !address.is_empty())
}

fn unix_socket_path(address: &str) -> Option<&str> {
    let first_entry = address.split(';').next()?;
    let params = first_entry.strip_prefix("unix:")?;
    params
        .split(',')
        .find_map(|param| param.strip_prefix("path="))
        .filter(|path| !path.is_empty() && !path.contains('%'))
}

fn is_reachable(address: &str) -> bool {
    match unix_socket_path(address) {
        Some(path) => UnixStream::connect(path).is_ok(),
        None => true,
    }
}

fn env_is_set(name: &str) -> bool {
    std::env::var_os(name).is_some_and(|value| !value.is_empty())
}

pub fn configure() {
    if env_is_set("NO_AT_BRIDGE") || env_is_set("AT_SPI_BUS_ADDRESS") {
        return;
    }
    match lookup_session_address() {
        Some(address) if is_reachable(&address) => {
            std::env::set_var("AT_SPI_BUS_ADDRESS", address);
        }
        _ => {
            std::env::set_var("NO_AT_BRIDGE", "1");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_path_from_launcher_address() {
        assert_eq!(
            unix_socket_path("unix:path=/run/user/1000/at-spi/bus_0,guid=0123abcd"),
            Some("/run/user/1000/at-spi/bus_0")
        );
    }

    #[test]
    fn reads_path_after_other_params() {
        assert_eq!(
            unix_socket_path("unix:guid=0123abcd,path=/root/.cache/at-spi/bus_0.0"),
            Some("/root/.cache/at-spi/bus_0.0")
        );
    }

    #[test]
    fn uses_first_address_entry() {
        assert_eq!(
            unix_socket_path("unix:path=/tmp/a;unix:path=/tmp/b"),
            Some("/tmp/a")
        );
    }

    #[test]
    fn skips_addresses_without_a_plain_path() {
        assert_eq!(unix_socket_path("unix:abstract=/tmp/dbus-x"), None);
        assert_eq!(unix_socket_path("tcp:host=localhost,port=1"), None);
        assert_eq!(unix_socket_path("unix:path=/tmp/a%20b"), None);
        assert_eq!(unix_socket_path(""), None);
    }

    #[test]
    fn missing_socket_is_unreachable() {
        assert!(!is_reachable("unix:path=/nonexistent/aster-bridge-a11y-test/bus_0"));
    }

    #[test]
    fn listening_socket_is_reachable() {
        let dir = std::env::temp_dir().join(format!("aster-a11y-test-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let socket = dir.join("bus_0");
        let _ = std::fs::remove_file(&socket);
        let _listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        assert!(is_reachable(&format!("unix:path={},guid=ab", socket.display())));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
