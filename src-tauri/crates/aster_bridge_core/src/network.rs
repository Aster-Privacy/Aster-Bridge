//
// Aster Communications Inc.
//
// Copyright (c) 2026 Aster Communications Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, OnceLock, RwLock};

use ipnet::IpNet;

pub const LOOPBACK_HOST: &str = "127.0.0.1";

pub const DEFAULT_PRIVATE_RANGES: &[&str] = &[
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "100.64.0.0/10",
    "169.254.0.0/16",
    "fc00::/7",
    "fe80::/10",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkPolicy {
    bind: IpAddr,
    allowed_peers: Vec<IpNet>,
    hostnames: Vec<String>,
}

impl Default for NetworkPolicy {
    fn default() -> Self {
        Self::loopback()
    }
}

fn unmap(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        other => other,
    }
}

fn split_authority(authority: &str) -> Option<(&str, Option<&str>)> {
    if authority.is_empty() {
        return None;
    }
    if let Some(rest) = authority.strip_prefix('[') {
        let end = rest.find(']')?;
        let host = &rest[..end];
        let tail = &rest[end + 1..];
        if tail.is_empty() {
            return Some((host, None));
        }
        let port = tail.strip_prefix(':')?;
        return Some((host, Some(port)));
    }
    if authority.matches(':').count() > 1 {
        return None;
    }
    match authority.split_once(':') {
        Some((host, port)) => Some((host, Some(port))),
        None => Some((authority, None)),
    }
}

fn valid_port(port: Option<&str>) -> bool {
    match port {
        None => true,
        Some(p) => !p.is_empty() && p.len() <= 5 && p.bytes().all(|b| b.is_ascii_digit()) && p.parse::<u16>().is_ok(),
    }
}

pub fn normalize_hostname(raw: &str) -> Option<String> {
    let name = raw.trim().trim_end_matches('.').to_ascii_lowercase();
    if name.is_empty() || name.len() > 253 {
        return None;
    }
    if name.parse::<IpAddr>().is_ok() {
        return Some(name);
    }
    let labels_ok = name.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
    });
    labels_ok.then_some(name)
}

impl NetworkPolicy {
    pub fn loopback() -> Self {
        Self {
            bind: IpAddr::V4(Ipv4Addr::LOCALHOST),
            allowed_peers: Vec::new(),
            hostnames: Vec::new(),
        }
    }

    pub fn network(bind: IpAddr, allowed_peers: Vec<IpNet>, hostnames: Vec<String>) -> Result<Self, String> {
        let bind = unmap(bind);
        if bind.is_loopback() {
            return Ok(Self::loopback());
        }
        if bind.is_multicast() {
            return Err(format!("{} is a multicast address and can't be used as a listen address.", bind));
        }
        let allowed_peers = if allowed_peers.is_empty() {
            default_private_ranges()
        } else {
            allowed_peers
        };
        let mut names = Vec::new();
        for raw in hostnames {
            let name = normalize_hostname(&raw)
                .ok_or_else(|| format!("{} isn't a valid host name.", raw.trim()))?;
            if !names.contains(&name) {
                names.push(name);
            }
        }
        Ok(Self {
            bind,
            allowed_peers,
            hostnames: names,
        })
    }

    pub fn is_network(&self) -> bool {
        !self.bind.is_loopback()
    }

    pub fn bind_ip(&self) -> IpAddr {
        self.bind
    }

    pub fn bind_host(&self) -> String {
        self.bind.to_string()
    }

    pub fn probe_host(&self) -> String {
        if !self.is_network() {
            return LOOPBACK_HOST.to_string();
        }
        match self.bind {
            IpAddr::V4(v4) if v4.is_unspecified() => LOOPBACK_HOST.to_string(),
            IpAddr::V6(v6) if v6.is_unspecified() => Ipv6Addr::LOCALHOST.to_string(),
            other => other.to_string(),
        }
    }

    pub fn allowed_peers(&self) -> &[IpNet] {
        &self.allowed_peers
    }

    pub fn hostnames(&self) -> &[String] {
        &self.hostnames
    }

    pub fn bind_allowed(&self, ip: IpAddr) -> bool {
        let ip = unmap(ip);
        if ip.is_loopback() {
            return true;
        }
        self.is_network() && ip == self.bind
    }

    pub fn peer_allowed(&self, ip: IpAddr) -> bool {
        let ip = unmap(ip);
        if ip.is_loopback() {
            return true;
        }
        if !self.is_network() {
            return false;
        }
        self.allowed_peers.iter().any(|net| net.contains(&ip))
    }

    pub fn host_allowed(&self, authority: &str, port: u16) -> bool {
        let loopback_forms = [
            format!("127.0.0.1:{}", port),
            format!("localhost:{}", port),
            format!("[::1]:{}", port),
        ];
        if loopback_forms.iter().any(|a| a.eq_ignore_ascii_case(authority)) {
            return true;
        }
        if !self.is_network() {
            return false;
        }
        let Some((host, host_port)) = split_authority(authority) else {
            return false;
        };
        if !valid_port(host_port) {
            return false;
        }
        if host.parse::<IpAddr>().is_ok() {
            return true;
        }
        let Some(name) = normalize_hostname(host) else {
            return false;
        };
        name == "localhost" || self.hostnames.iter().any(|h| *h == name)
    }

    pub fn origin_allowed(&self, origin: &str, scheme: &str, port: u16) -> bool {
        let prefix = format!("{}://", scheme);
        if origin.len() < prefix.len() || !origin[..prefix.len()].eq_ignore_ascii_case(&prefix) {
            return false;
        }
        let authority = &origin[prefix.len()..];
        if authority.contains('/') {
            return false;
        }
        self.host_allowed(authority, port)
    }

    pub fn advertised_authority(&self, host_header: Option<&str>, port: u16) -> String {
        let fallback = format!("{}:{}", LOOPBACK_HOST, port);
        if !self.is_network() {
            return fallback;
        }
        match host_header {
            Some(host) if self.host_allowed(host, port) => host.to_string(),
            _ => fallback,
        }
    }

    pub fn tls_names(&self) -> Vec<String> {
        let mut names = self.hostnames.clone();
        if self.is_network() && !self.bind.is_unspecified() {
            let bind = self.bind.to_string();
            if !names.contains(&bind) {
                names.push(bind);
            }
        }
        names
    }
}

pub fn default_private_ranges() -> Vec<IpNet> {
    DEFAULT_PRIVATE_RANGES
        .iter()
        .filter_map(|r| r.parse().ok())
        .collect()
}

pub fn parse_peer_ranges(raw: &str) -> Result<Vec<IpNet>, String> {
    let mut out = Vec::new();
    for item in raw.split(|c: char| c == ',' || c.is_whitespace()) {
        let item = item.trim();
        if item.is_empty() {
            continue;
        }
        let net = match item.parse::<IpNet>() {
            Ok(net) => net.trunc(),
            Err(_) => match item.parse::<IpAddr>() {
                Ok(ip) => IpNet::from(ip),
                Err(_) => return Err(format!("{} isn't an IP address or a range like 192.168.1.0/24.", item)),
            },
        };
        if !out.contains(&net) {
            out.push(net);
        }
    }
    Ok(out)
}

fn slot() -> &'static RwLock<Arc<NetworkPolicy>> {
    static SLOT: OnceLock<RwLock<Arc<NetworkPolicy>>> = OnceLock::new();
    SLOT.get_or_init(|| RwLock::new(Arc::new(NetworkPolicy::loopback())))
}

pub fn install(policy: NetworkPolicy) {
    let mut guard = match slot().write() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };
    *guard = Arc::new(policy);
}

pub fn current() -> Arc<NetworkPolicy> {
    match slot().read() {
        Ok(g) => g.clone(),
        Err(poisoned) => poisoned.into_inner().clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lan() -> NetworkPolicy {
        NetworkPolicy::network(
            "0.0.0.0".parse().unwrap(),
            Vec::new(),
            vec!["Bridge.Home.Arpa.".to_string()],
        )
        .unwrap()
    }

    #[test]
    fn loopback_policy_matches_the_old_rules() {
        let p = NetworkPolicy::loopback();
        assert!(!p.is_network());
        assert_eq!(p.bind_host(), "127.0.0.1");
        assert!(p.peer_allowed("127.0.0.1".parse().unwrap()));
        assert!(p.peer_allowed("::1".parse().unwrap()));
        assert!(!p.peer_allowed("192.168.1.5".parse().unwrap()));
        assert!(!p.bind_allowed("0.0.0.0".parse().unwrap()));
        assert!(p.host_allowed("127.0.0.1:1080", 1080));
        assert!(p.host_allowed("LOCALHOST:1080", 1080));
        assert!(p.host_allowed("[::1]:1080", 1080));
        assert!(!p.host_allowed("127.0.0.1:1081", 1080));
        assert!(!p.host_allowed("192.168.1.5:1080", 1080));
        assert!(!p.host_allowed("bridge.home.arpa:1080", 1080));
        assert_eq!(p.advertised_authority(Some("192.168.1.5:1080"), 1080), "127.0.0.1:1080");
        assert!(p.tls_names().is_empty());
    }

    #[test]
    fn a_loopback_bind_stays_in_loopback_mode() {
        let p = NetworkPolicy::network("127.0.0.1".parse().unwrap(), Vec::new(), Vec::new()).unwrap();
        assert_eq!(p, NetworkPolicy::loopback());
        let p = NetworkPolicy::network("::ffff:127.0.0.1".parse().unwrap(), Vec::new(), Vec::new()).unwrap();
        assert!(!p.is_network());
    }

    #[test]
    fn network_mode_admits_private_peers_by_default() {
        let p = lan();
        assert!(p.is_network());
        for ip in ["10.1.2.3", "172.17.0.1", "192.168.1.20", "100.100.1.1", "fd00::5", "fe80::1", "127.0.0.1", "::ffff:192.168.1.9"] {
            assert!(p.peer_allowed(ip.parse().unwrap()), "{} should be allowed", ip);
        }
        for ip in ["8.8.8.8", "1.1.1.1", "2001:4860::8888", "::ffff:8.8.8.8"] {
            assert!(!p.peer_allowed(ip.parse().unwrap()), "{} should be refused", ip);
        }
    }

    #[test]
    fn an_explicit_allow_list_replaces_the_default() {
        let peers = parse_peer_ranges("192.168.50.0/24, 203.0.113.7").unwrap();
        let p = NetworkPolicy::network("0.0.0.0".parse().unwrap(), peers, Vec::new()).unwrap();
        assert!(p.peer_allowed("192.168.50.9".parse().unwrap()));
        assert!(p.peer_allowed("203.0.113.7".parse().unwrap()));
        assert!(!p.peer_allowed("203.0.113.8".parse().unwrap()));
        assert!(!p.peer_allowed("10.0.0.1".parse().unwrap()));
        assert!(p.peer_allowed("127.0.0.1".parse().unwrap()));
    }

    #[test]
    fn peer_ranges_reject_garbage() {
        assert!(parse_peer_ranges("192.168.1.0/24,nope").is_err());
        assert!(parse_peer_ranges("10.0.0.0/33").is_err());
        assert_eq!(parse_peer_ranges("  ").unwrap(), Vec::<IpNet>::new());
        assert_eq!(parse_peer_ranges("10.0.0.9/8").unwrap(), vec!["10.0.0.0/8".parse::<IpNet>().unwrap()]);
    }

    #[test]
    fn network_hosts_accept_ip_literals_and_named_hosts_only() {
        let p = lan();
        assert!(p.host_allowed("192.168.1.5:1080", 1080));
        assert!(p.host_allowed("192.168.1.5:8443", 1080));
        assert!(p.host_allowed("192.168.1.5", 1080));
        assert!(p.host_allowed("[fd00::5]:1080", 1080));
        assert!(p.host_allowed("bridge.home.arpa:1080", 1080));
        assert!(p.host_allowed("BRIDGE.home.arpa.:9000", 1080));
        assert!(p.host_allowed("localhost:9000", 1080));
        assert!(!p.host_allowed("evil.example:1080", 1080));
        assert!(!p.host_allowed("bridge.home.arpa:99999", 1080));
        assert!(!p.host_allowed("bridge.home.arpa:", 1080));
        assert!(!p.host_allowed("fd00::5", 1080));
        assert!(!p.host_allowed("", 1080));
        assert!(!p.host_allowed("[fd00::5", 1080));
    }

    #[test]
    fn origins_follow_the_host_rules_and_scheme() {
        let p = lan();
        assert!(p.origin_allowed("https://192.168.1.5:1080", "https", 1080));
        assert!(p.origin_allowed("https://bridge.home.arpa", "https", 1080));
        assert!(!p.origin_allowed("http://192.168.1.5:1080", "https", 1080));
        assert!(!p.origin_allowed("https://evil.example", "https", 1080));
        assert!(!p.origin_allowed("https://192.168.1.5:1080/x", "https", 1080));
        let lo = NetworkPolicy::loopback();
        assert!(lo.origin_allowed("https://127.0.0.1:1080", "https", 1080));
        assert!(!lo.origin_allowed("https://192.168.1.5:1080", "https", 1080));
    }

    #[test]
    fn advertised_authority_uses_an_accepted_host_header() {
        let p = lan();
        assert_eq!(p.advertised_authority(Some("192.168.1.5:1080"), 1080), "192.168.1.5:1080");
        assert_eq!(p.advertised_authority(Some("bridge.home.arpa:8443"), 1080), "bridge.home.arpa:8443");
        assert_eq!(p.advertised_authority(Some("evil.example"), 1080), "127.0.0.1:1080");
        assert_eq!(p.advertised_authority(None, 1080), "127.0.0.1:1080");
    }

    #[test]
    fn hostnames_are_validated() {
        assert!(NetworkPolicy::network("0.0.0.0".parse().unwrap(), Vec::new(), vec!["bad name".into()]).is_err());
        assert!(NetworkPolicy::network("0.0.0.0".parse().unwrap(), Vec::new(), vec!["-x.lan".into()]).is_err());
        assert!(NetworkPolicy::network("224.0.0.1".parse().unwrap(), Vec::new(), Vec::new()).is_err());
        assert_eq!(normalize_hostname("NAS.Local."), Some("nas.local".to_string()));
    }

    #[test]
    fn tls_names_include_hostnames_and_a_specific_bind_address() {
        assert_eq!(lan().tls_names(), vec!["bridge.home.arpa".to_string()]);
        let p = NetworkPolicy::network("192.168.1.5".parse().unwrap(), Vec::new(), vec!["nas.lan".into()]).unwrap();
        assert_eq!(p.tls_names(), vec!["nas.lan".to_string(), "192.168.1.5".to_string()]);
        assert_eq!(p.probe_host(), "192.168.1.5");
        assert_eq!(lan().probe_host(), "127.0.0.1");
    }

    #[test]
    fn bind_is_limited_to_loopback_or_the_configured_address() {
        let p = lan();
        assert!(p.bind_allowed("0.0.0.0".parse().unwrap()));
        assert!(p.bind_allowed("127.0.0.1".parse().unwrap()));
        assert!(!p.bind_allowed("192.168.1.5".parse().unwrap()));
    }
}
