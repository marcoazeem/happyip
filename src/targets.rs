//! Parsing of IP range expressions and local interface discovery.

use std::net::Ipv4Addr;

/// Upper bound on hosts per scan, to keep the UI and process count sane.
pub const MAX_HOSTS: usize = 65_536;

/// Parse a comma-separated list of targets. Each item may be:
/// - a single IP: `192.168.1.10`
/// - a CIDR block: `192.168.1.0/24`
/// - a full range: `192.168.1.1 - 192.168.2.254`
/// - a last-octet range: `192.168.1.1-100`
/// - wildcards: `10.20.*.*`
/// - a computer name: `fileserver01` or `pc42.corp.example` (resolved via DNS)
pub fn parse_targets(input: &str) -> Result<Vec<Ipv4Addr>, String> {
    let mut out = Vec::new();
    for item in items(input) {
        if is_hostname(item) {
            if is_mistyped_address(item) {
                return Err(format!("'{item}' is not a valid IPv4 address"));
            }
            out.extend(resolve(item)?);
            continue;
        }
        if item.contains('*') {
            let ips = parse_wildcard(item)?;
            if out.len() + ips.len() > MAX_HOSTS {
                return Err(format!("too many hosts (limit is {MAX_HOSTS})"));
            }
            out.extend(ips);
            continue;
        }
        let (start, end) = parse_item(item)?;
        if end < start {
            return Err(format!("'{item}': end of range is before start"));
        }
        if out.len() + (end - start) as usize + 1 > MAX_HOSTS {
            return Err(format!("too many hosts (limit is {MAX_HOSTS})"));
        }
        out.extend((start..=end).map(Ipv4Addr::from));
    }
    if out.is_empty() {
        return Err("enter an IP range, e.g. 192.168.1.0/24".into());
    }
    out.sort();
    out.dedup();
    Ok(out)
}

fn items(input: &str) -> impl Iterator<Item = &str> {
    input.split([',', ';', '\n']).map(str::trim).filter(|s| !s.is_empty())
}

/// True when the input names computers. Looking those up in DNS can take
/// seconds, so callers with a window to keep responsive parse such input
/// on another thread.
pub fn has_names(input: &str) -> bool {
    items(input).any(|item| is_hostname(item) && !is_mistyped_address(item))
}

/// Parse a port list like `22, 80, 8000-8010` (at most 64 ports per scan).
pub fn parse_ports(input: &str) -> Result<Vec<u16>, String> {
    let mut ports = Vec::new();
    for p in input.split([',', ' ', ';']).filter(|s| !s.is_empty()) {
        let bad = || format!("'{p}' is not a valid port (1-65535)");
        let port = |s: &str| s.trim().parse::<u16>().ok().filter(|&n| n != 0).ok_or_else(bad);
        match p.split_once('-') {
            Some((a, b)) => {
                let (a, b) = (port(a)?, port(b)?);
                if b < a || (b - a) as usize >= MAX_PORTS {
                    return Err(format!("'{p}': a port range may cover at most {MAX_PORTS} ports"));
                }
                ports.extend(a..=b);
            }
            None => ports.push(port(p)?),
        }
    }
    ports.sort_unstable();
    ports.dedup();
    if ports.len() > MAX_PORTS {
        return Err(format!("at most {MAX_PORTS} ports per scan"));
    }
    Ok(ports)
}

pub const MAX_PORTS: usize = 64;

fn parse_ip(s: &str) -> Result<u32, String> {
    s.trim()
        .parse::<Ipv4Addr>()
        .map(u32::from)
        .map_err(|_| format!("'{}' is not a valid IPv4 address", s.trim()))
}

/// Looks like a name rather than an address/range: has a letter and only
/// characters valid in DNS names.
fn is_hostname(item: &str) -> bool {
    item.chars().any(|c| c.is_ascii_alphabetic())
        && item.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
}

/// `10.0.0.a` or `192.168.1.x`: four dot-separated parts that are nearly
/// all numbers are a typo in an address, not a computer to look up.
fn is_mistyped_address(item: &str) -> bool {
    let parts: Vec<&str> = item.split('.').collect();
    let numeric = parts.iter().filter(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit())).count();
    parts.len() == 4 && numeric >= 3
}

fn resolve(name: &str) -> Result<Vec<Ipv4Addr>, String> {
    let (tx, rx) = std::sync::mpsc::channel();
    let owned = name.to_string();
    std::thread::spawn(move || {
        let _ = tx.send(dns_lookup::lookup_host(&owned).ok().map(|a| a.collect::<Vec<_>>()));
    });
    let ips: Vec<Ipv4Addr> = rx
        .recv_timeout(std::time::Duration::from_secs(3))
        .ok()
        .flatten()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|ip| match ip {
            std::net::IpAddr::V4(v4) => Some(v4),
            _ => None,
        })
        .collect();
    if ips.is_empty() {
        Err(format!("'{name}' could not be resolved to an IPv4 address"))
    } else {
        Ok(ips)
    }
}

/// `10.20.*.*` → every 10.20.x.y; a wildcard last octet means 1-254.
fn parse_wildcard(item: &str) -> Result<Vec<Ipv4Addr>, String> {
    let bad = || format!("'{item}' is not a valid wildcard address");
    let parts: Vec<&str> = item.split('.').collect();
    if parts.len() != 4 {
        return Err(bad());
    }
    let mut choices: Vec<Vec<u8>> = Vec::with_capacity(4);
    for (i, p) in parts.iter().enumerate() {
        choices.push(match *p {
            "*" if i == 3 => (1..=254).collect(),
            "*" => (0..=255).collect(),
            n => vec![n.parse().map_err(|_| bad())?],
        });
    }
    let count: usize = choices.iter().map(Vec::len).product();
    if count > MAX_HOSTS {
        return Err(format!("too many hosts (limit is {MAX_HOSTS})"));
    }
    let mut out = Vec::with_capacity(count);
    for &a in &choices[0] {
        for &b in &choices[1] {
            for &c in &choices[2] {
                for &d in &choices[3] {
                    out.push(Ipv4Addr::new(a, b, c, d));
                }
            }
        }
    }
    Ok(out)
}

fn parse_item(item: &str) -> Result<(u32, u32), String> {
    if let Some((ip, prefix)) = item.split_once('/') {
        let ip = parse_ip(ip)?;
        let prefix: u8 = prefix
            .trim()
            .parse()
            .ok()
            .filter(|p| *p <= 32)
            .ok_or_else(|| format!("'{item}': invalid prefix length"))?;
        return Ok(cidr_host_range(ip, prefix));
    }
    if let Some((a, b)) = item.split_once('-') {
        let start = parse_ip(a)?;
        let b = b.trim();
        let end = if b.contains('.') {
            parse_ip(b)?
        } else {
            let last: u8 = b.parse().map_err(|_| format!("'{item}': invalid range end"))?;
            (start & 0xFFFF_FF00) | last as u32
        };
        return Ok((start, end));
    }
    let ip = parse_ip(item)?;
    Ok((ip, ip))
}

/// Usable host range of a CIDR block (network and broadcast excluded for /30 and larger).
pub fn cidr_host_range(ip: u32, prefix: u8) -> (u32, u32) {
    let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
    let network = ip & mask;
    let broadcast = network | !mask;
    if prefix <= 30 {
        (network + 1, broadcast - 1)
    } else {
        (network, broadcast)
    }
}

/// Is `ip` inside `network/prefix`?
pub fn in_subnet(ip: Ipv4Addr, network: Ipv4Addr, prefix: u8) -> bool {
    let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
    u32::from(ip) & mask == u32::from(network) & mask
}

/// Parse `10.20.0.0/24` into (network, prefix).
pub fn parse_cidr(s: &str) -> Option<(Ipv4Addr, u8)> {
    let (ip, prefix) = s.trim().split_once('/')?;
    let prefix: u8 = prefix.trim().parse().ok().filter(|p| *p <= 32)?;
    let ip: Ipv4Addr = ip.trim().parse().ok()?;
    let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
    Some((Ipv4Addr::from(u32::from(ip) & mask), prefix))
}

/// Where a network in the "Networks" list came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum NetSource {
    /// A subnet this computer is directly on.
    Local,
    /// A route in this computer's routing table (other VLANs / sites).
    Route,
    /// Active Directory Sites & Services subnet.
    AdSubnet,
    /// An AD-integrated DNS reverse lookup zone (e.g. 0.20.10.in-addr.arpa).
    DnsZone,
}

/// A network that can be scanned, e.g. a VLAN.
#[derive(Clone, Debug)]
pub struct Network {
    pub network: Ipv4Addr,
    pub prefix: u8,
    pub source: NetSource,
    /// Friendly description: interface name, AD site and description, etc.
    pub label: String,
}

impl Network {
    pub fn cidr(&self) -> String {
        format!("{}/{}", self.network, self.prefix)
    }

    pub fn hosts(&self) -> usize {
        let (a, b) = cidr_host_range(u32::from(self.network), self.prefix);
        (b - a) as usize + 1
    }

    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        in_subnet(ip, self.network, self.prefix)
    }

    /// "10.20.0.0/24 · HQ · VLAN 20 Staff" (the label is left out when it
    /// adds nothing, e.g. for DNS zones).
    pub fn describe(&self) -> String {
        match self.source {
            NetSource::AdSubnet if !self.label.is_empty() => format!("{} · {}", self.cidr(), self.label),
            NetSource::Local => format!("{} · local", self.cidr()),
            _ => self.cidr(),
        }
    }

    /// Label for the Networks menu.
    pub fn menu_label(&self) -> String {
        let source = match self.source {
            NetSource::Local => "this PC",
            NetSource::Route => "routed",
            NetSource::AdSubnet => "AD subnet",
            NetSource::DnsZone => "DNS zone",
        };
        let extra = if self.label.is_empty() || self.source == NetSource::DnsZone {
            String::new()
        } else {
            format!(" · {}", self.label)
        };
        format!("{}  ({source}{extra})", self.cidr())
    }
}

/// The network in `nets` that best describes `ip`: the most specific AD
/// subnet (they carry the site / VLAN name), else the most specific other one.
pub fn best_match(nets: &[Network], ip: Ipv4Addr) -> Option<&Network> {
    let rank = |n: &Network| match n.source {
        NetSource::AdSubnet => 3,
        NetSource::Local => 2,
        NetSource::Route => 1,
        NetSource::DnsZone => 0,
    };
    let containing = || nets.iter().filter(|n| n.contains(ip));
    containing()
        .filter(|n| n.source == NetSource::AdSubnet)
        .max_by_key(|n| n.prefix)
        .or_else(|| containing().max_by_key(|n| (n.prefix, rank(n))))
}

/// Networks reachable through specific routes in the routing table (not the
/// default route): typically other VLANs or sites behind a router or VPN.
pub fn routed_networks() -> Vec<Network> {
    #[cfg(windows)]
    let text = crate::probe::run_hidden("route", &["print", "-4"]);
    #[cfg(not(windows))]
    let text = crate::probe::run_hidden("/usr/sbin/netstat", &["-rn", "-f", "inet"])
        .or_else(|| crate::probe::run_hidden("netstat", &["-rn", "-f", "inet"]));
    let text = text.map(|o| String::from_utf8_lossy(&o.stdout).into_owned()).unwrap_or_default();
    let mut nets = if cfg!(windows) { parse_windows_routes(&text) } else { parse_bsd_routes(&text) };
    nets.sort_by_key(|n| (u32::from(n.network), n.prefix));
    nets.dedup_by_key(|n| (n.network, n.prefix));
    nets
}

/// Routes worth offering for a scan: not default/host/loopback/multicast/
/// link-local, and no bigger than a /16.
fn useful_route(network: Ipv4Addr, prefix: u8) -> bool {
    (16..=30).contains(&prefix)
        && !network.is_loopback()
        && !network.is_multicast()
        && !network.is_link_local()
        && !network.is_broadcast()
}

/// `route print -4`: "Network Destination  Netmask  Gateway  Interface  Metric"
/// rows under "Active Routes:".
pub fn parse_windows_routes(text: &str) -> Vec<Network> {
    let mut out = Vec::new();
    let mut active = false;
    for line in text.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("Active Routes") {
            active = true;
            continue;
        }
        if trimmed.starts_with("Persistent Routes") {
            active = false;
        }
        let t: Vec<&str> = line.split_whitespace().collect();
        if !active || t.len() < 4 {
            continue;
        }
        let (Ok(net), Ok(mask)) = (t[0].parse::<Ipv4Addr>(), t[1].parse::<Ipv4Addr>()) else { continue };
        let mask = u32::from(mask);
        if mask.leading_ones() + mask.trailing_zeros() != 32 {
            continue; // not a contiguous netmask
        }
        let prefix = mask.leading_ones() as u8;
        if !useful_route(net, prefix) {
            continue;
        }
        // "On-link" is localized on some Windows versions, but it's never an IP.
        let gateway = t[2];
        let on_link = gateway.parse::<Ipv4Addr>().is_err();
        out.push(Network {
            network: Ipv4Addr::from(u32::from(net) & mask),
            prefix,
            source: if on_link { NetSource::Local } else { NetSource::Route },
            label: if on_link { "on-link".into() } else { format!("route via {gateway}") },
        });
    }
    out
}

/// macOS / BSD `netstat -rn -f inet`: destinations like `10.20/16`,
/// `192.168.21` (implied /24) or `10.8.0.0/16`.
pub fn parse_bsd_routes(text: &str) -> Vec<Network> {
    let mut out = Vec::new();
    for line in text.lines() {
        let t: Vec<&str> = line.split_whitespace().collect();
        if t.len() < 2 || t[0] == "default" {
            continue;
        }
        let (addr, prefix) = match t[0].split_once('/') {
            Some((a, p)) => (a, p.parse::<u8>().ok()),
            None => (t[0], None),
        };
        let octets: Vec<u8> = match addr.split('.').map(str::parse).collect::<Result<Vec<u8>, _>>() {
            Ok(o) if (1..=4).contains(&o.len()) => o,
            _ => continue,
        };
        let prefix = prefix.unwrap_or(octets.len() as u8 * 8);
        let mut full = [0u8; 4];
        full[..octets.len()].copy_from_slice(&octets);
        let net = Ipv4Addr::from(full);
        if !useful_route(net, prefix) {
            continue;
        }
        let gateway = t[1];
        let on_link = gateway.starts_with("link#");
        if !on_link && gateway.parse::<Ipv4Addr>().is_err() {
            continue; // a neighbour (MAC) entry, not a route
        }
        let mask = u32::MAX << (32 - prefix);
        out.push(Network {
            network: Ipv4Addr::from(u32::from(net) & mask),
            prefix,
            source: if on_link { NetSource::Local } else { NetSource::Route },
            label: if on_link { "on-link".into() } else { format!("route via {gateway}") },
        });
    }
    out
}

/// An IPv4 interface on this machine.
#[derive(Clone, Debug)]
pub struct LocalInterface {
    pub name: String,
    pub ip: Ipv4Addr,
    pub prefix: u8,
    pub mac: Option<String>,
}

impl LocalInterface {
    /// The range suggested for scanning from this interface. Very large
    /// subnets are narrowed to the surrounding /24.
    pub fn suggested_range(&self) -> String {
        let prefix = if self.prefix < 22 { 24 } else { self.prefix };
        let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
        let network = Ipv4Addr::from(u32::from(self.ip) & mask);
        format!("{network}/{prefix}")
    }

    /// The subnet this interface is on, for the Networks menu. Very large
    /// subnets are narrowed to the surrounding /24, as for the default range.
    pub fn network(&self) -> Network {
        let (network, prefix) = parse_cidr(&self.suggested_range()).unwrap_or((self.ip, 32));
        Network { network, prefix, source: NetSource::Local, label: format!("{} {}", self.name, self.ip) }
    }

    /// The real subnet (for deciding which addresses are on-link).
    pub fn subnet(&self) -> (Ipv4Addr, u8) {
        let mask = if self.prefix == 0 { 0 } else { u32::MAX << (32 - self.prefix) };
        (Ipv4Addr::from(u32::from(self.ip) & mask), self.prefix)
    }
}

pub fn local_interfaces() -> Vec<LocalInterface> {
    let mut list: Vec<LocalInterface> = if_addrs::get_if_addrs()
        .unwrap_or_default()
        .into_iter()
        .filter(|i| !i.is_loopback())
        .filter_map(|i| match i.addr {
            if_addrs::IfAddr::V4(v4) if !v4.ip.is_link_local() => Some(LocalInterface {
                mac: mac_address::mac_address_by_name(&i.name)
                    .ok()
                    .flatten()
                    .and_then(|m| crate::probe::normalize_mac(&m.to_string())),
                name: i.name,
                ip: v4.ip,
                prefix: v4.prefixlen,
            }),
            _ => None,
        })
        .collect();
    // Prefer private LAN addresses (typical Wi-Fi / Ethernet) first.
    list.sort_by_key(|i| (!i.ip.is_private(), i.name.clone()));
    list
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wildcards_and_names() {
        assert_eq!(parse_targets("10.0.0.*").unwrap().len(), 254);
        assert_eq!(parse_targets("10.0.*.*").unwrap().len(), 256 * 254);
        let odd = parse_targets("10.*.5.1").unwrap();
        assert_eq!(odd.len(), 256);
        assert!(odd.iter().all(|ip| ip.octets()[2] == 5 && ip.octets()[3] == 1));
        assert!(parse_targets("10.*.*.*").is_err());
        assert!(is_hostname("fileserver01") && is_hostname("pc42.corp.example"));
        assert!(!is_hostname("10.0.0.1-50") && !is_hostname("10.0.0.0/24"));
        assert!(has_names("10.0.0.0/24, pc42") && !has_names("10.0.0.0/24, 10.0.1.1-9"));
    }

    #[test]
    fn typos_are_errors_not_dns_lookups() {
        // Rejected straight away, without a (slow) name lookup.
        let err = parse_targets("10.0.0.a").unwrap_err();
        assert!(err.contains("not a valid IPv4 address"), "{err}");
        assert!(parse_targets("192.168.1.x").is_err());
        assert!(!has_names("10.0.0.a"));
        assert!(parse_targets("10.0.0.300").is_err());
        assert!(parse_targets("10.0.0.9-3").is_err());
        assert!(parse_targets("10.0.0.0/33").is_err());
        assert!(parse_targets(" , ").is_err());
    }

    #[test]
    fn edge_ranges() {
        assert_eq!(parse_targets("10.0.0.4/31").unwrap().len(), 2);
        assert_eq!(parse_targets("10.0.0.7/32").unwrap(), [Ipv4Addr::new(10, 0, 0, 7)]);
        assert_eq!(parse_targets("10.0.0.0/16").unwrap().len(), 65_534);
        assert!(parse_targets("10.0.0.0/15").is_err());
        assert_eq!(parse_targets("255.255.255.250-255").unwrap().len(), 6);
    }

    #[test]
    fn port_lists() {
        assert_eq!(parse_ports("22, 80 443;8000-8002").unwrap(), [22, 80, 443, 8000, 8001, 8002]);
        assert_eq!(parse_ports("80,80").unwrap(), [80]);
        assert!(parse_ports("").unwrap().is_empty());
        for bad in ["0", "70000", "http", "90-80", "1-65535", "1-"] {
            assert!(parse_ports(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn subnets() {
        assert_eq!(parse_cidr("10.20.0.7/24"), Some((Ipv4Addr::new(10, 20, 0, 0), 24)));
        assert!(in_subnet(Ipv4Addr::new(10, 20, 0, 99), Ipv4Addr::new(10, 20, 0, 0), 24));
        assert!(!in_subnet(Ipv4Addr::new(10, 20, 1, 99), Ipv4Addr::new(10, 20, 0, 0), 24));
    }

    #[test]
    fn routes() {
        let win = "IPv4 Route Table\n===\nActive Routes:\n\
Network Destination        Netmask          Gateway       Interface  Metric\n\
          0.0.0.0          0.0.0.0      10.20.0.1     10.20.0.50     25\n\
        10.20.0.0    255.255.255.0         On-link     10.20.0.50    281\n\
       10.20.0.50  255.255.255.255         On-link     10.20.0.50    281\n\
        10.30.0.0      255.255.0.0      10.20.0.254     10.20.0.50     26\n\
        127.0.0.0        255.0.0.0         On-link     127.0.0.1    331\n\
        224.0.0.0        240.0.0.0         On-link     127.0.0.1    331\n\
===\nPersistent Routes:\n  10.40.0.0    255.255.255.0      10.20.0.254  1\n";
        let nets = parse_windows_routes(win);
        assert_eq!(nets.len(), 2);
        assert_eq!((nets[0].cidr(), nets[0].source), ("10.20.0.0/24".to_string(), NetSource::Local));
        assert_eq!((nets[1].cidr(), nets[1].source), ("10.30.0.0/16".to_string(), NetSource::Route));

        let mac = "Routing tables\n\nInternet:\nDestination        Gateway            Flags               Netif Expire\n\
default            192.168.21.1       UGScg                 en0\n\
10.8/16            10.8.0.1           UGSc                utun4\n\
127                127.0.0.1          UCS                   lo0\n\
192.168.21         link#14            UCS                   en0      !\n\
192.168.21.1/32    link#14            UCS                   en0      !\n\
192.168.21.5       aa:bb:cc:dd:ee:ff  UHLWIi                en0   1200\n";
        let cidrs: Vec<String> = parse_bsd_routes(mac).iter().map(Network::cidr).collect();
        assert_eq!(cidrs, ["10.8.0.0/16", "192.168.21.0/24"]);
    }

    #[test]
    fn parses_forms() {
        assert_eq!(parse_targets("10.0.0.0/30").unwrap().len(), 2);
        assert_eq!(parse_targets("10.0.0.0/24").unwrap().len(), 254);
        assert_eq!(parse_targets("10.0.0.5-10").unwrap().len(), 6);
        assert_eq!(parse_targets("10.0.0.250 - 10.0.1.5").unwrap().len(), 12);
        assert_eq!(parse_targets("10.0.0.1, 10.0.0.1, 10.0.0.2").unwrap().len(), 2);
        assert!(parse_targets("10.0.0.0/8").is_err());
        assert!(parse_targets("nope").is_err());
    }
}
