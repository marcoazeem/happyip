//! Parsing of IP range expressions and local interface discovery.

use std::net::Ipv4Addr;

/// Upper bound on hosts per scan, to keep the UI and process count sane.
pub const MAX_HOSTS: usize = 65_536;

/// Parse a comma-separated list of targets. Each item may be:
/// - a single IP: `192.168.1.10`
/// - a CIDR block: `192.168.1.0/24`
/// - a full range: `192.168.1.1 - 192.168.2.254`
/// - a last-octet range: `192.168.1.1-100`
pub fn parse_targets(input: &str) -> Result<Vec<Ipv4Addr>, String> {
    let mut out = Vec::new();
    for item in input.split([',', ';', '\n']).map(str::trim).filter(|s| !s.is_empty()) {
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

fn parse_ip(s: &str) -> Result<u32, String> {
    s.trim()
        .parse::<Ipv4Addr>()
        .map(u32::from)
        .map_err(|_| format!("'{}' is not a valid IPv4 address", s.trim()))
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

    pub fn label(&self) -> String {
        format!("{}  {}/{}", self.name, self.ip, self.prefix)
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
