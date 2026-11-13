//! IPv6 addresses of the devices found. A whole IPv6 network can't be
//! scanned address by address (a single subnet has 2^64 of them), but the
//! operating system keeps a neighbour table, the IPv6 counterpart of the
//! ARP table, listing the IPv6 addresses it has seen with their MAC
//! addresses. Matching those MACs to scanned hosts gives each host its
//! IPv6 addresses.

use std::collections::HashMap;
use std::net::Ipv6Addr;
use std::time::Duration;

/// Most addresses kept per device (privacy addresses rotate and pile up).
const MAX_PER_DEVICE: usize = 4;

/// Ask every IPv6 device on the local links to show itself, so that the
/// neighbour table is filled: one ping to the "all nodes" group per
/// interface. Windows PCs don't answer it, but they appear in the table
/// once anything has talked to them.
pub fn solicit(interfaces: &[String]) {
    for name in interfaces.iter().filter(|n| is_interface_name(n)) {
        let timeout = Duration::from_secs(3);
        #[cfg(target_os = "macos")]
        let _ = crate::probe::run_hidden_timeout("/sbin/ping6", &["-c", "2", "-i", "0.5", "-I", name, "ff02::1"], timeout);
        #[cfg(all(unix, not(target_os = "macos")))]
        let _ = crate::probe::run_hidden_timeout("ping", &["-6", "-c", "2", "-w", "2", &format!("ff02::1%{name}")], timeout);
        #[cfg(not(unix))]
        let _ = (name, timeout);
    }
}

/// Interface names come from the OS; still, only plain ones reach a command line.
fn is_interface_name(name: &str) -> bool {
    !name.is_empty() && name.len() <= 32 && !name.starts_with('-') && name.chars().all(|c| c.is_ascii_alphanumeric() || "._-".contains(c))
}

/// The OS neighbour table: IPv6 addresses by MAC address.
pub fn neighbors() -> HashMap<String, Vec<Ipv6Addr>> {
    #[cfg(windows)]
    let out = crate::probe::run_hidden("netsh", &["interface", "ipv6", "show", "neighbors"]);
    #[cfg(target_os = "macos")]
    let out = crate::probe::run_hidden("/usr/sbin/ndp", &["-an"]);
    #[cfg(all(unix, not(target_os = "macos")))]
    let out = crate::probe::run_hidden("ip", &["-6", "neigh", "show"]);
    out.map(|o| parse_neighbors(&String::from_utf8_lossy(&o.stdout))).unwrap_or_default()
}

/// Parses `netsh interface ipv6 show neighbors` (Windows), `ndp -an`
/// (macOS) and `ip -6 neigh` (Linux): on each line, the first IPv6 address
/// and the first MAC address. Entries the OS couldn't reach are skipped.
pub fn parse_neighbors(text: &str) -> HashMap<String, Vec<Ipv6Addr>> {
    let mut map: HashMap<String, Vec<Ipv6Addr>> = HashMap::new();
    for line in text.lines() {
        let lower = line.to_ascii_lowercase();
        if ["unreachable", "incomplete", "failed"].iter().any(|bad| lower.contains(bad)) {
            continue;
        }
        let mut ip = None;
        let mut mac = None;
        for tok in line.split_whitespace() {
            if ip.is_none() {
                // "fe80::1%en0": the part after % names the interface.
                ip = tok.split('%').next().and_then(|a| a.parse::<Ipv6Addr>().ok());
                if ip.is_some() {
                    continue;
                }
            }
            if mac.is_none() {
                mac = crate::probe::normalize_mac(tok);
            }
        }
        let (Some(ip), Some(mac)) = (ip, mac) else { continue };
        if ip.is_multicast() || ip.is_loopback() || ip.is_unspecified() {
            continue;
        }
        let list = map.entry(mac).or_default();
        if !list.contains(&ip) {
            list.push(ip);
        }
    }
    for list in map.values_mut() {
        // Routable addresses first, link-local (fe80::) ones last.
        list.sort_by_key(|ip| (is_link_local(ip), *ip));
        list.truncate(MAX_PER_DEVICE);
    }
    map
}

pub fn is_link_local(ip: &Ipv6Addr) -> bool {
    ip.segments()[0] & 0xFFC0 == 0xFE80
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addrs(map: &HashMap<String, Vec<Ipv6Addr>>, mac: &str) -> Vec<String> {
        map.get(mac).map(|l| l.iter().map(Ipv6Addr::to_string).collect()).unwrap_or_default()
    }

    #[test]
    fn parses_windows_macos_and_linux_tables() {
        let windows = "Interface 12: Ethernet\n\n\nInternet Address                              Physical Address   Type\n\
--------------------------------------------  -----------------  -----------\n\
fe80::1c3a:5bff:fe7c:2105                     00-06-5b-7c-21-05  Reachable (Router)\n\
2001:db8:20::5                                00-06-5b-7c-21-05  Stale\n\
fe80::9999                                    00-00-00-00-00-00  Unreachable\n\
ff02::1                                       33-33-00-00-00-01  Permanent\n\
ff02::fb                                      33-33-00-00-00-fb  Permanent\n";
        let map = parse_neighbors(windows);
        assert_eq!(map.len(), 1);
        assert_eq!(addrs(&map, "00:06:5B:7C:21:05"), ["2001:db8:20::5", "fe80::1c3a:5bff:fe7c:2105"]);

        let macos = "Neighbor                                Linklayer Address  Netif Expire    St Flgs Prbs\n\
2001:db8:20::17                         0:3:93:5d:7a:23      en0 23h59m58s S\n\
fe80::1463:8ff:fe5d:7a23%en0            0:3:93:5d:7a:23      en0 23h58m12s S\n\
fe80::aede:48ff:fe00:1122%en5           (incomplete)         en5 expired   N\n\
fe80::1%lo0                             (incomplete)         lo0 permanent R\n";
        let map = parse_neighbors(macos);
        assert_eq!(addrs(&map, "00:03:93:5D:7A:23"), ["2001:db8:20::17", "fe80::1463:8ff:fe5d:7a23"]);
        assert_eq!(map.len(), 1);

        let linux = "fe80::3e2a:f4ff:fe0b:1130 dev eth0 lladdr 3c:2a:f4:0b:11:30 REACHABLE\n\
2001:db8:20::30 dev eth0 lladdr 3c:2a:f4:0b:11:30 router STALE\n\
fe80::dead dev eth0 FAILED\n\
fe80::beef dev eth0 lladdr aa:bb:cc:00:00:01 INCOMPLETE\n";
        let map = parse_neighbors(linux);
        assert_eq!(addrs(&map, "3C:2A:F4:0B:11:30"), ["2001:db8:20::30", "fe80::3e2a:f4ff:fe0b:1130"]);
        assert_eq!(map.len(), 1);
    }

    #[test]
    fn keeps_a_few_addresses_per_device_and_survives_junk() {
        let many: String = (1..=9).map(|n| format!("2001:db8::{n} dev eth0 lladdr aa:bb:cc:00:00:02 STALE\n")).collect();
        let map = parse_neighbors(&format!("{many}fe80::2 dev eth0 lladdr aa:bb:cc:00:00:02 STALE\n"));
        assert_eq!(map["AA:BB:CC:00:00:02"].len(), MAX_PER_DEVICE);
        assert!(map["AA:BB:CC:00:00:02"].iter().all(|ip| !is_link_local(ip)));
        assert!(parse_neighbors("").is_empty());
        assert!(parse_neighbors("no neighbours here\n::::: zz-zz\n\u{feff}%%%\n").is_empty());
    }

    #[test]
    fn only_plain_interface_names_are_used() {
        assert!(is_interface_name("en0") && is_interface_name("eth0.20") && is_interface_name("wlan-1"));
        for bad in ["", "-I", "en0; reboot", "en 0", "en0%x"] {
            assert!(!is_interface_name(bad), "{bad:?}");
        }
    }
}
