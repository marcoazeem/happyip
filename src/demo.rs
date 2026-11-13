//! Fictional sample network used by `--demo` (screenshots, trying the UI
//! without scanning anything). Every name, user and address here is made up.

use std::net::Ipv4Addr;

use crate::ad::Directory;
use crate::identify;
use crate::scanner::{AliveBy, HostResult};

pub const RANGE: &str = "10.20.0.0/24";
pub const GATEWAY: Ipv4Addr = Ipv4Addr::new(10, 20, 0, 1);

struct Sample {
    last_octet: u8,
    ttl: u32,
    rtt_ms: f64,
    hostname: &'static str,
    netbios: &'static str,
    users: &'static [&'static str],
    mac: &'static str,
    ports: &'static [u16],
    web: &'static str,
}

const HOSTS: &[Sample] = &[
    Sample { last_octet: 1, ttl: 64, rtt_ms: 0.6, hostname: "gateway.corp.example", netbios: "", users: &[], mac: "00:15:6D:4A:10:01", ports: &[22, 80, 443], web: "UniFi Network" },
    Sample { last_octet: 5, ttl: 128, rtt_ms: 0.8, hostname: "dc01.corp.example", netbios: "DC01", users: &["administrator"], mac: "00:06:5B:7C:21:05", ports: &[53, 88, 135, 139, 445, 3389], web: "" },
    Sample { last_octet: 8, ttl: 64, rtt_ms: 1.1, hostname: "nas.corp.example", netbios: "NAS", users: &[], mac: "00:11:32:9E:44:08", ports: &[22, 80, 139, 445, 5000], web: "Synology DiskStation" },
    Sample { last_octet: 12, ttl: 128, rtt_ms: 2.4, hostname: "desktop-7hq2k.corp.example", netbios: "DESKTOP-7HQ2K", users: &["j.rivera"], mac: "00:2B:67:31:5C:12", ports: &[135, 139, 445], web: "" },
    Sample { last_octet: 14, ttl: 128, rtt_ms: 3.0, hostname: "laptop-finance02.corp.example", netbios: "LAPTOP-FINANCE02", users: &["a.chen"], mac: "00:12:F0:88:3A:14", ports: &[135, 139, 445, 3389], web: "" },
    Sample { last_octet: 15, ttl: 128, rtt_ms: 2.2, hostname: "desktop-recept.corp.example", netbios: "DESKTOP-RECEPT", users: &["frontdesk"], mac: "00:06:5B:12:9F:15", ports: &[135, 139, 445], web: "" },
    Sample { last_octet: 21, ttl: 128, rtt_ms: 4.7, hostname: "laptop-design1.corp.example", netbios: "LAPTOP-DESIGN1", users: &["m.okafor", "support"], mac: "00:2B:67:6E:01:21", ports: &[135, 139, 445, 3389], web: "" },
    Sample { last_octet: 23, ttl: 64, rtt_ms: 5.3, hostname: "studio-macbook.corp.example", netbios: "", users: &[], mac: "00:03:93:5D:7A:23", ports: &[22, 548, 5900], web: "" },
    Sample { last_octet: 30, ttl: 64, rtt_ms: 7.9, hostname: "brn3c2af4.corp.example", netbios: "", users: &[], mac: "3C:2A:F4:0B:11:30", ports: &[80, 443, 631, 9100], web: "Brother MFC-L8900CDW" },
    Sample { last_octet: 31, ttl: 255, rtt_ms: 9.2, hostname: "", netbios: "", users: &[], mac: "00:68:EB:42:7D:31", ports: &[80, 443, 9100], web: "HP LaserJet Pro M404dn" },
    Sample { last_octet: 40, ttl: 64, rtt_ms: 12.0, hostname: "", netbios: "", users: &[], mac: "00:BC:99:5A:0E:40", ports: &[80, 554], web: "" },
    Sample { last_octet: 52, ttl: 64, rtt_ms: 48.0, hostname: "iphone.corp.example", netbios: "", users: &[], mac: "DA:A1:19:3F:62:52", ports: &[62078], web: "" },
    Sample { last_octet: 57, ttl: 64, rtt_ms: 61.0, hostname: "galaxy-s24.corp.example", netbios: "", users: &[], mac: "00:00:F0:7B:14:57", ports: &[], web: "" },
    Sample { last_octet: 60, ttl: 64, rtt_ms: 15.0, hostname: "boardroom-tv.corp.example", netbios: "", users: &[], mac: "00:1A:11:C4:2E:60", ports: &[8009], web: "" },
    Sample { last_octet: 61, ttl: 64, rtt_ms: 18.0, hostname: "sonos-lobby.corp.example", netbios: "", users: &[], mac: "00:0E:58:A1:33:61", ports: &[80], web: "" },
    Sample { last_octet: 75, ttl: 255, rtt_ms: 22.0, hostname: "", netbios: "", users: &[], mac: "00:4B:12:5C:90:75", ports: &[80], web: "Tasmota" },
    Sample { last_octet: 99, ttl: 64, rtt_ms: 0.9, hostname: "build-01.corp.example", netbios: "", users: &[], mac: "00:12:F0:2D:4C:99", ports: &[22, 80, 443], web: "Jenkins" },
];

/// The fictional domain behind the sample hosts, in the format the real
/// Active Directory query returns (see `ad::parse`).
const DIRECTORY: &str = "DOMAIN=corp.example\n\
C=DC01|dc01.corp.example|Windows Server 2022 Standard|10.0 (20348)|Primary domain controller|CN=DC01,OU=Domain Controllers,DC=corp,DC=example|2026-11-12|532480|Server room\n\
C=NAS|nas.corp.example|||File shares and backups|CN=NAS,OU=Servers,DC=corp,DC=example|2026-11-10|4096|Server room\n\
C=DESKTOP-7HQ2K|desktop-7hq2k.corp.example|Windows 11 Pro|10.0 (26100)|Sales - J. Rivera|CN=DESKTOP-7HQ2K,OU=Sales,OU=Workstations,DC=corp,DC=example|2026-11-11|4096|1st floor\n\
C=LAPTOP-FINANCE02|laptop-finance02.corp.example|Windows 11 Enterprise|10.0 (26100)|Finance - A. Chen|CN=LAPTOP-FINANCE02,OU=Finance,OU=Workstations,DC=corp,DC=example|2026-11-12|4096|2nd floor\n\
C=DESKTOP-RECEPT|desktop-recept.corp.example|Windows 11 Pro|10.0 (22631)|Reception|CN=DESKTOP-RECEPT,OU=Front Desk,OU=Workstations,DC=corp,DC=example|2026-11-12|4096|Lobby\n\
C=LAPTOP-DESIGN1|laptop-design1.corp.example|Windows 11 Enterprise|10.0 (26100)|Design - M. Okafor|CN=LAPTOP-DESIGN1,OU=Design,OU=Workstations,DC=corp,DC=example|2026-09-02|4098|2nd floor\n\
S=10.20.0.0/24|HQ|VLAN 20 Staff|\n\
S=10.30.0.0/24|HQ|VLAN 30 Guests|\n\
S=10.40.0.0/23|Branch|Warehouse|\n\
Z=0.20.10.in-addr.arpa\n";

pub fn directory() -> Directory {
    crate::ad::parse(DIRECTORY).expect("demo directory is valid")
}

pub fn results() -> Vec<HostResult> {
    let gateway = Some(GATEWAY);
    let mut out: Vec<HostResult> = HOSTS
        .iter()
        .map(|s| {
            let mut r = HostResult::new(Ipv4Addr::new(10, 20, 0, s.last_octet));
            let some = |v: &str| (!v.is_empty()).then(|| v.to_string());
            r.alive = Some(AliveBy::Ping);
            r.ttl = Some(s.ttl);
            r.rtt_ms = Some(s.rtt_ms);
            r.hostname = some(s.hostname);
            r.netbios_name = some(s.netbios);
            if r.netbios_name.is_some() {
                r.domain = Some("corp.example".into());
                (r.os_name, r.model) = match s.last_octet {
                    5 => (Some("Windows Server 2022 Standard".into()), Some("Dell Inc. PowerEdge R650".into())),
                    12 | 15 => (Some("Windows 11 Pro".into()), Some("Dell Inc. OptiPlex 7090".into())),
                    14 | 21 => (Some("Windows 11 Enterprise".into()), Some("LENOVO ThinkPad T14 Gen 4".into())),
                    _ => (None, None),
                };
            }
            r.users = s.users.iter().map(|u| u.to_string()).collect();
            r.mac = some(s.mac);
            r.vendor = r.mac.as_deref().and_then(identify::vendor);
            r.open_ports = s.ports.to_vec();
            r.http_banner = some(s.web);
            r.device = Some(identify::classify(&r, gateway, false));
            r
        })
        .collect();
    // Pad with unanswered addresses so the totals look like a real /24 scan.
    let used: Vec<u8> = HOSTS.iter().map(|s| s.last_octet).collect();
    out.extend((1..=254u8).filter(|o| !used.contains(o)).map(|o| HostResult::new(Ipv4Addr::new(10, 20, 0, o))));
    out.sort_by_key(|r| r.ip);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The sample network doubles as a regression test for device
    /// identification: every host must come out as what it was written to be.
    #[test]
    fn sample_hosts_are_identified_as_intended() {
        let dir = directory();
        let mut results = results();
        for r in &mut results {
            r.enrich(Some(&dir), &dir.networks(), Some(GATEWAY));
        }
        let kind = |last: u8| results.iter().find(|r| r.ip.octets()[3] == last).unwrap().device_text();
        let expected = [
            (1, "Router / gateway"),
            (5, "Domain controller"),
            (8, "NAS / storage"),
            (12, "Windows PC"),
            (14, "Windows PC"),
            (15, "Windows PC"),
            (21, "Windows PC"),
            (23, "Mac"),
            (30, "Printer"),
            (31, "Printer"),
            (40, "IP camera"),
            (52, "iPhone / iPad"),
            (57, "Android phone / tablet"),
            (60, "TV / media player"),
            (61, "TV / media player"),
            (75, "Smart home / IoT"),
            (99, "Linux / Unix server"),
        ];
        for (last, want) in expected {
            assert_eq!(kind(last), want, "10.20.0.{last}");
        }
        assert_eq!(results.len(), 254);
        assert_eq!(results.iter().filter(|r| r.alive.is_some()).count(), HOSTS.len());
    }

    #[test]
    fn directory_matches_the_sample_hosts() {
        let dir = directory();
        assert_eq!(dir.domain, "corp.example");
        assert!(dir.warnings.is_empty());
        let pc = dir.find(Some("LAPTOP-DESIGN1"), None).unwrap();
        assert!(!pc.enabled, "one disabled account, to show the warning");
        assert!(dir.find(Some("DC01"), None).unwrap().is_dc);
        assert_eq!(dir.networks().len(), 3);
    }
}
