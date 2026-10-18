//! Fictional sample network used by `--demo` (screenshots, trying the UI
//! without scanning anything). Every name, user and address here is made up.

use std::net::Ipv4Addr;

use crate::identify;
use crate::scanner::{AliveBy, HostResult};

pub const RANGE: &str = "10.20.0.0/24";

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

pub fn results() -> Vec<HostResult> {
    let gateway = Some(Ipv4Addr::new(10, 20, 0, 1));
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
