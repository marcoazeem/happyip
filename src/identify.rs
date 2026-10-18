//! Device fingerprinting: MAC vendor lookup, HTTP banners, the default
//! gateway, and heuristics that combine every clue into a device type.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::sync::OnceLock;
use std::time::Duration;

use crate::scanner::HostResult;

/// IEEE OUI registry (MA-L /24, MA-M /28 and MA-S /36 blocks), generated from
/// Wireshark's `manuf` file: `<hex prefix>\t<organization>` per line.
const OUI_DB: &str = include_str!("../data/oui.tsv");

fn oui_map() -> &'static HashMap<&'static str, &'static str> {
    static MAP: OnceLock<HashMap<&str, &str>> = OnceLock::new();
    MAP.get_or_init(|| OUI_DB.lines().filter_map(|l| l.split_once('\t')).collect())
}

/// Manufacturer for a MAC like `AA:BB:CC:DD:EE:FF`. Randomized (locally
/// administered) addresses have no vendor.
pub fn vendor(mac: &str) -> Option<String> {
    let hex: String = mac.chars().filter(char::is_ascii_hexdigit).collect::<String>().to_uppercase();
    if hex.len() != 12 {
        return None;
    }
    if is_randomized_mac(mac) {
        return Some("Private (randomized) address".into());
    }
    [9, 7, 6].iter().find_map(|&n| oui_map().get(&hex[..n]).map(|v| v.to_string()))
}

/// Phones, tablets and laptops use random MACs per Wi-Fi network for privacy;
/// those set the "locally administered" bit.
pub fn is_randomized_mac(mac: &str) -> bool {
    u8::from_str_radix(mac.get(..2).unwrap_or("00"), 16).is_ok_and(|b| b & 0x02 != 0)
}

/// Fetch `/` over plain HTTP and return a short description from the page
/// title and/or `Server` header, e.g. "HP LaserJet M404 (HP HTTP Server)".
pub fn http_banner(ip: Ipv4Addr, port: u16, timeout: Duration) -> Option<String> {
    let mut stream = TcpStream::connect_timeout(&SocketAddr::new(IpAddr::V4(ip), port), timeout).ok()?;
    stream.set_read_timeout(Some(timeout)).ok()?;
    stream.set_write_timeout(Some(timeout)).ok()?;
    let req = format!("GET / HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: HappyIP\r\nConnection: close\r\n\r\n");
    stream.write_all(req.as_bytes()).ok()?;

    let mut buf = Vec::with_capacity(16 * 1024);
    let mut chunk = [0u8; 4096];
    while buf.len() < 16 * 1024 {
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    }
    let text = String::from_utf8_lossy(&buf);
    let lower = text.to_lowercase();

    let server = text
        .lines()
        .take_while(|l| !l.trim().is_empty())
        .find_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.trim().eq_ignore_ascii_case("server").then(|| v.trim().to_string())
        })
        .filter(|s| !s.is_empty());
    let title = lower.find("<title").and_then(|start| {
        let open_end = start + lower[start..].find('>')? + 1;
        let close = open_end + lower[open_end..].find("</title")?;
        let t = decode_entities(text[open_end..close].trim());
        let t: String = t.split_whitespace().collect::<Vec<_>>().join(" ");
        (!t.is_empty()).then(|| t.chars().take(80).collect::<String>())
    });

    match (title, server) {
        (Some(t), Some(s)) if !t.eq_ignore_ascii_case(&s) => Some(format!("{t} ({s})")),
        (Some(t), _) => Some(t),
        (None, Some(s)) => Some(s),
        (None, None) => None,
    }
}

fn decode_entities(s: &str) -> String {
    s.replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", "\"").replace("&#39;", "'")
}

/// The IPv4 default gateway (usually the router).
pub fn default_gateway() -> Option<Ipv4Addr> {
    #[cfg(windows)]
    {
        let out = crate::probe::run_hidden("route", &["print", "-4", "0.0.0.0"])?;
        String::from_utf8_lossy(&out.stdout).lines().find_map(|l| {
            let t: Vec<&str> = l.split_whitespace().collect();
            (t.len() >= 3 && t[0] == "0.0.0.0" && t[1] == "0.0.0.0").then(|| t[2].parse().ok()).flatten()
        })
    }
    #[cfg(target_os = "macos")]
    {
        let out = crate::probe::run_hidden("/sbin/route", &["-n", "get", "default"])?;
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .find_map(|l| l.trim().strip_prefix("gateway:").and_then(|g| g.trim().parse().ok()))
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        let out = crate::probe::run_hidden("ip", &["route", "show", "default"])?;
        let text = String::from_utf8_lossy(&out.stdout).to_string();
        let mut it = text.split_whitespace();
        it.find(|t| *t == "via").and_then(|_| it.next()).and_then(|g| g.parse().ok())
    }
}

#[derive(Clone, Debug)]
pub struct Device {
    pub kind: &'static str,
    pub os: Option<&'static str>,
    /// Human-readable clues the guess was based on.
    pub basis: Vec<String>,
}

impl Device {
    pub fn icon(&self) -> &'static str {
        match self.kind {
            "This computer" | "Windows PC" | "Windows computer" | "Mac" => "💻",
            "Windows server" | "Linux / Unix server" | "NAS / storage" => "🗄",
            "iPhone / iPad" | "Phone / tablet" | "Android phone / tablet" => "📱",
            "Router / gateway" | "Network device" => "📡",
            "Printer" => "🖨",
            "IP camera" => "📷",
            "TV / media player" => "📺",
            "Smart home / IoT" => "💡",
            "Embedded / IoT device" => "🔌",
            "Apple device" => "🍏",
            _ => "❔",
        }
    }
}

/// Typical starting TTL of the sender's OS, from the TTL we observed.
fn initial_ttl(ttl: u32) -> u32 {
    match ttl {
        0..=64 => 64,
        65..=128 => 128,
        _ => 255,
    }
}

fn any(hay: &str, needles: &[&str]) -> bool {
    needles.iter().any(|n| hay.contains(n))
}

pub fn classify(r: &HostResult, gateway: Option<Ipv4Addr>, is_local: bool) -> Device {
    let name = format!(
        "{} {}",
        r.hostname.as_deref().unwrap_or(""),
        r.netbios_name.as_deref().unwrap_or("")
    )
    .to_lowercase();
    let vendor = r.vendor.as_deref().unwrap_or("").to_lowercase();
    let web = r.http_banner.as_deref().unwrap_or("").to_lowercase();
    let port = |p: u16| r.open_ports.contains(&p);
    let ttl = r.ttl.map(initial_ttl);
    let randomized = r.mac.as_deref().is_some_and(is_randomized_mac);

    let mut basis = Vec::new();
    if let Some(t) = r.ttl {
        basis.push(format!("TTL {t}"));
    }
    if !r.vendor.as_deref().unwrap_or("").is_empty() {
        basis.push(format!("vendor {}", r.vendor.as_deref().unwrap()));
    }
    if !r.open_ports.is_empty() {
        basis.push(format!("ports {}", r.ports_text()));
    }
    if let Some(w) = &r.http_banner {
        basis.push(format!("web “{w}”"));
    }
    if r.netbios_name.is_some() {
        basis.push("answers NetBIOS".into());
    }

    let windows_ports = port(135) || port(139) || port(445) || port(3389);
    let wmi_os = r.os_name.as_deref().unwrap_or("").to_lowercase();
    if let Some(m) = &r.model {
        basis.push(format!("model {m}"));
    }
    let pick = |kind: &'static str, os: Option<&'static str>| (kind, os);

    let (kind, os) = if is_local {
        pick("This computer", Some(if cfg!(windows) { "Windows" } else if cfg!(target_os = "macos") { "macOS" } else { "Linux" }))
    } else if Some(r.ip) == gateway {
        pick("Router / gateway", None)
    } else if port(9100) || port(631) || port(515)
        || any(&web, &["printer", "laserjet", "officejet", "deskjet", "envy", "epson", "brother", "kyocera", "ricoh", "xerox", "lexmark", "imagerunner", "bizhub"])
        || any(&name, &["printer", "laserjet", "officejet", "epson", "brn", "npi"])
    {
        pick("Printer", None)
    } else if port(554)
        || any(&vendor, &["hikvision", "dahua", "axis communications", "reolink", "amcrest", "uniview", "hanwha"])
        || any(&web, &["camera", "nvr", "dvr", "hikvision", "dahua", "webcam"])
        || any(&name, &["camera", "cam-", "ipcam", "doorbell"])
    {
        pick("IP camera", None)
    } else if port(5000) && any(&web, &["synology", "diskstation", "qnap"])
        || any(&vendor, &["synology", "qnap"])
        || any(&name, &["nas", "diskstation", "synology", "qnap"])
    {
        pick("NAS / storage", None)
    } else if port(62078) || any(&name, &["iphone", "ipad"]) {
        pick("iPhone / iPad", Some("iOS / iPadOS"))
    } else if any(&name, &["appletv", "apple-tv", "homepod"]) {
        pick("TV / media player", Some("tvOS"))
    } else if any(&name, &["macbook", "imac", "mac-mini", "macmini", "mac-pro", "macpro"])
        || name.split_whitespace().any(|n| n == "mac" || n.starts_with("mac."))
        || (vendor.contains("apple") && (port(548) || port(5900) || port(22)))
    {
        pick("Mac", Some("macOS"))
    } else if vendor.contains("apple") {
        pick("Apple device", Some("Apple OS"))
    } else if windows_ports || r.netbios_name.is_some() && ttl == Some(128) {
        let server = wmi_os.contains("server")
            || wmi_os.is_empty() && port(3389) && (any(&name, &["srv", "server", "dc0", "dc1", "-dc", "sql", "exch", "file"]) || port(53) || port(88));
        if server {
            pick("Windows server", Some("Windows Server"))
        } else if any(&name, &["desktop-", "laptop-", "pc-", "-pc", "win"]) || port(445) || port(3389) {
            pick("Windows PC", Some("Windows"))
        } else {
            pick("Windows computer", Some("Windows"))
        }
    } else if port(8009)
        || any(&name, &["tv", "roku", "chromecast", "firetv", "fire-tv", "bravia", "shield", "sonos", "echo", "kindle", "playstation", "xbox", "nintendo", "webos", "tizen"])
        || any(&vendor, &["roku", "sonos", "vizio", "tcl", "hisense", "lg electronics", "sony interactive", "nintendo"])
    {
        pick("TV / media player", None)
    } else if any(&web, &["ship 2.0", "tapo", "kasa", "tasmota", "shelly", "esphome", "wled"])
        || any(&name, &["tapo", "kasa", "hs100", "hs110", "kp115"])
        || any(&name, &["yeelink", "yeelight", "light", "lamp", "bulb", "plug", "switch-", "esp_", "esp-", "esp32", "esp8266", "tasmota", "shelly", "tuya", "nest", "hue", "iot", "sensor", "vacuum", "roborock", "dreame", "thermostat", "zigbee", "smartthings"])
        || any(&vendor, &["espressif", "tuya", "shelly", "allterco", "signify", "philips lighting", "yeelight", "lifx", "wiz", "ecobee", "nest labs", "roborock", "beijing xiaomi electronics", "itead"])
    {
        pick("Smart home / IoT", None)
    } else if any(&name, &["router", "miwifi", "xiaoqiang", "gateway", "openwrt", "ubnt", "unifi", "mikrotik", "-ap", "ap-", "mesh", "deco", "eero", "orbi"])
        || any(&vendor, &["cisco", "ubiquiti", "mikrotik", "aruba", "ruckus", "juniper", "fortinet", "netgear", "tp-link", "zyxel", "d-link"]) && (port(80) || port(443) || port(22))
        || ttl == Some(255) && (port(80) || port(443))
    {
        pick("Network device", None)
    } else if any(&name, &["android", "galaxy", "sm-", "redmi", "poco", "oneplus", "pixel", "huawei", "honor", "oppo", "vivo", "realme", "moto", "nokia", "phone", "note"])
    {
        pick("Android phone / tablet", Some("Android"))
    } else if randomized && r.open_ports.is_empty() {
        pick("Phone / tablet", None)
    } else if ttl == Some(64) && port(22) {
        pick("Linux / Unix server", Some("Linux / Unix"))
    } else if any(&vendor, &["samsung", "xiaomi", "oneplus", "huawei", "oppo", "vivo", "motorola", "google", "realme", "honor"]) && r.open_ports.is_empty() {
        pick("Android phone / tablet", Some("Android"))
    } else if ttl == Some(255) {
        // Embedded network stacks (lwIP etc.) start at 255: IoT gadgets,
        // switches, access points.
        pick("Embedded / IoT device", None)
    } else {
        pick("Unknown", None)
    };

    // Fall back to an OS family from the TTL when nothing more specific is known.
    let os = os.or(match (kind, ttl) {
        ("Router / gateway" | "Network device" | "Printer" | "IP camera" | "Smart home / IoT" | "Embedded / IoT device", _) => None,
        (_, Some(128)) => Some("Windows"),
        (_, Some(64)) => Some("Linux / Unix-like"),
        _ => None,
    });

    Device { kind, os, basis }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vendors() {
        assert_eq!(vendor("14:94:6C:00:00:01").as_deref(), Some("Apple, Inc."));
        assert_eq!(vendor("02:11:22:33:44:55").as_deref(), Some("Private (randomized) address"));
        assert!(is_randomized_mac("DA:A1:19:00:00:00"));
        assert!(!is_randomized_mac("00:1A:2B:00:00:00"));
    }

    #[test]
    fn ttl_buckets() {
        assert_eq!(initial_ttl(57), 64);
        assert_eq!(initial_ttl(127), 128);
        assert_eq!(initial_ttl(250), 255);
    }
}
