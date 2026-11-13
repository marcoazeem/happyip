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
    parse_http_banner(&read_some(&mut stream, 16 * 1024))
}

/// Fetch `path` over plain HTTP and return the raw response (headers and
/// body), at most `limit` bytes. `path` must already be a clean URL path.
pub fn http_get(ip: Ipv4Addr, port: u16, path: &str, timeout: Duration, limit: usize) -> Option<Vec<u8>> {
    if !path.starts_with('/') || !path.bytes().all(|b| b.is_ascii_graphic()) {
        return None;
    }
    let mut stream = TcpStream::connect_timeout(&SocketAddr::new(IpAddr::V4(ip), port), timeout).ok()?;
    stream.set_read_timeout(Some(timeout)).ok()?;
    stream.set_write_timeout(Some(timeout)).ok()?;
    let req = format!("GET {path} HTTP/1.0\r\nHost: {ip}:{port}\r\nUser-Agent: HappyIP\r\nConnection: close\r\n\r\n");
    stream.write_all(req.as_bytes()).ok()?;
    let response = read_some(&mut stream, limit);
    (!response.is_empty()).then_some(response)
}

/// Read until the peer closes, an error/timeout, or `limit` bytes.
fn read_some(stream: &mut TcpStream, limit: usize) -> Vec<u8> {
    let mut buf = Vec::with_capacity(limit.min(16 * 1024));
    let mut chunk = [0u8; 4096];
    while buf.len() < limit {
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    }
    buf.truncate(limit);
    buf
}

/// Title and `Server` header from a raw HTTP response. The bytes come from
/// whatever answered on the network, so nothing here may assume they are
/// valid text or well-formed HTML.
pub fn parse_http_banner(response: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(response);
    // ASCII-only lowercasing keeps every byte offset the same as in `text`
    // (full Unicode lowercasing can change lengths, e.g. for "İ").
    let lower = text.to_ascii_lowercase();

    let server = text
        .lines()
        .take_while(|l| !l.trim().is_empty())
        .find_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.trim().eq_ignore_ascii_case("server").then(|| clean_banner(v))
        })
        .filter(|s| !s.is_empty());
    let title = lower.find("<title").and_then(|start| {
        let open_end = start + lower[start..].find('>')? + 1;
        let close = open_end + lower[open_end..].find("</title")?;
        let t = clean_banner(&decode_entities(text.get(open_end..close)?));
        (!t.is_empty()).then_some(t)
    });

    match (title, server) {
        (Some(t), Some(s)) if !t.eq_ignore_ascii_case(&s) => Some(format!("{t} ({s})")),
        (Some(t), _) => Some(t),
        (None, Some(s)) => Some(s),
        (None, None) => None,
    }
}

/// One line of printable text, at most 80 characters.
pub fn clean_banner(s: &str) -> String {
    let s: String = s.chars().filter(|c| !c.is_control() || c.is_whitespace()).collect();
    s.split_whitespace().collect::<Vec<_>>().join(" ").chars().take(80).collect()
}

/// The software an SSH server announces when you connect, e.g.
/// "OpenSSH_9.6p1 Ubuntu-3ubuntu13". It often names the OS or the device.
pub fn ssh_banner(ip: Ipv4Addr, timeout: Duration) -> Option<String> {
    let mut stream = TcpStream::connect_timeout(&SocketAddr::new(IpAddr::V4(ip), 22), timeout).ok()?;
    stream.set_read_timeout(Some(timeout)).ok()?;
    let mut buf = Vec::new();
    let mut chunk = [0u8; 256];
    while buf.len() < 512 && !buf.contains(&b'\n') {
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    }
    parse_ssh_banner(&buf)
}

/// "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13\r\n" → "OpenSSH_9.6p1 Ubuntu-3ubuntu13".
pub fn parse_ssh_banner(data: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(data);
    let line = text.lines().find(|l| l.starts_with("SSH-"))?;
    // "SSH-<protocol version>-<software and comments>"
    let software = clean_banner(line.splitn(3, '-').nth(2)?);
    (!software.is_empty()).then_some(software)
}

pub fn decode_entities(s: &str) -> String {
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
            "Windows server" | "Domain controller" | "Linux / Unix server" | "NAS / storage" => "🗄",
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

/// The names a host goes by, for matching naming conventions.
///
/// Short words such as "nas", "tv" or "note" are also parts of ordinary
/// names (JONAS-PC, the city BRNO, NOTEBOOK-12), so they only count as a
/// whole word of the name, optionally numbered ("nas", "nas2", "office-tv").
/// Only distinctive words ("synology", "laserjet") are matched anywhere.
struct Names {
    /// Lowercased computer name(s) without the DNS domain.
    text: String,
    words: Vec<String>,
}

impl Names {
    fn new(r: &HostResult) -> Self {
        let host = r.hostname.as_deref().unwrap_or("");
        let host = host.split('.').next().unwrap_or(host);
        let text = format!("{host} {}", r.netbios_name.as_deref().unwrap_or("")).to_lowercase();
        let words = text.split(|c: char| !c.is_alphanumeric()).filter(|w| !w.is_empty()).map(str::to_string).collect();
        Self { text, words }
    }

    /// A distinctive word appears anywhere in the name.
    fn has(&self, needles: &[&str]) -> bool {
        any(&self.text, needles)
    }

    /// One of `words` is a whole word of the name, or one followed only by
    /// digits ("cam3").
    fn word(&self, words: &[&str]) -> bool {
        self.words.iter().any(|w| {
            words.iter().any(|n| w.strip_prefix(n).is_some_and(|rest| rest.chars().all(|c| c.is_ascii_digit())))
        })
    }

    /// A word of the name starts with one of `prefixes`.
    fn starts(&self, prefixes: &[&str]) -> bool {
        self.words.iter().any(|w| prefixes.iter().any(|p| w.starts_with(p)))
    }

    /// Factory names like BRN3C2AF40B1130 (Brother) or NPI1A2B3C (HP): the
    /// prefix followed by part of the MAC address.
    fn factory_id(&self, prefixes: &[&str]) -> bool {
        self.words.iter().any(|w| {
            prefixes
                .iter()
                .any(|p| w.strip_prefix(p).is_some_and(|rest| rest.len() >= 6 && rest.chars().all(|c| c.is_ascii_hexdigit())))
        })
    }
}

pub fn classify(r: &HostResult, gateway: Option<Ipv4Addr>, is_local: bool) -> Device {
    let name = Names::new(r);
    let vendor = r.vendor.as_deref().unwrap_or("").to_lowercase();
    // Everything the device says about itself: its web page, the name on
    // its HTTPS certificate and its UPnP description.
    let snmp = r.snmp.as_ref().and_then(|s| s.description.as_deref()).unwrap_or("").to_lowercase();
    let web = [r.http_banner.as_deref(), r.tls_name.as_deref(), r.upnp.as_deref(), Some(snmp.as_str())]
        .into_iter()
        .flatten()
        .map(str::to_lowercase)
        .collect::<Vec<_>>()
        .join(" | ");
    // Model as an Apple device reports it over mDNS, e.g. "MacBookPro18,3".
    let model = r.model.as_deref().unwrap_or("").to_lowercase();
    let service = |names: &[&str]| r.mdns_services.iter().any(|s| names.contains(&s.as_str()));
    let ssh = r.ssh_banner.as_deref().unwrap_or("").to_lowercase();
    let port = |p: u16| r.open_ports.contains(&p);
    let ttl = r.ttl.map(initial_ttl);
    let randomized = r.mac.as_deref().is_some_and(is_randomized_mac);

    let mut basis = Vec::new();
    if let Some(t) = r.ttl {
        basis.push(format!("TTL {t}"));
    }
    if let Some(v) = r.vendor.as_deref().filter(|v| !v.is_empty()) {
        basis.push(format!("vendor {v}"));
    }
    if !r.open_ports.is_empty() {
        basis.push(format!("ports {}", r.ports_text()));
    }
    if let Some(w) = &r.http_banner {
        basis.push(format!("web “{w}”"));
    }
    if let Some(s) = &r.ssh_banner {
        basis.push(format!("SSH “{s}”"));
    }
    if let Some(n) = &r.tls_name {
        basis.push(format!("certificate “{n}”"));
    }
    if let Some(u) = &r.upnp {
        basis.push(format!("UPnP “{u}”"));
    }
    if let Some(d) = r.snmp.as_ref().and_then(|s| s.description.as_ref()) {
        basis.push(format!("SNMP “{d}”"));
    }
    if !r.mdns_services.is_empty() {
        basis.push(format!("mDNS services {}", r.mdns_services.join(", ")));
    }
    if r.netbios_name.is_some() {
        basis.push("answers NetBIOS".into());
    }

    let windows_ports = port(135) || port(139) || port(445) || port(3389);
    // Ports that computers have open and printers don't.
    let computer_ports = windows_ports || port(22) || port(548) || port(5900);
    // Exact OS from WMI, else what the computer registered in AD.
    let ad = r.ad.as_ref();
    let known_os = r.os_name.clone().or_else(|| ad?.os.clone()).unwrap_or_default().to_lowercase();
    if let Some(m) = &r.model {
        basis.push(format!("model {m}"));
    }
    if let Some(a) = ad {
        basis.push(match &a.ou {
            Some(ou) => format!("AD account in {ou}"),
            None => "AD computer account".into(),
        });
    }
    let pick = |kind: &'static str, os: Option<&'static str>| (kind, os);
    let windows = || {
        let server = known_os.contains("server")
            || known_os.is_empty()
                && port(3389)
                && (name.has(&["srv", "server", "dc0", "dc1", "-dc", "sql", "exch", "file"]) || port(53) || port(88));
        if server {
            pick("Windows server", Some("Windows Server"))
        } else if name.word(&["desktop", "laptop", "pc"]) || name.starts(&["win"]) || port(445) || port(3389) || !known_os.is_empty() {
            pick("Windows PC", Some("Windows"))
        } else {
            pick("Windows computer", Some("Windows"))
        }
    };
    let linux_names = ["linux", "ubuntu", "red hat", "centos", "debian", "suse", "rocky", "alma", "raspbian", "freebsd"];

    let (kind, os) = if is_local {
        pick("This computer", Some(if cfg!(windows) { "Windows" } else if cfg!(target_os = "macos") { "macOS" } else { "Linux" }))
    } else if ad.is_some_and(|a| a.is_dc) {
        pick("Domain controller", Some("Windows Server"))
    } else if Some(r.ip) == gateway {
        pick("Router / gateway", None)
    // What the machine itself (WMI) or the domain (AD) says it runs beats
    // any guess from its name or ports.
    } else if known_os.contains("windows") {
        windows()
    } else if known_os.contains("mac os") || known_os.contains("macos") {
        pick("Mac", Some("macOS"))
    } else if any(&known_os, &linux_names) {
        pick("Linux / Unix server", Some("Linux / Unix"))
    } else if snmp.contains("windows version") {
        windows()
    // Apple devices name their exact model over mDNS.
    } else if any(&model, &["macbook", "imac", "macmini", "macpro", "macstudio"]) || model.starts_with("mac") && model.contains(',') {
        pick("Mac", Some("macOS"))
    } else if model.starts_with("iphone") || model.starts_with("ipad") {
        pick("iPhone / iPad", Some("iOS / iPadOS"))
    } else if model.starts_with("appletv") || model.starts_with("audioaccessory") {
        pick("TV / media player", Some("tvOS"))
    // Network gear describes itself precisely over SNMP.
    } else if any(&snmp, &["cisco ios", "cisco nx-os", "routeros", "junos", "procurve", "arubaos", "fortigate", "edgeos", "edgeswitch", "switch", "router", "firewall", "access point", "wireless controller"]) {
        pick("Network device", None)
    // Port 631 (IPP) alone is also open on Macs and Linux PCs that share a
    // printer, so it only counts when nothing says "computer".
    } else if port(9100) || port(515) || (port(631) || service(&["ipp", "ipps", "printer", "pdl-datastream"])) && !computer_ports
        || any(&web, &["printer", "laserjet", "officejet", "deskjet", "envy", "epson", "brother", "kyocera", "ricoh", "xerox", "lexmark", "imagerunner", "bizhub"])
        || name.has(&["printer", "laserjet", "officejet", "epson"])
        || name.factory_id(&["brn", "brw", "npi"])
    {
        pick("Printer", None)
    } else if port(554)
        || any(&vendor, &["hikvision", "dahua", "axis communications", "reolink", "amcrest", "uniview", "hanwha"])
        || any(&web, &["camera", "nvr", "dvr", "hikvision", "dahua", "webcam"])
        || name.has(&["camera", "ipcam", "doorbell"])
        || name.word(&["cam"])
    {
        pick("IP camera", None)
    } else if port(5000) && any(&web, &["synology", "diskstation", "qnap"])
        || any(&vendor, &["synology", "qnap"])
        || name.has(&["diskstation", "synology", "qnap"])
        || name.word(&["nas"])
    {
        pick("NAS / storage", None)
    } else if port(62078) || name.has(&["iphone", "ipad"]) {
        pick("iPhone / iPad", Some("iOS / iPadOS"))
    } else if name.has(&["appletv", "apple-tv", "homepod"]) {
        pick("TV / media player", Some("tvOS"))
    } else if name.has(&["macbook", "imac", "mac-mini", "macmini", "mac-pro", "macpro"])
        || name.word(&["mac"])
        || (vendor.contains("apple") && (port(548) || port(5900) || port(22)))
    {
        pick("Mac", Some("macOS"))
    } else if vendor.contains("apple") {
        pick("Apple device", Some("Apple OS"))
    } else if windows_ports || r.netbios_name.is_some() && ttl == Some(128) {
        windows()
    } else if port(8009)
        || name.has(&["roku", "chromecast", "firetv", "fire-tv", "bravia", "sonos", "kindle", "playstation", "xbox", "nintendo", "webos", "tizen"])
        || name.word(&["tv", "echo", "shield"])
        || name.words.iter().any(|w| w.len() > 2 && w.ends_with("tv"))
        || any(&vendor, &["roku", "sonos", "vizio", "tcl", "hisense", "lg electronics", "sony interactive", "nintendo"])
        || any(&web, &["roku", "sonos", "chromecast", "bravia", "webos", "smart tv", "mediarenderer", "dlna"])
        || service(&["googlecast", "androidtvremote2", "amzn-wplay", "roku-rcp", "sonos", "spotify-connect"])
    {
        pick("TV / media player", None)
    } else if any(&web, &["ship 2.0", "tapo", "kasa", "tasmota", "shelly", "esphome", "wled"])
        || name.has(&["tapo", "kasa", "hs100", "hs110", "kp115", "yeelink", "yeelight", "esp32", "esp8266", "tasmota", "shelly", "tuya", "roborock", "dreame", "thermostat", "zigbee", "smartthings"])
        || name.word(&["light", "lamp", "bulb", "plug", "switch", "esp", "nest", "hue", "iot", "sensor", "vacuum"])
        || service(&["hap", "homekit", "matter", "matterc", "hue", "esphomelib"])
        || any(&vendor, &["espressif", "tuya", "shelly", "allterco", "signify", "philips lighting", "yeelight", "lifx", "wiz", "ecobee", "nest labs", "roborock", "beijing xiaomi electronics", "itead"])
    {
        pick("Smart home / IoT", None)
    } else if name.has(&["router", "miwifi", "xiaoqiang", "gateway", "openwrt", "ubnt", "unifi", "mikrotik"])
        || name.word(&["ap", "mesh", "deco", "eero", "orbi"])
        || any(&ssh, &["rosssh", "cisco"])
        || any(&vendor, &["cisco", "ubiquiti", "mikrotik", "aruba", "ruckus", "juniper", "fortinet", "netgear", "tp-link", "zyxel", "d-link"]) && (port(80) || port(443) || port(22))
        || ttl == Some(255) && (port(80) || port(443))
    {
        pick("Network device", None)
    } else if name.has(&["android", "galaxy", "redmi", "oneplus", "huawei", "realme", "nokia"])
        || name.word(&["poco", "pixel", "honor", "oppo", "vivo", "moto", "phone", "note"])
        // Samsung model numbers: SM-G991B.
        || name.text.split_whitespace().any(|n| n.starts_with("sm-"))
    {
        pick("Android phone / tablet", Some("Android"))
    } else if randomized && r.open_ports.is_empty() {
        pick("Phone / tablet", None)
    } else if ttl == Some(64) && port(22) || any(&ssh, &linux_names) || snmp.starts_with("linux") {
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
    fn banner_survives_hostile_pages() {
        let banner = |page: &str| parse_http_banner(page.as_bytes());
        assert_eq!(
            banner("HTTP/1.0 200 OK\r\nServer: HP HTTP Server\r\n\r\n<html><TITLE> HP LaserJet\n M404 </TITLE>").as_deref(),
            Some("HP LaserJet M404 (HP HTTP Server)")
        );
        // Characters whose lowercase form has a different byte length used
        // to shift the offsets and panic (or cut the title in the wrong place).
        assert_eq!(banner("<meta content=\"İ\"><title>Ürün</title>").as_deref(), Some("Ürün"));
        assert_eq!(banner("<title>İstanbul Modem</title>").as_deref(), Some("İstanbul Modem"));
        assert_eq!(banner("İİİİ<title>é</title>").as_deref(), Some("é"));
        // Broken or truncated markup yields nothing rather than a panic.
        for page in ["<title", "<title>", "<title>never closed", "</title><title", "", "\r\n\r\n"] {
            assert_eq!(banner(page), None, "{page:?}");
        }
        // Not UTF-8 at all, and a title cut in the middle of a character.
        assert!(parse_http_banner(&[0xFF, 0xFE, b'<', b't', b'i', b't', b'l', b'e', b'>', 0xC3]).is_none());
        assert_eq!(parse_http_banner(b"Server: \xFF\xFEbox\r\n\r\n").as_deref(), Some("\u{FFFD}\u{FFFD}box"));
        // Long and multi-line values are cut to one short line.
        let long = format!("<title>{}</title>", "x".repeat(500));
        assert_eq!(banner(&long).map(|b| b.len()), Some(80));
    }

    #[test]
    fn ssh_banners() {
        assert_eq!(parse_ssh_banner(b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13\r\n").as_deref(), Some("OpenSSH_9.6p1 Ubuntu-3ubuntu13"));
        assert_eq!(parse_ssh_banner(b"SSH-2.0-dropbear_2022.83\n").as_deref(), Some("dropbear_2022.83"));
        assert_eq!(parse_ssh_banner(b"220 mail.example ESMTP\r\n"), None);
        assert_eq!(parse_ssh_banner(b"SSH-2.0-"), None);
        assert_eq!(parse_ssh_banner(&[0xFF; 40]), None);
    }

    fn host(name: &str, ports: &[u16]) -> HostResult {
        let mut r = HostResult::new(Ipv4Addr::new(10, 0, 0, 9));
        r.hostname = Some(format!("{name}.corp.example"));
        r.open_ports = ports.to_vec();
        r.ttl = Some(64);
        r
    }

    #[test]
    fn short_words_inside_names_are_not_clues() {
        let kind = |r: &HostResult| classify(r, None, false).kind;
        // "nas" in Jonas, "brn" in Brno, "note" in notebook, "tv" in a name.
        let mut pc = host("jonas-pc", &[135, 445]);
        pc.ttl = Some(128);
        assert_eq!(kind(&pc), "Windows PC");
        let mut brno = host("brno-lt01", &[135, 445]);
        brno.ttl = Some(128);
        assert_eq!(kind(&brno), "Windows PC");
        assert_eq!(kind(&host("notebook-12", &[])), "Unknown");
        assert_eq!(kind(&host("vmtvx01", &[22])), "Linux / Unix server");
        // ...while the real conventions still work.
        assert_eq!(kind(&host("nas", &[])), "NAS / storage");
        assert_eq!(kind(&host("office-nas2", &[])), "NAS / storage");
        assert_eq!(kind(&host("brn3c2af40b1130", &[80])), "Printer");
        assert_eq!(kind(&host("npi1a2b3c", &[])), "Printer");
        assert_eq!(kind(&host("boardroom-tv", &[])), "TV / media player");
        assert_eq!(kind(&host("lobby-cam3", &[])), "IP camera");
        assert_eq!(kind(&host("galaxy-s24", &[])), "Android phone / tablet");
        // A domain called "nest.example" says nothing about the device.
        let mut r = host("build-01", &[22]);
        r.hostname = Some("build-01.nest.example".into());
        assert_eq!(kind(&r), "Linux / Unix server");
    }

    #[test]
    fn shared_printer_port_does_not_make_a_computer_a_printer() {
        let kind = |r: &HostResult| classify(r, None, false).kind;
        let mut mac = host("studio", &[22, 631]);
        mac.vendor = Some("Apple, Inc.".into());
        assert_eq!(kind(&mac), "Mac");
        assert_eq!(kind(&host("ws-17", &[22, 631])), "Linux / Unix server");
        assert_eq!(kind(&host("", &[631])), "Printer");
        assert_eq!(kind(&host("", &[80, 631, 9100])), "Printer");
    }

    #[test]
    fn known_os_beats_name_guesses() {
        let mut r = host("printer-server", &[135, 445, 9100]);
        r.os_name = Some("Windows Server 2022 Standard".into());
        assert_eq!(classify(&r, None, false).kind, "Windows server");
        let mut r = host("cam-review-pc", &[]);
        r.os_name = Some("Windows 11 Pro".into());
        assert_eq!(classify(&r, None, false).kind, "Windows PC");
    }

    #[test]
    fn certificate_and_upnp_names_are_clues() {
        let mut r = host("", &[443]);
        r.tls_name = Some("HP LaserJet M404dn".into());
        let d = classify(&r, None, false);
        assert_eq!(d.kind, "Printer");
        assert!(d.basis.iter().any(|b| b == "certificate “HP LaserJet M404dn”"));
        let mut r = host("", &[]);
        r.upnp = Some("Living Room (Sonos One)".into());
        assert_eq!(classify(&r, None, false).kind, "TV / media player");
        let mut r = host("", &[5000]);
        r.upnp = Some("Files (Synology DS220+)".into());
        assert_eq!(classify(&r, None, false).kind, "NAS / storage");
    }

    #[test]
    fn mdns_and_snmp_are_clues() {
        let kind = |r: &HostResult| classify(r, None, false).kind;
        let snmp = |descr: &str| Some(crate::snmp::Info { description: Some(descr.into()), ..Default::default() });
        let mut r = host("", &[]);
        r.model = Some("MacBookPro18,3".into());
        r.mdns_services = vec!["airplay".into(), "smb".into()];
        assert_eq!(kind(&r), "Mac");
        r.model = Some("iPad13,4".into());
        assert_eq!(kind(&r), "iPhone / iPad");
        let mut r = host("", &[80]);
        r.mdns_services = vec!["ipp".into(), "http".into()];
        assert_eq!(kind(&r), "Printer");
        let mut r = host("", &[]);
        r.mdns_services = vec!["googlecast".into()];
        assert_eq!(kind(&r), "TV / media player");
        r.mdns_services = vec!["hap".into()];
        assert_eq!(kind(&r), "Smart home / IoT");

        let mut r = host("", &[22, 80]);
        r.snmp = snmp("Cisco IOS Software, C2960 Software, Version 15.0(2)SE11");
        let d = classify(&r, None, false);
        assert_eq!(d.kind, "Network device");
        assert!(d.basis.iter().any(|b| b.starts_with("SNMP “Cisco IOS")));
        r.snmp = snmp("HP ETHERNET MULTI-ENVIRONMENT,ROM none,JETDIRECT,JD153,EEPROM JSI24090012 LaserJet");
        assert_eq!(kind(&r), "Printer");
        r.snmp = snmp("Hardware: Intel64 Family 6 - Software: Windows Version 6.3 (Build 20348 Multiprocessor Free)");
        // SNMP says Windows, but not whether it's a PC or a server.
        assert_eq!(kind(&r), "Windows computer");
        let mut r = host("", &[]);
        r.ttl = None;
        r.snmp = snmp("Linux backup01 5.15.0-91-generic #101-Ubuntu SMP x86_64");
        assert_eq!(kind(&r), "Linux / Unix server");
    }

    #[test]
    fn http_get_refuses_unclean_paths() {
        let t = Duration::from_millis(50);
        for path in ["", "x", "/a b", "/a\r\nHost: evil", "/\u{e9}"] {
            assert!(http_get(Ipv4Addr::LOCALHOST, 9, path, t, 100).is_none(), "{path:?}");
        }
    }

    #[test]
    fn ssh_banner_is_a_clue() {
        let mut r = host("", &[22]);
        r.ttl = None;
        r.ssh_banner = Some("OpenSSH_9.2p1 Debian-2+deb12u3".into());
        let d = classify(&r, None, false);
        assert_eq!(d.kind, "Linux / Unix server");
        assert!(d.basis.iter().any(|b| b.contains("Debian")));
        r.ssh_banner = Some("ROSSSH".into());
        assert_eq!(classify(&r, None, false).kind, "Network device");
    }

    #[test]
    fn ttl_buckets() {
        assert_eq!(initial_ttl(57), 64);
        assert_eq!(initial_ttl(127), 128);
        assert_eq!(initial_ttl(250), 255);
    }
}
