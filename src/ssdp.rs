//! UPnP discovery (SSDP). One multicast question at the start of a scan
//! makes TVs, media players, routers, NAS boxes, printers and smart-home
//! hubs on the local network announce themselves; each then describes itself
//! (name, maker, model) in a small XML document.
//!
//! Replies and descriptions are untrusted input.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant};

use crate::util::lock;

const GROUP: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(239, 255, 255, 250)), 1900);
const QUESTION: &str = "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n";
/// Devices answer within MX (1 s) of the question.
const LISTEN: Duration = Duration::from_millis(1600);

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Reply {
    /// The `SERVER` header, e.g. "Linux/5.10 UPnP/1.0 Sonos/70.3".
    pub server: Option<String>,
    /// Port and path of the device description on the device itself.
    pub description: Option<(u16, String)>,
}

/// Replies collected while the scan runs; scan threads wait for the short
/// listening window to close before asking.
pub struct Discovery {
    replies: Mutex<Option<HashMap<Ipv4Addr, Reply>>>,
    done: Condvar,
}

impl Discovery {
    pub fn new() -> Self {
        Self { replies: Mutex::new(None), done: Condvar::new() }
    }

    /// Ask from each local address and collect the answers. With `ask`
    /// false (nothing on the local network is being scanned) it finishes at once.
    pub fn run(&self, local: &[Ipv4Addr], ask: bool) {
        let found = if ask { discover(local) } else { HashMap::new() };
        *lock(&self.replies) = Some(found);
        self.done.notify_all();
    }

    /// What `ip` announced, once listening has finished.
    pub fn reply(&self, ip: Ipv4Addr) -> Option<Reply> {
        let deadline = Instant::now() + LISTEN + Duration::from_millis(500);
        let mut replies = lock(&self.replies);
        while replies.is_none() {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return None;
            }
            replies = self.done.wait_timeout(replies, left).unwrap_or_else(std::sync::PoisonError::into_inner).0;
        }
        replies.as_ref()?.get(&ip).cloned()
    }
}

fn discover(local: &[Ipv4Addr]) -> HashMap<Ipv4Addr, Reply> {
    let sockets: Vec<UdpSocket> = local
        .iter()
        .filter_map(|ip| {
            let sock = UdpSocket::bind((*ip, 0)).ok()?;
            sock.set_read_timeout(Some(Duration::from_millis(100))).ok()?;
            sock.send_to(QUESTION.as_bytes(), GROUP).ok()?;
            Some(sock)
        })
        .collect();
    let mut found: HashMap<Ipv4Addr, Reply> = HashMap::new();
    let deadline = Instant::now() + LISTEN;
    let mut buf = [0u8; 2048];
    while !sockets.is_empty() && Instant::now() < deadline {
        for sock in &sockets {
            let Ok((n, SocketAddr::V4(from))) = sock.recv_from(&mut buf) else { continue };
            let reply = parse_reply(&buf[..n], *from.ip());
            let entry = found.entry(*from.ip()).or_default();
            // A device answers once per service; keep the first of each detail.
            entry.server = entry.server.take().or(reply.server);
            entry.description = entry.description.take().or(reply.description);
        }
    }
    found
}

/// Headers of one SSDP reply sent by `from`. The description is only
/// accepted when it lives on the device that answered, so a reply can't
/// point the scanner at some other machine.
pub fn parse_reply(data: &[u8], from: Ipv4Addr) -> Reply {
    let text = String::from_utf8_lossy(data);
    let header = |name: &str| {
        text.lines().skip(1).take_while(|l| !l.trim().is_empty()).find_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.trim().eq_ignore_ascii_case(name).then(|| v.trim().to_string()).filter(|v| !v.is_empty())
        })
    };
    let server = header("server").map(|s| s.chars().filter(|c| !c.is_control()).take(80).collect());
    let description = header("location").and_then(|url| {
        let rest = url.strip_prefix("http://")?;
        let (authority, path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, "/"),
        };
        let (host, port) = match authority.rsplit_once(':') {
            Some((h, p)) => (h, p.parse::<u16>().ok()?),
            None => (authority, 80),
        };
        let safe_path = path.len() <= 200 && path.bytes().all(|b| b.is_ascii_graphic());
        (host.parse::<Ipv4Addr>().ok()? == from && port != 0 && safe_path).then(|| (port, path.to_string()))
    });
    Reply { server, description }
}

/// "Living Room TV (Samsung Electronics UE55)" from the device description,
/// else the software named in the reply.
pub fn describe(ip: Ipv4Addr, reply: &Reply, timeout: Duration) -> Option<String> {
    reply
        .description
        .as_ref()
        .and_then(|(port, path)| crate::identify::http_get(ip, *port, path, timeout, 32 * 1024))
        .and_then(|response| parse_description(&response))
        .or_else(|| reply.server.clone())
}

/// Friendly name, maker and model from a UPnP device description.
pub fn parse_description(response: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(response);
    let lower = text.to_ascii_lowercase(); // same byte offsets as `text`
    let tag = |name: &str| {
        let start = lower.find(&format!("<{name}>"))? + name.len() + 2;
        let end = start + lower[start..].find(&format!("</{name}>"))?;
        let value = crate::identify::clean_banner(&crate::identify::decode_entities(text.get(start..end)?));
        (!value.is_empty()).then_some(value)
    };
    let name = tag("friendlyname");
    let maker = tag("manufacturer");
    let model = tag("modelname");
    // "Sonos Sonos One" → "Sonos One"
    let model = match (&maker, model) {
        (Some(mk), Some(md)) if md.to_lowercase().starts_with(&mk.to_lowercase()) => Some(md),
        (Some(mk), Some(md)) => Some(format!("{mk} {md}")),
        (mk, md) => md.or(mk.clone()),
    };
    match (name, model) {
        (Some(n), Some(m)) if !n.to_lowercase().contains(&m.to_lowercase()) => Some(format!("{n} ({m})")),
        (Some(n), _) => Some(n),
        (None, m) => m,
    }
    .map(|s| s.chars().take(100).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    const TV: Ipv4Addr = Ipv4Addr::new(10, 20, 0, 60);

    #[test]
    fn parses_replies() {
        let reply = parse_reply(
            b"HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=1800\r\nLocation: http://10.20.0.60:9197/dmr\r\nSERVER: SHP, UPnP/1.0, Samsung UPnP SDK/1.0\r\nST: upnp:rootdevice\r\n\r\n",
            TV,
        );
        assert_eq!(reply.server.as_deref(), Some("SHP, UPnP/1.0, Samsung UPnP SDK/1.0"));
        assert_eq!(reply.description, Some((9197, "/dmr".to_string())));
        assert_eq!(parse_reply(b"HTTP/1.1 200 OK\r\nLOCATION: http://10.20.0.60\r\n\r\n", TV).description, Some((80, "/".to_string())));
    }

    #[test]
    fn description_must_be_on_the_device_that_answered() {
        let location = |url: &str| parse_reply(format!("HTTP/1.1 200 OK\r\nLOCATION: {url}\r\n\r\n").as_bytes(), TV).description;
        for bad in [
            "http://10.20.0.5:80/x",            // another machine
            "http://intranet.corp.example/x",   // a name
            "https://10.20.0.60/x",             // not plain HTTP
            "http://10.20.0.60:0/x",
            "http://10.20.0.60:99999/x",
            "http://10.20.0.60/a b",            // would split the request line
            "http://10.20.0.60/a\tb",
            "file:///etc/passwd",
            "",
        ] {
            assert_eq!(location(bad), None, "{bad:?}");
        }
        // Garbage and binary replies are simply empty.
        assert_eq!(parse_reply(&[0xFF; 300], TV), Reply::default());
        assert_eq!(parse_reply(b"", TV), Reply::default());
    }

    #[test]
    fn describes_devices() {
        let xml = |body: &str| parse_description(format!("HTTP/1.1 200 OK\r\n\r\n<root><device>{body}</device></root>").as_bytes());
        assert_eq!(
            xml("<friendlyName>Living Room TV</friendlyName><manufacturer>Samsung Electronics</manufacturer><modelName>UE55</modelName>").as_deref(),
            Some("Living Room TV (Samsung Electronics UE55)")
        );
        assert_eq!(xml("<manufacturer>Sonos</manufacturer><modelName>Sonos One</modelName>").as_deref(), Some("Sonos One"));
        assert_eq!(xml("<friendlyName>Tom &amp; Ann&#39;s NAS</friendlyName>").as_deref(), Some("Tom & Ann's NAS"));
        assert_eq!(xml("<friendlyName>İstasyon</friendlyName>").as_deref(), Some("İstasyon"));
        for broken in ["", "<friendlyName>", "<friendlyName>never closed", "</friendlyName><friendlyName>"] {
            assert_eq!(xml(broken), None, "{broken:?}");
        }
        assert_eq!(parse_description(&[0xFF, 0xFE, 0x00]), None);
    }

    #[test]
    fn discovery_that_does_not_ask_answers_at_once() {
        let d = Discovery::new();
        d.run(&[], false);
        let started = Instant::now();
        assert_eq!(d.reply(TV), None);
        assert!(started.elapsed() < Duration::from_millis(200));
    }
}
