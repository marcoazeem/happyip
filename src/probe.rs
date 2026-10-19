//! Host probes: ICMP ping (via the system `ping` binary, so no admin rights
//! are needed), TCP port checks, and the ARP table for MAC addresses.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::process::{Command, Output};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Run a command without flashing a console window on Windows.
pub fn run_hidden(program: &str, args: &[&str]) -> Option<Output> {
    hidden_command(program, args).output().ok()
}

fn hidden_command(program: &str, args: &[&str]) -> Command {
    let mut cmd = Command::new(program);
    cmd.args(args);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    cmd
}

/// Like [`run_hidden`], but kills the process if it runs past `timeout`
/// (remote management calls can hang for a long time on unreachable hosts).
/// Returns stdout only when the process exited successfully in time.
pub fn run_hidden_timeout(program: &str, args: &[&str], timeout: Duration) -> Option<String> {
    use std::io::Read;
    use std::process::Stdio;
    let mut child = hidden_command(program, args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    // Drain stdout on a thread so a chatty process can't block on a full pipe.
    let mut stdout = child.stdout.take()?;
    let reader = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stdout.read_to_end(&mut buf);
        buf
    });
    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(50)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
        }
    };
    let out = reader.join().ok()?;
    status.filter(|s| s.success()).map(|_| String::from_utf8_lossy(&out).into_owned())
}

#[derive(Clone, Copy, Debug)]
pub struct PingReply {
    /// Round-trip time in milliseconds; 0.0 means "<1 ms" (Windows).
    pub rtt_ms: f64,
    pub ttl: Option<u32>,
}

pub fn ping(ip: Ipv4Addr, timeout_ms: u64) -> Option<PingReply> {
    let ip_s = ip.to_string();
    let timeout = timeout_ms.max(100).to_string();

    #[cfg(windows)]
    let out = run_hidden("ping", &["-n", "1", "-w", &timeout, &ip_s])?;
    #[cfg(target_os = "macos")]
    let out = {
        // -W is the reply wait in ms; -t is an overall cap in seconds.
        let secs = timeout_ms.div_ceil(1000).max(1).to_string();
        run_hidden("/sbin/ping", &["-n", "-c", "1", "-W", &timeout, "-t", &secs, &ip_s])?
    };
    #[cfg(not(any(windows, target_os = "macos")))]
    let out = {
        let secs = (timeout_ms / 1000).max(1).to_string();
        run_hidden("ping", &["-n", "-c", "1", "-W", &secs, &ip_s])?
    };

    let text = String::from_utf8_lossy(&out.stdout).to_lowercase();
    // Windows exits 0 for "destination host unreachable" replies from the
    // gateway, so require a TTL in the output rather than trusting the code.
    // The reply must also come from the address we pinged: routers and
    // firewalls can answer on its behalf ("Reply from 10.0.0.1: ...").
    let text = reply_line(&text, ip)?;
    let ttl = number_after(text, "ttl=").map(|v| v as u32);
    if ttl.is_none() {
        return None;
    }
    let rtt_ms = if text.contains("time<") {
        0.0
    } else {
        number_after(&text, "time=").unwrap_or(0.0)
    };
    Some(PingReply { rtt_ms, ttl })
}

/// The line of `ping` output that is a reply from `ip` itself, e.g.
/// `reply from 10.0.0.5: bytes=32 time<1ms ttl=128` (Windows; French puts a
/// space before the colon) or `64 bytes from 10.0.0.5: icmp_seq=0 ttl=64`.
fn reply_line(text: &str, ip: Ipv4Addr) -> Option<&str> {
    let ip = ip.to_string();
    text.lines().find(|l| {
        l.contains("ttl=")
            && l.match_indices(&ip).any(|(i, _)| {
                let before = l[..i].chars().next_back();
                let after = l[i + ip.len()..].trim_start_matches(' ');
                // The whole address (10.0.0.5, not part of 10.0.0.15), then ':'.
                !before.is_some_and(|c| c.is_ascii_digit() || c == '.') && after.starts_with(':')
            })
    })
}

fn number_after(text: &str, key: &str) -> Option<f64> {
    let start = text.find(key)? + key.len();
    let num: String = text[start..]
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.')
        .collect();
    num.parse().ok()
}

pub enum PortState {
    Open,
    /// Connection actively refused: the port is closed but the host is up.
    Refused,
    NoAnswer,
}

pub fn probe_port(ip: Ipv4Addr, port: u16, timeout: Duration) -> PortState {
    let addr = SocketAddr::new(IpAddr::V4(ip), port);
    match TcpStream::connect_timeout(&addr, timeout) {
        Ok(_) => PortState::Open,
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => PortState::Refused,
        Err(_) => PortState::NoAnswer,
    }
}

/// Probe ports in parallel. Returns (open ports, whether the host answered at all).
pub fn probe_ports(ip: Ipv4Addr, ports: &[u16], timeout: Duration) -> (Vec<u16>, bool) {
    let states: Vec<(u16, PortState)> = std::thread::scope(|s| {
        let handles: Vec<_> = ports
            .iter()
            .map(|&p| s.spawn(move || (p, probe_port(ip, p, timeout))))
            .collect();
        handles.into_iter().filter_map(|h| h.join().ok()).collect()
    });
    let answered = states.iter().any(|(_, s)| !matches!(s, PortState::NoAnswer));
    let open = states
        .into_iter()
        .filter(|(_, s)| matches!(s, PortState::Open))
        .map(|(p, _)| p)
        .collect();
    (open, answered)
}

/// Shared snapshot of the OS ARP table, refreshed at most every 500 ms.
pub struct ArpCache {
    inner: Mutex<(HashMap<Ipv4Addr, String>, Option<Instant>)>,
}

impl ArpCache {
    pub fn new() -> Self {
        Self { inner: Mutex::new((HashMap::new(), None)) }
    }

    pub fn lookup(&self, ip: Ipv4Addr) -> Option<String> {
        let mut guard = self.inner.lock().unwrap();
        if let Some(mac) = guard.0.get(&ip) {
            return Some(mac.clone());
        }
        let stale = guard.1.is_none_or(|t| t.elapsed() > Duration::from_millis(500));
        if stale {
            guard.0 = read_arp_table();
            guard.1 = Some(Instant::now());
        }
        guard.0.get(&ip).cloned()
    }
}

fn read_arp_table() -> HashMap<Ipv4Addr, String> {
    #[cfg(windows)]
    let out = run_hidden("arp", &["-a"]);
    #[cfg(not(windows))]
    let out = run_hidden("/usr/sbin/arp", &["-an"]).or_else(|| run_hidden("arp", &["-an"]));
    out.map(|o| parse_arp(&String::from_utf8_lossy(&o.stdout))).unwrap_or_default()
}

/// Parses both macOS/Linux (`? (1.2.3.4) at a:b:c:d:e:f on en0`) and
/// Windows (`  1.2.3.4   aa-bb-cc-dd-ee-ff   dynamic`) formats.
pub fn parse_arp(text: &str) -> HashMap<Ipv4Addr, String> {
    let mut map = HashMap::new();
    for line in text.lines() {
        let mut ip = None;
        let mut mac = None;
        for tok in line.split_whitespace() {
            let tok = tok.trim_matches(|c| c == '(' || c == ')');
            if ip.is_none() {
                if let Ok(a) = tok.parse::<Ipv4Addr>() {
                    ip = Some(a);
                    continue;
                }
            }
            if mac.is_none() {
                mac = normalize_mac(tok);
            }
        }
        if let (Some(ip), Some(mac)) = (ip, mac) {
            map.insert(ip, mac);
        }
    }
    map
}

/// Normalize `0:1a:2b:3:4:5` or `00-1A-2B-03-04-05` to `00:1A:2B:03:04:05`.
/// Returns None for anything that isn't a real unicast-looking MAC.
pub fn normalize_mac(s: &str) -> Option<String> {
    let parts: Vec<&str> = s.split([':', '-']).collect();
    if parts.len() != 6 {
        return None;
    }
    let mut bytes = [0u8; 6];
    for (b, p) in bytes.iter_mut().zip(&parts) {
        if p.is_empty() || p.len() > 2 {
            return None;
        }
        *b = u8::from_str_radix(p, 16).ok()?;
    }
    // Empty, broadcast, multicast, or the 02:00:00:00:00:00 placeholder
    // newer macOS reports when it hides real hardware addresses.
    if bytes == [0; 6] || bytes == [0xFF; 6] || bytes[0] & 1 == 1 || bytes == [2, 0, 0, 0, 0, 0] {
        return None;
    }
    Some(format_mac(&bytes))
}

pub fn format_mac(b: &[u8; 6]) -> String {
    b.iter().map(|x| format!("{x:02X}")).collect::<Vec<_>>().join(":")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ping_reply_must_come_from_target() {
        let ip: Ipv4Addr = "10.0.0.5".parse().unwrap();
        let ok = |t: &str| reply_line(t, ip).is_some();
        assert!(ok("reply from 10.0.0.5: bytes=32 time<1ms ttl=128"));
        assert!(ok("réponse de 10.0.0.5 : octets=32 temps<1ms ttl=128"));
        assert!(ok("64 bytes from 10.0.0.5: icmp_seq=0 ttl=64 time=1.2 ms"));
        assert!(!ok("reply from 10.0.0.1: bytes=32 time=1ms ttl=255"));
        assert!(!ok("reply from 10.0.0.55: bytes=32 time=1ms ttl=128"));
        assert!(!ok("reply from 110.0.0.5: bytes=32 time=1ms ttl=128"));
        assert!(!ok("reply from 10.0.0.1: destination host unreachable."));
    }

    #[test]
    fn arp_formats() {
        let mac = "? (192.168.1.1) at 0:1a:2b:3c:4d:5e on en0 ifscope [ethernet]\n\
                   ? (192.168.1.9) at (incomplete) on en0 ifscope [ethernet]\n\
                   ? (224.0.0.251) at 1:0:5e:0:0:fb on en0 ifscope permanent [ethernet]";
        let m = parse_arp(mac);
        assert_eq!(m.get(&"192.168.1.1".parse().unwrap()).unwrap(), "00:1A:2B:3C:4D:5E");
        assert_eq!(m.len(), 1);

        let win = "Interface: 192.168.1.5 --- 0xb\n  Internet Address      Physical Address      Type\n  \
                   192.168.1.1           aa-bb-cc-dd-ee-ff     dynamic\n  \
                   192.168.1.255         ff-ff-ff-ff-ff-ff     static";
        let m = parse_arp(win);
        assert_eq!(m.get(&"192.168.1.1".parse().unwrap()).unwrap(), "AA:BB:CC:DD:EE:FF");
        assert_eq!(m.len(), 1);
    }

    #[test]
    fn ping_parsing() {
        assert_eq!(number_after("64 bytes: ttl=64 time=3.21 ms", "time="), Some(3.21));
        assert_eq!(number_after("reply from x: bytes=32 time<1ms ttl=128", "ttl="), Some(128.0));
    }
}
