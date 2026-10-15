//! NetBIOS node status (NBSTAT) queries over UDP 137, plus OS-level session
//! queries. This is how scanners like Angry IP find a computer's name,
//! workgroup, logged-in user and (for Windows hosts) MAC address remotely.

use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::time::Duration;

#[derive(Clone, Debug, Default)]
pub struct NetBiosInfo {
    pub computer: Option<String>,
    pub workgroup: Option<String>,
    pub users: Vec<String>,
    pub mac: Option<String>,
}

pub fn query(ip: Ipv4Addr, timeout: Duration) -> Option<NetBiosInfo> {
    let sock = UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.set_read_timeout(Some(timeout)).ok()?;
    let txid = (u32::from(ip) as u16) ^ 0x5A5A;
    sock.send_to(&request(txid), SocketAddr::from((ip, 137))).ok()?;

    let mut buf = [0u8; 2048];
    loop {
        let (n, from) = sock.recv_from(&mut buf).ok()?;
        if from.ip() == ip && n >= 2 && u16::from_be_bytes([buf[0], buf[1]]) == txid {
            return parse_response(&buf[..n]);
        }
    }
}

fn request(txid: u16) -> Vec<u8> {
    let mut p = Vec::with_capacity(50);
    p.extend_from_slice(&txid.to_be_bytes());
    p.extend_from_slice(&[0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    // Wildcard name "*" padded with NULs, first-level encoded (RFC 1002).
    p.push(0x20);
    let mut name = [0u8; 16];
    name[0] = b'*';
    for b in name {
        p.push(b'A' + (b >> 4));
        p.push(b'A' + (b & 0x0F));
    }
    p.push(0x00);
    p.extend_from_slice(&[0x00, 0x21, 0x00, 0x01]); // type NBSTAT, class IN
    p
}

fn parse_response(d: &[u8]) -> Option<NetBiosInfo> {
    if d.len() < 12 || u16::from_be_bytes([d[6], d[7]]) == 0 {
        return None;
    }
    // Skip the answer's name (labels or a compression pointer).
    let mut i = 12;
    loop {
        let len = *d.get(i)? as usize;
        if len == 0 {
            i += 1;
            break;
        }
        if len & 0xC0 == 0xC0 {
            i += 2;
            break;
        }
        i += 1 + len;
    }
    i += 2 + 2 + 4 + 2; // type, class, ttl, rdlength
    let count = *d.get(i)? as usize;
    i += 1;

    let mut info = NetBiosInfo::default();
    let mut user_candidates = Vec::new();
    for _ in 0..count {
        let entry = d.get(i..i + 18)?;
        i += 18;
        let name = String::from_utf8_lossy(&entry[..15]).trim_end().to_string();
        let suffix = entry[15];
        let group = entry[16] & 0x80 != 0;
        match (suffix, group) {
            (0x00, false) if info.computer.is_none() => info.computer = Some(name),
            (0x00, true) if info.workgroup.is_none() => info.workgroup = Some(name),
            (0x03, false) => user_candidates.push(name),
            _ => {}
        }
    }
    // <03> (messenger) names include the computer name itself; anything else
    // registered there is a logged-in user.
    for u in user_candidates {
        let is_machine = info.computer.as_deref().is_some_and(|c| c.eq_ignore_ascii_case(&u))
            || info.workgroup.as_deref().is_some_and(|w| w.eq_ignore_ascii_case(&u))
            || u.ends_with('$');
        if !is_machine && !u.is_empty() && !info.users.contains(&u) {
            info.users.push(u);
        }
    }
    if let Some(unit) = d.get(i..i + 6) {
        let bytes: [u8; 6] = unit.try_into().ok()?;
        info.mac = crate::probe::normalize_mac(&crate::probe::format_mac(&bytes));
    }
    Some(info)
}

/// Users with an interactive session on this machine.
pub fn local_users() -> Vec<String> {
    #[cfg(windows)]
    {
        let mut users = query_user_output(&[]);
        if users.is_empty() {
            users.extend(std::env::var("USERNAME").ok());
        }
        users
    }
    #[cfg(not(windows))]
    {
        let mut users: Vec<String> = crate::probe::run_hidden("who", &[])
            .map(|o| {
                String::from_utf8_lossy(&o.stdout)
                    .lines()
                    .filter_map(|l| l.split_whitespace().next().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        users.sort();
        users.dedup();
        users
    }
}

/// Sessions on a remote Windows machine via `query user /server:<ip>`.
/// Requires the scanning account to have rights on the target (typically a
/// domain admin) and the Pro/Enterprise `query.exe` tool. Returns empty
/// elsewhere.
pub fn remote_sessions(ip: Ipv4Addr) -> Vec<String> {
    #[cfg(windows)]
    {
        query_user_output(&[&format!("/server:{ip}")])
    }
    #[cfg(not(windows))]
    {
        let _ = ip;
        Vec::new()
    }
}

#[cfg(windows)]
fn query_user_output(extra: &[&str]) -> Vec<String> {
    let mut args = vec!["user"];
    args.extend_from_slice(extra);
    let Some(out) = crate::probe::run_hidden("query", &args) else {
        return Vec::new();
    };
    let mut users: Vec<String> = String::from_utf8_lossy(&out.stdout)
        .lines()
        .skip(1) // header row
        .filter_map(|l| l.trim_start_matches('>').split_whitespace().next().map(str::to_string))
        .collect();
    users.sort();
    users.dedup();
    users
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(name: &str, suffix: u8, group: bool) -> Vec<u8> {
        let mut e = format!("{name:<15}").into_bytes();
        e.push(suffix);
        e.extend_from_slice(&[if group { 0x84 } else { 0x04 }, 0x00]);
        e
    }

    #[test]
    fn parses_node_status() {
        let mut d = vec![0x12, 0x34, 0x84, 0x00, 0, 0, 0, 1, 0, 0, 0, 0];
        d.push(0x20);
        d.extend(std::iter::repeat_n(b'A', 32));
        d.extend_from_slice(&[0, 0, 0x21, 0, 1, 0, 0, 0, 0, 0, 0]);
        d.push(5);
        d.extend(entry("DESKTOP-1", 0x00, false));
        d.extend(entry("WORKGROUP", 0x00, true));
        d.extend(entry("DESKTOP-1", 0x03, false));
        d.extend(entry("ALICE", 0x03, false));
        d.extend(entry("DESKTOP-1", 0x20, false));
        d.extend_from_slice(&[0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E]);
        let info = parse_response(&d).unwrap();
        assert_eq!(info.computer.as_deref(), Some("DESKTOP-1"));
        assert_eq!(info.workgroup.as_deref(), Some("WORKGROUP"));
        assert_eq!(info.users, vec!["ALICE".to_string()]);
        assert_eq!(info.mac.as_deref(), Some("00:1A:2B:3C:4D:5E"));
    }

    #[test]
    fn request_shape() {
        let r = request(1);
        assert_eq!(r.len(), 50);
        assert_eq!(&r[13..15], b"CK"); // '*' = 0x2A -> 'C','K'
    }
}
