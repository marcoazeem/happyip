//! SNMP: asks a device for its description, name and location (the
//! "system" group) with a read-only community string. Switches, routers,
//! access points, printers, UPSes and NAS boxes answer when SNMP is enabled
//! on them, also across VLANs, and say exactly what they are.
//!
//! Replies are untrusted and parsed with checked lengths only.

use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use crate::tls::der;

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Info {
    /// sysDescr, e.g. "Cisco IOS Software, C2960 Software ... Version 15.0(2)SE".
    pub description: Option<String>,
    /// sysName, the name the administrator gave the device.
    pub name: Option<String>,
    /// sysLocation, e.g. "Server room, rack 2".
    pub location: Option<String>,
}

const SYS_DESCR: &[u8] = &[0x2B, 6, 1, 2, 1, 1, 1, 0];
const SYS_NAME: &[u8] = &[0x2B, 6, 1, 2, 1, 1, 5, 0];
const SYS_LOCATION: &[u8] = &[0x2B, 6, 1, 2, 1, 1, 6, 0];

/// Longest community string accepted.
pub const MAX_COMMUNITY: usize = 64;

/// Ask `ip` with `community`. `None` when it doesn't answer (SNMP off, a
/// different community, or filtered).
pub fn query(ip: Ipv4Addr, community: &str, timeout: Duration) -> Option<Info> {
    if community.is_empty() || community.len() > MAX_COMMUNITY {
        return None;
    }
    let sock = UdpSocket::bind("0.0.0.0:0").ok()?;
    let to = SocketAddr::from((ip, 161));
    let id = 0x1000 | (u32::from(ip) as u16 & 0x0FFF);
    // Newer devices speak v2c, some old printers only v1: ask both ways
    // and take whichever answers.
    sock.send_to(&request(1, community, id), to).ok()?;
    sock.send_to(&request(0, community, id + 0x1000), to).ok()?;

    let deadline = Instant::now() + timeout;
    let mut buf = [0u8; 2048];
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return None;
        }
        sock.set_read_timeout(Some(left)).ok()?;
        let (n, from) = sock.recv_from(&mut buf).ok()?;
        if from.ip() != ip {
            continue;
        }
        if let Some(info) = parse(&buf[..n], &[id, id + 0x1000]) {
            return Some(info);
        }
    }
}

/// One BER element.
fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    match content.len() {
        n if n < 0x80 => out.push(n as u8),
        n if n < 0x100 => out.extend_from_slice(&[0x81, n as u8]),
        n => out.extend_from_slice(&[0x82, (n >> 8) as u8, n as u8]),
    }
    out.extend_from_slice(content);
    out
}

/// A non-negative integer below 32768.
fn int(n: u16) -> Vec<u8> {
    if n < 0x80 { tlv(2, &[n as u8]) } else { tlv(2, &n.to_be_bytes()) }
}

/// A GET for the description, name and location. `version` 0 is SNMPv1, 1 is v2c.
fn request(version: u8, community: &str, id: u16) -> Vec<u8> {
    let bind = |oid: &[u8]| tlv(0x30, &[tlv(6, oid), tlv(5, &[])].concat());
    let bindings = tlv(0x30, &[bind(SYS_DESCR), bind(SYS_NAME), bind(SYS_LOCATION)].concat());
    let pdu = tlv(0xA0, &[int(id & 0x7FFF), int(0), int(0), bindings].concat());
    tlv(0x30, &[tlv(2, &[version]), tlv(4, community.as_bytes()), pdu].concat())
}

/// The answers in a GET response to one of our requests (`ids`).
pub fn parse(packet: &[u8], ids: &[u16]) -> Option<Info> {
    let (0x30, message, _) = der(packet)? else { return None };
    let (2, _version, rest) = der(message)? else { return None };
    let (4, _community, rest) = der(rest)? else { return None };
    let (0xA2, pdu, _) = der(rest)? else { return None };
    let (2, id, rest) = der(pdu)? else { return None };
    let id = id.iter().fold(0u32, |acc, b| acc << 8 | *b as u32);
    if id > 0xFFFF || !ids.iter().any(|want| u32::from(want & 0x7FFF) == id) {
        return None;
    }
    let (2, _error, rest) = der(rest)? else { return None };
    let (2, _index, rest) = der(rest)? else { return None };
    let (0x30, mut bindings, _) = der(rest)? else { return None };

    let mut info = Info::default();
    while let Some((_, binding, rest)) = der(bindings) {
        bindings = rest;
        let Some((6, oid, value)) = der(binding) else { continue };
        // Only text counts; "no such object" and friends have other tags.
        let Some((4, text, _)) = der(value) else { continue };
        let text = clean(text);
        match oid {
            o if o == SYS_DESCR => info.description = text,
            o if o == SYS_NAME => info.name = text,
            o if o == SYS_LOCATION => info.location = text,
            _ => {}
        }
    }
    (info != Info::default()).then_some(info)
}

/// One line of printable text, at most 160 characters.
fn clean(bytes: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(bytes);
    let text: String = text.chars().map(|c| if c.is_control() { ' ' } else { c }).collect();
    let text: String = text.split_whitespace().collect::<Vec<_>>().join(" ").chars().take(160).collect();
    (!text.is_empty()).then_some(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response(id: u16, values: &[(&[u8], Vec<u8>)]) -> Vec<u8> {
        let bindings: Vec<u8> = values.iter().flat_map(|(oid, value)| tlv(0x30, &[tlv(6, oid), value.clone()].concat())).collect();
        let pdu = tlv(0xA2, &[int(id), int(0), int(0), tlv(0x30, &bindings)].concat());
        tlv(0x30, &[tlv(2, &[1]), tlv(4, b"public"), pdu].concat())
    }

    #[test]
    fn reads_the_system_group() {
        let long = "Cisco IOS Software, C2960 Software (C2960-LANBASEK9-M),\r\nVersion 15.0(2)SE11, RELEASE SOFTWARE (fc3)";
        let packet = response(
            0x1005,
            &[(SYS_DESCR, tlv(4, long.as_bytes())), (SYS_NAME, tlv(4, b"sw-core-01")), (SYS_LOCATION, tlv(4, b"Server room, rack 2"))],
        );
        let info = parse(&packet, &[0x1005, 0x2005]).unwrap();
        assert_eq!(info.description.as_deref(), Some("Cisco IOS Software, C2960 Software (C2960-LANBASEK9-M), Version 15.0(2)SE11, RELEASE SOFTWARE (fc3)"));
        assert_eq!(info.name.as_deref(), Some("sw-core-01"));
        assert_eq!(info.location.as_deref(), Some("Server room, rack 2"));
    }

    #[test]
    fn ignores_replies_that_are_not_ours_or_hold_no_text() {
        let packet = response(0x1005, &[(SYS_NAME, tlv(4, b"sw-core-01"))]);
        assert_eq!(parse(&packet, &[0x1006]), None);
        // v1 "noSuchName" style answers and empty strings carry nothing.
        let packet = response(0x1005, &[(SYS_DESCR, tlv(0x80, &[])), (SYS_NAME, tlv(4, b"")), (SYS_LOCATION, tlv(5, &[]))]);
        assert_eq!(parse(&packet, &[0x1005]), None);
        // A request echoed back (tag A0, not A2) is not a response.
        assert_eq!(parse(&request(1, "public", 0x1005), &[0x1005]), None);
    }

    #[test]
    fn damaged_replies_never_panic() {
        let packet = response(0x1005, &[(SYS_DESCR, tlv(4, &[0xFF; 300])), (SYS_NAME, tlv(4, b"x"))]);
        for len in 0..packet.len() {
            assert_eq!(parse(&packet[..len], &[0x1005]), None, "{len}");
        }
        let mut bad = packet.clone();
        for i in 0..bad.len() {
            bad[i] ^= 0xFF;
            let _ = parse(&bad, &[0x1005]);
            bad[i] ^= 0xFF;
        }
        assert_eq!(parse(&packet, &[0x1005]).unwrap().description.map(|d| d.chars().count()), Some(160));
    }

    #[test]
    fn request_is_valid_ber() {
        let community = "c".repeat(MAX_COMMUNITY);
        for version in [0, 1] {
            let req = request(version, &community, 0x1ABC);
            let (0x30, message, rest) = der(&req).unwrap() else { panic!() };
            assert!(rest.is_empty());
            let (2, v, rest) = der(message).unwrap() else { panic!() };
            assert_eq!(v, [version]);
            let (4, c, rest) = der(rest).unwrap() else { panic!() };
            assert_eq!(c, community.as_bytes());
            let (0xA0, pdu, rest) = der(rest).unwrap() else { panic!() };
            assert!(rest.is_empty());
            let (2, id, _) = der(pdu).unwrap() else { panic!() };
            assert_eq!(id, [0x1A, 0xBC]);
        }
        assert!(query(Ipv4Addr::LOCALHOST, "", Duration::from_millis(10)).is_none());
    }
}
