//! Reads the name on a device's HTTPS certificate without a TLS library:
//! send a TLS 1.2 hello, and the server answers with its certificate in the
//! clear. Printers, NAS boxes, routers and management cards usually put
//! their model or host name there.
//!
//! Everything received is untrusted: every length is checked before use.

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::time::Duration;

/// Stop reading a handshake after this much (certificate chains are a few KB).
const MAX_HANDSHAKE: usize = 64 * 1024;

/// The most telling name on the certificate served at `ip:port`: its common
/// name, else its first DNS name, else the organization.
pub fn certificate_name(ip: Ipv4Addr, port: u16, timeout: Duration) -> Option<String> {
    let mut stream = TcpStream::connect_timeout(&SocketAddr::new(IpAddr::V4(ip), port), timeout).ok()?;
    stream.set_read_timeout(Some(timeout)).ok()?;
    stream.set_write_timeout(Some(timeout)).ok()?;
    stream.write_all(&client_hello(ip)).ok()?;

    let mut records = Vec::new();
    let mut chunk = [0u8; 4096];
    while records.len() < MAX_HANDSHAKE {
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => records.extend_from_slice(&chunk[..n]),
        }
        match first_certificate(&handshake_bytes(&records)) {
            Scan::Found(cert) => return name_on_certificate(&cert, ip),
            Scan::NoCertificate => return None,
            Scan::NeedMore => {}
        }
    }
    None
}

/// A TLS 1.2 ClientHello offering the usual RSA and ECDSA cipher suites.
fn client_hello(ip: Ipv4Addr) -> Vec<u8> {
    // The "random" only has to differ between connections; nothing here is
    // secret, since the handshake is abandoned once the certificate arrives.
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
    let mut seed = (nanos as u64) ^ (u64::from(u32::from(ip)) << 32) | 1;
    let mut random = [0u8; 32];
    for b in &mut random {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        *b = seed as u8;
    }
    const SUITES: [u16; 16] = [
        0xC02F, 0xC030, 0xC02B, 0xC02C, 0xCCA8, 0xCCA9, 0xC013, 0xC014, 0xC009, 0xC00A, 0x009C, 0x009D, 0x002F, 0x0035, 0x000A, 0x00FF,
    ];
    let mut body = vec![0x03, 0x03]; // TLS 1.2
    body.extend_from_slice(&random);
    body.push(0); // no session id
    body.extend_from_slice(&((SUITES.len() * 2) as u16).to_be_bytes());
    for s in SUITES {
        body.extend_from_slice(&s.to_be_bytes());
    }
    body.extend_from_slice(&[1, 0]); // no compression
    let extensions: &[u8] = &[
        0x00, 0x0A, 0x00, 0x08, 0x00, 0x06, 0x00, 0x1D, 0x00, 0x17, 0x00, 0x18, // curves: x25519, P-256, P-384
        0x00, 0x0B, 0x00, 0x02, 0x01, 0x00, // uncompressed points
        0x00, 0x0D, 0x00, 0x14, 0x00, 0x12, // signature algorithms
        0x04, 0x03, 0x05, 0x03, 0x06, 0x03, 0x08, 0x04, 0x08, 0x05, 0x08, 0x06, 0x04, 0x01, 0x05, 0x01, 0x02, 0x01,
    ];
    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(extensions);

    let mut hello = vec![0x16, 0x03, 0x01]; // handshake record
    hello.extend_from_slice(&((body.len() + 4) as u16).to_be_bytes());
    hello.push(0x01); // ClientHello
    hello.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    hello.extend_from_slice(&body);
    hello
}

/// The handshake messages carried by the complete TLS records in `data`.
fn handshake_bytes(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut rest = data;
    while let [kind, _, _, hi, lo, tail @ ..] = rest {
        let len = u16::from_be_bytes([*hi, *lo]) as usize;
        let Some(payload) = tail.get(..len) else { break };
        if *kind != 0x16 {
            break; // an alert, or the encrypted part of a newer handshake
        }
        out.extend_from_slice(payload);
        rest = &tail[len..];
    }
    out
}

#[derive(Debug, PartialEq)]
enum Scan {
    Found(Vec<u8>),
    /// The server finished its hello without a readable certificate.
    NoCertificate,
    NeedMore,
}

/// The server's own certificate (the first in its Certificate message).
fn first_certificate(handshake: &[u8]) -> Scan {
    let mut rest = handshake;
    while let [kind, a, b, c, tail @ ..] = rest {
        let len = u32::from_be_bytes([0, *a, *b, *c]) as usize;
        let Some(body) = tail.get(..len) else { return Scan::NeedMore };
        match kind {
            // Certificate: 3-byte list length, then 3-byte length + DER per certificate.
            11 => {
                let cert = body.get(3..6).and_then(|l| body.get(6..6 + u32::from_be_bytes([0, l[0], l[1], l[2]]) as usize));
                return cert.map_or(Scan::NoCertificate, |c| Scan::Found(c.to_vec()));
            }
            14 => return Scan::NoCertificate, // ServerHelloDone
            _ => rest = &tail[len..],
        }
    }
    // Only a handshake that has started can still deliver a certificate.
    if handshake.is_empty() || handshake[0] == 2 { Scan::NeedMore } else { Scan::NoCertificate }
}

/// One DER element: (tag, contents, what follows it).
pub fn der(data: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = data.split_first()?;
    let (&first, rest) = rest.split_first()?;
    let (len, rest) = if first < 0x80 {
        (first as usize, rest)
    } else {
        let n = (first & 0x7F) as usize;
        if n == 0 || n > 4 {
            return None;
        }
        let bytes = rest.get(..n)?;
        (bytes.iter().fold(0usize, |acc, b| acc << 8 | *b as usize), &rest[n..])
    };
    Some((tag, rest.get(..len)?, &rest[len..]))
}

const SEQUENCE: u8 = 0x30;
const SET: u8 = 0x31;
const OID: u8 = 0x06;
const OID_COMMON_NAME: &[u8] = &[0x55, 0x04, 0x03];
const OID_ORGANIZATION: &[u8] = &[0x55, 0x04, 0x0A];
const OID_SUBJECT_ALT_NAME: &[u8] = &[0x55, 0x1D, 0x11];

/// The value of attribute `oid` in an X.501 name (a sequence of sets of
/// OID/value pairs).
fn name_attribute(mut name: &[u8], oid: &[u8]) -> Option<String> {
    while let Some((tag, set, rest)) = der(name) {
        name = rest;
        if tag != SET {
            continue;
        }
        let mut pairs = set;
        while let Some((_, pair, more)) = der(pairs) {
            pairs = more;
            let Some((OID, id, value)) = der(pair) else { continue };
            if id == oid {
                let (_, text, _) = der(value)?;
                return Some(String::from_utf8_lossy(text).into_owned());
            }
        }
    }
    None
}

/// The first DNS name in the certificate's subjectAltName extension.
fn first_dns_name(mut extensions: &[u8]) -> Option<String> {
    while let Some((_, ext, rest)) = der(extensions) {
        extensions = rest;
        let Some((OID, id, mut value)) = der(ext) else { continue };
        if id != OID_SUBJECT_ALT_NAME {
            continue;
        }
        // Optional "critical" flag, then the names wrapped in an octet string.
        let mut names = loop {
            let (tag, content, rest) = der(value)?;
            if tag == 0x04 {
                break der(content)?.1;
            }
            value = rest;
        };
        while let Some((tag, name, rest)) = der(names) {
            names = rest;
            if tag == 0x82 {
                return Some(String::from_utf8_lossy(name).into_owned());
            }
        }
    }
    None
}

/// Pick the name that says most about the device. A name that is just the
/// address tells nothing new.
fn name_on_certificate(cert: &[u8], ip: Ipv4Addr) -> Option<String> {
    let (SEQUENCE, cert, _) = der(cert)? else { return None };
    let (SEQUENCE, mut tbs, _) = der(cert)? else { return None };
    // version [0], serial, signature algorithm, issuer, validity, subject, key, extensions [3]
    let mut sequences = Vec::new();
    let mut extensions = None;
    while let Some((tag, content, rest)) = der(tbs) {
        tbs = rest;
        match tag {
            SEQUENCE => sequences.push(content),
            0xA3 => extensions = der(content).map(|(_, list, _)| list),
            _ => {}
        }
    }
    // Sequences in order: algorithm, issuer, validity, subject, public key.
    let subject = *sequences.get(3)?;
    let useful = |s: String| {
        let s: String = s.chars().filter(|c| !c.is_control()).collect::<String>().trim().chars().take(80).collect();
        (!s.is_empty() && s != ip.to_string() && !s.eq_ignore_ascii_case("localhost")).then_some(s)
    };
    name_attribute(subject, OID_COMMON_NAME)
        .and_then(useful)
        .or_else(|| extensions.and_then(first_dns_name).and_then(useful))
        .or_else(|| name_attribute(subject, OID_ORGANIZATION).and_then(useful))
}

#[cfg(test)]
mod tests {
    use super::*;

    const WITH_CN: &[u8] = include_bytes!("../tests/data/cert-with-cn.der");
    const SAN_ONLY: &[u8] = include_bytes!("../tests/data/cert-san-only.der");
    const IP: Ipv4Addr = Ipv4Addr::new(10, 20, 0, 31);

    #[test]
    fn reads_names_from_certificates() {
        assert_eq!(name_on_certificate(WITH_CN, IP).as_deref(), Some("HP LaserJet M404dn"));
        // No common name: the DNS name beats the organization.
        assert_eq!(name_on_certificate(SAN_ONLY, IP).as_deref(), Some("nas.corp.example"));
    }

    #[test]
    fn damaged_certificates_never_panic() {
        for len in 0..WITH_CN.len() {
            let _ = name_on_certificate(&WITH_CN[..len], IP);
        }
        // Flip every byte in turn: lengths and tags become nonsense.
        let mut cert = WITH_CN.to_vec();
        for i in 0..cert.len() {
            cert[i] ^= 0xFF;
            let _ = name_on_certificate(&cert, IP);
            cert[i] ^= 0xFF;
        }
        assert_eq!(name_on_certificate(&[0x30, 0x84, 0xFF, 0xFF, 0xFF, 0xFF], IP), None);
        assert_eq!(der(&[0x30, 0x85, 1, 1, 1, 1, 1]), None);
    }

    /// A server's answer: ServerHello, Certificate (in two records) and ServerHelloDone.
    fn server_flight(cert: &[u8]) -> Vec<u8> {
        let message = |kind: u8, body: &[u8]| {
            let mut m = vec![kind];
            m.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
            m.extend_from_slice(body);
            m
        };
        let len3 = |n: usize| (n as u32).to_be_bytes()[1..].to_vec();
        let mut certs = len3(cert.len() + 3);
        certs.extend(len3(cert.len()));
        certs.extend_from_slice(cert);
        let mut handshake = message(2, &[0u8; 40]);
        handshake.extend(message(11, &certs));
        handshake.extend(message(14, &[]));
        let mut out = Vec::new();
        for part in handshake.chunks(200) {
            out.extend_from_slice(&[0x16, 0x03, 0x03]);
            out.extend_from_slice(&(part.len() as u16).to_be_bytes());
            out.extend_from_slice(part);
        }
        out
    }

    #[test]
    fn finds_the_certificate_in_a_handshake() {
        let flight = server_flight(WITH_CN);
        assert_eq!(first_certificate(&handshake_bytes(&flight)), Scan::Found(WITH_CN.to_vec()));
        // While it is still arriving, keep reading; never panic on a prefix.
        for len in 0..flight.len() - 9 {
            assert_eq!(first_certificate(&handshake_bytes(&flight[..len])), Scan::NeedMore, "{len} bytes");
        }
        // An alert (handshake refused) or junk ends it at once.
        assert_eq!(first_certificate(&handshake_bytes(&[0x15, 3, 3, 0, 2, 2, 40])), Scan::NeedMore);
        assert!(handshake_bytes(b"HTTP/1.1 400 Bad Request").is_empty());
        let no_cert = [0x16, 3, 3, 0, 4, 14, 0, 0, 0];
        assert_eq!(first_certificate(&handshake_bytes(&no_cert)), Scan::NoCertificate);
    }

    /// Against a real TLS server: `openssl s_server -accept 44330 -cert … -key …`,
    /// then `HAPPYIP_TLS_TEST_PORT=44330 cargo test live_handshake -- --ignored`.
    #[test]
    #[ignore = "needs a local TLS server"]
    fn live_handshake() {
        let port: u16 = std::env::var("HAPPYIP_TLS_TEST_PORT").expect("HAPPYIP_TLS_TEST_PORT").parse().unwrap();
        let name = certificate_name(Ipv4Addr::LOCALHOST, port, Duration::from_secs(2));
        assert_eq!(name.as_deref(), Some("HP LaserJet M404dn"));
    }

    #[test]
    fn hello_is_well_formed() {
        let hello = client_hello(IP);
        assert_eq!(hello[0], 0x16);
        assert_eq!(u16::from_be_bytes([hello[3], hello[4]]) as usize, hello.len() - 5);
        assert_eq!(u32::from_be_bytes([0, hello[6], hello[7], hello[8]]) as usize, hello.len() - 9);
        assert_eq!(handshake_bytes(&hello).len(), hello.len() - 5);
    }
}
