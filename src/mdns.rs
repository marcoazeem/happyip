//! mDNS (Bonjour) questions sent straight to one device on the local
//! network: its `.local` name, the services it offers and, for Apple
//! devices, the model. Macs, iPhones, printers, TVs, speakers and many
//! smart-home devices answer; Windows PCs mostly don't.
//!
//! Replies are untrusted: every offset is checked, and compressed names
//! can't loop.

use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

const SERVICES: &str = "_services._dns-sd._udp.local";
const DEVICE_INFO: &str = "_device-info._tcp.local";
const TYPE_PTR: u16 = 12;
const TYPE_TXT: u16 = 16;

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Info {
    /// e.g. "studio-macbook.local"
    pub name: Option<String>,
    /// e.g. "MacBookPro18,3"
    pub model: Option<String>,
    /// Service types without decoration: "airplay", "ipp", "smb"...
    pub services: Vec<String>,
}

impl Info {
    fn is_empty(&self) -> bool {
        *self == Info::default()
    }
}

/// Ask `ip` about itself. `None` when it doesn't speak mDNS.
pub fn query(ip: Ipv4Addr, timeout: Duration) -> Option<Info> {
    let sock = UdpSocket::bind("0.0.0.0:0").ok()?;
    let to = SocketAddr::from((ip, 5353));
    let reverse = reverse_name(ip);
    let id = (u32::from(ip) as u16) ^ 0x3D3D;
    let questions = [(labels(&reverse), TYPE_PTR), (labels(SERVICES), TYPE_PTR), (labels(DEVICE_INFO), TYPE_PTR)];
    sock.send_to(&question(id, &questions), to).ok()?;

    let mut info = Info::default();
    let mut device_info: Option<Vec<Vec<u8>>> = None;
    let mut asked_model = false;
    let mut deadline = Instant::now() + timeout;
    let mut buf = [0u8; 4096];
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() || sock.set_read_timeout(Some(left)).is_err() {
            break;
        }
        let Ok((n, from)) = sock.recv_from(&mut buf) else { break };
        if from.ip() != ip {
            continue;
        }
        parse(&buf[..n], ip, &mut info, &mut device_info);
        // Answers to the three questions may come separately; once the
        // device has spoken, the rest follow within a moment.
        deadline = deadline.min(Instant::now() + Duration::from_millis(250));
        // Apple devices name their model in a TXT record of the
        // device-info instance; ask for it if it wasn't volunteered.
        if info.model.is_none() && !asked_model && let Some(instance) = &device_info {
            asked_model = true;
            let _ = sock.send_to(&question(id.wrapping_add(1), &[(instance.clone(), TYPE_TXT)]), to);
            deadline = Instant::now() + Duration::from_millis(300);
        }
    }
    (!info.is_empty()).then_some(info)
}

/// "5.0.20.10.in-addr.arpa" for 10.20.0.5.
fn reverse_name(ip: Ipv4Addr) -> String {
    let o = ip.octets();
    format!("{}.{}.{}.{}.in-addr.arpa", o[3], o[2], o[1], o[0])
}

fn labels(name: &str) -> Vec<Vec<u8>> {
    name.split('.').filter(|l| !l.is_empty()).map(|l| l.as_bytes().to_vec()).collect()
}

/// One DNS query asking each question for a direct (unicast) answer.
fn question(id: u16, questions: &[(Vec<Vec<u8>>, u16)]) -> Vec<u8> {
    let mut p = id.to_be_bytes().to_vec();
    p.extend_from_slice(&[0, 0]); // standard query
    p.extend_from_slice(&(questions.len() as u16).to_be_bytes());
    p.extend_from_slice(&[0; 6]);
    for (name, kind) in questions {
        for label in name {
            let label = &label[..label.len().min(63)];
            p.push(label.len() as u8);
            p.extend_from_slice(label);
        }
        p.push(0);
        p.extend_from_slice(&kind.to_be_bytes());
        p.extend_from_slice(&[0x80, 0x01]); // class IN, unicast answer wanted
    }
    p
}

/// A (possibly compressed) name starting at `pos`: its labels, and where
/// the data after it continues.
fn read_name(packet: &[u8], mut pos: usize) -> Option<(Vec<Vec<u8>>, usize)> {
    let mut out = Vec::new();
    let mut after = None;
    // Every pointer must lead somewhere new; a packet can't hold more
    // jumps than this without looping.
    for _ in 0..64 {
        let len = *packet.get(pos)? as usize;
        match len {
            0 => return Some((out, after.unwrap_or(pos + 1))),
            l if l & 0xC0 == 0xC0 => {
                let target = (l & 0x3F) << 8 | *packet.get(pos + 1)? as usize;
                after.get_or_insert(pos + 2);
                pos = target;
            }
            l if l & 0xC0 != 0 => return None,
            l => {
                out.push(packet.get(pos + 1..pos + 1 + l)?.to_vec());
                pos += 1 + l;
            }
        }
    }
    None
}

fn dotted(labels: &[Vec<u8>]) -> String {
    labels.iter().map(|l| String::from_utf8_lossy(l).into_owned()).collect::<Vec<_>>().join(".")
}

/// Add what one reply from `ip` says to `info`.
fn parse(packet: &[u8], ip: Ipv4Addr, info: &mut Info, device_info: &mut Option<Vec<Vec<u8>>>) {
    let _ = parse_records(packet, ip, info, device_info);
}

fn parse_records(packet: &[u8], ip: Ipv4Addr, info: &mut Info, device_info: &mut Option<Vec<Vec<u8>>>) -> Option<()> {
    let count = |i: usize| Some(u16::from_be_bytes([*packet.get(i)?, *packet.get(i + 1)?]) as usize);
    let (questions, records) = (count(4)?, count(6)? + count(8)? + count(10)?);
    let mut pos = 12;
    for _ in 0..questions {
        pos = read_name(packet, pos)?.1 + 4;
    }
    let reverse = reverse_name(ip);
    for _ in 0..records {
        let (owner, next) = read_name(packet, pos)?;
        let header = packet.get(next..next + 10)?;
        let kind = u16::from_be_bytes([header[0], header[1]]);
        let len = u16::from_be_bytes([header[8], header[9]]) as usize;
        let data_at = next + 10;
        let data = packet.get(data_at..data_at + len)?;
        pos = data_at + len;
        let owner = dotted(&owner).to_lowercase();
        match kind {
            TYPE_PTR => {
                let Some((target, _)) = read_name(packet, data_at) else { continue };
                if owner == reverse {
                    let name = host_name(&dotted(&target));
                    info.name = info.name.take().or(name);
                } else if owner == SERVICES {
                    // "_airplay._tcp.local" → "airplay"
                    let service = target.first().map(|l| String::from_utf8_lossy(l).trim_start_matches('_').to_lowercase());
                    if let Some(s) = service.filter(|s| is_word(s) && !info.services.contains(s)) && info.services.len() < 40 {
                        info.services.push(s);
                    }
                } else if owner == DEVICE_INFO {
                    device_info.get_or_insert(target);
                }
            }
            TYPE_TXT if owner.ends_with(DEVICE_INFO) => {
                // Length-prefixed "key=value" strings.
                let mut rest = data;
                while let Some((&l, tail)) = rest.split_first() {
                    let Some(entry) = tail.get(..l as usize) else { break };
                    rest = &tail[l as usize..];
                    if let Some(model) = String::from_utf8_lossy(entry).strip_prefix("model=") {
                        let model: String = model.chars().filter(|c| c.is_ascii_graphic()).take(40).collect();
                        info.model = info.model.take().or((!model.is_empty()).then_some(model));
                    }
                }
            }
            _ => {}
        }
    }
    Some(())
}

fn is_word(s: &str) -> bool {
    !s.is_empty() && s.len() <= 40 && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// A usable host name: only the characters DNS names are made of.
fn host_name(s: &str) -> Option<String> {
    let s = s.trim_end_matches('.');
    let ok = !s.is_empty() && s.len() <= 253 && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_');
    ok.then(|| s.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    const IP: Ipv4Addr = Ipv4Addr::new(10, 20, 0, 23);

    fn name(n: &str) -> Vec<u8> {
        let mut out = Vec::new();
        for l in n.split('.') {
            out.push(l.len() as u8);
            out.extend_from_slice(l.as_bytes());
        }
        out.push(0);
        out
    }

    fn record(owner: &[u8], kind: u16, data: &[u8]) -> Vec<u8> {
        let mut r = owner.to_vec();
        r.extend_from_slice(&kind.to_be_bytes());
        r.extend_from_slice(&[0x80, 0x01, 0, 0, 0, 120]);
        r.extend_from_slice(&(data.len() as u16).to_be_bytes());
        r.extend_from_slice(data);
        r
    }

    fn reply(records: &[Vec<u8>]) -> Vec<u8> {
        let mut p = vec![0, 1, 0x84, 0, 0, 0];
        p.extend_from_slice(&(records.len() as u16).to_be_bytes());
        p.extend_from_slice(&[0; 4]);
        for r in records {
            p.extend_from_slice(r);
        }
        p
    }

    fn read(packet: &[u8]) -> (Info, Option<String>) {
        let (mut info, mut instance) = (Info::default(), None);
        parse(packet, IP, &mut info, &mut instance);
        (info, instance.map(|i| dotted(&i)))
    }

    #[test]
    fn reads_name_services_and_model() {
        let packet = reply(&[
            record(&name("23.0.20.10.in-addr.arpa"), TYPE_PTR, &name("Studio-MacBook.local")),
            record(&name(SERVICES), TYPE_PTR, &name("_airplay._tcp.local")),
            record(&name(SERVICES), TYPE_PTR, &name("_smb._tcp.local")),
            record(&name(SERVICES), TYPE_PTR, &name("_airplay._tcp.local")),
            record(&name(DEVICE_INFO), TYPE_PTR, &name("Studio MacBook._device-info._tcp.local")),
            record(&name("Studio MacBook._device-info._tcp.local"), TYPE_TXT, b"\x14model=MacBookPro18,3\x07osxvers"),
        ]);
        let (info, instance) = read(&packet);
        assert_eq!(info.name.as_deref(), Some("Studio-MacBook.local"));
        assert_eq!(info.services, ["airplay", "smb"]);
        assert_eq!(info.model.as_deref(), Some("MacBookPro18,3"));
        assert_eq!(instance.as_deref(), Some("Studio MacBook._device-info._tcp.local"));
    }

    #[test]
    fn a_name_for_another_address_is_ignored() {
        let packet = reply(&[record(&name("99.0.20.10.in-addr.arpa"), TYPE_PTR, &name("other.local"))]);
        assert_eq!(read(&packet).0, Info::default());
        // Names that aren't host names are dropped too.
        let packet = reply(&[record(&name("23.0.20.10.in-addr.arpa"), TYPE_PTR, &name("bad name; rm -rf.local"))]);
        assert_eq!(read(&packet).0.name, None);
    }

    #[test]
    fn compressed_names_are_followed_but_never_loop() {
        // The PTR target points back at the owner name (offset 12).
        let mut packet = reply(&[record(&name("23.0.20.10.in-addr.arpa"), TYPE_PTR, &[0xC0, 12])]);
        assert_eq!(read(&packet).0.name.as_deref(), Some("23.0.20.10.in-addr.arpa"));
        // A pointer to itself must end, not spin.
        let at = packet.len() - 2;
        packet[at + 1] = at as u8;
        assert_eq!(read(&packet).0.name, None);
    }

    #[test]
    fn damaged_replies_never_panic() {
        let packet = reply(&[
            record(&name("23.0.20.10.in-addr.arpa"), TYPE_PTR, &name("studio.local")),
            record(&name("x._device-info._tcp.local"), TYPE_TXT, b"\xFFmodel=short"),
        ]);
        for len in 0..packet.len() {
            let _ = read(&packet[..len]);
        }
        let mut bad = packet.clone();
        for i in 0..bad.len() {
            bad[i] ^= 0xFF;
            let _ = read(&bad);
            bad[i] ^= 0xFF;
        }
        let _ = read(&[0xFF; 600]);
    }

    /// Against a real responder, e.g. this computer's own address:
    /// `HAPPYIP_MDNS_TEST_IP=192.168.1.20 cargo test live_query -- --ignored --nocapture`.
    #[test]
    #[ignore = "needs an mDNS responder"]
    fn live_query() {
        let ip: Ipv4Addr = std::env::var("HAPPYIP_MDNS_TEST_IP").expect("HAPPYIP_MDNS_TEST_IP").parse().unwrap();
        let info = query(ip, Duration::from_secs(2)).expect("an answer");
        println!("{info:?}");
        assert!(info.name.is_some() || !info.services.is_empty());
    }

    #[test]
    fn question_is_well_formed() {
        let q = question(7, &[(labels(&reverse_name(IP)), TYPE_PTR), (labels(SERVICES), TYPE_PTR)]);
        assert_eq!(&q[..6], &[0, 7, 0, 0, 0, 2]);
        let (first, next) = read_name(&q, 12).unwrap();
        assert_eq!(dotted(&first), "23.0.20.10.in-addr.arpa");
        assert_eq!(&q[next..next + 4], &[0, 12, 0x80, 1]);
    }
}
