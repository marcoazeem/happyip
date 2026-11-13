//! Remembers the last complete scan of each range, so the next one can show
//! what changed: devices that are new, gone, or answering from a different
//! network card.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::path::PathBuf;

use crate::scanner::HostResult;

/// What a host looked like in the previous scan of the same range.
#[derive(Clone, Debug, PartialEq)]
pub struct Seen {
    pub mac: Option<String>,
    pub name: Option<String>,
    pub device: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Snapshot {
    /// When the scan was made, e.g. "2026-11-14 09:30".
    pub when: String,
    pub hosts: HashMap<Ipv4Addr, Seen>,
}

/// How a host differs from the previous scan of its range.
#[derive(Clone, Debug, PartialEq)]
pub enum Change {
    /// Alive now, wasn't last time.
    New,
    /// Was alive last time, isn't now.
    Gone(Seen),
    /// Same address, different hardware: another device took the address.
    MacChanged { was: String },
}

impl Change {
    pub fn label(&self) -> String {
        match self {
            Change::New => "New".into(),
            Change::Gone(seen) => {
                let what = [seen.name.as_deref(), Some(seen.device.as_str()), seen.mac.as_deref()]
                    .into_iter()
                    .flatten()
                    .filter(|s| !s.is_empty())
                    .collect::<Vec<_>>()
                    .join(" · ");
                if what.is_empty() { "Gone".into() } else { format!("Gone (was {what})") }
            }
            Change::MacChanged { was } => format!("Different device (MAC was {was})"),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Summary {
    pub new: usize,
    pub gone: usize,
    pub changed: usize,
}

impl Summary {
    pub fn text(&self, since: &str) -> String {
        if *self == Summary::default() {
            return format!("no changes since {since}");
        }
        let parts = [(self.new, "new"), (self.gone, "gone"), (self.changed, "replaced")];
        let parts: Vec<String> = parts.iter().filter(|(n, _)| *n > 0).map(|(n, what)| format!("{n} {what}")).collect();
        format!("since {since}: {}", parts.join(", "))
    }
}

pub fn snapshot(when: &str, results: &[HostResult]) -> Snapshot {
    let hosts = results
        .iter()
        .filter(|r| r.alive.is_some())
        .map(|r| (r.ip, Seen { mac: r.mac.clone(), name: r.display_name(), device: r.device_text() }))
        .collect();
    Snapshot { when: when.to_string(), hosts }
}

/// Mark each result with how it differs from `previous`.
pub fn compare(previous: &Snapshot, results: &mut [HostResult]) -> Summary {
    let mut summary = Summary::default();
    for r in results {
        let before = previous.hosts.get(&r.ip);
        r.change = match (before, r.alive.is_some()) {
            (None, true) => Some(Change::New),
            (Some(seen), false) => Some(Change::Gone(seen.clone())),
            (Some(Seen { mac: Some(was), .. }), true) if r.mac.as_ref().is_some_and(|now| now != was) => {
                Some(Change::MacChanged { was: was.clone() })
            }
            _ => None,
        };
        match r.change {
            Some(Change::New) => summary.new += 1,
            Some(Change::Gone(_)) => summary.gone += 1,
            Some(Change::MacChanged { .. }) => summary.changed += 1,
            None => {}
        }
    }
    summary
}

const HEADER: &str = "#happyip-scan 1";

fn field(s: &str) -> String {
    s.chars().map(|c| if c.is_control() { ' ' } else { c }).collect()
}

pub fn serialize(range: &str, snap: &Snapshot) -> String {
    let mut hosts: Vec<_> = snap.hosts.iter().collect();
    hosts.sort_by_key(|(ip, _)| **ip);
    let mut out = format!("{HEADER}\nwhen={}\nrange={}\n", field(&snap.when), field(range));
    for (ip, seen) in hosts {
        out.push_str(&format!(
            "{ip}\t{}\t{}\t{}\n",
            field(seen.mac.as_deref().unwrap_or("")),
            field(seen.name.as_deref().unwrap_or("")),
            field(&seen.device)
        ));
    }
    out
}

/// The snapshot in `text` if it is one for `range`.
pub fn parse(text: &str, range: &str) -> Option<Snapshot> {
    let mut lines = text.lines();
    if lines.next()? != HEADER {
        return None;
    }
    let when = lines.next()?.strip_prefix("when=")?.to_string();
    if lines.next()?.strip_prefix("range=")? != field(range) {
        return None;
    }
    let some = |s: &str| (!s.is_empty()).then(|| s.to_string());
    let hosts = lines
        .filter_map(|l| {
            let mut f = l.split('\t');
            let ip: Ipv4Addr = f.next()?.parse().ok()?;
            let (mac, name, device) = (f.next()?, f.next()?, f.next()?);
            Some((ip, Seen { mac: some(mac), name: some(name), device: device.to_string() }))
        })
        .collect();
    Some(Snapshot { when, hosts })
}

/// One file per range: a readable name plus a checksum, since ranges can
/// hold characters that file names can't.
fn path(range: &str) -> Option<PathBuf> {
    let readable: String = range.chars().map(|c| if c.is_ascii_alphanumeric() || c == '.' || c == '-' { c } else { '_' }).take(60).collect();
    let checksum = range.bytes().fold(0xcbf2_9ce4_8422_2325u64, |h, b| (h ^ b as u64).wrapping_mul(0x0000_0100_0000_01b3));
    Some(crate::settings::dir()?.join("history").join(format!("{readable}-{checksum:016x}.tsv")))
}

/// The range as typed, without differences that don't matter.
fn normalize(range: &str) -> String {
    range.split([',', ';']).map(str::trim).filter(|s| !s.is_empty()).collect::<Vec<_>>().join(",").to_lowercase()
}

pub fn load(range: &str) -> Option<Snapshot> {
    let range = normalize(range);
    parse(&std::fs::read_to_string(path(&range)?).ok()?, &range)
}

pub fn save(range: &str, snap: &Snapshot) -> Result<(), String> {
    let range = normalize(range);
    let path = path(&range).ok_or("no settings folder on this system")?;
    let dir = path.parent().ok_or("no history folder")?;
    std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    std::fs::write(&path, serialize(&range, snap)).map_err(|e| format!("{}: {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::AliveBy;

    fn host(last: u8, alive: bool, mac: Option<&str>) -> HostResult {
        let mut r = HostResult::new(Ipv4Addr::new(10, 0, 0, last));
        r.alive = alive.then_some(AliveBy::Ping);
        r.mac = mac.map(str::to_string);
        r.netbios_name = alive.then(|| format!("PC{last}"));
        r
    }

    #[test]
    fn spots_new_gone_and_replaced_devices() {
        let before = [host(1, true, Some("AA:00:00:00:00:01")), host(2, true, Some("AA:00:00:00:00:02")), host(3, true, None), host(4, false, None)];
        let previous = snapshot("2026-11-10 14:00", &before);
        assert_eq!(previous.hosts.len(), 3);

        let mut now = [
            host(1, true, Some("AA:00:00:00:00:01")), // unchanged
            host(2, true, Some("BB:00:00:00:00:99")), // another device on the address
            host(3, false, None),                     // gone
            host(4, true, None),                      // new
            host(5, false, None),                     // still nothing there
        ];
        let summary = compare(&previous, &mut now);
        assert_eq!(summary, Summary { new: 1, gone: 1, changed: 1 });
        assert_eq!(now[0].change, None);
        assert_eq!(now[1].change, Some(Change::MacChanged { was: "AA:00:00:00:00:02".into() }));
        assert!(matches!(now[2].change, Some(Change::Gone(_))));
        assert_eq!(now[2].change.as_ref().unwrap().label(), "Gone (was PC3)");
        assert_eq!(now[3].change, Some(Change::New));
        assert_eq!(now[4].change, None);
        assert_eq!(summary.text("2026-11-10 14:00"), "since 2026-11-10 14:00: 1 new, 1 gone, 1 replaced");

        // A MAC that is only known in one of the two scans is not a change.
        let mut now = [host(1, true, None), host(3, true, Some("CC:00:00:00:00:03"))];
        assert_eq!(compare(&previous, &mut now), Summary::default());
    }

    #[test]
    fn snapshots_round_trip() {
        let mut odd = host(7, true, Some("AA:00:00:00:00:07"));
        odd.netbios_name = Some("tab\tand\nnewline".into());
        let snap = snapshot("2026-11-14 09:30", &[host(1, true, None), odd]);
        let text = serialize("10.0.0.0/24", &snap);
        let back = parse(&text, "10.0.0.0/24").unwrap();
        assert_eq!(back.when, snap.when);
        assert_eq!(back.hosts.len(), 2);
        assert_eq!(back.hosts[&Ipv4Addr::new(10, 0, 0, 7)].name.as_deref(), Some("tab and newline"));
        // A file for another range, or not a snapshot at all, is ignored.
        assert_eq!(parse(&text, "10.0.1.0/24"), None);
        assert_eq!(parse("", "10.0.0.0/24"), None);
        assert_eq!(parse("garbage\n\n", "10.0.0.0/24"), None);
        // Broken lines are skipped, not fatal.
        let damaged = format!("{text}not-an-ip\tx\ty\tz\n10.0.0.9\n");
        assert_eq!(parse(&damaged, "10.0.0.0/24").unwrap().hosts.len(), 2);
    }

    #[test]
    fn ranges_map_to_distinct_safe_file_names() {
        assert_eq!(normalize(" 10.0.0.0/24 ,PC42 "), "10.0.0.0/24,pc42");
        if let (Some(a), Some(b)) = (path("10.0.0.0/24"), path("10.0.0.0_24")) {
            assert_ne!(a, b);
            let name = a.file_name().unwrap().to_string_lossy().into_owned();
            assert!(name.chars().all(|c| c.is_ascii_alphanumeric() || "._-".contains(c)), "{name}");
        }
    }
}
