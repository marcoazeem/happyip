//! Multithreaded scan engine. Results stream back over a channel so the UI
//! can fill the table while the scan runs.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::sync::Arc;
use std::time::Duration;

use crate::identify::{self, Device};
use crate::netbios;
use crate::wmi;
use crate::probe::{self, ArpCache};

#[derive(Clone)]
pub struct ScanConfig {
    pub targets: Vec<Ipv4Addr>,
    pub threads: usize,
    pub timeout_ms: u64,
    pub ports: Vec<u16>,
    pub resolve_names: bool,
    pub netbios: bool,
    /// Domain-admin queries (WMI inventory + `query user`), Windows only.
    pub admin_queries: bool,
    /// This machine's addresses and their MACs (they never appear in ARP).
    pub local: HashMap<Ipv4Addr, Option<String>>,
    pub gateway: Option<Ipv4Addr>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AliveBy {
    Ping,
    Tcp,
    Arp,
    NetBios,
    Local,
}

impl AliveBy {
    pub fn label(self) -> &'static str {
        match self {
            AliveBy::Ping => "ICMP",
            AliveBy::Tcp => "TCP",
            AliveBy::Arp => "ARP",
            AliveBy::NetBios => "NetBIOS",
            AliveBy::Local => "This PC",
        }
    }
}

#[derive(Clone, Debug)]
pub struct HostResult {
    pub ip: Ipv4Addr,
    pub alive: Option<AliveBy>,
    pub rtt_ms: Option<f64>,
    pub ttl: Option<u32>,
    pub hostname: Option<String>,
    pub mac: Option<String>,
    pub netbios_name: Option<String>,
    pub workgroup: Option<String>,
    pub users: Vec<String>,
    pub open_ports: Vec<u16>,
    pub vendor: Option<String>,
    pub http_banner: Option<String>,
    pub device: Option<Device>,
    /// AD/DNS domain the machine belongs to (WMI or its DNS name).
    pub domain: Option<String>,
    /// Exact OS from WMI, e.g. "Windows 11 Pro".
    pub os_name: Option<String>,
    /// Hardware manufacturer + model from WMI, e.g. "Dell Inc. OptiPlex 7090".
    pub model: Option<String>,
}

impl HostResult {
    pub(crate) fn new(ip: Ipv4Addr) -> Self {
        Self {
            ip,
            alive: None,
            rtt_ms: None,
            ttl: None,
            hostname: None,
            mac: None,
            netbios_name: None,
            workgroup: None,
            users: Vec::new(),
            open_ports: Vec::new(),
            vendor: None,
            http_banner: None,
            device: None,
            domain: None,
            os_name: None,
            model: None,
        }
    }

    pub fn ping_text(&self) -> String {
        match self.rtt_ms {
            Some(r) if r == 0.0 => "<1 ms".into(),
            Some(r) if r < 10.0 => format!("{r:.1} ms"),
            Some(r) => format!("{r:.0} ms"),
            None => String::new(),
        }
    }

    /// Best "computer name": NetBIOS name, else the short DNS name.
    pub fn display_name(&self) -> Option<String> {
        self.netbios_name.clone().or_else(|| {
            let h = self.hostname.as_deref()?;
            let short = h.split('.').next().unwrap_or(h);
            (!short.is_empty()).then(|| short.to_string())
        })
    }

    /// Domain, else NetBIOS workgroup, else the DNS suffix of the hostname
    /// (`pc42.corp.example` → `corp.example`).
    pub fn domain_text(&self) -> Option<String> {
        self.domain.clone().or_else(|| self.workgroup.clone()).or_else(|| {
            let h = self.hostname.as_deref()?;
            let (_, suffix) = h.split_once('.')?;
            let generic = ["local", "lan", "home", "localdomain", "home.arpa", "internal"];
            (!generic.contains(&suffix.to_lowercase().as_str())).then(|| suffix.to_string())
        })
    }

    /// Exact OS from WMI when known, else the fingerprinted OS family.
    pub fn os_text(&self) -> Option<String> {
        self.os_name.clone().or_else(|| self.device.as_ref()?.os.map(str::to_string))
    }

    pub fn device_text(&self) -> String {
        self.device.as_ref().map(|d| d.kind.to_string()).unwrap_or_default()
    }

    pub fn ports_text(&self) -> String {
        self.open_ports.iter().map(u16::to_string).collect::<Vec<_>>().join(", ")
    }
}

pub enum ScanEvent {
    Host(HostResult),
    Finished,
}

pub struct ScanHandle {
    pub rx: Receiver<ScanEvent>,
    cancel: Arc<AtomicBool>,
}

impl ScanHandle {
    pub fn stop(&self) {
        self.cancel.store(true, Ordering::Relaxed);
    }
}

/// Start a scan in the background. `notify` is called after each result so
/// the UI can repaint.
pub fn start(cfg: ScanConfig, notify: impl Fn() + Send + Sync + 'static) -> ScanHandle {
    let (tx, rx) = mpsc::channel();
    let cancel = Arc::new(AtomicBool::new(false));
    let cancel2 = cancel.clone();

    std::thread::spawn(move || {
        let cfg = Arc::new(cfg);
        let next = AtomicUsize::new(0);
        let arp = ArpCache::new();
        let notify = &notify;
        std::thread::scope(|s| {
            for _ in 0..cfg.threads.clamp(1, 512).min(cfg.targets.len()) {
                let (cfg, tx, next, arp, cancel) = (&cfg, tx.clone(), &next, &arp, &cancel2);
                s.spawn(move || loop {
                    if cancel.load(Ordering::Relaxed) {
                        break;
                    }
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    let Some(&ip) = cfg.targets.get(i) else { break };
                    let result = scan_host(ip, cfg, arp);
                    if tx.send(ScanEvent::Host(result)).is_err() {
                        break;
                    }
                    notify();
                });
            }
        });
        let _: Result<(), _> = tx.send(ScanEvent::Finished);
        notify();
    });

    ScanHandle { rx, cancel }
}

fn scan_host(ip: Ipv4Addr, cfg: &ScanConfig, arp: &ArpCache) -> HostResult {
    let mut r = HostResult::new(ip);
    let timeout = Duration::from_millis(cfg.timeout_ms);

    if let Some(reply) = probe::ping(ip, cfg.timeout_ms) {
        r.alive = Some(AliveBy::Ping);
        r.rtt_ms = Some(reply.rtt_ms);
        r.ttl = reply.ttl;
    }

    if !cfg.ports.is_empty() {
        let port_timeout = timeout.min(Duration::from_millis(1500));
        let (open, answered) = probe::probe_ports(ip, &cfg.ports, port_timeout);
        r.open_ports = open;
        if answered && r.alive.is_none() {
            r.alive = Some(AliveBy::Tcp);
        }
    }

    // The probes above populate the OS ARP cache for hosts on the local
    // subnet, which also catches devices that ignore ping and TCP.
    if let Some(local_mac) = cfg.local.get(&ip) {
        r.alive = Some(AliveBy::Local);
        r.mac = local_mac.clone();
    } else if let Some(mac) = arp.lookup(ip) {
        r.mac = Some(mac);
        r.alive.get_or_insert(AliveBy::Arp);
    }

    if cfg.netbios {
        // Query even if nothing answered yet: some Windows hosts drop ping
        // but still answer NetBIOS. Keep it short for hosts that look dead.
        let nb_timeout = if r.alive.is_some() { timeout } else { timeout.min(Duration::from_millis(400)) };
        if let Some(nb) = netbios::query(ip, nb_timeout) {
            r.alive.get_or_insert(AliveBy::NetBios);
            r.netbios_name = nb.computer;
            r.workgroup = nb.workgroup;
            r.users = nb.users;
            if r.mac.is_none() {
                r.mac = nb.mac;
            }
        }
    }

    if r.alive.is_none() {
        return r;
    }

    if cfg.resolve_names {
        r.hostname = reverse_dns(ip, Duration::from_millis(cfg.timeout_ms.max(1500)));
    }

    let is_local = r.alive == Some(AliveBy::Local);
    if is_local {
        merge_users(&mut r.users, netbios::local_users());
        if r.hostname.is_none() {
            r.hostname = dns_lookup::get_hostname().ok();
        }
    } else if cfg.admin_queries && looks_windows(&r) {
        if let Some(w) = wmi::query(ip, Duration::from_secs(20)) {
            if r.mac.is_none() {
                r.mac = w.mac; // the only MAC source for hosts on other VLANs
            }
            if r.netbios_name.is_none() {
                r.netbios_name = w.computer;
            }
            r.domain = w.domain;
            r.os_name = w.os;
            r.model = w.model;
            merge_users(&mut r.users, w.user.into_iter().collect());
        }
        merge_users(&mut r.users, netbios::remote_sessions(ip));
    }

    r.vendor = r.mac.as_deref().and_then(identify::vendor);
    if let Some(&port) = [80, 8080, 5000].iter().find(|p| r.open_ports.contains(p)) {
        r.http_banner = identify::http_banner(ip, port, timeout.max(Duration::from_millis(800)));
    }
    r.device = Some(identify::classify(&r, cfg.gateway, is_local));
    r
}

/// Reverse DNS with a deadline. The OS resolver can block for ~30 s on hosts
/// without a PTR record (macOS falls back to mDNS), so the lookup runs on its
/// own thread and is abandoned if it doesn't answer in time.
fn reverse_dns(ip: Ipv4Addr, timeout: Duration) -> Option<String> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(dns_lookup::lookup_addr(&IpAddr::V4(ip)).ok());
    });
    rx.recv_timeout(timeout)
        .ok()
        .flatten()
        .filter(|h| h != &ip.to_string())
        .map(|h| h.trim_end_matches('.').to_string())
}

/// Worth spending an admin query on: RPC/SMB/RDP open, or answers NetBIOS.
fn looks_windows(r: &HostResult) -> bool {
    [135, 139, 445, 3389].iter().any(|p| r.open_ports.contains(p)) || r.netbios_name.is_some()
}

fn merge_users(into: &mut Vec<String>, more: Vec<String>) {
    for u in more {
        if !into.iter().any(|x| x.eq_ignore_ascii_case(&u)) {
            into.push(u);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_from_dns_suffix() {
        let mut r = HostResult::new(Ipv4Addr::new(10, 0, 0, 5));
        r.hostname = Some("pc42.corp.example".into());
        assert_eq!(r.domain_text().as_deref(), Some("corp.example"));
        r.hostname = Some("iphone.local".into());
        assert_eq!(r.domain_text(), None);
        r.hostname = Some("printer".into());
        assert_eq!(r.domain_text(), None);
        r.domain = Some("ad.example".into());
        assert_eq!(r.domain_text().as_deref(), Some("ad.example"));
    }
}
