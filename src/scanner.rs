//! Multithreaded scan engine. Results stream back over a channel so the UI
//! can fill the table while the scan runs.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use crate::ad::{AdComputer, Directory};
use crate::identify::{self, Device};
use crate::netbios;
use crate::probe::{self, ArpCache, ArpReply};
use crate::targets::Network;
use crate::util::lock;
use crate::wmi;

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
    /// Subnets this machine is directly on (where ARP works).
    pub on_link: Vec<(Ipv4Addr, u8)>,
    pub gateway: Option<Ipv4Addr>,
    /// Ask devices on the local network about themselves (mDNS, UPnP) and
    /// collect their IPv6 addresses.
    pub local_discovery: bool,
    /// SNMP community to try on each live host; `None` leaves SNMP off.
    pub snmp_community: Option<String>,
    /// Names of this machine's network interfaces (for IPv6 discovery).
    pub interface_names: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AliveBy {
    Ping,
    Tcp,
    Arp,
    /// Only an ARP table entry that was already there before the scan
    /// (macOS/Linux): the device was here recently but may have left.
    ArpCached,
    NetBios,
    Local,
}

/// Outcome of the admin (WMI) lookup for a Windows PC.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdminDetails {
    /// Not asked: not a Windows PC, admin queries off, or the scan was stopped.
    NotTried,
    Answered,
    /// Access denied, blocked by a firewall, or no answer in time.
    Failed,
}

impl AliveBy {
    pub fn label(self) -> &'static str {
        match self {
            AliveBy::Ping => "ICMP",
            AliveBy::Tcp => "TCP",
            AliveBy::Arp => "ARP",
            AliveBy::ArpCached => "ARP (cached)",
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
    /// Software the SSH server on port 22 announces.
    pub ssh_banner: Option<String>,
    /// Name on the HTTPS certificate served on port 443.
    pub tls_name: Option<String>,
    /// How the device describes itself over UPnP: name, maker and model.
    pub upnp: Option<String>,
    /// How this host differs from the previous scan of the same range.
    pub change: Option<crate::history::Change>,
    /// IPv6 addresses seen with this host's MAC address, routable ones first.
    pub ipv6: Vec<Ipv6Addr>,
    /// Services the device advertises over mDNS, e.g. "airplay", "ipp".
    pub mdns_services: Vec<String>,
    /// What the device says about itself over SNMP.
    pub snmp: Option<crate::snmp::Info>,
    pub device: Option<Device>,
    /// AD/DNS domain the machine belongs to (WMI or its DNS name).
    pub domain: Option<String>,
    /// Exact OS from WMI, e.g. "Windows 11 Pro".
    pub os_name: Option<String>,
    /// Hardware manufacturer + model from WMI, e.g. "Dell Inc. OptiPlex 7090".
    pub model: Option<String>,
    pub admin: AdminDetails,
    /// Only a firewall/proxy answered for this address (see [`firewall_echoes`]),
    /// so it's treated as not alive.
    pub firewall_reply: bool,
    /// The computer's Active Directory account, if it has one.
    pub ad: Option<AdComputer>,
    /// The network / VLAN / AD site this address belongs to.
    pub network: Option<String>,
    /// Reverse DNS name that doesn't resolve back to this address (a stale
    /// DNS record from a previous owner), so it's not trusted as the name.
    pub dns_mismatch: Option<String>,
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
            ssh_banner: None,
            tls_name: None,
            upnp: None,
            change: None,
            ipv6: Vec::new(),
            mdns_services: Vec::new(),
            snmp: None,
            device: None,
            domain: None,
            os_name: None,
            model: None,
            admin: AdminDetails::NotTried,
            firewall_reply: false,
            ad: None,
            network: None,
            dns_mismatch: None,
        }
    }

    /// Attach the AD computer account (if any) and the network label, then
    /// redo the device classification with the extra information.
    pub fn enrich(&mut self, dir: Option<&Directory>, networks: &[Network], gateway: Option<Ipv4Addr>) {
        self.ad = dir.and_then(|d| d.find(self.netbios_name.as_deref(), self.hostname.as_deref()).cloned());
        if let (Some(_), Some(dir), None) = (&self.ad, dir, &self.domain) {
            self.domain = Some(dir.domain.clone());
        }
        self.network = Some(match crate::targets::best_match(networks, self.ip) {
            Some(n) => n.describe(),
            None => {
                let o = self.ip.octets();
                format!("{}.{}.{}.0/24", o[0], o[1], o[2])
            }
        });
        if self.alive.is_some() {
            self.device = Some(identify::classify(self, gateway, self.alive == Some(AliveBy::Local)));
        }
    }

    pub fn ping_text(&self) -> String {
        match self.rtt_ms {
            Some(0.0) => "<1 ms".into(),
            Some(r) if r < 10.0 => format!("{r:.1} ms"),
            Some(r) => format!("{r:.0} ms"),
            None => String::new(),
        }
    }

    /// Best "computer name": NetBIOS name, else the AD name, else the short
    /// DNS name, else the name set on the device (SNMP).
    pub fn display_name(&self) -> Option<String> {
        self.netbios_name
            .clone()
            .or_else(|| self.ad.as_ref().map(|a| a.name.clone()))
            .or_else(|| {
                let h = self.hostname.as_deref()?;
                let short = h.split('.').next().unwrap_or(h);
                (!short.is_empty()).then(|| short.to_string())
            })
            .or_else(|| self.snmp.as_ref()?.name.clone())
    }

    /// Take this host's IPv6 addresses from the OS neighbour table
    /// (addresses by MAC, see `ipv6::neighbors`).
    pub fn set_ipv6(&mut self, neighbors: &HashMap<String, Vec<Ipv6Addr>>) {
        if let Some(found) = self.mac.as_ref().and_then(|mac| neighbors.get(mac)) {
            self.ipv6 = found.clone();
        }
    }

    pub fn ipv6_text(&self) -> String {
        self.ipv6.iter().map(Ipv6Addr::to_string).collect::<Vec<_>>().join(", ")
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

    /// Exact OS from WMI or AD when known, else the fingerprinted OS family.
    pub fn os_text(&self) -> Option<String> {
        self.os_name
            .clone()
            .or_else(|| self.ad.as_ref()?.os.clone())
            .or_else(|| self.device.as_ref()?.os.map(str::to_string))
    }

    /// AD column text: OU path, with a warning for disabled accounts.
    pub fn ad_text(&self) -> String {
        match &self.ad {
            None => String::new(),
            Some(a) => {
                let ou = a.ou.clone().unwrap_or_else(|| "(domain root)".into());
                if a.enabled { ou } else { format!("{ou}  (disabled)") }
            }
        }
    }

    pub fn device_text(&self) -> String {
        self.device.as_ref().map(|d| d.kind.to_string()).unwrap_or_default()
    }

    /// "Seen via" column text.
    pub fn seen_via(&self) -> &'static str {
        match self.alive {
            Some(a) => a.label(),
            None if self.firewall_reply => "Firewall reply",
            None => "",
        }
    }

    pub fn ports_text(&self) -> String {
        self.open_ports.iter().map(u16::to_string).collect::<Vec<_>>().join(", ")
    }
}

pub enum ScanEvent {
    Host(HostResult),
    /// A host already sent as `Host`, with admin (WMI) details filled in.
    Update(HostResult),
    /// These addresses only "answered" through a firewall or proxy replying
    /// on behalf of every address, so they're not alive after all.
    NotAlive(Vec<Ipv4Addr>),
    /// These addresses were only in the ARP table from before the scan, and
    /// have dropped out of it since: the devices have left.
    Departed(Vec<Ipv4Addr>),
    /// IPv6 addresses by MAC address, from the OS neighbour table.
    Neighbors(HashMap<String, Vec<Ipv6Addr>>),
    /// Every address has been scanned. `admin_pending` hosts are still
    /// waiting for admin details, which arrive as `Update`s.
    HostsDone { admin_pending: usize },
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

/// How long one admin (WMI) lookup may take. Reachable PCs answer in a
/// second or two; firewalled ones would otherwise hang for 20 s or more.
const ADMIN_TIMEOUT: Duration = Duration::from_secs(8);
/// Admin lookups running at once (each one is a PowerShell process).
const ADMIN_WORKERS: usize = 16;

/// Start a scan in the background. `notify` is called after each result so
/// the UI can repaint.
///
/// The host scan never waits on admin lookups: hosts are reported as soon as
/// they are scanned, and Windows PCs are handed to a separate pool that sends
/// their WMI details as `Update`s, overlapping with the rest of the scan.
///
/// `Finished` is always the last event, whatever goes wrong on the way.
pub fn start(cfg: ScanConfig, notify: impl Fn() + Send + Sync + 'static) -> ScanHandle {
    let (tx, rx) = mpsc::channel();
    let cancel = Arc::new(AtomicBool::new(false));
    let cancel2 = cancel.clone();

    std::thread::spawn(move || {
        let run = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run_scan(&cfg, &cancel2, &tx, &notify)));
        if run.is_err() {
            crate::diag::log("scan ended early after an internal error");
        }
        let _: Result<(), _> = tx.send(ScanEvent::Finished);
        notify();
    });

    ScanHandle { rx, cancel }
}

fn run_scan(cfg: &ScanConfig, cancel: &AtomicBool, tx: &mpsc::Sender<ScanEvent>, notify: &(impl Fn() + Sync)) {
    let next = AtomicUsize::new(0);
    let arp = ArpCache::new();
    let (admin_tx, admin_rx) = mpsc::channel::<HostResult>();
    let admin_rx = Mutex::new(admin_rx);
    let admin_queued = AtomicUsize::new(0);
    let admin_done = AtomicUsize::new(0);
    let scanners = cfg.threads.clamp(1, 512).min(cfg.targets.len());
    let tally = Mutex::new(Tally::default());
    let spawn = |name: &str| std::thread::Builder::new().name(name.into());
    let upnp = crate::ssdp::Discovery::new();
    let on_link = |ip: &Ipv4Addr| cfg.on_link.iter().any(|&(net, prefix)| crate::targets::in_subnet(*ip, net, prefix));
    let ask_upnp = cfg.local_discovery && cfg.targets.iter().any(on_link);

    std::thread::scope(|s| {
        // Ask the local network's UPnP devices to announce themselves while
        // the first addresses are being scanned.
        let (upnp, local) = (&upnp, cfg.local.keys().copied().collect::<Vec<_>>());
        if spawn("upnp").spawn_scoped(s, move || upnp.run(&local, ask_upnp)).is_err() {
            upnp.run(&[], false);
        }
        // ...and the IPv6 ones to show up in the OS neighbour table.
        let ipv6 = ask_upnp.then(|| spawn("ipv6").spawn_scoped(s, || crate::ipv6::solicit(&cfg.interface_names)).ok()).flatten();

        let mut workers = Vec::with_capacity(scanners);
        for _ in 0..scanners {
            let (tx, next, arp, admin_tx) = (tx.clone(), &next, &arp, admin_tx.clone());
            let (admin_queued, tally) = (&admin_queued, &tally);
            let worker = spawn("scan").spawn_scoped(s, move || {
                loop {
                    if cancel.load(Ordering::Relaxed) {
                        break;
                    }
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    let Some(&ip) = cfg.targets.get(i) else { break };
                    // Whatever a device sends back, one host must never be
                    // able to end the whole scan.
                    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| scan_host(ip, cfg, arp, upnp)))
                        .unwrap_or_else(|_| {
                            crate::diag::log(format!("scanning {ip} failed with an internal error; reported as not answering"));
                            HostResult::new(ip)
                        });
                    lock(tally).add(&result);
                    if wants_admin_details(&result, cfg) {
                        admin_queued.fetch_add(1, Ordering::Relaxed);
                        let _ = admin_tx.send(result.clone());
                    }
                    if tx.send(ScanEvent::Host(result)).is_err() {
                        break;
                    }
                    notify();
                }
            });
            match worker {
                Ok(w) => workers.push(w),
                // Out of threads: carry on with the ones we got.
                Err(e) => {
                    crate::diag::log(format!("could only start {} of {scanners} scan threads: {e}", workers.len()));
                    break;
                }
            }
        }
        drop(admin_tx); // admin workers stop once every scanner has finished

        if cfg.admin_queries {
            for _ in 0..ADMIN_WORKERS {
                let (tx, admin_rx, admin_done) = (tx.clone(), &admin_rx, &admin_done);
                let _ = spawn("admin").spawn_scoped(s, move || loop {
                    let next = lock(admin_rx).recv();
                    let Ok(mut r) = next else { break };
                    if !cancel.load(Ordering::Relaxed) {
                        add_admin_details(&mut r, cfg);
                    }
                    admin_done.fetch_add(1, Ordering::Relaxed);
                    if tx.send(ScanEvent::Update(r)).is_err() {
                        break;
                    }
                    notify();
                });
            }
        }

        // Every address has been scanned once the scanners are done; admin
        // lookups may still be running.
        for w in workers {
            let _ = w.join();
        }
        let echoes = lock(&tally).firewall_echoes();
        if !echoes.is_empty() {
            let _ = tx.send(ScanEvent::NotAlive(echoes));
        }
        // The probes made the OS re-check its old ARP entries; the ones it
        // has dropped since belong to devices that are no longer there.
        let departed = arp.departed(&lock(&tally).arp_cached);
        if !departed.is_empty() {
            let _ = tx.send(ScanEvent::Departed(departed));
        }
        if cfg.local_discovery {
            if let Some(job) = ipv6 {
                let _ = job.join();
            }
            let neighbors = crate::ipv6::neighbors();
            if !neighbors.is_empty() {
                let _ = tx.send(ScanEvent::Neighbors(neighbors));
            }
        }
        let pending = admin_queued.load(Ordering::Relaxed).saturating_sub(admin_done.load(Ordering::Relaxed));
        let _ = tx.send(ScanEvent::HostsDone { admin_pending: pending });
        notify();
    });
}

/// Seen only via TCP: no ping reply, no ARP/MAC, no NetBIOS.
fn is_tcp_only(r: &HostResult) -> bool {
    r.alive == Some(AliveBy::Tcp) && r.mac.is_none() && r.netbios_name.is_none()
}

/// What the firewall-echo check needs to know about the scan so far.
#[derive(Default)]
struct Tally {
    /// Hosts seen only through TCP, with the ports they had open.
    tcp_only: Vec<(Ipv4Addr, Vec<u16>)>,
    /// Addresses that didn't answer at all, counted per /24.
    silent: HashMap<u32, usize>,
    /// Hosts known only from an ARP entry older than the scan.
    arp_cached: Vec<Ipv4Addr>,
}

fn net24(ip: Ipv4Addr) -> u32 {
    u32::from(ip) >> 8
}

impl Tally {
    fn add(&mut self, r: &HostResult) {
        if r.alive == Some(AliveBy::ArpCached) {
            self.arp_cached.push(r.ip);
        }
        if is_tcp_only(r) {
            self.tcp_only.push((r.ip, r.open_ports.clone()));
        } else if r.alive.is_none() {
            *self.silent.entry(net24(r.ip)).or_default() += 1;
        }
    }

    fn firewall_echoes(&self) -> Vec<Ipv4Addr> {
        firewall_echoes(&self.tcp_only, &self.silent)
    }
}

/// Spots a firewall or web proxy answering for addresses where nothing lives.
///
/// Some firewalls between VLANs reply "connection refused" for every address
/// they block, and transparent web proxies accept port 80/443 for any address.
/// Either makes empty addresses look alive. The tell is a group of TCP-only
/// "hosts" in one /24 with exactly the same answer that a real device
/// wouldn't give (all ports refused, or only web ports open) which accounts
/// for nearly every address there that isn't a real device: a firewall
/// answers for all of them, so hardly any stay silent.
///
/// Judging each /24 on its own (rather than the whole range) catches one
/// echoing subnet inside a big scan, and leaves alone a handful of real
/// ping-blocking web servers surrounded by silent, unused addresses.
/// `silent` is how many addresses in each /24 (see [`net24`]) didn't answer.
pub fn firewall_echoes(tcp_only: &[(Ipv4Addr, Vec<u16>)], silent: &HashMap<u32, usize>) -> Vec<Ipv4Addr> {
    const MIN_GROUP: usize = 8;
    let web_only = |ports: &Vec<u16>| ports.iter().all(|p| [80, 443, 8080].contains(p));
    let mut groups: HashMap<(u32, &Vec<u16>), Vec<Ipv4Addr>> = HashMap::new();
    for (ip, ports) in tcp_only.iter().filter(|(_, p)| web_only(p)) {
        groups.entry((net24(*ip), ports)).or_default().push(*ip);
    }
    let mut out: Vec<Ipv4Addr> = groups
        .into_iter()
        .filter(|((net, _), group)| {
            let unanswered = silent.get(net).copied().unwrap_or(0);
            // At least 9 in 10 of the addresses without a real device.
            group.len() >= MIN_GROUP && group.len() * 10 >= (group.len() + unanswered) * 9
        })
        .flat_map(|(_, group)| group)
        .collect();
    out.sort();
    out
}

/// Only Windows PCs with the RPC port (135) open can answer WMI; anything
/// else would just sit until the timeout.
fn wants_admin_details(r: &HostResult, cfg: &ScanConfig) -> bool {
    cfg.admin_queries && r.alive.is_some() && !is_tcp_only(r) && r.alive != Some(AliveBy::Local) && r.open_ports.contains(&135)
}

fn add_admin_details(r: &mut HostResult, cfg: &ScanConfig) {
    let w = match wmi::query(r.ip, ADMIN_TIMEOUT) {
        Ok(w) => w,
        Err(e) => {
            // No access or blocked; `query user` would fail the same way.
            crate::diag::log(format!("admin details for {}: {e}", r.ip));
            r.admin = AdminDetails::Failed;
            return;
        }
    };
    r.admin = AdminDetails::Answered;
    if r.mac.is_none() {
        r.mac = w.mac; // the only MAC source for hosts on other VLANs
        r.vendor = r.mac.as_deref().and_then(identify::vendor);
    }
    if r.netbios_name.is_none() {
        r.netbios_name = w.computer;
    }
    r.domain = w.domain;
    r.os_name = w.os;
    r.model = w.model;
    merge_users(&mut r.users, w.user.into_iter().collect());
    merge_users(&mut r.users, netbios::remote_sessions(r.ip));
    r.device = Some(identify::classify(r, cfg.gateway, false));
}

fn scan_host(ip: Ipv4Addr, cfg: &ScanConfig, arp: &ArpCache, upnp: &crate::ssdp::Discovery) -> HostResult {
    let mut r = HostResult::new(ip);
    let began = Instant::now();
    let timeout = Duration::from_millis(cfg.timeout_ms);
    let is_self = cfg.local.contains_key(&ip);
    let on_link = !is_self && cfg.on_link.iter().any(|&(net, prefix)| crate::targets::in_subnet(ip, net, prefix));

    // Ping, the port probes, NetBIOS and (on our own subnet) a fresh ARP
    // request all run at the same time, so an address where nothing answers
    // costs one timeout rather than one per kind of probe. ARP matters
    // because every device must answer it, even ones that ignore ping and TCP.
    // NetBIOS is asked regardless: some Windows hosts drop ping but answer it.
    //
    // The ARP request is not waited for beyond the timeout: a device that is
    // there answers within milliseconds, while the OS can take several
    // seconds to give up on an address nobody is using.
    let arp_answer = on_link.then(|| {
        let (tx, rx) = mpsc::channel();
        std::thread::Builder::new()
            .name("arp".into())
            .spawn(move || {
                let _ = tx.send(probe::arp_request(ip));
            })
            .ok()
            .map(|_| rx)
    });
    let (ping, ports, nb) = std::thread::scope(|s| {
        let ping_job = s.spawn(move || probe::ping(ip, cfg.timeout_ms));
        let nb_job = cfg.netbios.then(|| s.spawn(move || netbios::query(ip, timeout)));
        let ports = (!cfg.ports.is_empty())
            .then(|| probe::probe_ports(ip, &cfg.ports, timeout.min(Duration::from_millis(1500))));
        let ping = ping_job.join().ok().flatten();
        let nb = nb_job.and_then(|j| j.join().ok()).flatten();
        (ping, ports, nb)
    });
    let arp_reply = match arp_answer {
        // Not on our subnet, or the request couldn't be started.
        None | Some(None) => ArpReply::Unsupported,
        Some(Some(answer)) => {
            let left = timeout.saturating_sub(began.elapsed()).max(Duration::from_millis(20));
            answer.recv_timeout(left).unwrap_or(ArpReply::NoReply)
        }
    };

    if let Some(reply) = ping {
        r.alive = Some(AliveBy::Ping);
        r.rtt_ms = Some(reply.rtt_ms);
        r.ttl = reply.ttl;
    }
    if let Some((open, answered)) = ports {
        r.open_ports = open;
        if answered && r.alive.is_none() {
            r.alive = Some(AliveBy::Tcp);
        }
    }

    if let Some(local_mac) = cfg.local.get(&ip) {
        r.alive = Some(AliveBy::Local);
        r.mac = local_mac.clone();
    } else {
        match arp_reply {
            ArpReply::Mac(mac) => {
                r.mac = Some(mac);
                r.alive.get_or_insert(AliveBy::Arp);
            }
            // A fresh ARP request went unanswered: don't trust a cached entry.
            ArpReply::NoReply => {}
            // No ARP API (macOS/Linux): the probes above filled the OS ARP
            // cache for hosts on the local subnet. An entry that was already
            // there before the scan may be left over from a device that has
            // gone, so it's shown as such.
            ArpReply::Unsupported => {
                if let Some(entry) = arp.lookup(ip) {
                    r.mac = Some(entry.mac);
                    r.alive.get_or_insert(if entry.cached { AliveBy::ArpCached } else { AliveBy::Arp });
                }
            }
        }
    }

    if let Some(nb) = nb {
        // A NetBIOS answer upgrades "was in the ARP cache" to "is here now".
        if matches!(r.alive, None | Some(AliveBy::ArpCached)) {
            r.alive = Some(AliveBy::NetBios);
        }
        r.netbios_name = nb.computer;
        r.workgroup = nb.workgroup;
        r.users = nb.users;
        if r.mac.is_none() {
            r.mac = nb.mac;
        }
    }

    if r.alive.is_none() {
        return r;
    }

    // Questions only some devices answer run beside the name lookups and
    // banner reads below, so they don't add their waits to each live host.
    let side_timeout = timeout.min(Duration::from_millis(800));
    let mdns = (on_link && cfg.local_discovery).then(|| background(move || crate::mdns::query(ip, side_timeout))).flatten();
    let snmp = cfg.snmp_community.clone().and_then(|c| background(move || crate::snmp::query(ip, &c, side_timeout)));

    if cfg.resolve_names {
        let dns_timeout = Duration::from_millis(cfg.timeout_ms.max(1500));
        if let Some(name) = reverse_dns(ip, dns_timeout) {
            // A PTR record left behind by the address's previous owner would
            // give the wrong name, so check it resolves back to this address.
            if !is_self && resolves_elsewhere(&name, ip, dns_timeout) {
                r.dns_mismatch = Some(name);
            } else {
                r.hostname = Some(name);
            }
        }
    }

    let is_local = r.alive == Some(AliveBy::Local);
    if is_local {
        merge_users(&mut r.users, netbios::local_users());
        if r.hostname.is_none() {
            r.hostname = dns_lookup::get_hostname().ok();
        }
    }

    r.vendor = r.mac.as_deref().and_then(identify::vendor);
    let banner_timeout = timeout.max(Duration::from_millis(800));
    if let Some(&port) = [80, 8080, 5000].iter().find(|p| r.open_ports.contains(p)) {
        r.http_banner = identify::http_banner(ip, port, banner_timeout);
    }
    if r.open_ports.contains(&22) {
        r.ssh_banner = identify::ssh_banner(ip, banner_timeout);
    }
    if r.open_ports.contains(&443) {
        r.tls_name = crate::tls::certificate_name(ip, 443, banner_timeout);
    }
    if on_link && let Some(reply) = upnp.reply(ip) {
        r.upnp = crate::ssdp::describe(ip, &reply, banner_timeout);
    }
    if let Some(m) = mdns.and_then(|job| job.recv().ok()).flatten() {
        r.hostname = r.hostname.take().or(m.name);
        r.model = r.model.take().or(m.model);
        r.mdns_services = m.services;
    }
    r.snmp = snmp.and_then(|job| job.recv().ok()).flatten();
    r.device = Some(identify::classify(&r, cfg.gateway, is_local));
    r
}

/// Run `job` on its own thread; its result arrives on the returned channel.
/// `None` if no thread could be started.
fn background<T: Send + 'static>(job: impl FnOnce() -> T + Send + 'static) -> Option<Receiver<T>> {
    let (tx, rx) = mpsc::channel();
    std::thread::Builder::new()
        .name("probe".into())
        .spawn(move || {
            let _ = tx.send(job());
        })
        .ok()
        .map(|_| rx)
}

/// Caps the DNS lookups running at once. The OS resolver can't be cancelled,
/// so a lookup that outlives its deadline keeps its thread until it returns;
/// with a broken DNS server every live host would otherwise leave threads
/// behind for half a minute each.
struct DnsSlots {
    busy: Mutex<usize>,
    freed: Condvar,
}

const MAX_DNS_LOOKUPS: usize = 64;
static DNS: DnsSlots = DnsSlots { busy: Mutex::new(0), freed: Condvar::new() };

/// Run a blocking resolver call on its own thread, giving up after
/// `timeout` (including any wait for a free slot).
fn dns_call<T: Send + 'static>(timeout: Duration, call: impl FnOnce() -> T + Send + 'static) -> Option<T> {
    let deadline = Instant::now() + timeout;
    {
        let mut busy = lock(&DNS.busy);
        while *busy >= MAX_DNS_LOOKUPS {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return None;
            }
            busy = DNS.freed.wait_timeout(busy, left).unwrap_or_else(std::sync::PoisonError::into_inner).0;
        }
        *busy += 1;
    }
    let release = || {
        *lock(&DNS.busy) -= 1;
        DNS.freed.notify_one();
    };
    let (tx, rx) = mpsc::channel();
    let started = std::thread::Builder::new().name("dns".into()).spawn(move || {
        let _ = tx.send(call());
        release();
    });
    if started.is_err() {
        release();
        return None;
    }
    rx.recv_timeout(deadline.saturating_duration_since(Instant::now())).ok()
}

/// Reverse DNS with a deadline. The OS resolver can block for ~30 s on hosts
/// without a PTR record (macOS falls back to mDNS), so the lookup runs on its
/// own thread and is abandoned if it doesn't answer in time.
fn reverse_dns(ip: Ipv4Addr, timeout: Duration) -> Option<String> {
    dns_call(timeout, move || dns_lookup::lookup_addr(&IpAddr::V4(ip)).ok())
        .flatten()
        .filter(|h| h != &ip.to_string())
        .map(|h| h.trim_end_matches('.').to_string())
}

/// True when `name` definitely doesn't point back at `ip`: it resolves to
/// other addresses only, or not at all. A slow or failed lookup counts as
/// "can't tell" (false).
fn resolves_elsewhere(name: &str, ip: Ipv4Addr, timeout: Duration) -> bool {
    use dns_lookup::LookupErrorKind;
    let owned = name.to_string();
    let result = dns_call(timeout, move || {
        dns_lookup::lookup_host(&owned).map(|addrs| addrs.collect::<Vec<_>>()).map_err(|e| e.kind())
    });
    match result {
        Some(Ok(addrs)) => !addrs.is_empty() && !addrs.contains(&IpAddr::V4(ip)),
        // NXDOMAIN / no A record: nothing points at this address any more.
        Some(Err(LookupErrorKind::NoName | LookupErrorKind::NoData)) => true,
        _ => false,
    }
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

    fn tally(hosts: &[(Ipv4Addr, Option<Vec<u16>>)]) -> Tally {
        let mut t = Tally::default();
        for (ip, ports) in hosts {
            let mut r = HostResult::new(*ip);
            if let Some(ports) = ports {
                r.alive = Some(AliveBy::Tcp);
                r.open_ports = ports.clone();
            }
            t.add(&r);
        }
        t
    }

    #[test]
    fn spots_firewall_echoes() {
        let ip = |n: u8| Ipv4Addr::new(10, 9, 0, n);
        // A firewall refusing everything for the 251 empty addresses of a
        // /24, plus a few real ping-blocking hosts.
        let mut seen: Vec<(Ipv4Addr, Option<Vec<u16>>)> = (1..=251).map(|n| (ip(n), Some(vec![]))).collect();
        seen.push((ip(252), Some(vec![22])));
        seen.push((ip(253), Some(vec![135, 445])));
        seen.push((ip(254), Some(vec![443])));
        let echoes = tally(&seen).firewall_echoes();
        assert_eq!(echoes.len(), 251);
        assert!(!echoes.contains(&ip(252)) && !echoes.contains(&ip(254)));

        // A handful of TCP-only hosts is normal, not a firewall.
        assert!(tally(&seen[246..]).firewall_echoes().is_empty());
    }

    #[test]
    fn firewall_echoes_are_judged_per_subnet() {
        // One echoing /24 inside a /16 scan where everything else is silent:
        // far less than a quarter of the range, but all of its own subnet.
        let mut seen: Vec<(Ipv4Addr, Option<Vec<u16>>)> = Vec::new();
        for third in 0..=255u8 {
            for last in 1..=254u8 {
                let echo = third == 7;
                seen.push((Ipv4Addr::new(10, 9, third, last), echo.then(|| vec![80, 443])));
            }
        }
        let echoes = tally(&seen).firewall_echoes();
        assert_eq!(echoes.len(), 254);
        assert!(echoes.iter().all(|ip| ip.octets()[2] == 7));
    }

    #[test]
    fn real_web_servers_among_unused_addresses_stay_alive() {
        // A /28 with ten real ping-blocking servers that only expose 443 and
        // four unused addresses: a firewall would have answered for those too.
        let ip = |n: u8| Ipv4Addr::new(10, 50, 0, n);
        let seen: Vec<(Ipv4Addr, Option<Vec<u16>>)> =
            (1..=14).map(|n| (ip(n), (n <= 10).then(|| vec![443]))).collect();
        assert!(tally(&seen).firewall_echoes().is_empty());
    }

    #[test]
    fn scan_reports_every_host_then_finishes() {
        // Loopback addresses only, so nothing leaves this machine.
        let cfg = ScanConfig {
            targets: (1..=20).map(|n| Ipv4Addr::new(127, 0, 0, n)).collect(),
            threads: 4,
            timeout_ms: 100,
            ports: Vec::new(),
            resolve_names: false,
            netbios: false,
            admin_queries: false,
            // Every target is "this machine", so no ping is needed to answer.
            local: (1..=20).map(|n| (Ipv4Addr::new(127, 0, 0, n), None)).collect(),
            on_link: Vec::new(),
            gateway: None,
            local_discovery: true,
            snmp_community: None,
            interface_names: Vec::new(),
        };
        let scan = start(cfg, || {});
        let events: Vec<ScanEvent> = scan.rx.iter().collect();
        assert_eq!(events.iter().filter(|e| matches!(e, ScanEvent::Host(_))).count(), 20);
        assert!(events.iter().any(|e| matches!(e, ScanEvent::HostsDone { admin_pending: 0 })));
        assert!(matches!(events.last(), Some(ScanEvent::Finished)));
    }

    #[test]
    fn ipv6_addresses_are_matched_by_mac() {
        let mut neighbors = HashMap::new();
        neighbors.insert("AA:BB:CC:00:00:01".to_string(), vec!["2001:db8::1".parse().unwrap(), "fe80::1".parse().unwrap()]);
        let mut r = HostResult::new(Ipv4Addr::new(10, 0, 0, 5));
        r.set_ipv6(&neighbors);
        assert!(r.ipv6.is_empty(), "no MAC, no match");
        r.mac = Some("AA:BB:CC:00:00:01".into());
        r.set_ipv6(&neighbors);
        assert_eq!(r.ipv6_text(), "2001:db8::1, fe80::1");
        // The name set on a device over SNMP is the last resort for a name.
        r.snmp = Some(crate::snmp::Info { name: Some("sw-core-01".into()), ..Default::default() });
        assert_eq!(r.display_name().as_deref(), Some("sw-core-01"));
        r.hostname = Some("switch1.corp.example".into());
        assert_eq!(r.display_name().as_deref(), Some("switch1"));
    }

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
