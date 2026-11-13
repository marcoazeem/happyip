// Hide the console window on Windows release builds.
#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

mod actions;
mod ad;
mod cli;
mod demo;
mod diag;
mod export;
mod history;
mod identify;
mod ipv6;
mod mdns;
mod netbios;
mod probe;
mod report;
mod scanner;
mod settings;
mod snmp;
mod ssdp;
mod targets;
mod tls;
mod util;
mod wmi;

use std::cmp::Ordering;
use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use eframe::egui::{self, Color32, RichText};
use egui_extras::{Column, TableBuilder};

use ad::Directory;
use scanner::{AdminDetails, HostResult, ScanConfig, ScanEvent, ScanHandle};
use targets::{LocalInterface, NetSource, Network};
use util::lock;

const SOFTWARE_FLAG: &str = "--software";
/// Common services plus ports that help fingerprint devices: AFP (548, Mac),
/// RTSP (554, cameras), IPP/JetDirect (631/9100, printers), 5000 (NAS),
/// 8009 (Chromecast), 62078 (iPhone/iPad sync).
pub(crate) const DEFAULT_PORTS: &str = "22, 80, 135, 139, 443, 445, 548, 554, 631, 3389, 5000, 5900, 8009, 8080, 9100, 62078";
/// How long the Active Directory query may take (big domains, slow links).
pub(crate) const AD_TIMEOUT: Duration = Duration::from_secs(120);
/// Colour of error messages and rejected input.
const ERROR_COLOR: Color32 = Color32::from_rgb(224, 82, 60);

fn main() {
    diag::install_panic_hook();
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        // happyip --cli [range...] [--report file.html] [--csv file] [--json file] ...
        Some("--cli") => std::process::exit(cli::run(args.get(2..).unwrap_or_default())),
        Some("--help" | "-h") => println!("{}\n\nWithout --cli, HappyIP opens its window (--demo shows sample data).", cli::USAGE),
        Some("--demo-report") => {
            let path = args.get(2).map(String::as_str).unwrap_or("happyip-demo-report.html");
            let directory = demo::directory();
            let mut results = demo::results();
            for r in &mut results {
                r.enrich(Some(&directory), &directory.networks(), Some(demo::GATEWAY));
            }
            let alive: Vec<&HostResult> = results.iter().filter(|r| r.alive.is_some()).collect();
            let meta = report::ReportMeta {
                range: demo::RANGE.into(),
                generated: chrono::Local::now().format("%Y-%m-%d %H:%M").to_string(),
                scanned_from: "IT-ADMIN01".into(),
                hosts_scanned: results.len(),
                domain: Some(directory.domain.clone()),
                duration: Some(3.9),
            };
            match std::fs::write(path, report::html(&meta, &alive)) {
                Ok(()) => eprintln!("Demo report written to {path}"),
                Err(e) => {
                    eprintln!("error writing {path}: {e}");
                    std::process::exit(1);
                }
            }
        }
        Some(SOFTWARE_FLAG) => run_software(),
        _ => run_gpu(),
    }
}

/// `--demo` fills the window with a fictional network instead of scanning.
fn demo_mode() -> bool {
    std::env::args().any(|a| a == "--demo")
}

fn viewport() -> egui::ViewportBuilder {
    // Reopen at the size the window had last time.
    let saved = if demo_mode() { None } else { settings::load().window };
    let (w, h) = saved.unwrap_or((1180.0, 720.0));
    egui::ViewportBuilder::default()
        .with_title("HappyIP")
        .with_inner_size([w.max(760.0), h.max(400.0)])
        .with_min_inner_size([760.0, 400.0])
}

/// Normal path: GPU-rendered window via wgpu (DirectX 12 / Vulkan / OpenGL / Metal).
fn run_gpu() {
    let options = eframe::NativeOptions { viewport: viewport(), ..Default::default() };
    let result = eframe::run_native("HappyIP", options, Box::new(|cc| Ok(Box::new(App::new(cc.egui_ctx.clone())))));
    if let Err(e) = result {
        // No usable GPU (old Windows Server, VMs, Remote Desktop). winit can't
        // create a second event loop in one process, so relaunch ourselves in
        // CPU-rendering mode instead.
        diag::log(format!("GPU renderer unavailable ({e}); falling back to software rendering"));
        let relaunched = std::env::current_exe().and_then(|exe| {
            let mut cmd = std::process::Command::new(exe);
            cmd.arg(SOFTWARE_FLAG);
            if demo_mode() {
                cmd.arg("--demo");
            }
            cmd.spawn()
        });
        if let Err(spawn_err) = relaunched {
            show_fatal(&format!("{e}\n\nSoftware fallback also failed: {spawn_err}"));
        }
    }
}

/// Fallback path: the window is rasterized on the CPU and blitted with GDI /
/// the native compositor, so no GPU or OpenGL driver is needed.
fn run_software() {
    let config = egui_software_backend::SoftwareBackendAppConfiguration::new().viewport_builder(viewport());
    if let Err(e) = egui_software_backend::run_app_with_software_backend(config, App::new) {
        show_fatal(&format!("{e:?}"));
    }
}

fn show_fatal(msg: &str) {
    diag::log(format!("could not start: {msg}"));
    rfd::MessageDialog::new()
        .set_level(rfd::MessageLevel::Error)
        .set_title("HappyIP could not start")
        .set_description(msg)
        .show();
}

/// A table column; also what the table is sorted by.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum SortKey {
    Ip,
    Ipv6,
    Device,
    NetBios,
    Users,
    Mac,
    Vendor,
    Network,
    Domain,
    Ad,
    Hostname,
    Ping,
    Ttl,
    Ports,
    SeenVia,
    Changes,
}

impl SortKey {
    /// Every column, in the order they are shown.
    const ALL: [SortKey; 16] = [
        SortKey::Ip,
        SortKey::Ipv6,
        SortKey::Device,
        SortKey::NetBios,
        SortKey::Users,
        SortKey::Mac,
        SortKey::Vendor,
        SortKey::Network,
        SortKey::Domain,
        SortKey::Ad,
        SortKey::Hostname,
        SortKey::Ping,
        SortKey::Ttl,
        SortKey::Ports,
        SortKey::SeenVia,
        SortKey::Changes,
    ];

    /// Name used in the settings file.
    fn name(self) -> &'static str {
        match self {
            SortKey::Ip => "ip",
            SortKey::Ipv6 => "ipv6",
            SortKey::Ping => "ping",
            SortKey::Hostname => "hostname",
            SortKey::Mac => "mac",
            SortKey::NetBios => "name",
            SortKey::Users => "users",
            SortKey::Device => "device",
            SortKey::Vendor => "vendor",
            SortKey::Network => "network",
            SortKey::Domain => "domain",
            SortKey::Ad => "ad",
            SortKey::Ttl => "ttl",
            SortKey::Ports => "ports",
            SortKey::SeenVia => "seen_via",
            SortKey::Changes => "changes",
        }
    }

    fn from_name(name: &str) -> Option<SortKey> {
        Self::ALL.into_iter().find(|k| k.name() == name)
    }

    fn title(self) -> &'static str {
        match self {
            SortKey::Ip => "IP",
            SortKey::Ipv6 => "IPv6",
            SortKey::Device => "Device",
            SortKey::NetBios => "Computer name",
            SortKey::Users => "Logged-in users",
            SortKey::Mac => "MAC address",
            SortKey::Vendor => "Vendor",
            SortKey::Network => "Network / site",
            SortKey::Domain => "Domain / workgroup",
            SortKey::Ad => "AD (OU)",
            SortKey::Hostname => "Hostname",
            SortKey::Ping => "Ping",
            SortKey::Ttl => "TTL",
            SortKey::Ports => "Open ports",
            SortKey::SeenVia => "Seen via",
            SortKey::Changes => "Changes",
        }
    }

    /// Width before the user has resized the column.
    fn default_width(self) -> f32 {
        match self {
            SortKey::Ip => 110.0,
            SortKey::Device | SortKey::Vendor | SortKey::Ad => 150.0,
            SortKey::NetBios => 140.0,
            SortKey::Users => 120.0,
            SortKey::Mac | SortKey::Ports => 130.0,
            SortKey::Network | SortKey::Ipv6 => 190.0,
            SortKey::Domain => 110.0,
            SortKey::Hostname => 170.0,
            SortKey::Ping => 60.0,
            SortKey::Ttl => 44.0,
            SortKey::SeenVia => 90.0,
            SortKey::Changes => 160.0,
        }
    }
}

/// Background Active Directory lookup.
enum AdState {
    Off,
    Loading,
    Ready(Arc<Directory>),
    Failed(String),
}

/// A text box whose content was rejected, shown in the error colour until
/// it's edited.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Input {
    Range,
    Ports,
}

/// Computer names in the range being looked up in DNS (off the UI thread,
/// since each can take seconds), with the ports to scan once that's done.
struct Resolving {
    rx: Receiver<Result<Vec<Ipv4Addr>, String>>,
    ports: Vec<u16>,
}

struct App {
    ctx: egui::Context,
    interfaces: Vec<LocalInterface>,
    /// Local, routed and (once loaded) AD networks, for the Networks menu
    /// and the Network / site column.
    networks: Vec<Network>,
    range: String,
    threads: usize,
    timeout_ms: u64,
    ports: String,
    resolve_names: bool,
    netbios: bool,
    admin_queries: bool,
    use_ad: bool,
    local_discovery: bool,
    snmp: bool,
    snmp_community: String,
    /// IPv6 addresses by MAC from the last scan, for rows whose MAC only
    /// arrives later (admin details).
    ipv6_neighbors: std::collections::HashMap<String, Vec<std::net::Ipv6Addr>>,
    show_dead: bool,
    filter: String,
    focus_filter: bool,
    bad_input: Option<Input>,

    ad_state: Arc<Mutex<AdState>>,
    /// The loaded directory, once applied to the networks and results.
    directory: Option<Arc<Directory>>,
    gateway: Option<Ipv4Addr>,

    results: Vec<HostResult>,
    resolving: Option<Resolving>,
    scan: Option<ScanHandle>,
    total: usize,
    started: Option<Instant>,
    elapsed: f32,
    /// Shown in the status bar; messages starting with ⚠ are errors.
    status: String,
    sort: (SortKey, bool),
    /// Selected rows, and the row a Shift-click extends the selection from.
    selected: HashSet<Ipv4Addr>,
    anchor: Option<Ipv4Addr>,
    hidden: HashSet<SortKey>,
    /// Column widths as last drawn (and so as dragged by the user).
    col_widths: std::collections::HashMap<SortKey, f32>,
    show_details: bool,
    recent: Vec<String>,
    favourites: Vec<settings::Favourite>,
    /// The one address being scanned again, when a single row is rescanned.
    rescan: Option<Ipv4Addr>,
    scanned_range: String,
    /// Seconds until every address was scanned (admin details may follow).
    hosts_done_in: Option<f32>,
    admin_total: usize,
    admin_done: usize,
    admin_answered: usize,
    admin_failed: usize,

    /// Settings as last written to disk, and when that was last checked.
    saved: settings::Settings,
    save_checked: Instant,
    window: Option<(f32, f32)>,
}

impl App {
    fn new(ctx: egui::Context) -> Self {
        let demo = demo_mode();
        let saved = if demo { settings::Settings::default() } else { settings::load() };
        let interfaces = if demo {
            vec![LocalInterface { name: "Ethernet".into(), ip: Ipv4Addr::new(10, 20, 0, 50), prefix: 24, mac: None }]
        } else {
            targets::local_interfaces()
        };
        let range = saved
            .range
            .clone()
            .or_else(|| interfaces.first().map(LocalInterface::suggested_range))
            .unwrap_or_else(|| "192.168.1.0/24".into());
        let sort = saved.sort.as_deref().and_then(SortKey::from_name).unwrap_or(SortKey::Ip);
        let mut app = Self {
            ctx,
            networks: Vec::new(),
            interfaces,
            range,
            threads: saved.threads,
            timeout_ms: saved.timeout_ms,
            ports: saved.ports.clone().unwrap_or_else(|| DEFAULT_PORTS.into()),
            resolve_names: saved.resolve_names,
            netbios: saved.netbios,
            admin_queries: demo || saved.admin_queries && cfg!(windows),
            use_ad: demo || saved.use_ad && cfg!(windows),
            local_discovery: saved.discovery,
            snmp: saved.snmp,
            snmp_community: saved.snmp_community.clone().unwrap_or_else(|| "public".into()),
            ipv6_neighbors: Default::default(),
            show_dead: saved.show_dead,
            filter: saved.filter.clone().unwrap_or_default(),
            focus_filter: false,
            bad_input: None,
            ad_state: Arc::new(Mutex::new(AdState::Off)),
            directory: None,
            gateway: if demo { Some(demo::GATEWAY) } else { None },
            results: Vec::new(),
            resolving: None,
            scan: None,
            total: 0,
            started: None,
            elapsed: 0.0,
            status: "Ready".into(),
            sort: (sort, saved.sort_ascending),
            selected: HashSet::new(),
            anchor: None,
            hidden: saved.hidden_columns.iter().filter_map(|n| SortKey::from_name(n)).filter(|k| *k != SortKey::Ip).collect(),
            col_widths: saved.column_widths.iter().filter_map(|(n, w)| Some((SortKey::from_name(n)?, *w))).collect(),
            show_details: saved.details,
            recent: saved.recent.clone(),
            favourites: saved.favourites.clone(),
            rescan: None,
            scanned_range: String::new(),
            hosts_done_in: None,
            admin_total: 0,
            admin_done: 0,
            admin_answered: 0,
            admin_failed: 0,
            window: saved.window,
            saved,
            save_checked: Instant::now(),
        };
        app.rebuild_networks(if demo { Vec::new() } else { targets::routed_networks() });
        if demo {
            *lock(&app.ad_state) = AdState::Ready(Arc::new(demo::directory()));
            app.results = demo::results();
            app.total = app.results.len();
            app.range = demo::RANGE.into();
            app.scanned_range = demo::RANGE.into();
            app.hosts_done_in = Some(3.9);
            app.status = format!("Done: {} scanned, {} alive in 3.9s (demo data)", app.total, app.alive_count());
        } else if app.use_ad {
            app.load_ad();
        }
        app
    }

    /// Local interfaces first, then routes and AD networks not already listed.
    fn rebuild_networks(&mut self, routed: Vec<Network>) {
        let mut nets: Vec<Network> = self.interfaces.iter().map(LocalInterface::network).collect();
        let known = |nets: &Vec<Network>, n: &Network| nets.iter().any(|m| m.network == n.network && m.prefix == n.prefix);
        let ad_nets = self.directory.as_ref().map(|d| d.networks()).unwrap_or_default();
        for n in ad_nets.into_iter().chain(routed) {
            if !known(&nets, &n) {
                nets.push(n);
            }
        }
        self.networks = nets;
    }

    fn load_ad(&mut self) {
        {
            let mut state = lock(&self.ad_state);
            if matches!(*state, AdState::Loading | AdState::Ready(_)) {
                return;
            }
            *state = AdState::Loading;
        }
        let (state, ctx) = (self.ad_state.clone(), self.ctx.clone());
        std::thread::spawn(move || {
            let result = ad::load(AD_TIMEOUT);
            *lock(&state) = match result {
                Ok(dir) => AdState::Ready(Arc::new(dir)),
                Err(e) => AdState::Failed(e),
            };
            ctx.request_repaint();
        });
    }

    /// Once the AD lookup finishes, add its subnets to the Networks menu and
    /// fill in AD details for hosts already scanned.
    fn sync_ad(&mut self) {
        if self.directory.is_some() || !self.use_ad {
            return;
        }
        let dir = match &*lock(&self.ad_state) {
            AdState::Ready(d) => d.clone(),
            _ => return,
        };
        self.directory = Some(dir);
        let routed: Vec<Network> = self.networks.iter().filter(|n| n.source == NetSource::Route).cloned().collect();
        self.rebuild_networks(routed);
        self.enrich_all();
    }

    fn active_directory(&self) -> Option<&Directory> {
        self.directory.as_deref().filter(|_| self.use_ad)
    }

    fn enrich_all(&mut self) {
        let dir = self.directory.clone().filter(|_| self.use_ad);
        for r in &mut self.results {
            r.enrich(dir.as_deref(), &self.networks, self.gateway);
        }
    }

    /// What to remember for next time. The range is the last one scanned
    /// and the ports the last valid list, so half-typed input isn't saved.
    fn settings(&self) -> settings::Settings {
        settings::Settings {
            range: self.saved.range.clone(),
            threads: self.threads,
            timeout_ms: self.timeout_ms,
            ports: if targets::parse_ports(&self.ports).is_ok() { Some(self.ports.clone()) } else { self.saved.ports.clone() },
            resolve_names: self.resolve_names,
            netbios: self.netbios,
            admin_queries: self.admin_queries,
            use_ad: self.use_ad,
            show_dead: self.show_dead,
            discovery: self.local_discovery,
            snmp: self.snmp,
            snmp_community: Some(self.snmp_community.trim().to_string()).filter(|c| !c.is_empty()),
            sort: Some(self.sort.0.name().into()),
            sort_ascending: self.sort.1,
            window: self.window,
            filter: Some(self.filter.clone()).filter(|f| !f.is_empty()),
            details: self.show_details,
            hidden_columns: SortKey::ALL.iter().filter(|k| self.hidden.contains(k)).map(|k| k.name().to_string()).collect(),
            column_widths: SortKey::ALL.iter().filter_map(|k| Some((k.name().to_string(), self.col_widths.get(k)?.round()))).collect(),
            recent: self.recent.clone(),
            favourites: self.favourites.clone(),
        }
    }

    /// Write the settings when they differ from what's on disk.
    fn save_settings(&mut self) {
        if demo_mode() {
            return;
        }
        let now = self.settings();
        if now == self.saved {
            return;
        }
        if let Err(e) = settings::save(&now) {
            diag::log(format!("could not save settings: {e}"));
        }
        // Also on failure, so a read-only folder isn't retried every frame.
        self.saved = now;
    }

    /// Save changed options shortly after they change, not only on Start.
    fn autosave(&mut self, ui: &egui::Ui) {
        let size = ui.ctx().input(|i| {
            let v = i.viewport();
            let normal = v.maximized != Some(true) && v.fullscreen != Some(true) && v.minimized != Some(true);
            v.inner_rect.filter(|_| normal).map(|r| (r.width().round(), r.height().round()))
        });
        if size.is_some() {
            self.window = size;
        }
        if self.save_checked.elapsed() >= Duration::from_secs(2) {
            self.save_checked = Instant::now();
            self.save_settings();
        } else if !demo_mode() && self.settings() != self.saved {
            ui.ctx().request_repaint_after(Duration::from_secs(2));
        }
    }

    fn fail(&mut self, message: impl std::fmt::Display) {
        self.status = format!("⚠ {message}");
    }

    /// A scan is running or about to (names are being looked up).
    fn busy(&self) -> bool {
        self.scan.is_some() || self.resolving.is_some()
    }

    fn start_scan(&mut self) {
        if demo_mode() {
            self.status = "Demo mode: scanning is disabled (restart without --demo)".into();
            return;
        }
        if self.busy() {
            return;
        }
        self.bad_input = None;
        let ports = match targets::parse_ports(&self.ports) {
            Ok(p) => p,
            Err(e) => {
                self.bad_input = Some(Input::Ports);
                return self.fail(e);
            }
        };
        if targets::has_names(&self.range) {
            // DNS lookups can take seconds each: keep the window responsive.
            let (tx, rx) = mpsc::channel();
            let (range, ctx) = (self.range.clone(), self.ctx.clone());
            std::thread::spawn(move || {
                let _ = tx.send(targets::parse_targets(&range));
                ctx.request_repaint();
            });
            self.resolving = Some(Resolving { rx, ports });
            self.status = "Looking up computer names…".into();
        } else {
            match targets::parse_targets(&self.range) {
                Ok(targets) => self.begin_scan(targets, ports),
                Err(e) => {
                    self.bad_input = Some(Input::Range);
                    self.fail(e);
                }
            }
        }
    }

    fn poll_resolving(&mut self) {
        let Some(resolving) = &self.resolving else { return };
        let result = match resolving.rx.try_recv() {
            Ok(result) => result,
            Err(TryRecvError::Empty) => return,
            Err(TryRecvError::Disconnected) => Err("the name lookup failed".into()),
        };
        let Some(Resolving { ports, .. }) = self.resolving.take() else { return };
        match result {
            Ok(targets) => self.begin_scan(targets, ports),
            Err(e) => {
                self.bad_input = Some(Input::Range);
                self.fail(e);
            }
        }
    }

    fn scan_config(&self, targets: Vec<Ipv4Addr>, ports: Vec<u16>) -> ScanConfig {
        ScanConfig {
            targets,
            threads: self.threads,
            timeout_ms: self.timeout_ms,
            ports,
            resolve_names: self.resolve_names,
            netbios: self.netbios,
            admin_queries: self.admin_queries,
            local: self.interfaces.iter().map(|i| (i.ip, i.mac.clone())).collect(),
            on_link: self.interfaces.iter().map(LocalInterface::subnet).collect(),
            gateway: self.gateway,
            local_discovery: self.local_discovery,
            snmp_community: Some(self.snmp_community.trim().to_string()).filter(|c| self.snmp && !c.is_empty() && c.len() <= snmp::MAX_COMMUNITY),
            interface_names: self.interfaces.iter().map(|i| i.name.clone()).collect(),
        }
    }

    fn launch(&mut self, cfg: ScanConfig) {
        self.started = Some(Instant::now());
        self.admin_total = 0;
        self.admin_done = 0;
        self.admin_answered = 0;
        self.admin_failed = 0;
        let ctx = self.ctx.clone();
        self.scan = Some(scanner::start(cfg, move || ctx.request_repaint()));
    }

    fn begin_scan(&mut self, targets: Vec<Ipv4Addr>, ports: Vec<u16>) {
        let range = self.range.trim().to_string();
        self.recent.retain(|r| *r != range);
        self.recent.insert(0, range.clone());
        self.recent.truncate(settings::MAX_RECENT);
        self.saved.range = Some(self.range.clone());
        self.save_settings();
        self.gateway = identify::default_gateway();
        let cfg = self.scan_config(targets, ports);
        self.scanned_range = range;
        self.total = cfg.targets.len();
        self.results.clear();
        self.results.reserve(self.total);
        self.selected.clear();
        self.anchor = None;
        self.rescan = None;
        self.ipv6_neighbors.clear();
        self.hosts_done_in = None;
        self.status = format!("Scanning {} hosts…", self.total);
        self.launch(cfg);
    }

    /// Scan one address again and update its row, leaving the rest as it is.
    fn rescan_host(&mut self, ip: Ipv4Addr) {
        if demo_mode() {
            self.status = "Demo mode: scanning is disabled (restart without --demo)".into();
            return;
        }
        if self.busy() {
            return;
        }
        let ports = match targets::parse_ports(&self.ports) {
            Ok(p) => p,
            Err(e) => {
                self.bad_input = Some(Input::Ports);
                return self.fail(e);
            }
        };
        self.rescan = Some(ip);
        self.status = format!("Scanning {ip} again…");
        let cfg = self.scan_config(vec![ip], ports);
        self.launch(cfg);
    }

    /// Compare a finished scan with the previous one of the same range and
    /// remember it for next time. Returns what changed, for the status bar.
    fn record_history(&mut self) -> Option<String> {
        if demo_mode() {
            return None;
        }
        let previous = history::load(&self.scanned_range);
        let changes = previous.as_ref().map(|p| history::compare(p, &mut self.results).text(&p.when));
        let when = chrono::Local::now().format("%Y-%m-%d %H:%M").to_string();
        if let Err(e) = history::save(&self.scanned_range, &history::snapshot(&when, &self.results)) {
            diag::log(format!("could not save the scan history: {e}"));
        }
        changes
    }

    fn stop_scan(&mut self) {
        if self.resolving.take().is_some() {
            self.status = "Stopped".into();
        }
        if let Some(s) = &self.scan {
            s.stop();
            self.status = "Stopping…".into();
        }
    }

    fn poll_scan(&mut self) {
        let Some(scan) = &self.scan else { return };
        let dir = self.directory.clone().filter(|_| self.use_ad);
        let mut finished = false;
        loop {
            let ev = match scan.rx.try_recv() {
                Ok(ev) => ev,
                Err(TryRecvError::Empty) => break,
                // The scan thread is gone without saying so: never leave the
                // window stuck on "Scanning…".
                Err(TryRecvError::Disconnected) => {
                    finished = true;
                    break;
                }
            };
            match ev {
                ScanEvent::Host(mut h) => {
                    h.enrich(dir.as_deref(), &self.networks, self.gateway);
                    match self.results.iter_mut().find(|r| self.rescan == Some(r.ip) && r.ip == h.ip) {
                        // A single row scanned again: update it in place.
                        Some(row) => {
                            h.change = row.change.take();
                            *row = h;
                        }
                        None => self.results.push(h),
                    }
                }
                ScanEvent::Update(mut h) => {
                    h.enrich(dir.as_deref(), &self.networks, self.gateway);
                    h.set_ipv6(&self.ipv6_neighbors); // the MAC may be new
                    match h.admin {
                        AdminDetails::Answered => self.admin_answered += 1,
                        AdminDetails::Failed => self.admin_failed += 1,
                        AdminDetails::NotTried => {}
                    }
                    if let Some(row) = self.results.iter_mut().find(|r| r.ip == h.ip) {
                        h.change = row.change.take();
                        *row = h;
                    }
                    self.admin_done += 1;
                }
                ScanEvent::NotAlive(ips) => {
                    let ips: HashSet<Ipv4Addr> = ips.into_iter().collect();
                    for r in self.results.iter_mut().filter(|r| ips.contains(&r.ip)) {
                        r.alive = None;
                        r.firewall_reply = true;
                    }
                }
                ScanEvent::Neighbors(neighbors) => {
                    for r in &mut self.results {
                        r.set_ipv6(&neighbors);
                    }
                    self.ipv6_neighbors = neighbors;
                }
                ScanEvent::Departed(ips) => {
                    let ips: HashSet<Ipv4Addr> = ips.into_iter().collect();
                    for r in self.results.iter_mut().filter(|r| ips.contains(&r.ip)) {
                        r.alive = None;
                    }
                }
                ScanEvent::HostsDone { admin_pending } => {
                    if self.rescan.is_none() {
                        self.hosts_done_in = Some(self.elapsed_now());
                    }
                    self.admin_total = self.admin_done + admin_pending;
                }
                ScanEvent::Finished => finished = true,
            }
        }
        self.elapsed = self.elapsed_now();
        let alive = self.alive_count();
        if finished {
            self.scan = None;
            if let Some(ip) = self.rescan.take() {
                let via = self.results.iter().find(|r| r.ip == ip).map(|r| r.seen_via()).filter(|v| !v.is_empty());
                self.status = match via {
                    Some(via) => format!("Scanned {ip} again: alive ({via})"),
                    None => format!("Scanned {ip} again: no answer"),
                };
                return;
            }
            let complete = self.results.len() >= self.total;
            let stopped = if complete { "" } else { " (stopped)" };
            let hosts_in = self.hosts_done_in.unwrap_or(self.elapsed);
            // Only a complete scan says anything about what is gone.
            let changes = complete.then(|| self.record_history()).flatten().map(|c| format!("; {c}")).unwrap_or_default();
            let alive = self.alive_count();
            self.status =
                format!("Done{stopped}: {} scanned, {alive} alive in {hosts_in:.1}s{}{changes}", self.results.len(), self.admin_summary());
        } else if self.rescan.is_some() {
            // The status already says which address is being scanned again.
        } else if let Some(hosts_in) = self.hosts_done_in {
            self.status = format!(
                "Scanned {} hosts, {alive} alive in {hosts_in:.1}s. Getting admin details from Windows PCs: {}/{}…",
                self.results.len(),
                self.admin_done,
                self.admin_total
            );
        }
    }

    /// ", admin details from 12 of 40 Windows PCs…": says how many PCs
    /// actually answered, not how many were asked.
    fn admin_summary(&self) -> String {
        if self.admin_total == 0 {
            return String::new();
        }
        let (answered, failed) = (self.admin_answered, self.admin_failed);
        if failed == 0 {
            format!(", admin details from {answered} Windows PCs after {:.1}s", self.elapsed)
        } else {
            format!(
                ", admin details from {answered} of {} Windows PCs after {:.1}s ({failed} gave none: access denied or blocked by a firewall; see Copy diagnostics)",
                answered + failed,
                self.elapsed
            )
        }
    }

    fn elapsed_now(&self) -> f32 {
        self.started.map(|t| t.elapsed().as_secs_f32()).unwrap_or(self.elapsed)
    }

    fn alive_count(&self) -> usize {
        self.results.iter().filter(|r| r.alive.is_some()).count()
    }

    fn visible_rows(&self) -> Vec<usize> {
        let needle = self.filter.trim().to_lowercase();
        let mut rows: Vec<usize> = (0..self.results.len())
            .filter(|&i| {
                let r = &self.results[i];
                // A device that has gone since the last scan is worth
                // showing even when dead hosts are hidden.
                (self.show_dead || r.alive.is_some() || r.change.is_some()) && (needle.is_empty() || row_text(r).contains(&needle))
            })
            .collect();
        let (key, asc) = self.sort;
        rows.sort_by(|&a, &b| {
            let (a, b) = (&self.results[a], &self.results[b]);
            let ord = match key {
                SortKey::Ip => a.ip.cmp(&b.ip),
                // Hosts with an IPv6 address first.
                SortKey::Ipv6 => a.ipv6.is_empty().cmp(&b.ipv6.is_empty()).then_with(|| a.ipv6.cmp(&b.ipv6)),
                SortKey::Ping => cmp_opt(a.rtt_ms, b.rtt_ms),
                SortKey::Hostname => cmp_str(&a.hostname, &b.hostname),
                SortKey::Mac => cmp_str(&a.mac, &b.mac),
                SortKey::NetBios => cmp_str(&a.display_name(), &b.display_name()),
                SortKey::Device => cmp_str(&Some(a.device_text()), &Some(b.device_text())),
                SortKey::Vendor => cmp_str(&a.vendor, &b.vendor),
                SortKey::Users => cmp_str(&a.users.first().cloned(), &b.users.first().cloned()),
                SortKey::Network => cmp_str(&a.network, &b.network),
                SortKey::Domain => cmp_str(&a.domain_text(), &b.domain_text()),
                SortKey::Ad => cmp_str(&a.ad.as_ref().map(|_| a.ad_text()), &b.ad.as_ref().map(|_| b.ad_text())),
                SortKey::Ttl => cmp_opt(a.ttl.map(f64::from), b.ttl.map(f64::from)),
                // Hosts with open ports first, then by the ports themselves.
                SortKey::Ports => a.open_ports.is_empty().cmp(&b.open_ports.is_empty()).then_with(|| a.open_ports.cmp(&b.open_ports)),
                SortKey::SeenVia => {
                    let via = |r: &HostResult| Some(r.seen_via().to_string()).filter(|s| !s.is_empty());
                    cmp_str(&via(a), &via(b))
                }
                SortKey::Changes => {
                    let change = |r: &HostResult| r.change.as_ref().map(|c| c.label());
                    cmp_str(&change(a), &change(b))
                }
            };
            let ord = ord.then(a.ip.cmp(&b.ip));
            if asc { ord } else { ord.reverse() }
        });
        rows
    }

    /// Save the visible rows as CSV, or as JSON when the chosen file ends in `.json`.
    fn export_data(&mut self) {
        let Some(path) = rfd::FileDialog::new()
            .set_file_name("happyip-scan.csv")
            .add_filter("CSV (spreadsheet)", &["csv"])
            .add_filter("JSON", &["json"])
            .save_file()
        else {
            return;
        };
        let rows: Vec<&HostResult> = self.visible_rows().into_iter().map(|i| &self.results[i]).collect();
        let is_json = path.extension().is_some_and(|e| e.eq_ignore_ascii_case("json"));
        let out = if is_json {
            export::json(&self.scanned_range, &chrono::Local::now().format("%Y-%m-%d %H:%M").to_string(), &rows)
        } else {
            export::csv(&rows)
        };
        match std::fs::write(&path, out) {
            Ok(()) => self.status = format!("Exported {} rows to {}", rows.len(), path.display()),
            Err(e) => self.fail(format!("Export to {} failed: {e}", path.display())),
        }
    }

    fn export_report(&mut self) {
        let stamp = chrono::Local::now();
        let Some(path) = rfd::FileDialog::new()
            .set_file_name(format!("network-report-{}.html", stamp.format("%Y-%m-%d")))
            .add_filter("HTML report", &["html"])
            .save_file()
        else {
            return;
        };
        let hosts: Vec<&HostResult> = self
            .visible_rows()
            .into_iter()
            .map(|i| &self.results[i])
            .filter(|r| r.alive.is_some())
            .collect();
        let meta = report::ReportMeta {
            range: self.scanned_range.clone(),
            generated: stamp.format("%Y-%m-%d %H:%M").to_string(),
            scanned_from: dns_lookup::get_hostname().unwrap_or_default(),
            hosts_scanned: self.results.len(),
            domain: self.active_directory().map(|d| d.domain.clone()),
            duration: self.hosts_done_in,
        };
        match std::fs::write(&path, report::html(&meta, &hosts)) {
            Ok(()) => match actions::open_web(&path.to_string_lossy()) {
                Ok(()) => self.status = format!("Report saved to {}", path.display()),
                Err(e) => self.fail(format!("Report saved to {}, but {e}", path.display())),
            },
            Err(e) => self.fail(format!("Saving the report to {} failed: {e}", path.display())),
        }
    }

    /// Copy the selected rows, in the order shown, one per line.
    fn copy_selected(&mut self) {
        let rows: Vec<String> = self
            .visible_rows()
            .into_iter()
            .map(|i| &self.results[i])
            .filter(|r| self.selected.contains(&r.ip))
            .map(row_text_display)
            .collect();
        if rows.is_empty() {
            return;
        }
        self.status = if rows.len() == 1 { "Copied the selected row".into() } else { format!("Copied {} rows", rows.len()) };
        self.ctx.copy_text(rows.join("\n"));
    }

    fn run_action(&mut self, action: RowAction) {
        match action {
            RowAction::CopySelected => self.copy_selected(),
            RowAction::Rescan(ip) => self.rescan_host(ip),
            other => match other.run() {
                Ok(done) => self.status = done,
                Err(e) => {
                    diag::log(&e);
                    self.fail(e);
                }
            },
        }
    }

    /// Pin the current range (with its ports) to the Networks menu, or unpin it.
    fn toggle_favourite(&mut self) {
        let range = self.range.trim().to_string();
        if range.is_empty() {
            return;
        }
        let before = self.favourites.len();
        self.favourites.retain(|f| f.range != range);
        if self.favourites.len() == before {
            self.favourites.push(settings::Favourite { range, ports: self.ports.clone() });
        }
    }

    fn copy_diagnostics(&mut self) {
        // A community string other than the well-known default is a
        // password of sorts: it stays out of what gets pasted elsewhere.
        let mut settings = self.settings();
        if settings.snmp_community.as_deref().is_some_and(|c| c != "public") {
            settings.snmp_community = Some("(hidden)".into());
        }
        let report = diag::report(&settings::serialize(&settings));
        self.ctx.copy_text(report);
        self.status = match diag::log_path() {
            Some(p) => format!("Diagnostics copied to the clipboard (log file: {})", p.display()),
            None => "Diagnostics copied to the clipboard".into(),
        };
    }

    fn networks_menu(&mut self, ui: &mut egui::Ui) {
        // (range, add to the current range, ports that go with it)
        let mut picked: Option<(String, bool, Option<String>)> = None;
        egui::ComboBox::from_id_salt("networks")
            .selected_text(format!("Networks ({})", self.networks.len()))
            .width(150.0)
            .height(420.0)
            .show_ui(ui, |ui| {
                ui.label(RichText::new("Click to scan · Ctrl/⌘-click to add to the range").weak().small());
                if !self.favourites.is_empty() {
                    ui.separator();
                    ui.label(RichText::new("Pinned").strong());
                    for f in &self.favourites {
                        let ports = if f.ports.trim().is_empty() { "no ports".to_string() } else { format!("ports {}", f.ports) };
                        if ui.add(egui::Button::new(&f.range).frame(false)).on_hover_text(ports).clicked() {
                            picked = Some((f.range.clone(), false, Some(f.ports.clone())));
                        }
                    }
                }
                let recent: Vec<&String> = self.recent.iter().filter(|r| !self.favourites.iter().any(|f| f.range == **r)).collect();
                if !recent.is_empty() {
                    ui.separator();
                    ui.label(RichText::new("Recent").strong());
                    for r in recent {
                        if ui.add(egui::Button::new(r).frame(false)).clicked() {
                            picked = Some((r.clone(), false, None));
                        }
                    }
                }
                let groups = [
                    (NetSource::Local, "This computer"),
                    (NetSource::AdSubnet, "Active Directory sites & subnets"),
                    (NetSource::DnsZone, "DNS reverse zones"),
                    (NetSource::Route, "Routed networks"),
                ];
                for (source, title) in groups {
                    let nets: Vec<&Network> = self.networks.iter().filter(|n| n.source == source).collect();
                    if nets.is_empty() {
                        continue;
                    }
                    ui.separator();
                    ui.label(RichText::new(title).strong());
                    if source == NetSource::AdSubnet && nets.len() > 1 {
                        let total: usize = nets.iter().map(|n| n.hosts()).sum();
                        let fits = total <= targets::MAX_HOSTS;
                        let all = nets.iter().map(|n| n.cidr()).collect::<Vec<_>>().join(", ");
                        let resp = ui
                            .add_enabled(fits, egui::Button::new(format!("All {} AD subnets ({total} addresses)", nets.len())).frame(false))
                            .on_disabled_hover_text(format!("More than {} addresses; pick subnets one by one", targets::MAX_HOSTS));
                        if resp.clicked() {
                            picked = Some((all, false, None));
                        }
                    }
                    for n in nets {
                        let resp = ui.add(egui::Button::new(n.menu_label()).frame(false));
                        if resp.clicked() {
                            picked = Some((n.cidr(), ui.input(|i| i.modifiers.command), None));
                        }
                    }
                }
            });
        if let Some((range, add, ports)) = picked {
            self.bad_input = None;
            if let Some(ports) = ports {
                self.ports = ports;
            }
            if add && !self.range.trim().is_empty() {
                self.range = format!("{}, {range}", self.range.trim().trim_end_matches(','));
            } else {
                self.range = range;
            }
        }
    }

    fn ad_status(&self) -> (String, String) {
        if !cfg!(windows) && !demo_mode() {
            return (String::new(), String::new());
        }
        if !self.use_ad {
            return ("AD: off".into(), "Active Directory lookups are turned off".into());
        }
        match &*lock(&self.ad_state) {
            AdState::Off => ("AD: off".into(), String::new()),
            AdState::Loading => ("AD: loading…".into(), "Reading computers and subnets from Active Directory".into()),
            AdState::Ready(d) => {
                let mut tip = format!(
                    "Domain {}\n{} computer accounts\n{} AD subnets, {} DNS reverse zones",
                    d.domain,
                    d.computers.len(),
                    d.subnets.len(),
                    d.zones.len()
                );
                for w in &d.warnings {
                    tip.push_str(&format!("\n⚠ {w}"));
                }
                (format!("AD: {} · {} computers", d.domain, d.computers.len()), tip)
            }
            AdState::Failed(e) => ("⚠ AD: unavailable".into(), format!("Active Directory lookup failed: {e}")),
        }
    }

    /// F5 or Ctrl/⌘+Enter starts a scan, Esc stops it, Ctrl/⌘+F jumps to the
    /// filter, Ctrl/⌘+A selects every row shown and Ctrl/⌘+C copies the
    /// selected rows.
    fn shortcuts(&mut self, ui: &egui::Ui) {
        let (start, stop, find, copy, all) = ui.input(|i| {
            (
                i.key_pressed(egui::Key::F5) || i.modifiers.command && i.key_pressed(egui::Key::Enter),
                i.key_pressed(egui::Key::Escape),
                i.modifiers.command && i.key_pressed(egui::Key::F),
                i.events.iter().any(|e| matches!(e, egui::Event::Copy)),
                i.modifiers.command && i.key_pressed(egui::Key::A),
            )
        });
        let typing = ui.ctx().memory(|m| m.focused().is_some());
        if start && !self.busy() {
            self.start_scan();
        } else if stop && self.busy() && !typing {
            self.stop_scan();
        }
        if find {
            self.focus_filter = true;
        }
        if copy && !typing {
            self.copy_selected();
        }
        if all && !typing {
            self.selected = self.visible_rows().into_iter().map(|i| self.results[i].ip).collect();
        }
    }

    fn toolbar(&mut self, ui: &mut egui::Ui) {
        let scanning = self.busy();
        let error_text = |bad: bool| bad.then_some(ERROR_COLOR);
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            ui.label("IP range:");
            let edit = ui.add_enabled(
                !scanning,
                egui::TextEdit::singleline(&mut self.range)
                    .desired_width(280.0)
                    .text_color_opt(error_text(self.bad_input == Some(Input::Range)))
                    .hint_text("192.168.1.0/24, 10.0.0.1-50, 10.20.*.*, pc42"),
            );
            if edit.changed() && self.bad_input == Some(Input::Range) {
                self.bad_input = None;
            }
            let edit = edit.on_hover_text("CIDR (10.20.0.0/24), ranges (10.0.0.1-50 or 10.0.0.1 - 10.0.3.254), wildcards (10.20.*.*) or computer names, separated by commas");
            if edit.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) && !scanning {
                self.start_scan();
            }
            ui.add_enabled_ui(!scanning, |ui| self.networks_menu(ui));
            let pinned = self.favourites.iter().any(|f| f.range == self.range.trim());
            let pin = ui.small_button(if pinned { "Unpin" } else { "Pin" }).on_hover_text(if pinned {
                "Remove this range from the Networks menu"
            } else {
                "Keep this range, with the ports below, at the top of the Networks menu"
            });
            if pin.clicked() {
                self.toggle_favourite();
            }

            ui.separator();
            if scanning {
                if ui.button(RichText::new("Stop").strong()).on_hover_text("Esc").clicked() {
                    self.stop_scan();
                }
            } else if ui.button(RichText::new("▶ Start").strong()).on_hover_text("F5, or Ctrl/⌘+Enter").clicked() {
                self.start_scan();
            }
            // Results can be exported as soon as every address has been
            // scanned; admin details still arriving are simply not in yet.
            let has_results = !self.results.is_empty() && self.resolving.is_none() && (self.scan.is_none() || self.hosts_done_in.is_some());
            if ui
                .add_enabled(has_results, egui::Button::new(RichText::new("Export report…").strong()))
                .on_hover_text("Save a formatted HTML report (device type, PC name, user, MAC, network, AD) and open it in your browser")
                .clicked()
            {
                self.export_report();
            }
            if ui
                .add_enabled(has_results, egui::Button::new("CSV / JSON…"))
                .on_hover_text("Save the rows shown below as a spreadsheet (CSV), or as JSON by choosing a .json file name")
                .clicked()
            {
                self.export_data();
            }
        });

        ui.horizontal_wrapped(|ui| {
            ui.add_enabled_ui(!scanning, |ui| {
                ui.label("Threads:");
                ui.add(egui::DragValue::new(&mut self.threads).range(1..=512));
                ui.label("Timeout (ms):");
                ui.add(egui::DragValue::new(&mut self.timeout_ms).range(100..=10_000).speed(10));
                ui.label("Ports:");
                let ports = ui.add(
                    egui::TextEdit::singleline(&mut self.ports)
                        .desired_width(230.0)
                        .text_color_opt(error_text(self.bad_input == Some(Input::Ports)))
                        .hint_text("none"),
                );
                if ports.changed() && self.bad_input == Some(Input::Ports) {
                    self.bad_input = None;
                }
                if self.ports != DEFAULT_PORTS && ui.small_button("Reset").on_hover_text("Back to the default port list").clicked() {
                    self.ports = DEFAULT_PORTS.into();
                    self.bad_input = self.bad_input.filter(|i| *i != Input::Ports);
                }
                ui.checkbox(&mut self.resolve_names, "Hostnames");
                ui.checkbox(&mut self.netbios, "NetBIOS (names & users)")
                    .on_hover_text("Asks each host for its computer name, workgroup and logged-in user over UDP 137. Works mainly for Windows and Samba hosts.");
                ui.checkbox(&mut self.local_discovery, "mDNS / UPnP / IPv6").on_hover_text(
                    "On your own network: asks each device for its Bonjour (mDNS) name, model and services, asks UPnP devices to describe themselves, and lists the IPv6 addresses this computer has seen for each device.",
                );
                ui.checkbox(&mut self.snmp, "SNMP").on_hover_text(
                    "Asks each live device for its description, name and location over SNMP (v2c and v1) with the community string given. Switches, routers, access points, printers and NAS boxes answer when SNMP is enabled on them, also across VLANs. Devices set to report failed logins may log the attempt.",
                );
                if self.snmp {
                    ui.add(egui::TextEdit::singleline(&mut self.snmp_community).desired_width(70.0).char_limit(snmp::MAX_COMMUNITY).hint_text("community"))
                        .on_hover_text("SNMP community string (usually \"public\" for read-only access). Saved in the settings file as plain text.");
                }
                if cfg!(windows) || demo_mode() {
                    ui.checkbox(&mut self.admin_queries, "Admin queries")
                        .on_hover_text("For Windows PCs, asks each machine over WMI for its MAC address (works across VLANs), logged-in user, domain, OS and model, and lists sessions with `query user`. Run HappyIP as a domain admin (or an account with admin rights on the targets).");
                    let ad = ui
                        .checkbox(&mut self.use_ad, "Active Directory")
                        .on_hover_text("Reads computer accounts (OS, OU, description, last logon) and Sites & Services subnets from your domain. Works as a normal domain user.");
                    if ad.changed() {
                        if self.use_ad {
                            self.load_ad();
                        }
                        self.directory = None; // re-applied (or removed) below
                        if !self.use_ad {
                            self.enrich_all();
                            let routed: Vec<Network> = self.networks.iter().filter(|n| n.source == NetSource::Route).cloned().collect();
                            self.rebuild_networks(routed);
                        }
                    }
                }
            });
        });

        ui.horizontal(|ui| {
            ui.checkbox(&mut self.show_dead, "Show dead hosts");
            ui.label("Filter:");
            let filter = ui
                .add(egui::TextEdit::singleline(&mut self.filter).desired_width(200.0).hint_text("ip, name, mac, user, OU, site…"))
                .on_hover_text("Ctrl/⌘+F");
            if std::mem::take(&mut self.focus_filter) {
                filter.request_focus();
            }
            if !self.filter.is_empty() && ui.small_button("Clear").clicked() {
                self.filter.clear();
            }
            ui.separator();
            ui.menu_button("Columns", |ui| {
                for col in SortKey::ALL.into_iter().filter(|c| *c != SortKey::Ip) {
                    let mut shown = !self.hidden.contains(&col);
                    if ui.checkbox(&mut shown, col.title()).changed() {
                        if shown {
                            self.hidden.remove(&col);
                        } else {
                            self.hidden.insert(col);
                        }
                    }
                }
                ui.separator();
                if ui.button("Show all, default widths").clicked() {
                    self.hidden.clear();
                    self.col_widths.clear();
                    ui.close();
                }
            });
            ui.checkbox(&mut self.show_details, "Details").on_hover_text("Show everything known about the selected device in a panel on the right");
            let (ad_label, ad_tip) = self.ad_status();
            if !ad_label.is_empty() {
                ui.separator();
                let text = RichText::new(&ad_label);
                let text = if ad_label.starts_with('⚠') { text.color(ERROR_COLOR) } else { text.weak() };
                let resp = ui.label(text);
                if !ad_tip.is_empty() {
                    resp.on_hover_text(ad_tip);
                }
            }
        });

        if self.rescan.is_none() && (self.scan.is_some() || (self.total > 0 && self.results.len() < self.total)) {
            let frac = self.results.len() as f32 / self.total.max(1) as f32;
            // Estimate the time left once enough has been scanned to tell.
            let left = if self.scan.is_some() && frac > 0.05 && frac < 1.0 && self.elapsed > 2.0 {
                format!("  •  about {:.0}s left", self.elapsed * (1.0 - frac) / frac)
            } else {
                String::new()
            };
            ui.add(
                egui::ProgressBar::new(frac)
                    .show_percentage()
                    .text(format!("{}/{}  •  {} alive{left}", self.results.len(), self.total, self.alive_count())),
            );
        }
        ui.add_space(4.0);
    }

    fn table(&mut self, ui: &mut egui::Ui) {
        let rows = self.visible_rows();
        if rows.is_empty() {
            ui.centered_and_justified(|ui| {
                let msg = if self.resolving.is_some() {
                    "Looking up computer names…"
                } else if self.scan.is_some() {
                    "Scanning… live hosts will appear here."
                } else if self.results.is_empty() {
                    "Enter a range (or pick one from Networks) and press Start."
                } else {
                    "No hosts match."
                };
                ui.label(RichText::new(msg).weak());
            });
            return;
        }

        let cols: Vec<SortKey> = SortKey::ALL.into_iter().filter(|c| !self.hidden.contains(c)).collect();
        let mut new_sort = None;
        let mut clicked_row = None;
        let mut context_row = None;
        let mut action: Option<RowAction> = None;
        let mut widths: Vec<(SortKey, f32)> = Vec::with_capacity(cols.len());
        let networks = &self.networks;
        let selected = &self.selected;
        egui::ScrollArea::horizontal().show(ui, |ui| {
            let mut table = TableBuilder::new(ui)
                // Each set of columns keeps its own layout.
                .id_salt(cols.iter().map(|c| c.name()).collect::<Vec<_>>())
                .striped(true)
                .resizable(true)
                .sense(egui::Sense::click())
                .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                .column(Column::exact(16.0));
            for col in &cols {
                let width = self.col_widths.get(col).copied().unwrap_or(col.default_width());
                table = table.column(Column::initial(width).at_least(36.0).clip(true));
            }
            table
                .header(22.0, |mut header| {
                    header.col(|_| {});
                    for &col in &cols {
                        header.col(|ui| {
                            widths.push((col, ui.available_width()));
                            let arrow = match self.sort {
                                (s, true) if s == col => " ^",
                                (s, false) if s == col => " v",
                                _ => "",
                            };
                            if ui.add(egui::Button::new(RichText::new(format!("{}{arrow}", col.title())).strong()).frame(false)).clicked() {
                                new_sort = Some(col);
                            }
                        });
                    }
                })
                .body(|body| {
                    body.rows(20.0, rows.len(), |mut row| {
                        let index = row.index();
                        let r = &self.results[rows[index]];
                        row.set_selected(selected.contains(&r.ip));
                        let dot = if r.alive.is_some() { Color32::from_rgb(46, 180, 90) } else { Color32::from_gray(140) };
                        row.col(|ui| {
                            let (rect, _) = ui.allocate_exact_size(egui::vec2(10.0, 10.0), egui::Sense::hover());
                            ui.painter().circle_filled(rect.center(), 4.5, dot);
                        });
                        for &col in &cols {
                            row.col(|ui| cell(ui, col, r));
                        }

                        let resp = row.response();
                        if resp.double_clicked() {
                            action = RowAction::open(r);
                        }
                        if resp.clicked() {
                            clicked_row = Some((r.ip, index));
                        }
                        if resp.secondary_clicked() {
                            context_row = Some(r.ip);
                        }
                        let also_selected = if selected.contains(&r.ip) { selected.len() } else { 1 };
                        resp.context_menu(|ui| {
                            if let Some(a) = row_menu(ui, r, networks, also_selected) {
                                action = Some(a);
                            }
                        });
                    });
                });
        });

        for (col, width) in widths {
            self.col_widths.insert(col, width);
        }
        if let Some(k) = new_sort {
            self.sort = if self.sort.0 == k { (k, !self.sort.1) } else { (k, true) };
        }
        if let Some((ip, index)) = clicked_row {
            let modifiers = ui.input(|i| i.modifiers);
            let anchor = self.anchor.and_then(|a| rows.iter().position(|&i| self.results[i].ip == a));
            match anchor {
                // Shift-click: everything between the last clicked row and this one.
                Some(from) if modifiers.shift => {
                    let (lo, hi) = (from.min(index), from.max(index));
                    self.selected = rows[lo..=hi].iter().map(|&i| self.results[i].ip).collect();
                }
                // Ctrl/⌘-click: add or remove this row.
                _ if modifiers.command => {
                    if !self.selected.remove(&ip) {
                        self.selected.insert(ip);
                    }
                    self.anchor = Some(ip);
                }
                _ => {
                    self.selected = HashSet::from([ip]);
                    self.anchor = Some(ip);
                }
            }
        }
        // Right-clicking outside the selection acts on that row alone.
        if let Some(ip) = context_row.filter(|ip| !self.selected.contains(ip)) {
            self.selected = HashSet::from([ip]);
            self.anchor = Some(ip);
        }
        if let Some(a) = action {
            self.run_action(a);
        }
    }

    /// Everything known about the selected device, in a side panel.
    fn details(&self, ui: &mut egui::Ui) {
        let one = (self.selected.len() == 1).then(|| self.selected.iter().next()).flatten();
        let Some(r) = one.and_then(|ip| self.results.iter().find(|r| r.ip == *ip)) else {
            ui.add_space(8.0);
            let hint = if self.selected.len() > 1 { format!("{} rows selected", self.selected.len()) } else { "Select a row to see its details.".into() };
            ui.label(RichText::new(hint).weak());
            return;
        };
        ui.add_space(6.0);
        ui.heading(r.display_name().unwrap_or_else(|| r.ip.to_string()));
        ui.add_space(4.0);
        egui::ScrollArea::vertical().show(ui, |ui| {
            egui::Grid::new("details").num_columns(2).striped(true).spacing([10.0, 6.0]).show(ui, |ui| {
                for (label, value) in host_details(r) {
                    ui.label(RichText::new(label).weak());
                    ui.add(egui::Label::new(value).wrap());
                    ui.end_row();
                }
            });
        });
    }
}

/// One table cell.
fn cell(ui: &mut egui::Ui, col: SortKey, r: &HostResult) {
    match col {
        SortKey::Ip => {
            ui.label(RichText::new(r.ip.to_string()).monospace());
        }
        SortKey::Ipv6 => {
            if !r.ipv6.is_empty() {
                ui.label(RichText::new(r.ipv6_text()).monospace()).on_hover_text(r.ipv6.iter().map(|a| a.to_string()).collect::<Vec<_>>().join("\n"));
            }
        }
        SortKey::Device => {
            let label = ui.label(r.device_text());
            let tip = device_tooltip(r);
            if !tip.is_empty() {
                label.on_hover_text(tip);
            }
        }
        SortKey::NetBios => {
            ui.label(RichText::new(r.display_name().unwrap_or_default()).strong());
        }
        SortKey::Users => {
            if r.admin == AdminDetails::Failed && r.users.is_empty() {
                ui.label(RichText::new("no admin answer").weak().italics()).on_hover_text(ADMIN_FAILED_TIP);
            } else {
                ui.label(r.users.join(", "));
            }
        }
        SortKey::Mac => {
            ui.label(RichText::new(r.mac.as_deref().unwrap_or("")).monospace());
        }
        SortKey::Vendor => {
            ui.label(r.vendor.as_deref().unwrap_or(""));
        }
        SortKey::Network => {
            ui.label(r.network.as_deref().unwrap_or(""));
        }
        SortKey::Domain => {
            ui.label(r.domain_text().unwrap_or_default());
        }
        SortKey::Ad => match &r.ad {
            Some(a) if !a.enabled => {
                ui.label(RichText::new(r.ad_text()).color(Color32::from_rgb(210, 120, 40)))
                    .on_hover_text("This computer account is disabled in Active Directory, but the device is online");
            }
            Some(a) => {
                let resp = ui.label(r.ad_text());
                if let Some(d) = &a.description {
                    resp.on_hover_text(d);
                }
            }
            None => {}
        },
        SortKey::Hostname => match (&r.hostname, &r.dns_mismatch) {
            (Some(h), _) => {
                ui.label(h);
            }
            (None, Some(stale)) => {
                ui.label(RichText::new(format!("⚠ {stale}")).weak()).on_hover_text(format!(
                    "Reverse DNS says {stale}, but that name doesn't point back to this address. It's probably a stale DNS record left by a device that used this IP before, so HappyIP doesn't use it as the name."
                ));
            }
            _ => {}
        },
        SortKey::Ping => {
            ui.label(r.ping_text());
        }
        SortKey::Ttl => {
            ui.label(r.ttl.map(|t| t.to_string()).unwrap_or_default());
        }
        SortKey::Ports => {
            ui.label(r.ports_text());
        }
        SortKey::SeenVia => {
            let via = ui.label(RichText::new(r.seen_via()).weak());
            if r.alive == Some(scanner::AliveBy::ArpCached) {
                via.on_hover_text(ARP_CACHED_TIP);
            }
        }
        SortKey::Changes => {
            if let Some(change) = &r.change {
                let color = match change {
                    history::Change::New => Color32::from_rgb(46, 160, 90),
                    history::Change::Gone(_) => Color32::from_gray(140),
                    history::Change::MacChanged { .. } => Color32::from_rgb(210, 120, 40),
                };
                ui.label(RichText::new(change.label()).color(color)).on_hover_text("Compared with the previous complete scan of this range");
            }
        }
    }
}

const ARP_CACHED_TIP: &str = "Nothing answered during this scan. The address was only found in this computer's ARP table, where it was already listed before the scan, so the device was here recently but may have left since.";

/// Label and value of everything known about a host, for the details panel.
fn host_details(r: &HostResult) -> Vec<(&'static str, String)> {
    let ad = r.ad.as_ref();
    let status = match r.alive {
        Some(by) => format!("Alive (seen via {})", by.label()),
        None if r.firewall_reply => "Not alive (only a firewall or proxy answered)".into(),
        None => "No answer".into(),
    };
    let rows = [
        ("IP address", r.ip.to_string()),
        ("IPv6 addresses", r.ipv6.iter().map(|a| a.to_string()).collect::<Vec<_>>().join("\n")),
        ("Status", status),
        ("Change", r.change.as_ref().map(|c| c.label()).unwrap_or_default()),
        ("Device", r.device_text()),
        ("OS", r.os_text().unwrap_or_default()),
        ("Model", r.model.clone().unwrap_or_default()),
        ("Computer name", r.display_name().unwrap_or_default()),
        ("Hostname", r.hostname.clone().unwrap_or_default()),
        ("Stale DNS name", r.dns_mismatch.clone().unwrap_or_default()),
        ("Domain / workgroup", r.domain_text().unwrap_or_default()),
        ("Logged-in users", r.users.join(", ")),
        ("MAC address", r.mac.clone().unwrap_or_default()),
        ("Vendor", r.vendor.clone().unwrap_or_default()),
        ("Network / site", r.network.clone().unwrap_or_default()),
        ("Ping", r.ping_text()),
        ("TTL", r.ttl.map(|t| t.to_string()).unwrap_or_default()),
        ("Open ports", r.ports_text()),
        ("Web page", r.http_banner.clone().unwrap_or_default()),
        ("HTTPS certificate", r.tls_name.clone().unwrap_or_default()),
        ("SSH server", r.ssh_banner.clone().unwrap_or_default()),
        ("UPnP", r.upnp.clone().unwrap_or_default()),
        ("mDNS services", r.mdns_services.join(", ")),
        ("SNMP description", r.snmp.as_ref().and_then(|s| s.description.clone()).unwrap_or_default()),
        ("SNMP name", r.snmp.as_ref().and_then(|s| s.name.clone()).unwrap_or_default()),
        ("SNMP location", r.snmp.as_ref().and_then(|s| s.location.clone()).unwrap_or_default()),
        ("AD OU", ad.map(|_| r.ad_text()).unwrap_or_default()),
        ("AD description", ad.and_then(|a| a.description.clone()).unwrap_or_default()),
        ("AD location", ad.and_then(|a| a.location.clone()).unwrap_or_default()),
        ("AD last logon", ad.and_then(|a| a.last_logon.clone()).unwrap_or_default()),
        (
            "Admin details",
            match r.admin {
                AdminDetails::NotTried => String::new(),
                AdminDetails::Answered => "Answered".into(),
                AdminDetails::Failed => "No answer (access denied or blocked by a firewall)".into(),
            },
        ),
        ("Identified by", r.device.as_ref().map(|d| d.basis.join(", ")).unwrap_or_default()),
    ];
    rows.into_iter().filter(|(_, value)| !value.is_empty()).collect()
}

impl Drop for App {
    /// Remember options changed just before the window was closed.
    fn drop(&mut self) {
        self.save_settings();
    }
}

const ADMIN_FAILED_TIP: &str = "This PC didn't give admin details (logged-in user, MAC, OS, model). Either the account running HappyIP has no admin rights on it, or a firewall blocks remote management (WMI/RPC), or it didn't answer in time. \"Copy diagnostics\" in the status bar has the exact error.";

/// Something chosen from a row's right-click menu (or by double-clicking
/// it) that reports back in the status bar.
enum RowAction {
    WakeOnLan { mac: String, name: String, broadcasts: Vec<Ipv4Addr> },
    RemoteDesktop(String),
    Web(String),
    Shares(String),
    Ssh(String),
    Vnc(String),
    /// Scan this one address again.
    Rescan(Ipv4Addr),
    CopySelected,
}

impl RowAction {
    /// Double-click: Remote Desktop for PCs that offer it, else the
    /// device's web page.
    fn open(r: &HostResult) -> Option<RowAction> {
        if r.open_ports.contains(&3389) {
            Some(RowAction::RemoteDesktop(actions::connect_target(r)))
        } else {
            actions::web_url(r).map(RowAction::Web)
        }
    }

    /// What was done, or why it couldn't be.
    fn run(self) -> Result<String, String> {
        match self {
            RowAction::WakeOnLan { mac, name, broadcasts } => probe::wake_on_lan(&mac, &broadcasts)
                .map(|()| format!("Wake-on-LAN packet sent to {name} ({mac})"))
                .map_err(|e| format!("Wake-on-LAN failed: {e}")),
            RowAction::RemoteDesktop(target) => actions::open_remote_desktop(&target)
                .map(|()| format!("Opening Remote Desktop to {target}"))
                .map_err(|e| format!("Remote Desktop to {target}: {e}")),
            RowAction::Web(url) => actions::open_web(&url).map(|()| format!("Opening {url}")),
            RowAction::Shares(target) => actions::open_shares(&target)
                .map(|()| format!("Opening the shares on {target}"))
                .map_err(|e| format!("Shares on {target}: {e}")),
            RowAction::Ssh(target) => actions::open_ssh(&target)
                .map(|()| format!("Opening an SSH session to {target}"))
                .map_err(|e| format!("SSH to {target}: {e}")),
            RowAction::Vnc(target) => actions::open_vnc(&target)
                .map(|()| format!("Opening screen sharing (VNC) to {target}"))
                .map_err(|e| format!("VNC to {target}: {e}")),
            // Handled by the window, which owns the scan and the selection.
            RowAction::Rescan(_) | RowAction::CopySelected => Ok(String::new()),
        }
    }
}

fn row_menu(ui: &mut egui::Ui, r: &HostResult, networks: &[Network], selected: usize) -> Option<RowAction> {
    let mut action = None;
    if selected > 1 {
        if ui.button(format!("Copy {selected} selected rows")).clicked() {
            action = Some(RowAction::CopySelected);
            ui.close();
        }
        ui.separator();
    }
    let copy = |ui: &mut egui::Ui, label: &str, text: String| {
        if ui.add_enabled(!text.is_empty(), egui::Button::new(label)).clicked() {
            ui.ctx().copy_text(text);
            ui.close();
        }
    };
    copy(ui, "Copy IP", r.ip.to_string());
    copy(ui, "Copy MAC", r.mac.clone().unwrap_or_default());
    copy(ui, "Copy name", r.hostname.clone().or_else(|| r.display_name()).unwrap_or_default());
    copy(ui, "Copy users", r.users.join(", "));
    copy(ui, "Copy row", row_text_display(r));
    ui.separator();

    let target = actions::connect_target(r);
    let hint = if r.open_ports.contains(&3389) {
        format!("Connect to {target}")
    } else {
        format!("Connect to {target} (port 3389 wasn't seen open)")
    };
    if ui.button("Remote Desktop…").on_hover_text(hint).clicked() {
        action = Some(RowAction::RemoteDesktop(target.clone()));
        ui.close();
    }
    let web = actions::web_url(r);
    if ui
        .add_enabled(web.is_some(), egui::Button::new("Open web page"))
        .on_hover_text(web.clone().unwrap_or_else(|| "No web port (80, 443, 8080, 5000) seen open".into()))
        .clicked()
    {
        action = web.map(RowAction::Web);
        ui.close();
    }
    let smb = r.open_ports.contains(&445) || r.open_ports.contains(&139);
    if ui
        .add_enabled(smb, egui::Button::new("Browse shares"))
        .on_hover_text(format!("Open \\\\{target} in {}", if cfg!(windows) { "Explorer" } else { "Finder" }))
        .clicked()
    {
        action = Some(RowAction::Shares(target.clone()));
        ui.close();
    }
    if ui
        .add_enabled(r.open_ports.contains(&22), egui::Button::new("SSH"))
        .on_hover_text(format!("Open a terminal with ssh {target}"))
        .on_disabled_hover_text("Port 22 wasn't seen open")
        .clicked()
    {
        action = Some(RowAction::Ssh(target.clone()));
        ui.close();
    }
    if ui
        .add_enabled(r.open_ports.contains(&5900), egui::Button::new("Screen sharing (VNC)"))
        .on_hover_text(format!("Open vnc://{target} in the system's VNC viewer"))
        .on_disabled_hover_text("Port 5900 wasn't seen open")
        .clicked()
    {
        action = Some(RowAction::Vnc(target));
        ui.close();
    }
    ui.separator();
    if ui.button("Scan this address again").clicked() {
        action = Some(RowAction::Rescan(r.ip));
        ui.close();
    }
    if let Some(mac) = r.mac.clone()
        && ui
            .button("Wake on LAN")
            .on_hover_text("Send a magic packet to this MAC (the PC must have Wake-on-LAN enabled; across VLANs the router must forward directed broadcasts)")
            .clicked()
    {
        let mut broadcasts = vec![Ipv4Addr::BROADCAST];
        let (net, prefix) = targets::best_match(networks, r.ip)
            .map(|n| (n.network, n.prefix))
            .unwrap_or((Ipv4Addr::from(u32::from(r.ip) & 0xFFFF_FF00), 24));
        let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
        broadcasts.push(Ipv4Addr::from(u32::from(net) | !mask));
        action = Some(RowAction::WakeOnLan { mac, name: r.display_name().unwrap_or_else(|| r.ip.to_string()), broadcasts });
        ui.close();
    }
    action
}

fn device_tooltip(r: &HostResult) -> String {
    let mut tip: Vec<String> = r.os_text().into_iter().chain(r.model.clone()).collect();
    if let Some(a) = &r.ad {
        if let Some(d) = &a.description {
            tip.push(format!("AD description: {d}"));
        }
        if let Some(l) = &a.location {
            tip.push(format!("AD location: {l}"));
        }
        if let Some(l) = &a.last_logon {
            tip.push(format!("AD last logon: {l}"));
        }
        if !a.enabled {
            tip.push("AD account is disabled".into());
        }
    }
    if let Some(d) = r.device.as_ref().filter(|d| !d.basis.is_empty()) {
        tip.push(format!("Based on: {}", d.basis.join(", ")));
    }
    if r.admin == AdminDetails::Failed {
        tip.push("Admin details: no answer (access denied or blocked by a firewall)".into());
    }
    tip.join("\n")
}

impl eframe::App for App {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.draw(ui);
    }
}

impl egui_software_backend::App for App {
    fn ui(&mut self, ui: &mut egui::Ui, _backend: &mut egui_software_backend::SoftwareBackend) {
        self.draw(ui);
    }
}

impl App {
    fn draw(&mut self, ui: &mut egui::Ui) {
        self.sync_ad();
        self.poll_resolving();
        self.poll_scan();
        self.shortcuts(ui);

        egui::Panel::top("toolbar").show_inside(ui, |ui| self.toolbar(ui));
        egui::Panel::bottom("status").show_inside(ui, |ui| {
            ui.horizontal(|ui| {
                // Errors stand out; everything else is plain.
                if self.status.starts_with('⚠') {
                    ui.label(RichText::new(&self.status).color(ERROR_COLOR).strong());
                } else {
                    ui.label(&self.status);
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui
                        .small_button("Copy diagnostics")
                        .on_hover_text("Copies the version, settings and recent log (failed admin and Active Directory lookups, errors) to the clipboard, to check or send when something doesn't work")
                        .clicked()
                    {
                        self.copy_diagnostics();
                    }
                    if !self.results.is_empty() {
                        ui.label(format!(
                            "{} alive / {} scanned{}",
                            self.alive_count(),
                            self.results.len(),
                            if self.scan.is_some() { format!("  •  {:.1}s", self.elapsed) } else { String::new() }
                        ));
                    }
                });
            });
        });
        if self.show_details {
            egui::Panel::right("details").resizable(true).default_size(330.0).min_size(220.0).show_inside(ui, |ui| self.details(ui));
        }
        egui::CentralPanel::default_margins().show_inside(ui, |ui| self.table(ui));

        if self.busy() {
            // Keep the elapsed timer ticking even between results.
            ui.ctx().request_repaint_after(std::time::Duration::from_millis(250));
        }
        self.autosave(ui);
    }
}

fn row_text(r: &HostResult) -> String {
    row_text_display(r).to_lowercase()
}

fn row_text_display(r: &HostResult) -> String {
    let ad = r.ad.as_ref();
    [
        r.ip.to_string(),
        r.device_text(),
        r.os_text().unwrap_or_default(),
        r.hostname.clone().unwrap_or_default(),
        r.mac.clone().unwrap_or_default(),
        r.vendor.clone().unwrap_or_default(),
        r.netbios_name.clone().unwrap_or_default(),
        r.domain_text().unwrap_or_default(),
        r.users.join(", "),
        r.network.clone().unwrap_or_default(),
        r.ad_text(),
        ad.and_then(|a| a.description.clone()).unwrap_or_default(),
        r.ports_text(),
        r.seen_via().to_string(),
        r.change.as_ref().map(|c| c.label()).unwrap_or_default(),
        r.ipv6_text(),
        r.snmp.as_ref().and_then(|s| s.description.clone()).unwrap_or_default(),
        r.snmp.as_ref().and_then(|s| s.location.clone()).unwrap_or_default(),
    ]
    .into_iter()
    .filter(|s| !s.is_empty())
    .collect::<Vec<_>>()
    .join("\t")
}

fn cmp_opt(a: Option<f64>, b: Option<f64>) -> Ordering {
    match (a, b) {
        (Some(a), Some(b)) => a.partial_cmp(&b).unwrap_or(Ordering::Equal),
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        (None, None) => Ordering::Equal,
    }
}

fn cmp_str(a: &Option<String>, b: &Option<String>) -> Ordering {
    match (a, b) {
        (Some(a), Some(b)) => a.to_lowercase().cmp(&b.to_lowercase()),
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        (None, None) => Ordering::Equal,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn column_names_round_trip_and_are_unique() {
        let mut names: Vec<&str> = SortKey::ALL.iter().map(|k| k.name()).collect();
        for k in SortKey::ALL {
            assert_eq!(SortKey::from_name(k.name()), Some(k));
            assert!(!k.title().is_empty() && k.default_width() > 0.0);
        }
        names.sort();
        names.dedup();
        assert_eq!(names.len(), SortKey::ALL.len());
        assert_eq!(SortKey::from_name("nonsense"), None);
    }

    #[test]
    fn details_list_what_is_known_and_nothing_else() {
        let dir = demo::directory();
        let mut results = demo::results();
        for r in &mut results {
            r.enrich(Some(&dir), &dir.networks(), Some(demo::GATEWAY));
        }
        let get = |r: &HostResult, label: &str| host_details(r).into_iter().find(|(l, _)| *l == label).map(|(_, v)| v);

        let pc = results.iter().find(|r| r.netbios_name.as_deref() == Some("LAPTOP-FINANCE02")).unwrap();
        assert_eq!(get(pc, "IP address").as_deref(), Some("10.20.0.14"));
        assert_eq!(get(pc, "Status").as_deref(), Some("Alive (seen via ICMP)"));
        assert_eq!(get(pc, "Logged-in users").as_deref(), Some("a.chen"));
        assert_eq!(get(pc, "AD OU").as_deref(), Some("Workstations/Finance"));
        assert_eq!(get(pc, "AD location").as_deref(), Some("2nd floor"));
        assert_eq!(get(pc, "Model").as_deref(), Some("LENOVO ThinkPad T14 Gen 4"));
        assert_eq!(get(pc, "Web page"), None);
        assert_eq!(get(pc, "Change"), None);

        let dead = results.iter().find(|r| r.alive.is_none()).unwrap();
        let labels: Vec<&str> = host_details(dead).into_iter().map(|(l, _)| l).collect();
        assert_eq!(labels, ["IP address", "Status", "Network / site"]);
    }

    #[test]
    fn rows_can_be_filtered_by_what_changed() {
        let mut r = HostResult::new(Ipv4Addr::new(10, 0, 0, 9));
        r.change = Some(history::Change::New);
        assert!(row_text(&r).contains("new"));
    }
}
