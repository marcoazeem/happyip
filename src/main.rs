// Hide the console window on Windows release builds.
#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

mod demo;
mod identify;
mod netbios;
mod probe;
mod report;
mod scanner;
mod targets;
mod wmi;

use std::cmp::Ordering;
use std::time::Instant;

use eframe::egui::{self, Color32, RichText};
use egui_extras::{Column, TableBuilder};

use scanner::{HostResult, ScanConfig, ScanEvent, ScanHandle};
use targets::LocalInterface;

const SOFTWARE_FLAG: &str = "--software";
/// Common services plus ports that help fingerprint devices: AFP (548, Mac),
/// RTSP (554, cameras), IPP/JetDirect (631/9100, printers), 5000 (NAS),
/// 8009 (Chromecast), 62078 (iPhone/iPad sync).
const DEFAULT_PORTS: &str = "22, 80, 135, 139, 443, 445, 548, 554, 631, 3389, 5000, 5900, 8009, 8080, 9100, 62078";

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("--cli") => {
            // happyip --cli [range...] [--report file.html]
            let rest = args.get(2..).unwrap_or_default();
            let report_at = rest.iter().position(|a| a == "--report");
            let report = report_at.and_then(|i| rest.get(i + 1)).map(std::path::PathBuf::from);
            let range = rest[..report_at.unwrap_or(rest.len())].join(",");
            run_cli(range, report);
        }
        Some("--demo-report") => {
            let path = args.get(2).map(String::as_str).unwrap_or("happyip-demo-report.html");
            let results = demo::results();
            let alive: Vec<&HostResult> = results.iter().filter(|r| r.alive.is_some()).collect();
            let meta = report::ReportMeta {
                range: demo::RANGE.into(),
                generated: chrono::Local::now().format("%Y-%m-%d %H:%M").to_string(),
                scanned_from: "IT-ADMIN01".into(),
                hosts_scanned: results.len(),
            };
            std::fs::write(path, report::html(&meta, &alive)).expect("write demo report");
            eprintln!("Demo report written to {path}");
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
    egui::ViewportBuilder::default()
        .with_title("HappyIP")
        .with_inner_size([1180.0, 720.0])
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
        eprintln!("GPU renderer unavailable ({e}); falling back to software rendering");
        let relaunched = std::env::current_exe()
            .and_then(|exe| {
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
    eprintln!("HappyIP error: {msg}");
    rfd::MessageDialog::new()
        .set_level(rfd::MessageLevel::Error)
        .set_title("HappyIP could not start")
        .set_description(msg)
        .show();
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SortKey {
    Ip,
    Ping,
    Hostname,
    Mac,
    NetBios,
    Users,
    Device,
    Vendor,
}

struct App {
    ctx: egui::Context,
    interfaces: Vec<LocalInterface>,
    selected_iface: usize,
    range: String,
    threads: usize,
    timeout_ms: u64,
    ports: String,
    resolve_names: bool,
    netbios: bool,
    admin_queries: bool,
    show_dead: bool,
    filter: String,

    results: Vec<HostResult>,
    scan: Option<ScanHandle>,
    total: usize,
    started: Option<Instant>,
    elapsed: f32,
    status: String,
    sort: (SortKey, bool),
    selected_row: Option<std::net::Ipv4Addr>,
    scanned_range: String,
}

impl App {
    fn new(ctx: egui::Context) -> Self {
        let interfaces = targets::local_interfaces();
        let range = interfaces
            .first()
            .map(LocalInterface::suggested_range)
            .unwrap_or_else(|| "192.168.1.0/24".into());
        let mut app = Self {
            ctx,
            interfaces,
            selected_iface: 0,
            range,
            threads: 128,
            timeout_ms: 1000,
            ports: DEFAULT_PORTS.into(),
            resolve_names: true,
            netbios: true,
            admin_queries: cfg!(windows),
            show_dead: false,
            filter: String::new(),
            results: Vec::new(),
            scan: None,
            total: 0,
            started: None,
            elapsed: 0.0,
            status: "Ready".into(),
            sort: (SortKey::Ip, true),
            selected_row: None,
            scanned_range: String::new(),
        };
        if demo_mode() {
            app.interfaces = vec![LocalInterface {
                name: "Ethernet".into(),
                ip: std::net::Ipv4Addr::new(10, 20, 0, 50),
                prefix: 24,
                mac: None,
            }];
            app.results = demo::results();
            app.total = app.results.len();
            app.range = demo::RANGE.into();
            app.scanned_range = demo::RANGE.into();
            app.status = format!("Done: {} scanned, {} alive in 3.9s (demo data)", app.total, app.alive_count());
        }
        app
    }

    fn parse_ports(&self) -> Result<Vec<u16>, String> {
        let mut ports = Vec::new();
        for p in self.ports.split([',', ' ']).filter(|s| !s.is_empty()) {
            if let Some((a, b)) = p.split_once('-') {
                let (a, b): (u16, u16) = (
                    a.parse().map_err(|_| format!("bad port '{p}'"))?,
                    b.parse().map_err(|_| format!("bad port '{p}'"))?,
                );
                ports.extend(a..=b);
            } else {
                ports.push(p.parse().map_err(|_| format!("bad port '{p}'"))?);
            }
        }
        ports.sort();
        ports.dedup();
        if ports.len() > 64 {
            return Err("at most 64 ports per scan".into());
        }
        Ok(ports)
    }

    fn start_scan(&mut self) {
        let targets = match targets::parse_targets(&self.range) {
            Ok(t) => t,
            Err(e) => return self.status = format!("⚠ {e}"),
        };
        let ports = match self.parse_ports() {
            Ok(p) => p,
            Err(e) => return self.status = format!("⚠ {e}"),
        };
        let cfg = ScanConfig {
            targets,
            threads: self.threads,
            timeout_ms: self.timeout_ms,
            ports,
            resolve_names: self.resolve_names,
            netbios: self.netbios,
            admin_queries: self.admin_queries,
            local: self.interfaces.iter().map(|i| (i.ip, i.mac.clone())).collect(),
            gateway: identify::default_gateway(),
        };
        self.scanned_range = self.range.clone();
        self.total = cfg.targets.len();
        self.results.clear();
        self.results.reserve(self.total);
        self.selected_row = None;
        self.started = Some(Instant::now());
        self.status = format!("Scanning {} hosts…", self.total);
        let ctx = self.ctx.clone();
        self.scan = Some(scanner::start(cfg, move || ctx.request_repaint()));
    }

    fn poll_scan(&mut self) {
        let Some(scan) = &self.scan else { return };
        let mut finished = false;
        while let Ok(ev) = scan.rx.try_recv() {
            match ev {
                ScanEvent::Host(h) => self.results.push(h),
                ScanEvent::Finished => finished = true,
            }
        }
        if let Some(t) = self.started {
            self.elapsed = t.elapsed().as_secs_f32();
        }
        if finished {
            self.scan = None;
            let alive = self.alive_count();
            let stopped = if self.results.len() < self.total { " (stopped)" } else { "" };
            self.status = format!(
                "Done{stopped}: {} scanned, {alive} alive in {:.1}s",
                self.results.len(),
                self.elapsed
            );
        }
    }

    fn alive_count(&self) -> usize {
        self.results.iter().filter(|r| r.alive.is_some()).count()
    }

    fn visible_rows(&self) -> Vec<usize> {
        let needle = self.filter.trim().to_lowercase();
        let mut rows: Vec<usize> = (0..self.results.len())
            .filter(|&i| {
                let r = &self.results[i];
                (self.show_dead || r.alive.is_some()) && (needle.is_empty() || row_text(r).contains(&needle))
            })
            .collect();
        let (key, asc) = self.sort;
        rows.sort_by(|&a, &b| {
            let (a, b) = (&self.results[a], &self.results[b]);
            let ord = match key {
                SortKey::Ip => a.ip.cmp(&b.ip),
                SortKey::Ping => cmp_opt(a.rtt_ms, b.rtt_ms),
                SortKey::Hostname => cmp_str(&a.hostname, &b.hostname),
                SortKey::Mac => cmp_str(&a.mac, &b.mac),
                SortKey::NetBios => cmp_str(&a.display_name(), &b.display_name()),
                SortKey::Device => cmp_str(&Some(a.device_text()), &Some(b.device_text())),
                SortKey::Vendor => cmp_str(&a.vendor, &b.vendor),
                SortKey::Users => cmp_str(&a.users.first().cloned(), &b.users.first().cloned()),
            };
            let ord = ord.then(a.ip.cmp(&b.ip));
            if asc { ord } else { ord.reverse() }
        });
        rows
    }

    fn export_csv(&mut self) {
        let Some(path) = rfd::FileDialog::new()
            .set_file_name("happyip-scan.csv")
            .add_filter("CSV", &["csv"])
            .save_file()
        else {
            return;
        };
        let mut out = String::from("IP,Status,Device Type,OS,Computer Name,Users,Domain,MAC,Vendor,Model,Hostname,NetBIOS Name,Ping,TTL,Open Ports,Web Banner,Detected By\n");
        for &i in &self.visible_rows() {
            let r = &self.results[i];
            let fields = [
                r.ip.to_string(),
                if r.alive.is_some() { "Alive" } else { "Dead" }.into(),
                r.device_text(),
                r.os_text().unwrap_or_default(),
                r.display_name().unwrap_or_default(),
                r.users.join("; "),
                r.domain_text().unwrap_or_default(),
                r.mac.clone().unwrap_or_default(),
                r.vendor.clone().unwrap_or_default(),
                r.model.clone().unwrap_or_default(),
                r.hostname.clone().unwrap_or_default(),
                r.netbios_name.clone().unwrap_or_default(),
                r.ping_text(),
                r.ttl.map(|t| t.to_string()).unwrap_or_default(),
                r.ports_text(),
                r.http_banner.clone().unwrap_or_default(),
                r.alive.map(|a| a.label().to_string()).unwrap_or_default(),
            ];
            let line: Vec<String> = fields.iter().map(|f| csv_escape(f)).collect();
            out.push_str(&line.join(","));
            out.push('\n');
        }
        self.status = match std::fs::write(&path, out) {
            Ok(()) => format!("Exported to {}", path.display()),
            Err(e) => format!("⚠ Export failed: {e}"),
        };
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
        };
        self.status = match std::fs::write(&path, report::html(&meta, &hosts)) {
            Ok(()) => {
                let _ = webbrowser::open(&path.to_string_lossy());
                format!("Report saved to {}", path.display())
            }
            Err(e) => format!("⚠ Export failed: {e}"),
        };
    }

    fn toolbar(&mut self, ui: &mut egui::Ui) {
        let scanning = self.scan.is_some();
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            ui.label("IP range:");
            let edit = ui.add_enabled(
                !scanning,
                egui::TextEdit::singleline(&mut self.range)
                    .desired_width(260.0)
                    .hint_text("192.168.1.0/24, 10.0.0.1-50"),
            );
            if edit.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) && !scanning {
                self.start_scan();
            }

            if !self.interfaces.is_empty() {
                let current = self.interfaces[self.selected_iface].label();
                ui.add_enabled_ui(!scanning, |ui| {
                    egui::ComboBox::from_id_salt("iface")
                        .selected_text(current)
                        .width(220.0)
                        .show_ui(ui, |ui| {
                            for (i, iface) in self.interfaces.iter().enumerate() {
                                if ui.selectable_label(i == self.selected_iface, iface.label()).clicked() {
                                    self.selected_iface = i;
                                    self.range = iface.suggested_range();
                                }
                            }
                        });
                });
            }

            ui.separator();
            if scanning {
                if ui.button(RichText::new("Stop").strong()).clicked() {
                    if let Some(s) = &self.scan {
                        s.stop();
                    }
                    self.status = "Stopping…".into();
                }
            } else if ui.button(RichText::new("▶ Start").strong()).clicked() {
                self.start_scan();
            }
            let has_results = !self.results.is_empty() && !scanning;
            if ui
                .add_enabled(has_results, egui::Button::new(RichText::new("Export report…").strong()))
                .on_hover_text("Save a formatted HTML report (device type, PC name, user, MAC) and open it in your browser")
                .clicked()
            {
                self.export_report();
            }
            if ui.add_enabled(has_results, egui::Button::new("CSV…")).clicked() {
                self.export_csv();
            }
        });

        ui.horizontal_wrapped(|ui| {
            ui.add_enabled_ui(!scanning, |ui| {
                ui.label("Threads:");
                ui.add(egui::DragValue::new(&mut self.threads).range(1..=512));
                ui.label("Timeout (ms):");
                ui.add(egui::DragValue::new(&mut self.timeout_ms).range(100..=10_000).speed(10));
                ui.label("Ports:");
                ui.add(egui::TextEdit::singleline(&mut self.ports).desired_width(230.0).hint_text("none"));
                ui.checkbox(&mut self.resolve_names, "Hostnames");
                ui.checkbox(&mut self.netbios, "NetBIOS (names & users)")
                    .on_hover_text("Asks each host for its computer name, workgroup and logged-in user over UDP 137. Works mainly for Windows and Samba hosts.");
                if cfg!(windows) {
                    ui.checkbox(&mut self.admin_queries, "Admin queries")
                        .on_hover_text("For Windows PCs, asks each machine over WMI for its MAC address (works across VLANs), logged-in user, domain, OS and model, and lists sessions with `query user`. Run HappyIP as a domain admin (or an account with admin rights on the targets).");
                }
            });
        });

        ui.horizontal(|ui| {
            ui.checkbox(&mut self.show_dead, "Show dead hosts");
            ui.label("Filter:");
            ui.add(egui::TextEdit::singleline(&mut self.filter).desired_width(200.0).hint_text("ip, name, mac, user…"));
        });

        if scanning || (self.total > 0 && self.results.len() < self.total) {
            let frac = self.results.len() as f32 / self.total.max(1) as f32;
            ui.add(
                egui::ProgressBar::new(frac)
                    .show_percentage()
                    .text(format!("{}/{}  •  {} alive", self.results.len(), self.total, self.alive_count())),
            );
        }
        ui.add_space(4.0);
    }

    fn table(&mut self, ui: &mut egui::Ui) {
        let rows = self.visible_rows();
        if rows.is_empty() {
            ui.centered_and_justified(|ui| {
                let msg = if self.scan.is_some() {
                    "Scanning… live hosts will appear here."
                } else if self.results.is_empty() {
                    "Enter a range and press Start."
                } else {
                    "No hosts match."
                };
                ui.label(RichText::new(msg).weak());
            });
            return;
        }

        let headers: [(&str, Option<SortKey>); 13] = [
            ("", None),
            ("IP", Some(SortKey::Ip)),
            ("Device", Some(SortKey::Device)),
            ("Computer name", Some(SortKey::NetBios)),
            ("Logged-in users", Some(SortKey::Users)),
            ("MAC address", Some(SortKey::Mac)),
            ("Vendor", Some(SortKey::Vendor)),
            ("Ping", Some(SortKey::Ping)),
            ("TTL", None),
            ("Hostname", Some(SortKey::Hostname)),
            ("Domain / workgroup", None),
            ("Open ports", None),
            ("Seen via", None),
        ];

        let mut new_sort = None;
        let mut clicked_row = None;
        TableBuilder::new(ui)
            .striped(true)
            .resizable(true)
            .sense(egui::Sense::click())
            .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
            .column(Column::exact(16.0))
            .column(Column::initial(110.0).at_least(90.0))
            .column(Column::initial(150.0).clip(true))
            .column(Column::initial(140.0).clip(true))
            .column(Column::initial(120.0).clip(true))
            .column(Column::initial(130.0))
            .column(Column::initial(150.0).clip(true))
            .column(Column::initial(60.0))
            .column(Column::initial(36.0))
            .column(Column::initial(170.0).clip(true))
            .column(Column::initial(90.0).clip(true))
            .column(Column::initial(130.0).clip(true))
            .column(Column::remainder().at_least(60.0))
            .header(22.0, |mut header| {
                for (title, key) in headers {
                    header.col(|ui| match key {
                        Some(k) => {
                            let arrow = match self.sort {
                                (s, true) if s == k => " ^",
                                (s, false) if s == k => " v",
                                _ => "",
                            };
                            if ui.add(egui::Button::new(RichText::new(format!("{title}{arrow}")).strong()).frame(false)).clicked() {
                                new_sort = Some(k);
                            }
                        }
                        None => {
                            ui.strong(title);
                        }
                    });
                }
            })
            .body(|body| {
                body.rows(20.0, rows.len(), |mut row| {
                    let r = &self.results[rows[row.index()]];
                    row.set_selected(self.selected_row == Some(r.ip));
                    let dot = if r.alive.is_some() { Color32::from_rgb(46, 180, 90) } else { Color32::from_gray(140) };
                    row.col(|ui| {
                        let (rect, _) = ui.allocate_exact_size(egui::vec2(10.0, 10.0), egui::Sense::hover());
                        ui.painter().circle_filled(rect.center(), 4.5, dot);
                    });
                    row.col(|ui| {
                        ui.label(RichText::new(r.ip.to_string()).monospace());
                    });
                    row.col(|ui| {
                        let label = ui.label(r.device_text());
                        if let Some(d) = &r.device {
                            let mut tip: Vec<String> = r.os_text().into_iter().chain(r.model.clone()).collect();
                            if !d.basis.is_empty() {
                                tip.push(format!("Based on: {}", d.basis.join(", ")));
                            }
                            if !tip.is_empty() {
                                label.on_hover_text(tip.join("\n"));
                            }
                        }
                    });
                    row.col(|ui| {
                        ui.label(RichText::new(r.display_name().unwrap_or_default()).strong());
                    });
                    row.col(|ui| {
                        ui.label(r.users.join(", "));
                    });
                    row.col(|ui| {
                        ui.label(RichText::new(r.mac.as_deref().unwrap_or("")).monospace());
                    });
                    row.col(|ui| {
                        ui.label(r.vendor.as_deref().unwrap_or(""));
                    });
                    row.col(|ui| {
                        ui.label(r.ping_text());
                    });
                    row.col(|ui| {
                        ui.label(r.ttl.map(|t| t.to_string()).unwrap_or_default());
                    });
                    row.col(|ui| {
                        ui.label(r.hostname.as_deref().unwrap_or(""));
                    });
                    row.col(|ui| {
                        ui.label(r.domain_text().unwrap_or_default());
                    });
                    row.col(|ui| {
                        ui.label(r.ports_text());
                    });
                    row.col(|ui| {
                        ui.label(RichText::new(r.alive.map(|a| a.label()).unwrap_or("")).weak());
                    });

                    let resp = row.response();
                    if resp.clicked() {
                        clicked_row = Some(r.ip);
                    }
                    resp.context_menu(|ui| {
                        let mut copy = |label: &str, text: String| {
                            if ui.add_enabled(!text.is_empty(), egui::Button::new(label)).clicked() {
                                ui.ctx().copy_text(text);
                                ui.close();
                            }
                        };
                        copy("Copy IP", r.ip.to_string());
                        copy("Copy MAC", r.mac.clone().unwrap_or_default());
                        copy("Copy hostname", r.hostname.clone().unwrap_or_default());
                        copy("Copy users", r.users.join(", "));
                        copy("Copy row", row_text_display(r));
                    });
                });
            });

        if let Some(k) = new_sort {
            self.sort = if self.sort.0 == k { (k, !self.sort.1) } else { (k, true) };
        }
        if let Some(ip) = clicked_row {
            self.selected_row = Some(ip);
        }
    }
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
        self.poll_scan();

        egui::Panel::top("toolbar").show_inside(ui, |ui| self.toolbar(ui));
        egui::Panel::bottom("status").show_inside(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(&self.status);
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
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
        egui::CentralPanel::default_margins().show_inside(ui, |ui| self.table(ui));

        if self.scan.is_some() {
            // Keep the elapsed timer ticking even between results.
            ui.ctx().request_repaint_after(std::time::Duration::from_millis(250));
        }
    }
}

/// Headless mode: `happyip --cli 192.168.1.0/24` prints live hosts as TSV.
fn run_cli(range: String, report_path: Option<std::path::PathBuf>) {
    let interfaces = targets::local_interfaces();
    let range = if range.trim().is_empty() {
        interfaces.first().map(LocalInterface::suggested_range).unwrap_or_default()
    } else {
        range
    };
    let targets = match targets::parse_targets(&range) {
        Ok(t) => t,
        Err(e) => return eprintln!("error: {e}"),
    };
    eprintln!("Scanning {} hosts in {range}…", targets.len());
    let cfg = ScanConfig {
        targets,
        threads: 128,
        timeout_ms: 1000,
        ports: DEFAULT_PORTS.split(", ").filter_map(|p| p.parse().ok()).collect(),
        resolve_names: true,
        netbios: true,
        admin_queries: cfg!(windows),
        local: interfaces.iter().map(|i| (i.ip, i.mac.clone())).collect(),
        gateway: identify::default_gateway(),
    };
    let started = Instant::now();
    let scan = scanner::start(cfg, || {});
    let all: Vec<HostResult> = scan
        .rx
        .iter()
        .map_while(|ev| match ev {
            ScanEvent::Host(h) => Some(h),
            ScanEvent::Finished => None,
        })
        .collect();
    let scanned = all.len();
    let mut alive: Vec<HostResult> = all.into_iter().filter(|h| h.alive.is_some()).collect();
    alive.sort_by_key(|h| h.ip);
    println!("IP\tDevice\tName\tUsers\tMAC\tVendor\tPorts\tWeb\tClues");
    for r in &alive {
        println!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            r.ip,
            r.device_text(),
            r.display_name().unwrap_or_else(|| "-".into()),
            if r.users.is_empty() { "-".into() } else { r.users.join(", ") },
            r.mac.as_deref().unwrap_or("-"),
            r.vendor.as_deref().unwrap_or("-"),
            r.ports_text(),
            r.http_banner.as_deref().unwrap_or("-"),
            r.device.as_ref().map(|d| d.basis.join("; ")).unwrap_or_default(),
        );
    }
    eprintln!("{} alive in {:.1}s", alive.len(), started.elapsed().as_secs_f32());
    if let Some(path) = report_path {
        let meta = report::ReportMeta {
            range,
            generated: chrono::Local::now().format("%Y-%m-%d %H:%M").to_string(),
            scanned_from: dns_lookup::get_hostname().unwrap_or_default(),
            hosts_scanned: scanned,
        };
        match std::fs::write(&path, report::html(&meta, &alive.iter().collect::<Vec<_>>())) {
            Ok(()) => eprintln!("Report written to {}", path.display()),
            Err(e) => eprintln!("error writing report: {e}"),
        }
    }
}

fn row_text(r: &HostResult) -> String {
    row_text_display(r).to_lowercase()
}

fn row_text_display(r: &HostResult) -> String {
    [
        r.ip.to_string(),
        r.device_text(),
        r.hostname.clone().unwrap_or_default(),
        r.mac.clone().unwrap_or_default(),
        r.vendor.clone().unwrap_or_default(),
        r.netbios_name.clone().unwrap_or_default(),
        r.workgroup.clone().unwrap_or_default(),
        r.users.join(", "),
        r.ports_text(),
    ]
    .into_iter()
    .filter(|s| !s.is_empty())
    .collect::<Vec<_>>()
    .join("\t")
}

fn csv_escape(s: &str) -> String {
    if s.contains([',', '"', '\n']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
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
