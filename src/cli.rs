//! Headless mode: `happyip --cli 192.168.1.0/24` prints live hosts as TSV
//! and can write the HTML report, a CSV and a JSON file.

use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::time::Instant;

use crate::scanner::{self, AdminDetails, HostResult, ScanConfig, ScanEvent};
use crate::targets::{self, LocalInterface, Network};
use crate::{ad, export, identify, report, settings};

pub const USAGE: &str = "\
Usage: happyip --cli [RANGE...] [options]

RANGE     e.g. 192.168.1.0/24, 10.0.0.1-50, 10.20.*.*, pc42
          (default: this computer's own subnet)

Options:
  --report FILE    write the HTML report
  --csv FILE       write every scanned address as CSV
  --json FILE      write every scanned address as JSON
  --ports LIST     ports to check, e.g. \"22, 80, 8000-8010\" (\"\" for none)
  --timeout MS     wait per probe, 100-10000 (default: saved setting, else 1000)
  --threads N      addresses scanned at once, 1-512 (default: saved setting, else 128)
  --snmp COMMUNITY ask live hosts for their description over SNMP (e.g. public)
  --no-discovery   skip mDNS, UPnP and IPv6 neighbour discovery
  --no-admin       skip the admin (WMI) queries to Windows PCs
  --no-ad          skip the Active Directory lookup
  --help           show this text

Ports, timeout and threads default to what was last used in the window.";

#[derive(Debug, Default, PartialEq)]
pub struct Options {
    pub range: String,
    pub report: Option<PathBuf>,
    pub csv: Option<PathBuf>,
    pub json: Option<PathBuf>,
    pub ports: Option<String>,
    pub timeout_ms: Option<u64>,
    pub threads: Option<usize>,
    pub snmp: Option<String>,
    pub no_discovery: bool,
    pub no_admin: bool,
    pub no_ad: bool,
    pub help: bool,
}

pub fn parse_args(args: &[String]) -> Result<Options, String> {
    let mut o = Options::default();
    let mut ranges: Vec<&str> = Vec::new();
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        let mut value = || it.next().ok_or_else(|| format!("{arg} needs a value")).map(String::as_str);
        match arg.as_str() {
            "--report" => o.report = Some(PathBuf::from(value()?)),
            "--csv" => o.csv = Some(PathBuf::from(value()?)),
            "--json" => o.json = Some(PathBuf::from(value()?)),
            "--ports" => o.ports = Some(value()?.to_string()),
            "--timeout" => {
                let v = value()?;
                o.timeout_ms = Some(v.parse().ok().filter(|t| (100..=10_000).contains(t)).ok_or(format!("--timeout {v}: expected 100-10000"))?);
            }
            "--threads" => {
                let v = value()?;
                o.threads = Some(v.parse().ok().filter(|t| (1..=512).contains(t)).ok_or(format!("--threads {v}: expected 1-512"))?);
            }
            "--snmp" => {
                let v = value()?;
                if v.is_empty() || v.len() > crate::snmp::MAX_COMMUNITY {
                    return Err(format!("--snmp: the community must be 1-{} characters", crate::snmp::MAX_COMMUNITY));
                }
                o.snmp = Some(v.to_string());
            }
            "--no-discovery" => o.no_discovery = true,
            "--no-admin" => o.no_admin = true,
            "--no-ad" => o.no_ad = true,
            "--help" | "-h" => o.help = true,
            other if other.starts_with("--") => return Err(format!("unknown option {other}")),
            range => ranges.push(range),
        }
    }
    o.range = ranges.join(",");
    Ok(o)
}

/// Returns the process exit code.
pub fn run(args: &[String]) -> i32 {
    let opts = match parse_args(args) {
        Ok(o) if o.help => {
            println!("{USAGE}");
            return 0;
        }
        Ok(o) => o,
        Err(e) => {
            eprintln!("error: {e}\n\n{USAGE}");
            return 2;
        }
    };
    let saved = settings::load();
    let interfaces = targets::local_interfaces();
    let range = if opts.range.trim().is_empty() {
        interfaces.first().map(LocalInterface::suggested_range).unwrap_or_default()
    } else {
        opts.range.clone()
    };
    let ports_text = opts.ports.clone().or(saved.ports.clone()).unwrap_or_else(|| crate::DEFAULT_PORTS.into());
    let parsed = targets::parse_targets(&range).and_then(|t| Ok((t, targets::parse_ports(&ports_text)?)));
    let (targets, ports) = match parsed {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: {e}");
            return 2;
        }
    };

    let directory = if cfg!(windows) && !opts.no_ad {
        match ad::load(crate::AD_TIMEOUT) {
            Ok(d) => {
                eprintln!("Active Directory: {} ({} computers, {} subnets)", d.domain, d.computers.len(), d.subnets.len());
                Some(d)
            }
            Err(e) => {
                eprintln!("Active Directory: {e}");
                None
            }
        }
    } else {
        None
    };
    let mut networks: Vec<Network> = interfaces.iter().map(LocalInterface::network).collect();
    networks.extend(directory.as_ref().map(|d| d.networks()).unwrap_or_default());
    networks.extend(targets::routed_networks());
    let gateway = identify::default_gateway();

    eprintln!("Scanning {} hosts in {range}…", targets.len());
    let cfg = ScanConfig {
        targets,
        threads: opts.threads.unwrap_or(saved.threads),
        timeout_ms: opts.timeout_ms.unwrap_or(saved.timeout_ms),
        ports,
        resolve_names: true,
        netbios: true,
        admin_queries: cfg!(windows) && !opts.no_admin,
        local: interfaces.iter().map(|i| (i.ip, i.mac.clone())).collect(),
        on_link: interfaces.iter().map(LocalInterface::subnet).collect(),
        gateway,
        local_discovery: !opts.no_discovery,
        snmp_community: opts.snmp.clone(),
        interface_names: interfaces.iter().map(|i| i.name.clone()).collect(),
    };
    let started = Instant::now();
    let scan = scanner::start(cfg, || {});
    let mut all: Vec<HostResult> = Vec::new();
    let mut ipv6 = std::collections::HashMap::new();
    for ev in scan.rx.iter() {
        match ev {
            ScanEvent::Host(h) => all.push(h),
            ScanEvent::Update(mut h) => {
                h.set_ipv6(&ipv6); // admin details may have brought the MAC
                if let Some(row) = all.iter_mut().find(|r| r.ip == h.ip) {
                    *row = h;
                }
            }
            ScanEvent::NotAlive(ips) => {
                eprintln!("Ignoring {} addresses answered only by a firewall/proxy", ips.len());
                let ips: HashSet<Ipv4Addr> = ips.into_iter().collect();
                for r in all.iter_mut().filter(|r| ips.contains(&r.ip)) {
                    r.alive = None;
                    r.firewall_reply = true;
                }
            }
            ScanEvent::Neighbors(neighbors) => {
                for r in &mut all {
                    r.set_ipv6(&neighbors);
                }
                ipv6 = neighbors;
            }
            ScanEvent::Departed(ips) => {
                for r in all.iter_mut().filter(|r| ips.contains(&r.ip)) {
                    r.alive = None;
                }
            }
            ScanEvent::HostsDone { admin_pending } => {
                eprintln!("Hosts scanned in {:.1}s", started.elapsed().as_secs_f32());
                if admin_pending > 0 {
                    eprintln!("Getting admin details from {admin_pending} Windows PCs…");
                }
            }
            ScanEvent::Finished => break,
        }
    }
    for r in &mut all {
        r.enrich(directory.as_ref(), &networks, gateway);
    }
    all.sort_by_key(|h| h.ip);
    let alive: Vec<&HostResult> = all.iter().filter(|h| h.alive.is_some()).collect();
    println!("IP\tDevice\tName\tUsers\tMAC\tVendor\tNetwork\tAD OU\tPorts\tWeb\tIPv6\tClues");
    for r in &alive {
        println!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            r.ip,
            r.device_text(),
            r.display_name().unwrap_or_else(|| "-".into()),
            if r.users.is_empty() { "-".into() } else { r.users.join(", ") },
            r.mac.as_deref().unwrap_or("-"),
            r.vendor.as_deref().unwrap_or("-"),
            r.network.as_deref().unwrap_or("-"),
            if r.ad.is_some() { r.ad_text() } else { "-".into() },
            r.ports_text(),
            r.http_banner.as_deref().unwrap_or("-"),
            if r.ipv6.is_empty() { "-".into() } else { r.ipv6_text() },
            r.device.as_ref().map(|d| d.basis.join("; ")).unwrap_or_default(),
        );
    }
    let secs = started.elapsed().as_secs_f32();
    eprintln!("{} alive in {secs:.1}s", alive.len());
    let failed = all.iter().filter(|r| r.admin == AdminDetails::Failed).count();
    if failed > 0 {
        let answered = all.iter().filter(|r| r.admin == AdminDetails::Answered).count();
        eprintln!("Admin details: {answered} Windows PCs answered, {failed} didn't (access denied or blocked)");
    }

    let generated = chrono::Local::now().format("%Y-%m-%d %H:%M").to_string();
    let everything: Vec<&HostResult> = all.iter().collect();
    let mut exit = 0;
    let mut write = |what: &str, path: &Option<PathBuf>, content: &dyn Fn() -> String| {
        let Some(path) = path else { return };
        match std::fs::write(path, content()) {
            Ok(()) => eprintln!("{what} written to {}", path.display()),
            Err(e) => {
                eprintln!("error writing {}: {e}", path.display());
                exit = 1;
            }
        }
    };
    write("Report", &opts.report, &|| {
        let meta = report::ReportMeta {
            range: range.clone(),
            generated: generated.clone(),
            scanned_from: dns_lookup::get_hostname().unwrap_or_default(),
            hosts_scanned: all.len(),
            domain: directory.as_ref().map(|d| d.domain.clone()),
            duration: Some(secs),
        };
        report::html(&meta, &alive)
    });
    write("CSV", &opts.csv, &|| export::csv(&everything));
    write("JSON", &opts.json, &|| export::json(&range, &generated, &everything));
    exit
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(s: &str) -> Vec<String> {
        s.split_whitespace().map(str::to_string).collect()
    }

    #[test]
    fn parses_options() {
        let o = parse_args(&args("10.0.0.0/24 10.0.1.1-9 --report r.html --csv out.csv --json out.json --timeout 500 --threads 32 --no-admin")).unwrap();
        assert_eq!(o.range, "10.0.0.0/24,10.0.1.1-9");
        assert_eq!(o.report, Some(PathBuf::from("r.html")));
        assert_eq!(o.csv, Some(PathBuf::from("out.csv")));
        assert_eq!(o.json, Some(PathBuf::from("out.json")));
        assert_eq!((o.timeout_ms, o.threads), (Some(500), Some(32)));
        assert!(o.no_admin && !o.no_ad && !o.help);
        let o = parse_args(&args("10.0.0.5 --snmp public --no-discovery")).unwrap();
        assert_eq!((o.snmp.as_deref(), o.no_discovery), (Some("public"), true));
        // Ranges may come after options too.
        assert_eq!(parse_args(&args("--ports 22,80 10.0.0.5")).unwrap().range, "10.0.0.5");
        assert_eq!(parse_args(&[]).unwrap(), Options::default());
    }

    #[test]
    fn rejects_bad_options() {
        for bad in ["--report", "--timeout 5", "--timeout abc", "--threads 0", "--threads 9999", "--frobnicate", "--snmp"] {
            assert!(parse_args(&args(bad)).is_err(), "{bad}");
        }
    }
}
