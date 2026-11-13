//! Remembers the scan options between runs in a small `key=value` file:
//! `%APPDATA%\HappyIP\settings.ini` on Windows,
//! `~/Library/Application Support/HappyIP/settings.ini` on macOS.

use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Clone, Debug, PartialEq)]
pub struct Settings {
    pub range: Option<String>,
    pub threads: usize,
    pub timeout_ms: u64,
    pub ports: Option<String>,
    pub resolve_names: bool,
    pub netbios: bool,
    pub admin_queries: bool,
    pub use_ad: bool,
    pub show_dead: bool,
    /// Ask local devices about themselves (mDNS, UPnP, IPv6 neighbours).
    pub discovery: bool,
    /// Try SNMP on live hosts, with this community string.
    pub snmp: bool,
    pub snmp_community: Option<String>,
    /// Column the table is sorted by (see `SortKey::name`) and its direction.
    pub sort: Option<String>,
    pub sort_ascending: bool,
    /// Window size in points.
    pub window: Option<(f32, f32)>,
    pub filter: Option<String>,
    /// Show the details panel for the selected row.
    pub details: bool,
    /// Columns hidden with the Columns menu, and widths changed by dragging.
    pub hidden_columns: Vec<String>,
    pub column_widths: Vec<(String, f32)>,
    /// The last few ranges scanned, newest first.
    pub recent: Vec<String>,
    /// Ranges pinned to the Networks menu, with the ports to scan there.
    pub favourites: Vec<Favourite>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Favourite {
    pub range: String,
    pub ports: String,
}

/// Most ranges kept in the "recent" list.
pub const MAX_RECENT: usize = 8;

impl Default for Settings {
    fn default() -> Self {
        Self {
            range: None,
            threads: 128,
            timeout_ms: 1000,
            ports: None,
            resolve_names: true,
            netbios: true,
            admin_queries: cfg!(windows),
            use_ad: cfg!(windows),
            show_dead: false,
            discovery: true,
            snmp: false,
            snmp_community: None,
            sort: None,
            sort_ascending: true,
            window: None,
            filter: None,
            details: false,
            hidden_columns: Vec::new(),
            column_widths: Vec::new(),
            recent: Vec::new(),
            favourites: Vec::new(),
        }
    }
}

/// The folder holding the settings and the diagnostics log.
pub fn dir() -> Option<PathBuf> {
    let base = if cfg!(windows) {
        PathBuf::from(std::env::var_os("APPDATA")?)
    } else if cfg!(target_os = "macos") {
        PathBuf::from(std::env::var_os("HOME")?).join("Library/Application Support")
    } else {
        std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| Some(PathBuf::from(std::env::var_os("HOME")?).join(".config")))?
    };
    Some(base.join("HappyIP"))
}

fn path() -> Option<PathBuf> {
    dir().map(|d| d.join("settings.ini"))
}

pub fn load() -> Settings {
    path().and_then(|p| std::fs::read_to_string(p).ok()).map(|t| parse(&t)).unwrap_or_default()
}

pub fn save(s: &Settings) -> Result<(), String> {
    let p = path().ok_or("no settings folder on this system")?;
    if let Some(dir) = p.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    }
    std::fs::write(&p, serialize(s)).map_err(|e| format!("{}: {e}", p.display()))
}

fn parse(text: &str) -> Settings {
    let map: HashMap<&str, &str> = text
        .lines()
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| (k.trim(), v.trim()))
        .collect();
    let d = Settings::default();
    let flag = |k: &str, default: bool| map.get(k).map_or(default, |v| *v == "1" || v.eq_ignore_ascii_case("true"));
    let text = |k: &str| map.get(k).filter(|v| !v.is_empty()).map(|v| v.to_string());
    let list = |k: &str, sep: char| -> Vec<String> {
        map.get(k).map(|v| v.split(sep).map(str::trim).filter(|s| !s.is_empty()).map(str::to_string).collect()).unwrap_or_default()
    };
    Settings {
        range: text("range"),
        threads: map.get("threads").and_then(|v| v.parse().ok()).filter(|t| (1..=512).contains(t)).unwrap_or(d.threads),
        timeout_ms: map
            .get("timeout_ms")
            .and_then(|v| v.parse().ok())
            .filter(|t| (100..=10_000).contains(t))
            .unwrap_or(d.timeout_ms),
        ports: text("ports"),
        resolve_names: flag("resolve_names", d.resolve_names),
        netbios: flag("netbios", d.netbios),
        admin_queries: flag("admin_queries", d.admin_queries),
        use_ad: flag("use_ad", d.use_ad),
        show_dead: flag("show_dead", d.show_dead),
        discovery: flag("discovery", d.discovery),
        snmp: flag("snmp", d.snmp),
        snmp_community: text("snmp_community"),
        sort: text("sort"),
        sort_ascending: flag("sort_ascending", d.sort_ascending),
        window: map.get("window").and_then(|v| {
            let (w, h) = v.split_once('x')?;
            let (w, h): (f32, f32) = (w.trim().parse().ok()?, h.trim().parse().ok()?);
            ((300.0..=20_000.0).contains(&w) && (200.0..=20_000.0).contains(&h)).then_some((w, h))
        }),
        filter: text("filter"),
        details: flag("details", d.details),
        hidden_columns: list("hidden", ','),
        column_widths: list("widths", ',')
            .iter()
            .filter_map(|item| {
                let (name, width) = item.split_once(':')?;
                let width: f32 = width.parse().ok()?;
                (10.0..=5000.0).contains(&width).then(|| (name.to_string(), width))
            })
            .collect(),
        recent: list("recent", '|').into_iter().take(MAX_RECENT).collect(),
        favourites: list("favourites", '|')
            .iter()
            .filter_map(|item| {
                let (range, ports) = item.split_once('~')?;
                (!range.trim().is_empty()).then(|| Favourite { range: range.trim().to_string(), ports: ports.trim().to_string() })
            })
            .collect(),
    }
}

pub fn serialize(s: &Settings) -> String {
    let b = |v: bool| if v { "1" } else { "0" };
    // Values are single-line by construction (the range box is single-line).
    let clean = |v: &Option<String>| v.as_deref().unwrap_or("").replace(['\r', '\n'], " ");
    // List items can't hold their separators; ranges and ports never do.
    let item = |v: &str| v.replace(['\r', '\n', '|', '~'], " ");
    let lists = format!(
        "discovery={}\nsnmp={}\nsnmp_community={}\nfilter={}\ndetails={}\nhidden={}\nwidths={}\nrecent={}\nfavourites={}\n",
        b(s.discovery),
        b(s.snmp),
        clean(&s.snmp_community),
        clean(&s.filter),
        b(s.details),
        s.hidden_columns.join(","),
        s.column_widths.iter().map(|(name, w)| format!("{name}:{w:.0}")).collect::<Vec<_>>().join(","),
        s.recent.iter().map(|r| item(r)).collect::<Vec<_>>().join("|"),
        s.favourites.iter().map(|f| format!("{}~{}", item(&f.range), item(&f.ports))).collect::<Vec<_>>().join("|"),
    );
    format!(
        "range={}\nthreads={}\ntimeout_ms={}\nports={}\nresolve_names={}\nnetbios={}\nadmin_queries={}\nuse_ad={}\nshow_dead={}\nsort={}\nsort_ascending={}\nwindow={}\n",
        clean(&s.range),
        s.threads,
        s.timeout_ms,
        clean(&s.ports),
        b(s.resolve_names),
        b(s.netbios),
        b(s.admin_queries),
        b(s.use_ad),
        b(s.show_dead),
        clean(&s.sort),
        b(s.sort_ascending),
        s.window.map(|(w, h)| format!("{w:.0}x{h:.0}")).unwrap_or_default(),
    ) + &lists
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let s = Settings {
            range: Some("10.20.0.0/24, 10.30.*.*".into()),
            threads: 64,
            timeout_ms: 1500,
            ports: Some("22, 80".into()),
            resolve_names: false,
            netbios: true,
            admin_queries: false,
            use_ad: true,
            show_dead: true,
            discovery: false,
            snmp: true,
            snmp_community: Some("lab-ro".into()),
            sort: Some("vendor".into()),
            sort_ascending: false,
            window: Some((1400.0, 900.0)),
            filter: Some("printer".into()),
            details: true,
            hidden_columns: vec!["ttl".into(), "seen_via".into()],
            column_widths: vec![("ip".into(), 120.0), ("device".into(), 210.0)],
            recent: vec!["10.20.0.0/24".into(), "10.30.0.1-50, pc42".into()],
            favourites: vec![
                Favourite { range: "10.20.0.0/24, 10.30.*.*".into(), ports: "22, 80, 443".into() },
                Favourite { range: "fileserver01".into(), ports: String::new() },
            ],
        };
        assert_eq!(parse(&serialize(&s)), s);
        // Junk and out-of-range values fall back to defaults.
        let d = parse("threads=99999\ntimeout_ms=abc\nnonsense\n");
        assert_eq!(d.threads, 128);
        assert_eq!(d.timeout_ms, 1000);
        assert_eq!(parse("window=5x5\n").window, None);
        let d = parse("widths=ip:abc,device:99999,name:150\nfavourites=~80|10.0.0.0/24~\n");
        assert_eq!(d.column_widths, vec![("name".to_string(), 150.0)]);
        assert_eq!(d.favourites, vec![Favourite { range: "10.0.0.0/24".into(), ports: String::new() }]);
    }
}
