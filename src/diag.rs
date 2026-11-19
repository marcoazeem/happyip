//! Diagnostics log: `happyip.log` next to the settings file. Records what
//! would otherwise vanish (failed admin and Active Directory lookups,
//! programs that wouldn't start, crashes), so there is something to look at,
//! or send, when a scan doesn't show what was expected.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;

use crate::util::lock;

/// The log starts over (keeping one old copy) once it grows past this.
const MAX_LOG_BYTES: u64 = 512 * 1024;

static FILE: Mutex<Option<File>> = Mutex::new(None);

pub fn log_path() -> Option<PathBuf> {
    crate::settings::dir().map(|d| d.join("happyip.log"))
}

fn open() -> Option<File> {
    let path = log_path()?;
    std::fs::create_dir_all(path.parent()?).ok()?;
    if std::fs::metadata(&path).is_ok_and(|m| m.len() > MAX_LOG_BYTES) {
        let _ = std::fs::rename(&path, path.with_extension("old.log"));
    }
    OpenOptions::new().create(true).append(true).open(path).ok()
}

/// Append one timestamped line to the log (and stderr, for console runs).
pub fn log(msg: impl AsRef<str>) {
    let msg = msg.as_ref().split_whitespace().collect::<Vec<_>>().join(" ");
    let line = format!("{} {msg}\n", chrono::Local::now().format("%Y-%m-%d %H:%M:%S"));
    if cfg!(test) {
        return;
    }
    eprint!("{line}");
    let mut file = lock(&FILE);
    if file.is_none() {
        *file = open();
    }
    if let Some(f) = file.as_mut() {
        let _ = f.write_all(line.as_bytes());
    }
}

/// Record crashes in the log: release builds on Windows have no console, so
/// a panic message would otherwise be lost.
pub fn install_panic_hook() {
    let default = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        log(format!("PANIC: {info}"));
        default(info);
    }));
}

/// Text for "Copy diagnostics": version, system and the end of the log.
pub fn report(settings: &str) -> String {
    let tail = log_path()
        .and_then(|p| std::fs::read_to_string(p).ok())
        .map(|t| {
            let lines: Vec<&str> = t.lines().collect();
            lines[lines.len().saturating_sub(200)..].join("\n")
        })
        .unwrap_or_default();
    format!(
        "HappyIP {} on {} ({})\n\n[settings]\n{settings}\n[log: {}]\n{}\n",
        env!("CARGO_PKG_VERSION"),
        std::env::consts::OS,
        std::env::consts::ARCH,
        log_path().map(|p| p.display().to_string()).unwrap_or_else(|| "unavailable".into()),
        if tail.is_empty() { "(empty)" } else { &tail },
    )
}
