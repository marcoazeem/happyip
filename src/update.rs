//! Self-update from GitHub Releases.
//!
//! Every release carries a small manifest, `update.txt`, naming its version
//! and the SHA-256 of each download. HappyIP reads the manifest of the
//! latest release, and when that is newer than itself it can download the
//! file for this system, check it against the manifest and put it in place
//! of the running copy.
//!
//! Downloads go through the system's `curl` (part of Windows 10 and later,
//! macOS and nearly every Linux), restricted to HTTPS, so the operating
//! system's own certificate checks apply and HappyIP needs no TLS code of
//! its own. Nothing is installed unless the user asks for it.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::probe::hidden_command;

/// Where releases are published.
pub const RELEASES_PAGE: &str = "https://github.com/marcoazeem/happyip/releases";
const MANIFEST: &str = "update.txt";

/// The download for this system, if one is published.
pub const ASSET: Option<&str> = if cfg!(all(windows, target_arch = "x86_64")) {
    Some("HappyIP-Windows-x64.exe")
} else if cfg!(target_os = "macos") {
    Some("HappyIP-macOS.dmg")
} else if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
    Some("HappyIP-Linux-x64.tar.gz")
} else if cfg!(all(target_os = "linux", target_arch = "aarch64")) {
    Some("HappyIP-Linux-arm64.tar.gz")
} else {
    None
};

pub fn current_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// A published version newer than this one.
#[derive(Clone, Debug, PartialEq)]
pub struct Release {
    pub version: String,
    /// SHA-256 of this system's download; `None` if the release has no
    /// download for this system.
    sha256: Option<String>,
}

impl Release {
    /// Can this release be installed from inside the app?
    pub fn installable(&self) -> bool {
        self.sha256.is_some() && ASSET.is_some()
    }
}

/// `[major, minor, patch]` of a plain version like "0.4.0".
fn parse_version(v: &str) -> Option<[u32; 3]> {
    let mut parts = v.split('.');
    let mut out = [0u32; 3];
    for slot in &mut out {
        let part = parts.next()?;
        if part.is_empty() || part.len() > 5 || !part.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        *slot = part.parse().ok()?;
    }
    parts.next().is_none().then_some(out)
}

pub fn is_newer(candidate: &str, current: &str) -> bool {
    matches!((parse_version(candidate), parse_version(current)), (Some(a), Some(b)) if a > b)
}

/// Read a manifest:
///
/// ```text
/// version=0.4.0
/// HappyIP-Windows-x64.exe=<64 hex digits>
/// HappyIP-macOS.dmg=<64 hex digits>
/// ```
///
/// It comes from the network, so only a plain version number and a
/// well-formed checksum are accepted; nothing in it is used as a path or URL.
pub fn parse_manifest(text: &str, asset: Option<&str>) -> Result<Release, String> {
    let value = |key: &str| text.lines().filter_map(|l| l.trim().split_once('=')).find(|(k, _)| k.trim() == key).map(|(_, v)| v.trim());
    let version = value("version").filter(|v| parse_version(v).is_some()).ok_or("the update information is not readable")?;
    let sha256 = asset
        .and_then(value)
        .filter(|h| h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit()))
        .map(|h| h.to_ascii_lowercase());
    Ok(Release { version: version.to_string(), sha256 })
}

/// Where to fetch from. Debug builds can be pointed at a test server.
fn base_url() -> String {
    #[cfg(debug_assertions)]
    if let Ok(url) = std::env::var("HAPPYIP_UPDATE_BASE") {
        return url;
    }
    RELEASES_PAGE.to_string()
}

fn curl() -> Command {
    // Windows ships curl.exe in System32 (started by full path); macOS has
    // /usr/bin/curl; elsewhere it's found on the PATH.
    let program = if cfg!(target_os = "macos") { "/usr/bin/curl" } else { "curl" };
    let mut cmd = hidden_command(program, &["--fail", "--silent", "--show-error", "--location", "--user-agent"]);
    cmd.arg(format!("HappyIP/{}", current_version()));
    // Release builds only ever talk HTTPS, also after redirects.
    if !cfg!(debug_assertions) || std::env::var_os("HAPPYIP_UPDATE_BASE").is_none() {
        cmd.args(["--proto", "=https", "--proto-redir", "=https", "--tlsv1.2"]);
    }
    cmd.stdin(Stdio::null());
    cmd
}

fn run_curl(mut cmd: Command) -> Result<Vec<u8>, String> {
    let out = cmd.output().map_err(|e| format!("couldn't start curl, which HappyIP uses to download updates ({e})"))?;
    if out.status.success() {
        return Ok(out.stdout);
    }
    let reason = String::from_utf8_lossy(&out.stderr);
    let reason = reason.lines().map(str::trim).find(|l| !l.is_empty()).unwrap_or("no connection?");
    Err(reason.trim_start_matches("curl: ").chars().take(200).collect())
}

/// Ask GitHub for the latest release. `Ok(None)` when this copy is current.
pub fn check() -> Result<Option<Release>, String> {
    let mut cmd = curl();
    cmd.args(["--max-time", "20", "--max-filesize", "65536"]);
    cmd.arg(format!("{}/latest/download/{MANIFEST}", base_url()));
    let text = run_curl(cmd).map_err(|e| format!("couldn't check for updates: {e}"))?;
    let release = parse_manifest(&String::from_utf8_lossy(&text), ASSET)?;
    Ok(is_newer(&release.version, current_version()).then_some(release))
}

/// Download `release`, verify it and put it in place of the running copy.
/// Returns what to start to run the new version.
pub fn install(release: &Release) -> Result<PathBuf, String> {
    let (Some(asset), Some(expected)) = (ASSET, release.sha256.as_deref()) else {
        return Err(format!("version {} has no download for this system; get it from {RELEASES_PAGE}", release.version));
    };
    if !is_newer(&release.version, current_version()) {
        return Err("that version is not newer than this one".into());
    }
    let work = crate::settings::dir().ok_or("no folder to download to")?.join("update");
    let _ = std::fs::remove_dir_all(&work);
    std::fs::create_dir_all(&work).map_err(|e| format!("{}: {e}", work.display()))?;
    let file = work.join(asset);

    let mut cmd = curl();
    cmd.args(["--max-time", "900", "--max-filesize", "209715200", "--output"]);
    cmd.arg(&file);
    cmd.arg(format!("{}/download/v{}/{asset}", base_url(), release.version));
    run_curl(cmd).map_err(|e| format!("the download failed: {e}"))?;

    let actual = crate::sha256::of_file(&file).map_err(|e| format!("couldn't read the download: {e}"))?;
    if actual != expected {
        let _ = std::fs::remove_dir_all(&work);
        return Err("the download doesn't match the published checksum, so it was not installed".into());
    }
    let exe = std::env::current_exe().map_err(|e| format!("can't tell where HappyIP is installed: {e}"))?;
    let result = replace_running_copy(&exe, &file, &work);
    let _ = std::fs::remove_dir_all(&work);
    if result.is_ok() {
        crate::diag::log(format!("updated from {} to {}", current_version(), release.version));
    }
    result
}

fn no_access(what: &Path, e: std::io::Error) -> String {
    format!("couldn't replace {} ({e}). Is HappyIP in a folder you can't write to?", what.display())
}

/// Windows: a running .exe can't be overwritten, but it can be renamed.
/// The old copy is moved aside and removed the next time HappyIP starts.
#[cfg(windows)]
fn replace_running_copy(exe: &Path, download: &Path, _work: &Path) -> Result<PathBuf, String> {
    swap_in(exe, download, &old_copy(exe))?;
    Ok(exe.to_path_buf())
}

/// Linux: unpack the program from the archive and rename it over the
/// running one (the running process keeps its old file open).
#[cfg(all(unix, not(target_os = "macos")))]
fn replace_running_copy(exe: &Path, download: &Path, work: &Path) -> Result<PathBuf, String> {
    let mut tar = hidden_command("tar", &["-xzf"]);
    tar.arg(download).arg("-C").arg(work).arg("HappyIP/happyip");
    let unpacked = tar.output().map_err(|e| format!("couldn't start tar: {e}"))?;
    if !unpacked.status.success() {
        return Err("the download couldn't be unpacked".into());
    }
    swap_in(exe, &work.join("HappyIP").join("happyip"), &old_copy(exe))?;
    Ok(exe.to_path_buf())
}

/// macOS: copy HappyIP.app out of the disk image and swap it with the
/// installed one.
#[cfg(target_os = "macos")]
fn replace_running_copy(exe: &Path, download: &Path, work: &Path) -> Result<PathBuf, String> {
    let bundle = exe
        .ancestors()
        .find(|p| p.extension().is_some_and(|e| e == "app"))
        .ok_or_else(|| format!("this copy isn't running from HappyIP.app; download the new version from {RELEASES_PAGE}"))?;
    let parent = bundle.parent().ok_or("HappyIP.app has no folder")?;
    let mount = work.join("image");
    std::fs::create_dir_all(&mount).map_err(|e| e.to_string())?;
    let run = |program: &str, args: &[&std::ffi::OsStr]| {
        Command::new(program).args(args).stdin(Stdio::null()).output().is_ok_and(|o| o.status.success())
    };
    if !run("/usr/bin/hdiutil", &["attach".as_ref(), "-nobrowse".as_ref(), "-readonly".as_ref(), "-mountpoint".as_ref(), mount.as_os_str(), download.as_os_str()]) {
        return Err("the downloaded disk image couldn't be opened".into());
    }
    let staged = parent.join(".HappyIP-update.app");
    let _ = std::fs::remove_dir_all(&staged);
    let source = mount.join("HappyIP.app");
    let copied = source.join("Contents/MacOS/HappyIP").is_file() && run("/usr/bin/ditto", &[source.as_os_str(), staged.as_os_str()]);
    run("/usr/bin/hdiutil", &["detach".as_ref(), mount.as_os_str(), "-quiet".as_ref()]);
    if !copied {
        let _ = std::fs::remove_dir_all(&staged);
        return Err(format!("couldn't copy the new HappyIP.app next to {}. Is that folder writable?", bundle.display()));
    }
    let old = parent.join(".HappyIP-old.app");
    let _ = std::fs::remove_dir_all(&old);
    std::fs::rename(bundle, &old).map_err(|e| no_access(bundle, e))?;
    if let Err(e) = std::fs::rename(&staged, bundle) {
        let _ = std::fs::rename(&old, bundle);
        let _ = std::fs::remove_dir_all(&staged);
        return Err(no_access(bundle, e));
    }
    let _ = std::fs::remove_dir_all(&old);
    Ok(bundle.to_path_buf())
}

/// Where the replaced program is kept until the next start.
#[cfg_attr(target_os = "macos", allow(dead_code))]
fn old_copy(exe: &Path) -> PathBuf {
    let mut name = exe.file_name().unwrap_or_default().to_os_string();
    name.push(".old");
    exe.with_file_name(name)
}

/// Put `new` where `exe` is, keeping `exe` as `old` until it has worked.
/// If the new file can't be put in place the original is restored.
#[cfg_attr(target_os = "macos", allow(dead_code))]
fn swap_in(exe: &Path, new: &Path, old: &Path) -> Result<(), String> {
    if !new.is_file() {
        return Err("the new version wasn't found in the download".into());
    }
    // Stage the new file in the same folder first: that is where a missing
    // permission shows up, before anything has been moved.
    let mut staged = exe.file_name().unwrap_or_default().to_os_string();
    staged.push(".new");
    let staged = exe.with_file_name(staged);
    std::fs::copy(new, &staged).map_err(|e| no_access(exe, e))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o755));
    }
    let _ = std::fs::remove_file(old);
    if let Err(e) = std::fs::rename(exe, old) {
        let _ = std::fs::remove_file(&staged);
        return Err(no_access(exe, e));
    }
    if let Err(e) = std::fs::rename(&staged, exe) {
        let _ = std::fs::rename(old, exe);
        let _ = std::fs::remove_file(&staged);
        return Err(no_access(exe, e));
    }
    Ok(())
}

/// Remove what an earlier update left behind. Called at startup.
pub fn clean_up() {
    if let Ok(exe) = std::env::current_exe() {
        let _ = std::fs::remove_file(old_copy(&exe));
    }
}

/// Start the updated copy (`target` comes from [`install`]).
pub fn relaunch(target: &Path) -> Result<(), String> {
    let mut cmd = if cfg!(target_os = "macos") {
        let mut open = Command::new("/usr/bin/open");
        open.arg("-n").arg(target);
        open
    } else {
        Command::new(target)
    };
    cmd.stdin(Stdio::null()).spawn().map(|_| ()).map_err(|e| format!("couldn't start the new version: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const HASH: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    #[test]
    fn compares_versions_by_number() {
        assert!(is_newer("0.4.0", "0.3.9"));
        assert!(is_newer("0.10.0", "0.9.9"));
        assert!(is_newer("1.0.0", "0.99.99"));
        assert!(!is_newer("0.4.0", "0.4.0"));
        assert!(!is_newer("0.3.9", "0.4.0"));
        // Anything that isn't a plain version is never "newer".
        for odd in ["", "v0.5.0", "0.5", "0.5.0.1", "0.5.0-beta", "9999999.0.0", "1..0", " 1.0.0", "1.0.x"] {
            assert!(!is_newer(odd, "0.4.0"), "{odd:?}");
        }
    }

    #[test]
    fn reads_manifests() {
        let text = format!("version=0.5.0\r\nHappyIP-Windows-x64.exe={}\r\nHappyIP-macOS.dmg={HASH}\n", HASH.to_uppercase());
        let r = parse_manifest(&text, Some("HappyIP-Windows-x64.exe")).unwrap();
        assert_eq!((r.version.as_str(), r.sha256.as_deref()), ("0.5.0", Some(HASH)));
        // A release without a download for this system is still reported.
        let r = parse_manifest(&text, Some("HappyIP-Linux-x64.tar.gz")).unwrap();
        assert_eq!(r.sha256, None);
        assert!(!r.installable());
        assert_eq!(parse_manifest(&text, None).unwrap().sha256, None);
    }

    #[test]
    fn rejects_manifests_that_are_not_manifests() {
        for bad in [
            "",
            "<html>Not Found</html>",
            "version=\n",
            "version=latest\n",
            "version=0.5.0/../../evil\n",
            "version=0.5.0 && calc\n",
            "ver=0.5.0\n",
        ] {
            assert!(parse_manifest(bad, Some("HappyIP-macOS.dmg")).is_err(), "{bad:?}");
        }
        // A checksum that isn't one is ignored, so nothing can be installed.
        for bad_hash in ["", "abc", &"g".repeat(64), &format!("{HASH}00"), "../../x"] {
            let r = parse_manifest(&format!("version=0.5.0\nHappyIP-macOS.dmg={bad_hash}\n"), Some("HappyIP-macOS.dmg")).unwrap();
            assert_eq!(r.sha256, None, "{bad_hash:?}");
        }
    }

    #[test]
    fn swaps_the_program_and_keeps_the_old_one_aside() {
        let dir = std::env::temp_dir().join(format!("happyip-swap-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let exe = dir.join(if cfg!(windows) { "HappyIP.exe" } else { "happyip" });
        let new = dir.join("download");
        std::fs::write(&exe, b"old version").unwrap();
        std::fs::write(&new, b"new version").unwrap();

        swap_in(&exe, &new, &old_copy(&exe)).unwrap();
        assert_eq!(std::fs::read(&exe).unwrap(), b"new version");
        assert_eq!(std::fs::read(old_copy(&exe)).unwrap(), b"old version");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&exe).unwrap().permissions().mode() & 0o111, 0o111, "must be runnable");
        }

        // A second update replaces the leftover of the first.
        std::fs::write(&new, b"newer version").unwrap();
        swap_in(&exe, &new, &old_copy(&exe)).unwrap();
        assert_eq!(std::fs::read(&exe).unwrap(), b"newer version");
        assert_eq!(std::fs::read(old_copy(&exe)).unwrap(), b"new version");

        // Nothing to install: the program is left exactly as it was.
        assert!(swap_in(&exe, &dir.join("missing"), &old_copy(&exe)).is_err());
        assert_eq!(std::fs::read(&exe).unwrap(), b"newer version");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn every_supported_system_has_a_download() {
        if cfg!(any(windows, target_os = "macos", target_os = "linux")) && cfg!(any(target_arch = "x86_64", target_arch = "aarch64")) {
            // Windows on ARM runs the x64 build but isn't offered in-app updates.
            assert!(ASSET.is_some() || cfg!(all(windows, target_arch = "aarch64")));
        }
        assert!(parse_version(current_version()).is_some(), "the version in Cargo.toml must be plain x.y.z");
    }
}
