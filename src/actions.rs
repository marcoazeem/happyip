//! Things a row's right-click menu starts in other programs.

use crate::scanner::HostResult;

/// Name to connect to: a DNS name lets Windows use Kerberos (domain sign-in
/// without warnings); fall back to the AD DNS name, the NetBIOS name, then the IP.
/// Names come from the network, so anything that isn't a plain host name is
/// replaced by the IP before it's handed to another program.
pub fn connect_target(r: &HostResult) -> String {
    let safe = |s: &String| {
        !s.is_empty()
            && s.len() <= 253
            && !s.starts_with('-')
            && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
    };
    r.hostname
        .clone()
        .or_else(|| r.ad.as_ref()?.dns_name.clone())
        .or_else(|| r.netbios_name.clone())
        .filter(safe)
        .unwrap_or_else(|| r.ip.to_string())
}

pub fn web_url(r: &HostResult) -> Option<String> {
    let port = |p: u16| r.open_ports.contains(&p);
    if port(443) {
        Some(format!("https://{}", r.ip))
    } else if port(80) {
        Some(format!("http://{}", r.ip))
    } else if port(8080) {
        Some(format!("http://{}:8080", r.ip))
    } else if port(5000) {
        Some(format!("http://{}:5000", r.ip))
    } else {
        None
    }
}

pub fn open_web(url: &str) -> Result<(), String> {
    webbrowser::open(url).map_err(|e| format!("could not open {url}: {e}"))
}

#[allow(unused_variables)]
fn launch(program: &str, arg: String) -> Result<(), String> {
    #[cfg(any(windows, target_os = "macos"))]
    {
        std::process::Command::new(crate::probe::program_path(program))
            .arg(arg)
            .spawn()
            .map(|_| ())
            .map_err(|e| format!("could not start {program}: {e}"))
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        Err("not available on this system".into())
    }
}

/// Opens the system Remote Desktop client: `mstsc` on Windows, or the
/// Microsoft "Windows App" (rdp:// link) on macOS.
pub fn open_remote_desktop(target: &str) -> Result<(), String> {
    if cfg!(windows) {
        launch("mstsc", format!("/v:{target}"))
    } else {
        launch("/usr/bin/open", format!("rdp://full%20address=s:{target}"))
    }
}

/// Opens the host's file shares in Explorer (Windows) or Finder (macOS).
pub fn open_shares(target: &str) -> Result<(), String> {
    if cfg!(windows) {
        launch("explorer.exe", format!("\\\\{target}"))
    } else {
        launch("/usr/bin/open", format!("smb://{target}"))
    }
}

/// Opens a terminal running `ssh <target>`: a new console window on
/// Windows (which ships OpenSSH), Terminal on macOS.
pub fn open_ssh(target: &str) -> Result<(), String> {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NEW_CONSOLE: u32 = 0x0000_0010;
        // `target` is a plain host name or address (see `connect_target`),
        // so it can't add commands or options.
        std::process::Command::new(crate::probe::program_path("cmd"))
            .args(["/k", "ssh", target])
            .creation_flags(CREATE_NEW_CONSOLE)
            .spawn()
            .map(|_| ())
            .map_err(|e| format!("could not start a console: {e}"))
    }
    #[cfg(not(windows))]
    {
        launch("/usr/bin/open", format!("ssh://{target}"))
    }
}

/// Opens the host in the system's VNC viewer (Screen Sharing on macOS; on
/// Windows whichever viewer registered `vnc://` links).
pub fn open_vnc(target: &str) -> Result<(), String> {
    if cfg!(windows) {
        launch("explorer.exe", format!("vnc://{target}"))
    } else {
        launch("/usr/bin/open", format!("vnc://{target}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn hostile_names_are_never_passed_to_other_programs() {
        let ip = Ipv4Addr::new(10, 0, 0, 7);
        let target = |name: &str| {
            let mut r = HostResult::new(ip);
            r.hostname = Some(name.into());
            connect_target(&r)
        };
        assert_eq!(target("pc42.corp.example"), "pc42.corp.example");
        assert_eq!(target("FILE_SRV-01"), "FILE_SRV-01");
        // Anything that could be read as an option, a path or a second
        // argument falls back to the address.
        for evil in ["pc /admin", "pc\" /v:evil", "/v:evil", "-evil", "pc&calc", "..\\..\\share", "pc\n", "", "é.example"] {
            assert_eq!(target(evil), "10.0.0.7", "{evil:?}");
        }
        assert_eq!(target(&"a".repeat(300)), "10.0.0.7");
        // A bad DNS name isn't rescued by a NetBIOS name: the first name
        // found decides, and it falls back to the IP.
        let mut r = HostResult::new(ip);
        r.netbios_name = Some("PC42".into());
        assert_eq!(connect_target(&r), "PC42");
    }

    #[test]
    fn web_url_prefers_https() {
        let mut r = HostResult::new(Ipv4Addr::new(10, 0, 0, 7));
        assert_eq!(web_url(&r), None);
        r.open_ports = vec![80, 443, 8080];
        assert_eq!(web_url(&r).as_deref(), Some("https://10.0.0.7"));
        r.open_ports = vec![5000];
        assert_eq!(web_url(&r).as_deref(), Some("http://10.0.0.7:5000"));
    }
}
