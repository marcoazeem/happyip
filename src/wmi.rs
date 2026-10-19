//! Admin inventory of remote Windows machines over WMI, using the rights of
//! the account running HappyIP (e.g. a domain admin). This is what gives MAC
//! addresses for Windows hosts on other VLANs, where ARP can't see them, plus
//! the console user, domain, exact OS and hardware model.

use std::net::Ipv4Addr;
use std::time::Duration;

#[derive(Clone, Debug, Default, PartialEq)]
pub struct WmiInfo {
    pub computer: Option<String>,
    pub domain: Option<String>,
    pub user: Option<String>,
    pub os: Option<String>,
    pub model: Option<String>,
    pub mac: Option<String>,
}

pub fn query(ip: Ipv4Addr, timeout: Duration) -> Option<WmiInfo> {
    if !cfg!(windows) {
        return None;
    }
    run(ip, timeout).map(|text| parse(&text, ip))
}

fn run(ip: Ipv4Addr, timeout: Duration) -> Option<String> {
    // `ip` is a parsed Ipv4Addr, so it can only ever be digits and dots.
    let script = format!(
        "$ErrorActionPreference='Stop';$c='{ip}';\
         $cs=Get-WmiObject -ComputerName $c -Class Win32_ComputerSystem;\
         $os=Get-WmiObject -ComputerName $c -Class Win32_OperatingSystem;\
         'NAME='+$cs.Name;'DOMAIN='+$cs.Domain;'PARTOFDOMAIN='+$cs.PartOfDomain;'USER='+$cs.UserName;\
         'MODEL='+$cs.Manufacturer+' '+$cs.Model;'OS='+$os.Caption;\
         Get-WmiObject -ComputerName $c -Class Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=TRUE' |\
         ForEach-Object {{ 'NIC='+$_.MACAddress+'|'+($_.IPAddress -join ',') }}"
    );
    crate::probe::run_hidden_timeout(
        "powershell.exe",
        &["-NoProfile", "-NonInteractive", "-Command", &script],
        timeout,
    )
}

fn parse(text: &str, ip: Ipv4Addr) -> WmiInfo {
    let mut info = WmiInfo::default();
    let mut part_of_domain = true;
    let mut nics: Vec<(String, Vec<String>)> = Vec::new();
    let clean = |v: &str| {
        let v = v.trim();
        (!v.is_empty()).then(|| v.to_string())
    };
    for line in text.lines() {
        let Some((key, value)) = line.split_once('=') else { continue };
        match key.trim() {
            "NAME" => info.computer = clean(value),
            "DOMAIN" => info.domain = clean(value),
            "PARTOFDOMAIN" => part_of_domain = !value.trim().eq_ignore_ascii_case("false"),
            // "CORP\\jsmith" → "jsmith"; the domain has its own column.
            "USER" => info.user = clean(value.rsplit('\\').next().unwrap_or(value)),
            "MODEL" => info.model = clean(value).filter(|m| !m.eq_ignore_ascii_case("system manufacturer system product name")),
            "OS" => info.os = clean(value.trim_start_matches("Microsoft ")),
            "NIC" => {
                let (mac, ips) = value.split_once('|').unwrap_or((value, ""));
                if let Some(mac) = crate::probe::normalize_mac(mac.trim()) {
                    nics.push((mac, ips.split(',').map(|s| s.trim().to_string()).collect()));
                }
            }
            _ => {}
        }
    }
    if !part_of_domain {
        info.domain = None; // a workgroup name, not a domain
    }
    // Prefer the adapter that owns the scanned address.
    let target = ip.to_string();
    info.mac = nics
        .iter()
        .find(|(_, ips)| ips.contains(&target))
        .or_else(|| (nics.len() == 1).then(|| &nics[0]))
        .map(|(mac, _)| mac.clone());
    info
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_output() {
        let out = "NAME=PC42\r\nDOMAIN=corp.example\r\nPARTOFDOMAIN=True\r\nUSER=CORP\\jsmith\r\n\
                   MODEL=Dell Inc. OptiPlex 7090\r\nOS=Microsoft Windows 11 Pro\r\n\
                   NIC=00:11:22:33:44:55|10.9.0.4,fe80::1\r\nNIC=AA:BB:CC:DD:EE:01|10.20.0.42,fe80::2\r\n";
        let info = parse(out, "10.20.0.42".parse().unwrap());
        assert_eq!(info.computer.as_deref(), Some("PC42"));
        assert_eq!(info.domain.as_deref(), Some("corp.example"));
        assert_eq!(info.user.as_deref(), Some("jsmith"));
        assert_eq!(info.os.as_deref(), Some("Windows 11 Pro"));
        assert_eq!(info.model.as_deref(), Some("Dell Inc. OptiPlex 7090"));
        assert_eq!(info.mac.as_deref(), Some("AA:BB:CC:DD:EE:01"));

        let wg = parse("DOMAIN=WORKGROUP\nPARTOFDOMAIN=False\nUSER=\n", "10.0.0.1".parse().unwrap());
        assert_eq!(wg.domain, None);
        assert_eq!(wg.user, None);
    }
}
