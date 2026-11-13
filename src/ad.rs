//! Active Directory lookups that work for any domain user (no admin rights):
//! computer accounts (OS, OU, description, last logon, disabled, domain
//! controller), Sites & Services subnets (which name the VLANs / sites) and
//! DNS reverse lookup zones. One read-only LDAP query via PowerShell's
//! built-in DirectoryServices classes, so RSAT isn't needed.

use std::collections::HashMap;
use std::time::Duration;

use crate::targets::{NetSource, Network};

#[derive(Clone, Debug, Default, PartialEq)]
pub struct AdComputer {
    pub name: String,
    pub dns_name: Option<String>,
    /// e.g. "Windows 11 Enterprise 23H2"
    pub os: Option<String>,
    pub description: Option<String>,
    /// OU path from the domain root, e.g. "Workstations/Finance".
    pub ou: Option<String>,
    /// Last logon (replicated, accurate to ~2 weeks), yyyy-mm-dd.
    pub last_logon: Option<String>,
    pub enabled: bool,
    pub is_dc: bool,
    pub location: Option<String>,
}

pub struct Directory {
    pub domain: String,
    pub computers: Vec<AdComputer>,
    by_name: HashMap<String, usize>,
    by_dns: HashMap<String, usize>,
    /// Sites & Services subnets, labelled with site / description / location.
    pub subnets: Vec<Network>,
    /// Networks from DNS reverse lookup zones.
    pub zones: Vec<Network>,
    /// Parts of the query that failed (shown as a hint, not fatal).
    pub warnings: Vec<String>,
}

impl Directory {
    /// The computer account for a scanned host, matched by DNS name, then by
    /// NetBIOS name / the first label of its DNS name.
    pub fn find(&self, netbios: Option<&str>, hostname: Option<&str>) -> Option<&AdComputer> {
        let lower = |s: &str| s.trim_end_matches('.').to_lowercase();
        hostname
            .and_then(|h| self.by_dns.get(&lower(h)))
            .or_else(|| netbios.and_then(|n| self.by_name.get(&lower(n))))
            .or_else(|| hostname.and_then(|h| self.by_name.get(&lower(h.split('.').next().unwrap_or(h)))))
            .map(|&i| &self.computers[i])
    }

    /// AD subnets plus DNS zones not already covered by a subnet.
    pub fn networks(&self) -> Vec<Network> {
        let mut out = self.subnets.clone();
        for z in &self.zones {
            if !out.iter().any(|n| n.network == z.network && n.prefix == z.prefix) {
                out.push(z.clone());
            }
        }
        out.sort_by_key(|n| (u32::from(n.network), n.prefix));
        out
    }
}

/// Query AD for this computer's domain. `Err` explains why nothing was loaded
/// (not domain-joined, no DC reachable, not Windows...).
pub fn load(timeout: Duration) -> Result<Directory, String> {
    if !cfg!(windows) {
        return Err("Active Directory lookups are only available on Windows".into());
    }
    let result = crate::probe::run_powershell(SCRIPT, timeout).and_then(|out| parse(&out));
    match &result {
        Ok(dir) => {
            for w in &dir.warnings {
                crate::diag::log(format!("Active Directory: {w}"));
            }
        }
        Err(e) => crate::diag::log(format!("Active Directory: {e}")),
    }
    result
}

/// PowerShell 2.0 compatible (Windows 7 / Server 2008 R2 and later).
const SCRIPT: &str = r#"
$ErrorActionPreference='Stop'
try{[Console]::OutputEncoding=[Text.Encoding]::UTF8}catch{}
try{$d=[DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain()}catch{'NODOMAIN';exit 0}
'DOMAIN='+$d.Name
function V($p,$n){$v=$p[$n];if($v -ne $null -and $v.Count -gt 0){([string]$v[0]) -replace '[\r\n\t|]',' '}else{''}}
function Find($root,$filter,$props){
 $s=New-Object DirectoryServices.DirectorySearcher
 $s.SearchRoot=New-Object DirectoryServices.DirectoryEntry($root)
 $s.Filter=$filter;$s.PageSize=1000
 foreach($p in $props){[void]$s.PropertiesToLoad.Add($p)}
 $s.FindAll()
}
$rd=New-Object DirectoryServices.DirectoryEntry('LDAP://RootDSE')
$def=[string]$rd.Properties['defaultNamingContext'][0]
$cfg=[string]$rd.Properties['configurationNamingContext'][0]
$fr=[string]$rd.Properties['rootDomainNamingContext'][0]
try{
 foreach($r in (Find ('LDAP://'+$def) '(objectCategory=computer)' @('name','dnshostname','operatingsystem','operatingsystemversion','description','distinguishedname','lastlogontimestamp','useraccountcontrol','location'))){
  try{
   $p=$r.Properties;$ll='';$t=V $p 'lastlogontimestamp'
   if($t){$ll=[DateTime]::FromFileTimeUtc([long]$t).ToString('yyyy-MM-dd',[Globalization.CultureInfo]::InvariantCulture)}
   'C='+(V $p 'name')+'|'+(V $p 'dnshostname')+'|'+(V $p 'operatingsystem')+'|'+(V $p 'operatingsystemversion')+'|'+(V $p 'description')+'|'+(V $p 'distinguishedname')+'|'+$ll+'|'+(V $p 'useraccountcontrol')+'|'+(V $p 'location')
  }catch{}
 }
}catch{'ERR=computers: '+$_.Exception.Message}
try{
 foreach($r in (Find ('LDAP://CN=Subnets,CN=Sites,'+$cfg) '(objectClass=subnet)' @('name','siteobject','description','location'))){
  $p=$r.Properties;$site=V $p 'siteobject'
  if($site -match '^CN=([^,]+)'){$site=$matches[1]}
  'S='+(V $p 'name')+'|'+$site+'|'+(V $p 'description')+'|'+(V $p 'location')
 }
}catch{'ERR=subnets: '+$_.Exception.Message}
foreach($z in @('DC=DomainDnsZones,'+$def,'DC=ForestDnsZones,'+$fr,'CN=MicrosoftDNS,CN=System,'+$def)){
 try{foreach($r in (Find ('LDAP://'+$z) '(&(objectClass=dnsZone)(name=*.in-addr.arpa))' @('name'))){'Z='+(V $r.Properties 'name')}}catch{}
}
"#;

const UAC_DISABLED: u32 = 0x2;
const UAC_DC: u32 = 0x2000;
const UAC_RODC: u32 = 0x0400_0000;

pub fn parse(text: &str) -> Result<Directory, String> {
    let mut dir = Directory {
        domain: String::new(),
        computers: Vec::new(),
        by_name: HashMap::new(),
        by_dns: HashMap::new(),
        subnets: Vec::new(),
        zones: Vec::new(),
        warnings: Vec::new(),
    };
    let opt = |s: &str| {
        let s = s.trim();
        (!s.is_empty()).then(|| s.to_string())
    };
    for line in text.lines() {
        let line = line.trim_end_matches('\r');
        if line.trim() == "NODOMAIN" {
            return Err("this computer isn't joined to a domain".into());
        }
        let Some((key, value)) = line.split_once('=') else { continue };
        let f: Vec<&str> = value.split('|').collect();
        match key {
            "DOMAIN" => dir.domain = value.trim().to_string(),
            "ERR" => dir.warnings.push(value.trim().to_string()),
            "C" if f.len() >= 9 && !f[0].trim().is_empty() => {
                let uac: u32 = f[7].trim().parse().unwrap_or(0);
                dir.computers.push(AdComputer {
                    name: f[0].trim().to_string(),
                    dns_name: opt(f[1]),
                    os: opt(f[2]).map(|os| friendly_os(&os, f[3])),
                    description: opt(f[4]),
                    ou: ou_path(f[5]),
                    last_logon: opt(f[6]),
                    enabled: uac & UAC_DISABLED == 0,
                    is_dc: uac & (UAC_DC | UAC_RODC) != 0,
                    location: opt(f[8]),
                });
            }
            "S" => {
                if let Some((network, prefix)) = crate::targets::parse_cidr(f[0]) {
                    let label = f[1..]
                        .iter()
                        .map(|s| s.trim())
                        .filter(|s| !s.is_empty())
                        .collect::<Vec<_>>()
                        .join(" · ");
                    dir.subnets.push(Network { network, prefix, source: NetSource::AdSubnet, label });
                }
            }
            "Z" => {
                if let Some((network, prefix)) = reverse_zone(value.trim()) {
                    dir.zones.push(Network {
                        network,
                        prefix,
                        source: NetSource::DnsZone,
                        label: "DNS reverse zone".into(),
                    });
                }
            }
            _ => {}
        }
    }
    if dir.domain.is_empty() {
        return Err("couldn't read the domain (no domain controller reachable?)".into());
    }
    for (i, c) in dir.computers.iter().enumerate() {
        dir.by_name.insert(c.name.to_lowercase(), i);
        if let Some(d) = &c.dns_name {
            dir.by_dns.insert(d.to_lowercase(), i);
        }
    }
    dir.zones.sort_by_key(|n| (u32::from(n.network), n.prefix));
    dir.zones.dedup_by_key(|n| (n.network, n.prefix));
    Ok(dir)
}

/// "CN=PC42,OU=Finance,OU=Workstations,DC=corp,DC=example" → "Workstations/Finance".
fn ou_path(dn: &str) -> Option<String> {
    let mut parts = Vec::new();
    let mut cur = String::new();
    let mut escaped = false;
    for c in dn.chars() {
        match c {
            _ if escaped => {
                cur.push(c);
                escaped = false;
            }
            '\\' => escaped = true,
            ',' => parts.push(std::mem::take(&mut cur)),
            _ => cur.push(c),
        }
    }
    parts.push(cur);
    let containers: Vec<String> = parts
        .iter()
        .skip(1) // the computer's own CN
        .filter_map(|p| {
            let (k, v) = p.split_once('=')?;
            matches!(k.trim().to_ascii_uppercase().as_str(), "OU" | "CN").then(|| v.trim().to_string())
        })
        .collect();
    (!containers.is_empty()).then(|| containers.into_iter().rev().collect::<Vec<_>>().join("/"))
}

/// Adds the feature release (e.g. "23H2") for Windows 10/11, and fixes
/// Windows 11 machines that report themselves as "Windows 10".
fn friendly_os(os: &str, version: &str) -> String {
    let build: Option<u32> = version
        .split(['(', ')'])
        .nth(1)
        .and_then(|b| b.trim().parse().ok());
    let Some(build) = build else { return os.to_string() };
    if os.contains("Server") || !os.contains("Windows") {
        return os.to_string();
    }
    let os = if build >= 22000 { os.replace("Windows 10", "Windows 11") } else { os.to_string() };
    let release = match build {
        10240 => "1507",
        10586 => "1511",
        14393 => "1607",
        15063 => "1703",
        16299 => "1709",
        17134 => "1803",
        17763 => "1809",
        18362 => "1903",
        18363 => "1909",
        19041 => "2004",
        19042 => "20H2",
        19043 => "21H1",
        19044 => "21H2",
        19045 => "22H2",
        22000 => "21H2",
        22621 => "22H2",
        22631 => "23H2",
        26100 => "24H2",
        26200 => "25H2",
        _ => return format!("{os} (build {build})"),
    };
    format!("{os} {release}")
}

/// "0.20.10.in-addr.arpa" → 10.20.0.0/24; "20.10.in-addr.arpa" → 10.20.0.0/16.
fn reverse_zone(name: &str) -> Option<(std::net::Ipv4Addr, u8)> {
    let rest = name.to_ascii_lowercase();
    let rest = rest.strip_suffix(".in-addr.arpa")?;
    let mut octets: Vec<u8> = rest.split('.').map(|o| o.parse().ok()).collect::<Option<Vec<u8>>>()?;
    if !(2..=3).contains(&octets.len()) {
        return None; // /8 zones are too big to be a useful network
    }
    octets.reverse();
    let prefix = octets.len() as u8 * 8;
    octets.resize(4, 0);
    Some((std::net::Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]), prefix))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_directory() {
        let out = "DOMAIN=corp.example\r\n\
C=PC42|pc42.corp.example|Windows 10 Pro|10.0 (22631)|Finance - J. Smith|CN=PC42,OU=Finance,OU=Workstations,DC=corp,DC=example|2026-10-01|4096|2nd floor\r\n\
C=DC01|dc01.corp.example|Windows Server 2022 Standard|10.0 (20348)||CN=DC01,OU=Domain Controllers,DC=corp,DC=example|2026-10-20|532480|\r\n\
C=OLDPC|oldpc.corp.example|Windows 10 Enterprise|10.0 (19045)||CN=OLDPC,CN=Computers,DC=corp,DC=example|2025-01-02|4098|\r\n\
S=10.20.0.0/24|HQ|VLAN 20 Staff|\r\n\
S=10.30.0.0/16|Branch|\r\n\
S=2001:db8::/48|HQ||\r\n\
Z=0.20.10.in-addr.arpa\r\nZ=40.10.in-addr.arpa\r\nZ=10.in-addr.arpa\r\n\
ERR=subnets: something\r\n";
        let dir = parse(out).unwrap();
        assert_eq!(dir.domain, "corp.example");
        assert_eq!(dir.computers.len(), 3);

        let pc = dir.find(None, Some("PC42.corp.example.")).unwrap();
        assert_eq!(pc.os.as_deref(), Some("Windows 11 Pro 23H2"));
        assert_eq!(pc.ou.as_deref(), Some("Workstations/Finance"));
        assert_eq!(pc.description.as_deref(), Some("Finance - J. Smith"));
        assert!(pc.enabled && !pc.is_dc);

        let dc = dir.find(Some("dc01"), None).unwrap();
        assert!(dc.is_dc);
        assert_eq!(dc.os.as_deref(), Some("Windows Server 2022 Standard"));

        let old = dir.find(None, Some("oldpc.other.example")).unwrap();
        assert!(!old.enabled);
        assert_eq!(old.ou.as_deref(), Some("Computers"));
        assert_eq!(old.os.as_deref(), Some("Windows 10 Enterprise 22H2"));

        assert_eq!(dir.subnets.len(), 2);
        assert_eq!(dir.subnets[0].label, "HQ · VLAN 20 Staff");
        assert_eq!(dir.zones.len(), 2);
        let cidrs: Vec<String> = dir.networks().iter().map(Network::cidr).collect();
        assert_eq!(cidrs, ["10.20.0.0/24", "10.30.0.0/16", "10.40.0.0/16"]);
        assert_eq!(dir.warnings.len(), 1);
    }

    #[test]
    fn script_survives_the_command_line() {
        assert!(crate::probe::is_plain_script(SCRIPT));
    }

    #[test]
    fn not_joined() {
        assert!(parse("NODOMAIN\r\n").is_err());
    }

    #[test]
    fn ou_paths() {
        assert_eq!(ou_path(r"CN=PC1,OU=Sales\, East,OU=Sites,DC=x,DC=y").as_deref(), Some("Sites/Sales, East"));
        assert_eq!(ou_path("CN=PC1,DC=x").as_deref(), None);
    }
}
