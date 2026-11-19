//! CSV and JSON exports of scan results.

use crate::scanner::{AdminDetails, HostResult};

pub const CSV_HEADER: &str = "IP,IPv6,Status,Device Type,OS,Computer Name,Users,Domain,MAC,Vendor,Model,Network / Site,AD OU,AD Description,AD Last Logon,AD Account,Hostname,Stale DNS Name,NetBIOS Name,Ping,TTL,Open Ports,Web Banner,SSH Banner,HTTPS Certificate,UPnP,mDNS Services,SNMP Description,SNMP Location,Detected By,Change";

pub fn csv(rows: &[&HostResult]) -> String {
    let mut out = String::from(CSV_HEADER);
    out.push('\n');
    for r in rows {
        let ad = r.ad.as_ref();
        let snmp = r.snmp.as_ref();
        let fields = [
            r.ip.to_string(),
            r.ipv6_text(),
            if r.alive.is_some() { "Alive" } else { "Dead" }.into(),
            r.device_text(),
            r.os_text().unwrap_or_default(),
            r.display_name().unwrap_or_default(),
            r.users.join("; "),
            r.domain_text().unwrap_or_default(),
            r.mac.clone().unwrap_or_default(),
            r.vendor.clone().unwrap_or_default(),
            r.model.clone().unwrap_or_default(),
            r.network.clone().unwrap_or_default(),
            ad.and_then(|a| a.ou.clone()).unwrap_or_default(),
            ad.and_then(|a| a.description.clone()).unwrap_or_default(),
            ad.and_then(|a| a.last_logon.clone()).unwrap_or_default(),
            ad.map(|a| if a.enabled { "Enabled" } else { "Disabled" }).unwrap_or_default().into(),
            r.hostname.clone().unwrap_or_default(),
            r.dns_mismatch.clone().unwrap_or_default(),
            r.netbios_name.clone().unwrap_or_default(),
            r.ping_text(),
            r.ttl.map(|t| t.to_string()).unwrap_or_default(),
            r.ports_text(),
            r.http_banner.clone().unwrap_or_default(),
            r.ssh_banner.clone().unwrap_or_default(),
            r.tls_name.clone().unwrap_or_default(),
            r.upnp.clone().unwrap_or_default(),
            r.mdns_services.join("; "),
            snmp.and_then(|s| s.description.clone()).unwrap_or_default(),
            snmp.and_then(|s| s.location.clone()).unwrap_or_default(),
            r.seen_via().to_string(),
            r.change.as_ref().map(|c| c.label()).unwrap_or_default(),
        ];
        let line: Vec<String> = fields.iter().map(|f| csv_escape(f)).collect();
        out.push_str(&line.join(","));
        out.push('\n');
    }
    out
}

/// Quote a CSV field. Values come from the network (names, banners), so a
/// field a spreadsheet would run as a formula (leading `=`, `+`, `-`, `@`,
/// tab or carriage return) is prefixed with `'` to keep it text.
pub fn csv_escape(s: &str) -> String {
    let s = if s.starts_with(['=', '+', '-', '@', '\t', '\r']) { format!("'{s}") } else { s.to_string() };
    if s.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s
    }
}

/// A JSON string literal.
fn js(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn js_opt(s: Option<&str>) -> String {
    s.filter(|s| !s.is_empty()).map(js).unwrap_or_else(|| "null".into())
}

fn js_list(items: impl Iterator<Item = String>) -> String {
    format!("[{}]", items.collect::<Vec<_>>().join(", "))
}

/// One JSON document: scan details plus one object per host, for scripts
/// and for comparing scans.
pub fn json(range: &str, generated: &str, rows: &[&HostResult]) -> String {
    let hosts: Vec<String> = rows
        .iter()
        .map(|r| {
            let ad = match &r.ad {
                None => "null".to_string(),
                Some(a) => format!(
                    "{{\"name\": {}, \"dns_name\": {}, \"ou\": {}, \"description\": {}, \"location\": {}, \"last_logon\": {}, \"enabled\": {}, \"domain_controller\": {}}}",
                    js(&a.name),
                    js_opt(a.dns_name.as_deref()),
                    js_opt(a.ou.as_deref()),
                    js_opt(a.description.as_deref()),
                    js_opt(a.location.as_deref()),
                    js_opt(a.last_logon.as_deref()),
                    a.enabled,
                    a.is_dc,
                ),
            };
            let fields = [
                ("ip", js(&r.ip.to_string())),
                ("ipv6", js_list(r.ipv6.iter().map(|a| js(&a.to_string())))),
                ("alive", r.alive.is_some().to_string()),
                ("detected_by", js_opt(Some(r.seen_via()))),
                ("device", js_opt(Some(&r.device_text()))),
                ("os", js_opt(r.os_text().as_deref())),
                ("name", js_opt(r.display_name().as_deref())),
                ("users", js_list(r.users.iter().map(|u| js(u)))),
                ("domain", js_opt(r.domain_text().as_deref())),
                ("mac", js_opt(r.mac.as_deref())),
                ("vendor", js_opt(r.vendor.as_deref())),
                ("model", js_opt(r.model.as_deref())),
                ("network", js_opt(r.network.as_deref())),
                ("ad", ad),
                ("hostname", js_opt(r.hostname.as_deref())),
                ("stale_dns_name", js_opt(r.dns_mismatch.as_deref())),
                ("netbios_name", js_opt(r.netbios_name.as_deref())),
                ("ping_ms", r.rtt_ms.map(|v| v.to_string()).unwrap_or_else(|| "null".into())),
                ("ttl", r.ttl.map(|v| v.to_string()).unwrap_or_else(|| "null".into())),
                ("open_ports", js_list(r.open_ports.iter().map(u16::to_string))),
                ("web_banner", js_opt(r.http_banner.as_deref())),
                ("ssh_banner", js_opt(r.ssh_banner.as_deref())),
                ("https_certificate", js_opt(r.tls_name.as_deref())),
                ("upnp", js_opt(r.upnp.as_deref())),
                ("mdns_services", js_list(r.mdns_services.iter().map(|s| js(s)))),
                ("snmp_description", js_opt(r.snmp.as_ref().and_then(|s| s.description.as_deref()))),
                ("snmp_name", js_opt(r.snmp.as_ref().and_then(|s| s.name.as_deref()))),
                ("snmp_location", js_opt(r.snmp.as_ref().and_then(|s| s.location.as_deref()))),
                ("change", js_opt(r.change.as_ref().map(|c| c.label()).as_deref())),
                (
                    "admin_details",
                    match r.admin {
                        AdminDetails::NotTried => "null".into(),
                        AdminDetails::Answered => js("answered"),
                        AdminDetails::Failed => js("no answer"),
                    },
                ),
            ];
            let body: Vec<String> = fields.iter().map(|(k, v)| format!("\"{k}\": {v}")).collect();
            format!("    {{{}}}", body.join(", "))
        })
        .collect();
    format!(
        "{{\n  \"tool\": \"HappyIP {}\",\n  \"range\": {},\n  \"generated\": {},\n  \"hosts\": [\n{}\n  ]\n}}\n",
        env!("CARGO_PKG_VERSION"),
        js(range),
        js(generated),
        hosts.join(",\n"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn csv_neutralises_formulas_and_quotes() {
        assert_eq!(csv_escape("plain"), "plain");
        assert_eq!(csv_escape("a,b"), "\"a,b\"");
        assert_eq!(csv_escape("say \"hi\""), "\"say \"\"hi\"\"\"");
        assert_eq!(csv_escape("=HYPERLINK(\"http://x\")"), "\"'=HYPERLINK(\"\"http://x\"\")\"");
        for lead in ["+1", "-1", "@SUM(A1)", "\t=1"] {
            assert!(csv_escape(lead).starts_with('\''), "{lead:?}");
        }
        // A bare carriage return would otherwise start a new row.
        assert_eq!(csv_escape("a\rb"), "\"a\rb\"");
        assert_eq!(csv_escape("\r=1"), "\"'\r=1\"");
    }

    #[test]
    fn csv_has_one_row_per_host_with_every_column() {
        let results = crate::demo::results();
        let rows: Vec<&HostResult> = results.iter().collect();
        let text = csv(&rows);
        let columns = CSV_HEADER.split(',').count();
        assert_eq!(text.lines().count(), rows.len() + 1);
        // Demo data has no quoted commas except in port/user lists, so
        // count columns on a host without either.
        let dead = text.lines().find(|l| l.contains(",Dead,")).unwrap();
        assert_eq!(dead.split(',').count(), columns);
    }

    #[test]
    fn json_escapes_hostile_names() {
        let mut r = HostResult::new(Ipv4Addr::new(10, 0, 0, 1));
        r.netbios_name = Some("PC\"},\n{\"ip\": \"evil\\".into());
        r.users = vec!["a\tb".into()];
        r.open_ports = vec![22, 80];
        let out = json("10.0.0.0/24", "now", &[&r]);
        assert!(out.contains(r#""name": "PC\"},\n{\"ip\": \"evil\\""#), "{out}");
        assert!(out.contains(r#""users": ["a\tb"]"#));
        assert!(out.contains(r#""open_ports": [22, 80]"#));
        assert!(out.contains(r#""mac": null"#));
        // Still exactly one host object, on one line.
        assert_eq!(out.lines().filter(|l| l.starts_with("    {")).count(), 1);
    }
}
