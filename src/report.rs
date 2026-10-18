//! Self-contained HTML inventory report (opens in any browser, prints to PDF).

use std::collections::BTreeMap;
use std::fmt::Write;

use crate::scanner::HostResult;

pub struct ReportMeta {
    pub range: String,
    pub generated: String,
    pub scanned_from: String,
    pub hosts_scanned: usize,
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

pub fn html(meta: &ReportMeta, hosts: &[&HostResult]) -> String {
    let mut by_kind: BTreeMap<&str, usize> = BTreeMap::new();
    for h in hosts {
        *by_kind.entry(h.device.as_ref().map_or("Unknown", |d| d.kind)).or_default() += 1;
    }
    let mut kinds: Vec<_> = by_kind.into_iter().collect();
    kinds.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));

    let named = hosts.iter().filter(|h| h.display_name().is_some()).count();
    let with_users = hosts.iter().filter(|h| !h.users.is_empty()).count();
    let with_mac = hosts.iter().filter(|h| h.mac.is_some()).count();

    let mut rows = String::new();
    for (i, h) in hosts.iter().enumerate() {
        let dev = h.device.as_ref();
        let kind = dev.map_or("Unknown", |d| d.kind);
        let icon = dev.map_or("❔", |d| d.icon());
        let os = h.os_text().unwrap_or_default();
        let os = [Some(os), h.model.clone()].into_iter().flatten().filter(|s| !s.is_empty()).collect::<Vec<_>>().join(" · ");
        let name = h.display_name().unwrap_or_default();
        let fqdn = h.hostname.as_deref().filter(|f| !f.eq_ignore_ascii_case(&name)).unwrap_or("");
        let users = if h.users.is_empty() {
            "<span class=muted>—</span>".to_string()
        } else {
            h.users.iter().map(|u| format!("<span class=user>{}</span>", esc(u))).collect::<Vec<_>>().join(" ")
        };
        let basis = dev.map(|d| d.basis.join(" · ")).unwrap_or_default();
        let _ = write!(
            rows,
            "<tr>\
<td class=num>{n}</td>\
<td data-sort=\"{kind_e}\"><span class=icon>{icon}</span><b>{kind_e}</b>{os_html}</td>\
<td data-sort=\"{name_e}\">{name_html}{fqdn_html}{wg_html}</td>\
<td data-sort=\"{users_sort}\">{users}</td>\
<td class=mono data-sort=\"{ip_sort:010}\">{ip}</td>\
<td data-sort=\"{mac_e}\"><span class=mono>{mac_html}</span>{vendor_html}</td>\
<td class=mono>{ports}</td>\
<td class=clues>{basis}</td>\
</tr>\n",
            n = i + 1,
            kind_e = esc(kind),
            os_html = if os.is_empty() { String::new() } else { format!("<small>{}</small>", esc(&os)) },
            name_e = esc(&name),
            name_html = if name.is_empty() { "<span class=muted>—</span>".into() } else { format!("<b>{}</b>", esc(&name)) },
            fqdn_html = if fqdn.is_empty() { String::new() } else { format!("<small>{}</small>", esc(fqdn)) },
            wg_html = h.domain_text().map(|w| format!("<small>Domain: {}</small>", esc(&w))).unwrap_or_default(),
            users_sort = esc(&h.users.join(", ")),
            ip_sort = u32::from(h.ip),
            ip = h.ip,
            mac_e = esc(h.mac.as_deref().unwrap_or("")),
            mac_html = h.mac.as_deref().map(esc).unwrap_or_else(|| "<span class=muted>—</span>".into()),
            vendor_html = h.vendor.as_deref().map(|v| format!("<small>{}</small>", esc(v))).unwrap_or_default(),
            ports = esc(&h.ports_text()),
            basis = esc(&basis),
        );
    }

    let chips: String = kinds
        .iter()
        .map(|(k, n)| format!("<span class=chip>{} <b>{n}</b></span>", esc(k)))
        .collect();

    format!(
        r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>HappyIP Network Report</title>
<style>
:root{{--bg:#f6f7f9;--card:#fff;--ink:#1d2330;--muted:#6b7385;--line:#e3e6ec;--accent:#2563eb;--chip:#eef2fb;--user:#e7f6ec;--userink:#166534}}
@media (prefers-color-scheme:dark){{:root{{--bg:#0f1218;--card:#171b23;--ink:#e6e9ef;--muted:#8d95a6;--line:#2a303c;--accent:#60a5fa;--chip:#1e2533;--user:#163222;--userink:#86efac}}}}
*{{box-sizing:border-box}}
body{{margin:0;background:var(--bg);color:var(--ink);font:14px/1.45 "Segoe UI",system-ui,-apple-system,Roboto,sans-serif}}
.wrap{{max-width:1400px;margin:0 auto;padding:28px 20px 48px}}
h1{{margin:0 0 4px;font-size:24px}}
.meta{{color:var(--muted);font-size:13px}}
.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px;margin:22px 0 14px}}
.card{{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 16px}}
.card .v{{font-size:28px;font-weight:700}}
.card .l{{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.04em}}
.chips{{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:18px}}
.chip{{background:var(--chip);border-radius:999px;padding:4px 12px;font-size:13px}}
.bar{{display:flex;gap:12px;align-items:center;margin-bottom:10px}}
input[type=search]{{flex:1;max-width:360px;padding:8px 12px;border:1px solid var(--line);border-radius:8px;background:var(--card);color:var(--ink);font:inherit}}
.tablewrap{{background:var(--card);border:1px solid var(--line);border-radius:10px;overflow-x:auto}}
table{{border-collapse:collapse;width:100%}}
th,td{{text-align:left;padding:9px 12px;border-bottom:1px solid var(--line);vertical-align:top}}
th{{font-size:12px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted);cursor:pointer;white-space:nowrap;user-select:none;position:sticky;top:0;background:var(--card)}}
th:hover{{color:var(--accent)}}
tr:last-child td{{border-bottom:none}}
td small{{display:block;color:var(--muted);font-size:12px}}
.mono{{font-family:ui-monospace,Consolas,Menlo,monospace;font-size:13px}}
.num{{color:var(--muted);width:1%}}
td:nth-child(2){{min-width:200px}}
.icon{{margin-right:6px}}
.user{{display:inline-block;background:var(--user);color:var(--userink);border-radius:6px;padding:1px 8px;margin:1px 2px 1px 0;font-weight:600}}
.muted{{color:var(--muted)}}
.clues{{color:var(--muted);font-size:12px;max-width:320px}}
footer{{color:var(--muted);font-size:12px;margin-top:16px}}
@media print{{body{{background:#fff}}.bar{{display:none}}.card,.tablewrap{{border-color:#ccc}}th{{position:static}}}}
</style></head><body><div class="wrap">
<h1>Network Inventory Report</h1>
<div class="meta">Range <b>{range}</b> · Generated {generated} · Scanned from {from}</div>
<div class="cards">
<div class="card"><div class="v">{alive}</div><div class="l">Devices online</div></div>
<div class="card"><div class="v">{named}</div><div class="l">With computer name</div></div>
<div class="card"><div class="v">{with_users}</div><div class="l">With logged-in user</div></div>
<div class="card"><div class="v">{with_mac}</div><div class="l">With MAC address</div></div>
<div class="card"><div class="v">{scanned}</div><div class="l">Addresses scanned</div></div>
</div>
<div class="chips">{chips}</div>
<div class="bar"><input type="search" id="q" placeholder="Search name, user, IP, MAC, vendor…"><span class="meta" id="count"></span></div>
<div class="tablewrap"><table id="t"><thead><tr>
<th>#</th><th>Device</th><th>Computer name</th><th>Logged-in user</th><th>IP address</th><th>MAC address / vendor</th><th>Open ports</th><th>Identified by</th>
</tr></thead><tbody>
{rows}</tbody></table></div>
<footer>Device types are best-effort guesses from MAC vendor, TTL, open ports, hostnames and web banners. Logged-in users are only visible for Windows hosts that advertise them over NetBIOS or allow session queries.</footer>
</div>
<script>
const t=document.getElementById('t'),tb=t.tBodies[0],q=document.getElementById('q'),c=document.getElementById('count');
function upd(){{const s=q.value.toLowerCase();let n=0;for(const r of tb.rows){{const m=r.textContent.toLowerCase().includes(s);r.style.display=m?'':'none';if(m)n++}}c.textContent=n+' shown'}}
q.addEventListener('input',upd);upd();
let dir={{}};
t.tHead.querySelectorAll('th').forEach((th,i)=>th.addEventListener('click',()=>{{
 dir[i]=!dir[i];const k=r=>{{const td=r.cells[i];return (td.dataset.sort??td.textContent).toLowerCase()}};
 const rs=[...tb.rows].sort((a,b)=>{{const x=k(a),y=k(b);const nx=parseFloat(x),ny=parseFloat(y);
  const o=(!isNaN(nx)&&!isNaN(ny)&&i==0)?nx-ny:x.localeCompare(y,undefined,{{numeric:true}});return dir[i]?o:-o}});
 rs.forEach(r=>tb.appendChild(r));
}}));
</script>
</body></html>
"#,
        range = esc(&meta.range),
        generated = esc(&meta.generated),
        from = esc(&meta.scanned_from),
        alive = hosts.len(),
        scanned = meta.hosts_scanned,
    )
}
