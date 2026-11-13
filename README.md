<p align="center">
  <img src="assets/icon.png" width="112" alt="HappyIP icon">
</p>

<h1 align="center">HappyIP</h1>

<p align="center">
  A fast, friendly network scanner for <b>Windows</b> and <b>macOS</b>, in the spirit of Angry IP Scanner.<br>
  Find every device on your network with its <b>computer name, logged-in user, MAC address, vendor and device type</b>,
  then export a clean report.
</p>

<p align="center">
  <a href="https://github.com/marcoazeem/happyip/releases/latest"><img alt="Download" src="https://img.shields.io/github/v/release/marcoazeem/happyip?label=download&color=22c55e"></a>
  <img alt="Platforms" src="https://img.shields.io/badge/platform-Windows%20%7C%20macOS-0e7490">
  <img alt="Rust" src="https://img.shields.io/badge/made%20with-Rust-orange">
  <a href="LICENSE"><img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-blue"></a>
</p>

<p align="center">
  <img src="docs/app.png" alt="HappyIP main window showing scanned devices" width="100%">
</p>

> Screenshots use HappyIP's built-in demo data (`--demo`). All names and addresses are fictional.

## Download

| Platform | File | Runs on |
|---|---|---|
| **Windows** | [HappyIP-Windows-x64.exe](https://github.com/marcoazeem/happyip/releases/latest/download/HappyIP-Windows-x64.exe) | Windows 10 / 11 and Server 2016+ (64-bit). Also built to run on Windows 7 / 8 and Server 2008 R2 / 2012 (these need the [Universal C Runtime](https://support.microsoft.com/help/2999226) update). |
| **macOS** | [HappyIP-macOS.dmg](https://github.com/marcoazeem/happyip/releases/latest/download/HappyIP-macOS.dmg) | macOS 11 Big Sur or later, Apple Silicon and Intel (universal) |

There's nothing to install on Windows: it's a single portable `.exe`. On Mac, open the DMG and drag **HappyIP** into **Applications**.

<details>
<summary><b>First launch: "Windows protected your PC" / "Apple could not verify…"</b></summary>

HappyIP isn't code-signed with a paid certificate yet, so your OS will warn you the first time:

- **Windows SmartScreen:** click **More info → Run anyway**. If Windows Firewall asks, allow access so NetBIOS name and user lookups get replies.
- **macOS Gatekeeper:** right-click (or Control-click) HappyIP in Applications → **Open** → **Open**.
  On macOS 15+ you may need **System Settings → Privacy & Security → Open Anyway**. Or from Terminal:
  ```sh
  xattr -dr com.apple.quarantine /Applications/HappyIP.app
  ```
  Allow **Local Network** access when macOS asks, or the scan won't see other devices.
</details>

## Features

- **Fast multithreaded scanning:** a typical /24 home or office network takes a few seconds (128 threads by default).
- **Finds devices that ignore ping:** combines ICMP ping, TCP probes (open *or refused* ports both mean "alive"), the ARP table and NetBIOS.
- **Computer names:** reverse DNS plus NetBIOS names and workgroups for Windows and Samba machines.
- **Logged-in users:** from NetBIOS, your own machine's sessions, and on Windows optionally `query user /server:` (see [limits](#good-to-know)).
- **MAC address + manufacturer:** the full IEEE vendor registry (58,000+ entries) is built in, and works offline.
- **Device type detection:** Windows PC/server, Mac, iPhone/iPad, Android, printer, IP camera, NAS, router, TV/media player, smart-home/IoT, Linux server. Hover a device in the app to see *why* it was classified that way.
- **Active Directory (Windows):** as a normal domain user, HappyIP reads computer accounts (OS, OU, description, last logon, disabled accounts, domain controllers) and the Sites & Services subnets, and shows them next to each host.
- **Networks menu:** pick what to scan from this computer's subnets, routed networks, Active Directory subnets and DNS reverse zones (Ctrl/⌘-click adds to the range).
- **Reports:** one click exports a polished, searchable, sortable **HTML report** that opens in your browser and prints to PDF, with the network / site, AD details and a click-to-filter list of device types. **CSV** and **JSON** exports are also available.
- **Works on old servers and VMs:** uses the GPU when available and automatically falls back to CPU rendering on machines without one (Windows Server 2012, Remote Desktop, VMs).
- **Flexible ranges:** `192.168.1.0/24`, `10.0.0.1-50`, `10.0.0.1 - 10.0.3.254`, wildcards (`10.20.*.*`), computer names (`fileserver01`), or several separated by commas. It auto-detects your network.
- Sort by any column, filter as you type, right-click a row to copy IP / MAC / hostname / users, **Remote Desktop** straight into it (`mstsc` on Windows; the Microsoft *Windows App* on Mac), open its web page, browse its shares, or send **Wake-on-LAN**. Double-click a row for Remote Desktop (or the web page).
- **mDNS, UPnP and SNMP:** on your own network HappyIP asks each device for its Bonjour (mDNS) name and services and its UPnP description; with **SNMP** switched on it also asks every live device, on any VLAN, for its description, name and location.
- **IPv6 addresses:** each device's IPv6 addresses are listed next to its IPv4 address, matched by MAC from this computer's IPv6 neighbour table.
- **What changed since last time:** HappyIP remembers the last complete scan of each range and marks devices that are **new**, **gone**, or **replaced** (same address, different MAC) in the Changes column.
- **Pinned and recent ranges:** *Pin* keeps a range, with its port list, at the top of the Networks menu; the last few ranges scanned are listed there too.
- **Choose your columns:** hide or show columns from the *Columns* menu and drag them to size; *Details* opens a panel with everything known about the selected device.
- **More row actions:** SSH, screen sharing (VNC), and *Scan this address again* to refresh one row. Select several rows with Shift- or Ctrl/⌘-click to copy them together.
- **Keyboard:** `F5` or `Ctrl/⌘+Enter` starts a scan, `Esc` stops it, `Ctrl/⌘+F` jumps to the filter, `Ctrl/⌘+A` selects all rows, `Ctrl/⌘+C` copies the selected rows.
- **Remembers your options:** range, ports, threads, timeout, checkboxes, filter, sort order, columns and window size are saved as you change them.

## Network report

**Export report…** creates a single self-contained HTML file. Share it, archive it, or print it to PDF.

<p align="center">
  <img src="docs/report-light.png" alt="HappyIP HTML network inventory report" width="100%">
</p>

<details>
<summary>Dark mode (follows your system theme)</summary>
<img src="docs/report-dark.png" alt="HappyIP report in dark mode" width="100%">
</details>

## How it works

| Column | How HappyIP finds it |
|---|---|
| **Alive** | Ping (no admin rights needed), TCP connects to common ports, an ARP request (the OS ARP table on macOS/Linux) and a NetBIOS query, all at the same time, so an empty address costs one timeout. "Seen via" shows which one answered; "ARP (cached)" means only an old ARP table entry was found, so the device may have left. |
| **Computer name** | NetBIOS name if the device answers on UDP 137, otherwise its reverse-DNS name. |
| **Logged-in users** | Names registered under the NetBIOS `<03>` suffix; `who` / `query user` for your own computer; with **Admin queries** (Windows): the console user from WMI plus `query user /server:<ip>` sessions. |
| **MAC address** | The OS ARP table (devices on your own subnet/VLAN), the MAC inside a Windows machine's NetBIOS reply, or with **Admin queries** the Windows PC's own adapter list over WMI (works across VLANs). |
| **Domain** | WMI (with **Admin queries**), else the NetBIOS domain/workgroup, else the DNS suffix of the hostname (`pc42.corp.example` → `corp.example`), which works for normal users and across VLANs. |
| **OS / model** | With **Admin queries**: the exact Windows edition and hardware model (e.g. *Windows 11 Pro · Dell Inc. OptiPlex 7090*) from WMI. |
| **Vendor** | MAC prefix looked up in the built-in IEEE OUI registry. Randomized "private" MACs (phones) are flagged. |
| **Device type** | Combines vendor, TTL (128 = Windows, 64 = Linux/Apple/Android, 255 = embedded), open ports (e.g. 9100 printer, 62078 iPhone, 554 camera, 8009 Chromecast, 548 Mac), hostname patterns, the HTTP page title / `Server` header, the name on its HTTPS certificate, the SSH server's banner, what it announces over UPnP (name, maker and model, on your own subnet), and whether it's your default gateway. The exact OS from WMI or Active Directory, when known, beats any guess. |

## Command line

```sh
happyip --cli 192.168.1.0/24                       # scan and print live hosts as TSV
happyip --cli 192.168.1.0/24 --report report.html  # ...and write the HTML report
happyip --cli 10.20.0.0/24 --csv scan.csv --json scan.json --ports "22, 80, 443" --timeout 500
happyip --cli 10.20.0.0/24 --snmp public           # also ask live hosts over SNMP
happyip --cli --help                               # all options
happyip --demo                                     # open the app with fictional sample data
happyip --software                                 # force CPU rendering
```

On Windows, `--cli` output is only visible from a debug build or when redirected (`HappyIP.exe --cli … > out.txt`), because the release `.exe` is a GUI app.

## Good to know

- **Admin queries (Windows):** the scan itself runs at full speed; admin details (MAC, users, domain, OS, model) are then collected in parallel from Windows PCs with RPC port 135 open and fill in as they arrive. Run HappyIP as a domain admin (or *Run as different user* with an account that is admin on the targets). The PCs must allow remote WMI (the *Windows Management Instrumentation* firewall rules, typically enabled by Group Policy in managed domains). Without admin rights you still get names, domains (from DNS) and device types, but not logged-in users.
- **MAC addresses across VLANs:** ARP only sees your own VLAN, and Windows Firewall answers NetBIOS only from the local subnet by default. For Windows PCs on other VLANs, enable **Admin queries**. Non-Windows devices (printers, phones, cameras) on other VLANs don't expose their MAC remotely; only the router/switch knows it.
- **Logged-in users on other PCs** need **Admin queries**. Modern Windows rarely advertises the user over NetBIOS. Phones, Macs and IoT devices don't expose users at all.
- **MAC addresses on macOS:** recent macOS versions may hide hardware addresses from apps (the ARP table comes back empty). The MAC and Vendor columns can then be blank on Mac. Windows is unaffected.
- **Remote Desktop** connects by DNS name when one is known, so domain accounts sign in with Kerberos (no certificate warning on domain PCs). Your account needs RDP access on the target (e.g. member of *Remote Desktop Users* or a local admin).
- **When something doesn't work:** errors appear in red in the status bar. **Copy diagnostics** (bottom right) copies the version, settings and recent log to the clipboard, including why admin or Active Directory lookups failed for each PC. The log is `happyip.log` next to `settings.ini`, in `%APPDATA%\HappyIP` on Windows and `~/Library/Application Support/HappyIP` on macOS.
- **Firewalls that answer for empty addresses:** when nearly every unused address in a subnet "answers" identically over TCP only (all ports refused, or only web ports open), HappyIP treats those as a firewall or proxy replying and shows them as not alive ("Firewall reply").
- **IPv6:** HappyIP scans IPv4 ranges. An IPv6 subnet is far too large to scan address by address, so IPv6 addresses are collected for the devices found over IPv4 (when their MAC is known); devices that only speak IPv6 are not listed.
- **SNMP** is off by default. It sends the community string you enter (usually `public`) to every live host; devices configured to report failed SNMP logins may raise an alert. The community is saved in `settings.ini` as plain text and is left out of *Copy diagnostics* unless it is `public`.
- **Device types are best-effort guesses.** The report's *Identified by* column shows the clues behind each one.
- **Only scan networks you own or are authorized to scan.**

## Build from source

Requires [Rust](https://rustup.rs) (stable).

```sh
git clone https://github.com/marcoazeem/happyip && cd happyip
cargo run --release
```

**Release packages**

```sh
scripts/package-macos.sh     # → dist/HappyIP-macOS.dmg (universal .app, needs macOS + Xcode CLT)
scripts/package-windows.sh   # → dist/HappyIP-Windows-x64.exe (cross-compiled; needs `brew install mingw-w64`)
```

Both scripts sign the result when you provide a certificate (see the comments at the top of each): `MACOS_SIGN_IDENTITY` and `MACOS_NOTARY_PROFILE` for a Developer ID signature and notarization, `WINDOWS_SIGN_PFX` and `WINDOWS_SIGN_PASSWORD` for Authenticode (via `osslsigncode`).

On Windows you can also just run `cargo build --release`, but note that Rust's standard Windows targets only support **Windows 10+**. `package-windows.sh` uses the `x86_64-win7-windows-gnu` target (pinned nightly + `build-std`) so the exe also runs on Windows 7/8 and Server 2008 R2/2012.

**Project layout**

| File | Purpose |
|---|---|
| `src/main.rs` | GUI (egui/eframe) |
| `src/cli.rs` | `--cli` mode |
| `src/scanner.rs` | Multithreaded scan engine |
| `src/probe.rs` | Ping, TCP probes, ARP, Wake-on-LAN, starting system tools |
| `src/targets.rs` | Range and port parsing, local and routed networks |
| `src/netbios.rs` | NetBIOS node-status queries, user sessions |
| `src/wmi.rs` | Admin queries to Windows PCs (WMI) |
| `src/ad.rs` | Active Directory computers, subnets and DNS zones |
| `src/identify.rs` | MAC vendor lookup, HTTP/SSH banners, device classification |
| `src/tls.rs` | Name on a device's HTTPS certificate |
| `src/ssdp.rs` | UPnP discovery and device descriptions |
| `src/mdns.rs` | Bonjour (mDNS) name, services and model of a device |
| `src/snmp.rs` | SNMP description, name and location |
| `src/ipv6.rs` | IPv6 addresses from the OS neighbour table |
| `src/history.rs` | Previous scan of each range, and what changed |
| `src/report.rs` | HTML report |
| `src/export.rs` | CSV and JSON exports |
| `src/actions.rs` | Remote Desktop, web page and shares for a row |
| `src/settings.rs` | Saved options |
| `src/diag.rs` | Diagnostics log |
| `src/demo.rs` | Fictional demo network |
| `data/oui.tsv` | IEEE OUI vendor registry |

## Credits

- UI built with [egui](https://github.com/emilk/egui); CPU fallback via [egui_software_backend](https://github.com/DGriffin91/egui_software_backend).
- MAC vendor data: the IEEE Registration Authority's public OUI registry, as compiled in [Wireshark's `manuf` file](https://www.wireshark.org/download/automated/data/manuf).
- Inspired by [Angry IP Scanner](https://angryip.org).

## License

[MIT](LICENSE)
