# HappyIP

A fast LAN scanner in the style of Angry IP Scanner, written in Rust with an egui GUI. Runs on macOS and Windows (and Linux).

For every live host it shows: IP, ping/TTL, hostname, MAC address, NetBIOS name, workgroup, logged-in users, and open ports.

## Build & run

```sh
cargo run --release                         # GUI
cargo run --release -- --cli 192.168.1.0/24 # headless, prints TSV
```

Windows: build on a Windows machine with `cargo build --release` → `target\release\happyip.exe`, or cross-compile from a Mac:

```sh
brew install mingw-w64 && rustup target add x86_64-pc-windows-gnu
cargo build --release --target x86_64-pc-windows-gnu   # → target/x86_64-pc-windows-gnu/release/happyip.exe
```

Current Rust's standard Windows targets only run on Windows 10+. For Windows 7/8 and Server 2008 R2/2012, build the tier-3
`win7` target with a pinned nightly (the latest nightly's win7 std was broken at the time of writing):

```sh
rustup toolchain install nightly-2026-09-01 --profile minimal --component rust-src
CARGO_TARGET_X86_64_WIN7_WINDOWS_GNU_LINKER=x86_64-w64-mingw32-gcc \
  cargo +nightly-2026-09-01 build --release -Zbuild-std=std,panic_abort --target x86_64-win7-windows-gnu
```

That exe also runs on Windows 10/11. On Server 2012 it needs the Universal C Runtime (KB2999226, included in normal
Windows Update).

## Rendering

The window is GPU-rendered (wgpu: DirectX 12 / Vulkan / OpenGL / Metal). If no adapter is available (old Windows Server,
VMs, Remote Desktop), HappyIP relaunches itself with `--software` and draws on the CPU instead
(`egui_software_backend`). You can force that mode with `happyip --software`.

(release builds have no console window, so `--cli` output only shows from a debug build).

Range syntax: `192.168.1.0/24`, `10.0.0.1-50`, `10.0.0.1 - 10.0.3.254`, comma-separated, max 65,536 hosts.

**Export report…** saves a self-contained HTML inventory (device type, computer name, logged-in user, IP, MAC + vendor,
open ports, and the clues behind each guess) and opens it in your browser; print it to get a PDF. Headless:
`happyip --cli 192.168.1.0/24 --report report.html`. **CSV…** exports the raw table.

Device type is a best-effort guess combining the MAC vendor (IEEE OUI list built in from Wireshark's `manuf`,
`data/oui.tsv`), randomized-MAC detection, TTL, open ports (e.g. 9100 printer, 62078 iPhone, 554 camera, 8009 Chromecast),
hostnames, HTTP page titles / `Server` headers, and the default gateway.

## How each column is found

| Column | Method | Notes |
|---|---|---|
| Alive / Ping | system `ping` (no admin needed) → TCP probe of ports (an open *or refused* port means it's up) → ARP → NetBIOS | "Seen via" shows which one found it |
| Hostname | reverse DNS, 1.5 s deadline | |
| MAC | OS ARP table (`arp -a`), fallback to the NetBIOS reply | Only for hosts on your own subnet (or Windows hosts via NetBIOS) |
| NetBIOS name / workgroup / users | NBSTAT query on UDP 137 | Windows & Samba hosts only |
| Logged-in users | NetBIOS `<03>` names; your own PC via `who` / `query user`; on Windows optionally `query user /server:<ip>` | See limits below |

## Limitations

- **Logged-in users on remote PCs:** modern Windows rarely advertises the user over NetBIOS anymore. The reliable way is the Windows-only "Query sessions" option, which needs admin rights on the target (for example a domain admin account). Phones, Macs, and IoT devices don't expose their users.
- **macOS 26+/27 MAC privacy:** some macOS versions hide hardware addresses from regular processes (`arp -an` comes back empty and the local MAC shows as `02:00:00:00:00:00`). When that happens the MAC column stays blank on Mac. Windows is unaffected.
