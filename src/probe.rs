//! Host probes: ICMP ping (the Windows ICMP API, or the system `ping`
//! binary elsewhere, so no admin rights are needed), TCP port checks, ARP
//! requests / the ARP table for MAC addresses, and Wake-on-LAN.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::{Condvar, Mutex, OnceLock};
use std::time::{Duration, Instant};

use crate::util::lock;

// The ICMP reply struct below is the 64-bit layout.
#[cfg(all(windows, not(target_pointer_width = "64")))]
compile_error!("HappyIP supports 64-bit Windows only");

/// Where a helper program is started from.
///
/// On Windows a bare name like `powershell.exe` is looked up in the folder
/// HappyIP itself was started from before the system folders, so a program
/// planted next to a portable copy would run with the user's (often admin)
/// rights. Windows tools are therefore always started by their full path
/// under the Windows folder.
pub fn program_path(program: &str) -> PathBuf {
    if !cfg!(windows) || program.contains(['/', '\\']) {
        return PathBuf::from(program);
    }
    static ROOT: OnceLock<PathBuf> = OnceLock::new();
    let root = ROOT.get_or_init(|| {
        std::env::var_os("SystemRoot")
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
            .unwrap_or_else(|| PathBuf::from(r"C:\Windows"))
    });
    let file = if program.contains('.') { program.to_string() } else { format!("{program}.exe") };
    match file.to_ascii_lowercase().as_str() {
        "explorer.exe" => root.join(file),
        "powershell.exe" => root.join("System32").join("WindowsPowerShell").join("v1.0").join(file),
        _ => root.join("System32").join(file),
    }
}

/// Run a command without flashing a console window on Windows.
pub fn run_hidden(program: &str, args: &[&str]) -> Option<Output> {
    hidden_command(program, args).output().ok()
}

pub fn hidden_command(program: &str, args: &[&str]) -> Command {
    let mut cmd = Command::new(program_path(program));
    cmd.args(args);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    cmd
}

/// Like [`run_hidden`], but kills the process if it runs past `timeout`
/// (remote management calls can hang for a long time on unreachable hosts).
/// Returns stdout when the process exited successfully in time, else a short
/// reason (its error output, or that it timed out) for the diagnostics log.
pub fn run_hidden_timeout(program: &str, args: &[&str], timeout: Duration) -> Result<String, String> {
    use std::io::Read;
    use std::process::Stdio;
    let mut child = hidden_command(program, args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("could not start {program}: {e}"))?;
    // Drain both pipes on threads so a chatty process can't block on a full pipe.
    fn drain(pipe: Option<impl Read + Send + 'static>) -> std::thread::JoinHandle<Vec<u8>> {
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            if let Some(mut pipe) = pipe {
                let _ = pipe.read_to_end(&mut buf);
            }
            buf
        })
    }
    let (out, err) = (drain(child.stdout.take()), drain(child.stderr.take()));
    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(50)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
        }
    };
    let out = out.join().unwrap_or_default();
    let err = err.join().unwrap_or_default();
    match status {
        Some(s) if s.success() => Ok(String::from_utf8_lossy(&out).into_owned()),
        Some(s) => Err(first_line(&String::from_utf8_lossy(&err)).unwrap_or_else(|| format!("{program} failed ({s})"))),
        None => Err(format!("no answer within {} s", timeout.as_secs())),
    }
}

/// The first non-empty line of a program's error output, shortened.
fn first_line(text: &str) -> Option<String> {
    let line = text.lines().map(str::trim).find(|l| !l.is_empty())?;
    Some(line.chars().take(200).collect())
}

/// Run a PowerShell script and return its output.
///
/// The script is passed as plain `-Command` text. An encoded command (or an
/// execution-policy bypass) is what malware uses to hide what it runs, so
/// security software flags programs that start PowerShell that way; plain
/// text shows exactly what is being asked. Scripts must therefore be ASCII
/// without double quotes, which would not survive the command line.
pub fn run_powershell(script: &str, timeout: Duration) -> Result<String, String> {
    if !is_plain_script(script) {
        return Err("internal error: script can't be passed on a command line".into());
    }
    run_hidden_timeout("powershell.exe", &["-NoProfile", "-NonInteractive", "-Command", script], timeout)
}

/// Can `script` be handed to PowerShell as one command-line argument?
pub fn is_plain_script(script: &str) -> bool {
    script.is_ascii() && !script.contains('"') && !script.ends_with('\\') && script.len() < 30_000
}

#[derive(Clone, Copy, Debug)]
pub struct PingReply {
    /// Round-trip time in milliseconds; 0.0 means "<1 ms" (Windows).
    pub rtt_ms: f64,
    pub ttl: Option<u32>,
}

/// Ping `ip`, asking a second time if the first request is still
/// unanswered a third of the way in. The first packet to a device is the one
/// most often lost: a router may drop it while it looks up the device's MAC,
/// and phones and laptops on Wi-Fi sleep between packets. The retry shares
/// the same deadline, so it costs no extra time.
pub fn ping(ip: Ipv4Addr, timeout_ms: u64) -> Option<PingReply> {
    use std::sync::mpsc::{self, RecvTimeoutError};
    let wait = timeout_ms / 3;
    let (first_done, signal) = mpsc::channel::<()>();
    std::thread::scope(|s| {
        let retry = std::thread::Builder::new().name("ping-retry".into()).spawn_scoped(s, move || {
            match signal.recv_timeout(Duration::from_millis(wait)) {
                Err(RecvTimeoutError::Timeout) => ping_once(ip, timeout_ms - wait),
                _ => None, // the first request finished in time
            }
        });
        let first = ping_once(ip, timeout_ms);
        drop(first_done);
        let retry = retry.ok().and_then(|r| r.join().ok()).flatten();
        first.or(retry)
    })
}

fn ping_once(ip: Ipv4Addr, timeout_ms: u64) -> Option<PingReply> {
    // Windows: ask the ICMP API directly. It's much faster than starting
    // ping.exe for every address and reports exactly who replied.
    #[cfg(windows)]
    if let Ok(reply) = win::icmp_ping(ip, timeout_ms) {
        return reply;
    }
    ping_command(ip, timeout_ms)
}

/// Result of asking a host on our own subnet for its MAC with a fresh ARP request.
#[cfg_attr(not(windows), allow(dead_code))] // only Windows can ask
pub enum ArpReply {
    Mac(String),
    /// Nobody answered: nothing is using this address right now.
    NoReply,
    /// Not supported on this OS (fall back to the ARP table).
    Unsupported,
}

/// Send a real ARP request and wait for the answer (Windows `SendARP`).
/// Unlike reading the ARP table this never returns a stale entry for a
/// device that has since gone offline. Only meaningful for on-link addresses.
pub fn arp_request(ip: Ipv4Addr) -> ArpReply {
    #[cfg(windows)]
    {
        win::send_arp(ip)
    }
    #[cfg(not(windows))]
    {
        let _ = ip;
        ArpReply::Unsupported
    }
}

/// Send a Wake-on-LAN "magic packet" for `mac` to each broadcast address.
pub fn wake_on_lan(mac: &str, broadcasts: &[Ipv4Addr]) -> std::io::Result<()> {
    let hex: String = mac.chars().filter(char::is_ascii_hexdigit).collect();
    let bad = || std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid MAC address");
    if hex.len() != 12 {
        return Err(bad());
    }
    let mut bytes = [0u8; 6];
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).map_err(|_| bad())?;
    }
    let mut packet = vec![0xFFu8; 6];
    for _ in 0..16 {
        packet.extend_from_slice(&bytes);
    }
    let sock = std::net::UdpSocket::bind("0.0.0.0:0")?;
    sock.set_broadcast(true)?;
    let mut sent = false;
    for &addr in broadcasts {
        for port in [9, 7] {
            sent |= sock.send_to(&packet, SocketAddr::new(IpAddr::V4(addr), port)).is_ok();
        }
    }
    if sent { Ok(()) } else { Err(std::io::Error::other("could not send the packet")) }
}

#[cfg(windows)]
mod win {
    //! Direct calls into iphlpapi.dll (available since Windows XP, so fine
    //! on Server 2008 R2 / 2012). No admin rights needed for either call.
    use std::ffi::c_void;
    use std::net::Ipv4Addr;

    use super::{ArpReply, PingReply};

    #[repr(C)]
    struct IpOptionInformation {
        ttl: u8,
        tos: u8,
        flags: u8,
        options_size: u8,
        options_data: *mut u8,
    }

    /// ICMP_ECHO_REPLY for 64-bit processes.
    #[repr(C)]
    struct IcmpEchoReply {
        address: u32,
        status: u32,
        round_trip_time: u32,
        data_size: u16,
        reserved: u16,
        data: *mut c_void,
        options: IpOptionInformation,
    }

    #[link(name = "iphlpapi")]
    unsafe extern "system" {
        fn IcmpCreateFile() -> *mut c_void;
        fn IcmpCloseHandle(handle: *mut c_void) -> i32;
        fn IcmpSendEcho(
            handle: *mut c_void,
            destination: u32,
            request_data: *const c_void,
            request_size: u16,
            request_options: *const IpOptionInformation,
            reply_buffer: *mut c_void,
            reply_size: u32,
            timeout_ms: u32,
        ) -> u32;
        fn SendARP(dest_ip: u32, src_ip: u32, mac: *mut c_void, mac_len: *mut u32) -> u32;
        fn GetBestInterface(dest_ip: u32, if_index: *mut u32) -> u32;
        fn ResolveIpNetEntry2(row: *mut MibIpnetRow2, source: *const c_void) -> u32;
    }

    /// MIB_IPNET_ROW2 (netioapi.h), 88 bytes.
    #[repr(C)]
    struct MibIpnetRow2 {
        address: [u8; 28], // SOCKADDR_INET
        interface_index: u32,
        interface_luid: u64,
        physical_address: [u8; 32],
        physical_address_length: u32,
        state: i32,
        flags: u8,
        reachability_time: u32,
    }

    const _: () = assert!(std::mem::size_of::<MibIpnetRow2>() == 88);
    const _: () = assert!(std::mem::size_of::<IcmpEchoReply>() == 40);

    const INVALID_HANDLE_VALUE: *mut c_void = -1isize as *mut c_void;
    const IP_SUCCESS: u32 = 0;

    /// IPv4 address as the API expects it (network byte order in memory).
    fn ip_addr(ip: Ipv4Addr) -> u32 {
        u32::from_ne_bytes(ip.octets())
    }

    /// `Err` if the ICMP API can't be used at all (caller falls back to ping.exe).
    pub fn icmp_ping(ip: Ipv4Addr, timeout_ms: u64) -> Result<Option<PingReply>, ()> {
        let payload = *b"abcdefghijklmnopqrstuvwabcdefghi"; // same 32 bytes as ping.exe
        // Room for the reply struct, the echoed payload and an ICMP error.
        let mut buf = [0u64; 32];
        // SAFETY: plain Win32 calls with buffers that outlive them; the
        // handle is closed before returning.
        unsafe {
            let handle = IcmpCreateFile();
            if handle.is_null() || handle == INVALID_HANDLE_VALUE {
                return Err(());
            }
            let replies = IcmpSendEcho(
                handle,
                ip_addr(ip),
                payload.as_ptr().cast(),
                payload.len() as u16,
                std::ptr::null(),
                buf.as_mut_ptr().cast(),
                std::mem::size_of_val(&buf) as u32,
                timeout_ms.clamp(100, 10_000) as u32,
            );
            IcmpCloseHandle(handle);
            if replies == 0 {
                return Ok(None); // timed out or unreachable
            }
            let reply = &*(buf.as_ptr() as *const IcmpEchoReply);
            // A router answering "host unreachable" for the address has a
            // different status and source address; only the host itself counts.
            if reply.status != IP_SUCCESS || reply.address != ip_addr(ip) {
                return Ok(None);
            }
            Ok(Some(PingReply { rtt_ms: reply.round_trip_time as f64, ttl: Some(reply.options.ttl as u32) }))
        }
    }

    const NO_ERROR: u32 = 0;
    const ERROR_GEN_FAILURE: u32 = 31;
    const ERROR_BAD_NET_NAME: u32 = 67;
    const ERROR_NOT_FOUND: u32 = 1168;

    fn mac_reply(bytes: &[u8]) -> ArpReply {
        let bytes: [u8; 6] = bytes.try_into().unwrap_or([0; 6]);
        match super::normalize_mac(&super::format_mac(&bytes)) {
            Some(m) => ArpReply::Mac(m),
            None => ArpReply::NoReply,
        }
    }

    /// Fresh ARP resolution. `ResolveIpNetEntry2` (Vista / Server 2008+)
    /// drops any cached entry and asks the network again, so a device that
    /// went offline a minute ago isn't reported as alive. Falls back to
    /// `SendARP`, which may answer from the cache.
    pub fn send_arp(ip: Ipv4Addr) -> ArpReply {
        match resolve_neighbor(ip) {
            ArpReply::Unsupported => send_arp_cached(ip),
            reply => reply,
        }
    }

    fn resolve_neighbor(ip: Ipv4Addr) -> ArpReply {
        const AF_INET: u16 = 2;
        const NLNS_INCOMPLETE: i32 = 1;
        let mut if_index = 0u32;
        // SAFETY: plain Win32 calls with properly sized, initialized structs.
        unsafe {
            if GetBestInterface(ip_addr(ip), &mut if_index) != NO_ERROR {
                return ArpReply::Unsupported;
            }
            let mut row: MibIpnetRow2 = std::mem::zeroed();
            row.address[..2].copy_from_slice(&AF_INET.to_ne_bytes());
            row.address[4..8].copy_from_slice(&ip.octets());
            row.interface_index = if_index;
            match ResolveIpNetEntry2(&mut row, std::ptr::null()) {
                NO_ERROR if row.physical_address_length == 6 && row.state > NLNS_INCOMPLETE => {
                    mac_reply(&row.physical_address[..6])
                }
                NO_ERROR | ERROR_GEN_FAILURE | ERROR_BAD_NET_NAME | ERROR_NOT_FOUND => ArpReply::NoReply,
                _ => ArpReply::Unsupported,
            }
        }
    }

    fn send_arp_cached(ip: Ipv4Addr) -> ArpReply {
        let mut mac = [0u32; 2];
        let mut len: u32 = 6;
        // SAFETY: `mac` is 8 bytes and `len` says we accept 6.
        let rc = unsafe { SendARP(ip_addr(ip), 0, mac.as_mut_ptr().cast(), &mut len) };
        match rc {
            // SAFETY: `mac` is 8 bytes long.
            NO_ERROR if len == 6 => mac_reply(unsafe { std::slice::from_raw_parts(mac.as_ptr() as *const u8, 6) }),
            ERROR_GEN_FAILURE | ERROR_BAD_NET_NAME | ERROR_NOT_FOUND => ArpReply::NoReply,
            _ => ArpReply::Unsupported,
        }
    }
}

/// `ping` via the system command (macOS/Linux, and the Windows fallback).
fn ping_command(ip: Ipv4Addr, timeout_ms: u64) -> Option<PingReply> {
    let ip_s = ip.to_string();
    let timeout = timeout_ms.max(100).to_string();

    #[cfg(windows)]
    let out = run_hidden("ping", &["-n", "1", "-w", &timeout, &ip_s])?;
    #[cfg(target_os = "macos")]
    let out = {
        // -W is the reply wait in ms; -t is an overall cap in seconds.
        let secs = timeout_ms.div_ceil(1000).max(1).to_string();
        run_hidden("/sbin/ping", &["-n", "-c", "1", "-W", &timeout, "-t", &secs, &ip_s])?
    };
    #[cfg(not(any(windows, target_os = "macos")))]
    let out = {
        let secs = (timeout_ms / 1000).max(1).to_string();
        run_hidden("ping", &["-n", "-c", "1", "-W", &secs, &ip_s])?
    };

    let text = String::from_utf8_lossy(&out.stdout).to_lowercase();
    // Windows exits 0 for "destination host unreachable" replies from the
    // gateway, so require a TTL in the output rather than trusting the code.
    // The reply must also come from the address we pinged: routers and
    // firewalls can answer on its behalf ("Reply from 10.0.0.1: ...").
    let text = reply_line(&text, ip)?;
    let ttl = number_after(text, "ttl=").map(|v| v as u32);
    ttl?;
    let rtt_ms = if text.contains("time<") {
        0.0
    } else {
        number_after(text, "time=").unwrap_or(0.0)
    };
    Some(PingReply { rtt_ms, ttl })
}

/// The line of `ping` output that is a reply from `ip` itself, e.g.
/// `reply from 10.0.0.5: bytes=32 time<1ms ttl=128` (Windows; French puts a
/// space before the colon) or `64 bytes from 10.0.0.5: icmp_seq=0 ttl=64`.
fn reply_line(text: &str, ip: Ipv4Addr) -> Option<&str> {
    let ip = ip.to_string();
    text.lines().find(|l| {
        l.contains("ttl=")
            && l.match_indices(&ip).any(|(i, _)| {
                let before = l[..i].chars().next_back();
                let after = l[i + ip.len()..].trim_start_matches(' ');
                // The whole address (10.0.0.5, not part of 10.0.0.15), then ':'.
                !before.is_some_and(|c| c.is_ascii_digit() || c == '.') && after.starts_with(':')
            })
    })
}

fn number_after(text: &str, key: &str) -> Option<f64> {
    let start = text.find(key)? + key.len();
    let num: String = text[start..]
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.')
        .collect();
    num.parse().ok()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PortState {
    Open,
    /// Connection actively refused: the port is closed but the host is up.
    Refused,
    NoAnswer,
}

/// Counting semaphore: caps how many TCP connections are in flight across
/// the whole scan, so many threads times many ports can't run the process
/// out of sockets (which would look like "no answer" from live hosts).
struct Semaphore {
    free: Mutex<usize>,
    cv: Condvar,
}

struct Permit<'a>(&'a Semaphore, usize);

impl Semaphore {
    fn acquire(&self, n: usize) -> Permit<'_> {
        let mut free = lock(&self.free);
        while *free < n {
            free = self.cv.wait(free).unwrap_or_else(std::sync::PoisonError::into_inner);
        }
        *free -= n;
        Permit(self, n)
    }
}

impl Drop for Permit<'_> {
    fn drop(&mut self) {
        *lock(&self.0.free) += self.1;
        self.0.cv.notify_all();
    }
}

/// Most ports one host probe may check at once (the size of a Windows `fd_set`).
const PORT_BATCH: usize = 64;

fn sockets() -> &'static Semaphore {
    static SOCKETS: OnceLock<Semaphore> = OnceLock::new();
    SOCKETS.get_or_init(|| Semaphore { free: Mutex::new(socket_budget()), cv: Condvar::new() })
}

/// How many probe sockets may be open at once. Unix processes start with a
/// low open-file limit (256 for macOS apps), so raise it and stay below it.
fn socket_budget() -> usize {
    const WANTED: usize = 2048;
    #[cfg(unix)]
    {
        // Leave room for pipes to `ping`/`arp`, UDP sockets and the UI.
        let limit = raise_open_file_limit(WANTED as u64 * 2) as usize;
        WANTED.min(limit / 2).max(PORT_BATCH)
    }
    #[cfg(not(unix))]
    {
        WANTED
    }
}

/// Raise the soft open-file limit towards `wanted`; returns the limit in effect.
#[cfg(unix)]
fn raise_open_file_limit(wanted: u64) -> u64 {
    // SAFETY: getrlimit/setrlimit with a valid, initialized struct.
    unsafe {
        let mut lim = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) != 0 {
            return 256;
        }
        #[allow(clippy::unnecessary_cast)] // rlim_t differs between systems
        let (current, hard) = (lim.rlim_cur as u64, lim.rlim_max as u64);
        // macOS refuses values above OPEN_MAX (10240) even when the hard
        // limit says "unlimited".
        let target = wanted.min(hard).min(10_240);
        if target > current {
            let raised = libc::rlimit { rlim_cur: target as libc::rlim_t, rlim_max: lim.rlim_max };
            if libc::setrlimit(libc::RLIMIT_NOFILE, &raised) == 0 {
                return target;
            }
        }
        current
    }
}

/// Probe ports at once. Returns (open ports, whether the host answered at all).
///
/// All connections are started without blocking and watched from this one
/// thread, so a host costs one thread however many ports are checked.
pub fn probe_ports(ip: Ipv4Addr, ports: &[u16], timeout: Duration) -> (Vec<u16>, bool) {
    let mut open = Vec::new();
    let mut answered = false;
    for batch in ports.chunks(PORT_BATCH) {
        let _permit = sockets().acquire(batch.len());
        for (port, state) in connect_all(ip, batch, timeout) {
            answered |= state != PortState::NoAnswer;
            if state == PortState::Open {
                open.push(port);
            }
        }
    }
    open.sort_unstable();
    (open, answered)
}

fn connect_all(ip: Ipv4Addr, ports: &[u16], timeout: Duration) -> Vec<(u16, PortState)> {
    use socket2::{Domain, Protocol, Socket, Type};
    let refused = |e: &std::io::Error| e.kind() == std::io::ErrorKind::ConnectionRefused;
    let mut states = Vec::with_capacity(ports.len());
    let mut pending: Vec<(u16, Socket)> = Vec::with_capacity(ports.len());
    for &port in ports {
        let sock = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP)).and_then(|s| s.set_nonblocking(true).map(|()| s));
        let Ok(sock) = sock else {
            states.push((port, PortState::NoAnswer));
            continue;
        };
        match sock.connect(&SocketAddr::new(IpAddr::V4(ip), port).into()) {
            Ok(()) => states.push((port, PortState::Open)),
            Err(e) if in_progress(&e) => pending.push((port, sock)),
            Err(e) if refused(&e) => states.push((port, PortState::Refused)),
            Err(_) => states.push((port, PortState::NoAnswer)),
        }
    }
    let deadline = Instant::now() + timeout;
    while !pending.is_empty() {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            break;
        }
        let Some(done) = wait_connected(&pending, left) else { break };
        let mut still = Vec::with_capacity(pending.len());
        for ((port, sock), done) in pending.into_iter().zip(done) {
            if !done {
                still.push((port, sock));
                continue;
            }
            states.push((port, match sock.take_error() {
                // Connected only if the socket really has a peer now.
                Ok(None) if sock.peer_addr().is_ok() => PortState::Open,
                Ok(Some(e)) if refused(&e) => PortState::Refused,
                _ => PortState::NoAnswer,
            }));
        }
        pending = still;
    }
    states.extend(pending.into_iter().map(|(port, _)| (port, PortState::NoAnswer)));
    states
}

/// A non-blocking connect that has started and will finish later.
fn in_progress(e: &std::io::Error) -> bool {
    #[cfg(unix)]
    {
        e.raw_os_error() == Some(libc::EINPROGRESS)
    }
    #[cfg(not(unix))]
    {
        e.kind() == std::io::ErrorKind::WouldBlock
    }
}

/// Wait up to `timeout` for any pending connect to succeed or fail. Returns
/// which ones finished, or None if waiting itself failed.
#[cfg(unix)]
fn wait_connected(pending: &[(u16, socket2::Socket)], timeout: Duration) -> Option<Vec<bool>> {
    use std::os::fd::AsRawFd;
    let mut fds: Vec<libc::pollfd> =
        pending.iter().map(|(_, s)| libc::pollfd { fd: s.as_raw_fd(), events: libc::POLLOUT, revents: 0 }).collect();
    let ms = timeout.as_millis().clamp(1, i32::MAX as u128) as libc::c_int;
    // SAFETY: `fds` is a valid array of `fds.len()` pollfd structs.
    let n = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, ms) };
    if n < 0 {
        let interrupted = std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted;
        return interrupted.then(|| vec![false; pending.len()]);
    }
    Some(fds.iter().map(|f| f.revents != 0).collect())
}

/// Windows: `select` reports finished connects in the write set and failed
/// ones in the except set. (`WSAPoll` misses failed connects before Windows
/// 10 2004, and HappyIP still runs on Windows 7.)
#[cfg(windows)]
fn wait_connected(pending: &[(u16, socket2::Socket)], timeout: Duration) -> Option<Vec<bool>> {
    use std::os::windows::io::AsRawSocket;

    #[repr(C)]
    struct FdSet {
        count: u32,
        array: [usize; PORT_BATCH],
    }
    #[repr(C)]
    struct TimeVal {
        sec: i32,
        usec: i32,
    }
    #[link(name = "ws2_32")]
    unsafe extern "system" {
        fn select(nfds: i32, read: *mut FdSet, write: *mut FdSet, except: *mut FdSet, timeout: *const TimeVal) -> i32;
    }

    let fill = || {
        let mut set = FdSet { count: 0, array: [0; PORT_BATCH] };
        for (_, s) in pending.iter().take(PORT_BATCH) {
            set.array[set.count as usize] = s.as_raw_socket() as usize;
            set.count += 1;
        }
        set
    };
    let (mut write, mut except) = (fill(), fill());
    let tv = TimeVal { sec: timeout.as_secs().min(3600) as i32, usec: timeout.subsec_micros().max(1) as i32 };
    // SAFETY: both sets are valid `fd_set`s holding at most FD_SETSIZE (64)
    // sockets that stay open for the call; the first argument is ignored.
    let n = unsafe { select(0, std::ptr::null_mut(), &mut write, &mut except, &tv) };
    if n < 0 {
        return None;
    }
    let has = |set: &FdSet, sock: usize| set.array[..set.count as usize].contains(&sock);
    Some(pending.iter().map(|(_, s)| has(&write, s.as_raw_socket() as usize) || has(&except, s.as_raw_socket() as usize)).collect())
}

/// Shared snapshot of the OS ARP table, refreshed at most every 500 ms.
/// Used where there's no API for a fresh ARP request (macOS/Linux).
pub struct ArpCache {
    /// The table as it was before the scan sent anything.
    before: HashMap<Ipv4Addr, String>,
    inner: Mutex<(HashMap<Ipv4Addr, String>, Option<Instant>)>,
}

pub struct ArpEntry {
    pub mac: String,
    /// The same entry was already in the table before the scan started, so
    /// it doesn't prove the device is there now: the OS keeps entries for
    /// many minutes after a device leaves.
    pub cached: bool,
}

impl ArpCache {
    pub fn new() -> Self {
        // Windows asks for fresh ARP replies instead (see `arp_request`).
        let before = if cfg!(windows) { HashMap::new() } else { read_arp_table() };
        Self { before, inner: Mutex::new((HashMap::new(), None)) }
    }

    pub fn lookup(&self, ip: Ipv4Addr) -> Option<ArpEntry> {
        let entry = |mac: &String| ArpEntry { mac: mac.clone(), cached: self.before.get(&ip) == Some(mac) };
        {
            let guard = lock(&self.inner);
            if let Some(mac) = guard.0.get(&ip) {
                return Some(entry(mac));
            }
            if guard.1.is_some_and(|t| t.elapsed() <= Duration::from_millis(500)) {
                return None;
            }
        }
        // Read the table without holding the lock, so other scan threads
        // aren't queued behind the `arp` command.
        let table = read_arp_table();
        let mut guard = lock(&self.inner);
        *guard = (table, Some(Instant::now()));
        guard.0.get(&ip).map(entry)
    }

    /// Which of `ips` (hosts known only from an entry older than the scan)
    /// are no longer in the ARP table. Sending to an address makes the OS
    /// verify an old entry and drop it when the device doesn't answer.
    pub fn departed(&self, ips: &[Ipv4Addr]) -> Vec<Ipv4Addr> {
        if ips.is_empty() {
            return Vec::new();
        }
        let now = read_arp_table();
        if now.is_empty() {
            return Vec::new(); // the table couldn't be read: no evidence either way
        }
        ips.iter().copied().filter(|ip| !now.contains_key(ip)).collect()
    }
}

fn read_arp_table() -> HashMap<Ipv4Addr, String> {
    #[cfg(windows)]
    let out = run_hidden("arp", &["-a"]);
    #[cfg(not(windows))]
    let out = run_hidden("/usr/sbin/arp", &["-an"]).or_else(|| run_hidden("arp", &["-an"]));
    out.map(|o| parse_arp(&String::from_utf8_lossy(&o.stdout))).unwrap_or_default()
}

/// Parses both macOS/Linux (`? (1.2.3.4) at a:b:c:d:e:f on en0`) and
/// Windows (`  1.2.3.4   aa-bb-cc-dd-ee-ff   dynamic`) formats.
pub fn parse_arp(text: &str) -> HashMap<Ipv4Addr, String> {
    let mut map = HashMap::new();
    for line in text.lines() {
        let mut ip = None;
        let mut mac = None;
        for tok in line.split_whitespace() {
            let tok = tok.trim_matches(|c| c == '(' || c == ')');
            if ip.is_none() && let Ok(a) = tok.parse::<Ipv4Addr>() {
                ip = Some(a);
                continue;
            }
            if mac.is_none() {
                mac = normalize_mac(tok);
            }
        }
        if let (Some(ip), Some(mac)) = (ip, mac) {
            map.insert(ip, mac);
        }
    }
    map
}

/// Normalize `0:1a:2b:3:4:5` or `00-1A-2B-03-04-05` to `00:1A:2B:03:04:05`.
/// Returns None for anything that isn't a real unicast-looking MAC.
pub fn normalize_mac(s: &str) -> Option<String> {
    let parts: Vec<&str> = s.split([':', '-']).collect();
    if parts.len() != 6 {
        return None;
    }
    let mut bytes = [0u8; 6];
    for (b, p) in bytes.iter_mut().zip(&parts) {
        if p.is_empty() || p.len() > 2 {
            return None;
        }
        *b = u8::from_str_radix(p, 16).ok()?;
    }
    // Empty, broadcast, multicast, or the 02:00:00:00:00:00 placeholder
    // newer macOS reports when it hides real hardware addresses.
    if bytes == [0; 6] || bytes == [0xFF; 6] || bytes[0] & 1 == 1 || bytes == [2, 0, 0, 0, 0, 0] {
        return None;
    }
    Some(format_mac(&bytes))
}

pub fn format_mac(b: &[u8; 6]) -> String {
    b.iter().map(|x| format!("{x:02X}")).collect::<Vec<_>>().join(":")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ping_reply_must_come_from_target() {
        let ip: Ipv4Addr = "10.0.0.5".parse().unwrap();
        let ok = |t: &str| reply_line(t, ip).is_some();
        assert!(ok("reply from 10.0.0.5: bytes=32 time<1ms ttl=128"));
        assert!(ok("réponse de 10.0.0.5 : octets=32 temps<1ms ttl=128"));
        assert!(ok("64 bytes from 10.0.0.5: icmp_seq=0 ttl=64 time=1.2 ms"));
        assert!(!ok("reply from 10.0.0.1: bytes=32 time=1ms ttl=255"));
        assert!(!ok("reply from 10.0.0.55: bytes=32 time=1ms ttl=128"));
        assert!(!ok("reply from 110.0.0.5: bytes=32 time=1ms ttl=128"));
        assert!(!ok("reply from 10.0.0.1: destination host unreachable."));
    }

    #[test]
    fn arp_formats() {
        let mac = "? (192.168.1.1) at 0:1a:2b:3c:4d:5e on en0 ifscope [ethernet]\n\
                   ? (192.168.1.9) at (incomplete) on en0 ifscope [ethernet]\n\
                   ? (224.0.0.251) at 1:0:5e:0:0:fb on en0 ifscope permanent [ethernet]";
        let m = parse_arp(mac);
        assert_eq!(m.get(&"192.168.1.1".parse().unwrap()).unwrap(), "00:1A:2B:3C:4D:5E");
        assert_eq!(m.len(), 1);

        let win = "Interface: 192.168.1.5 --- 0xb\n  Internet Address      Physical Address      Type\n  \
                   192.168.1.1           aa-bb-cc-dd-ee-ff     dynamic\n  \
                   192.168.1.255         ff-ff-ff-ff-ff-ff     static";
        let m = parse_arp(win);
        assert_eq!(m.get(&"192.168.1.1".parse().unwrap()).unwrap(), "AA:BB:CC:DD:EE:FF");
        assert_eq!(m.len(), 1);
    }

    #[test]
    fn scripts_are_passed_as_plain_text() {
        assert!(is_plain_script("$x='a b'; 'NAME='+$x"));
        assert!(!is_plain_script("Write-Host \"hi\""));
        assert!(!is_plain_script("'caf\u{e9}'"));
        assert!(!is_plain_script("'C:\\"));
        assert!(run_powershell("\"", Duration::from_millis(10)).is_err());
    }

    #[test]
    fn ping_answers_once_without_waiting_for_the_retry() {
        // Loopback always answers the first request.
        let started = Instant::now();
        let reply = ping(Ipv4Addr::LOCALHOST, 3000);
        assert!(reply.is_some());
        assert!(started.elapsed() < Duration::from_millis(900), "took {:?}", started.elapsed());
    }

    #[test]
    fn wol_rejects_bad_mac() {
        assert!(wake_on_lan("nope", &[]).is_err());
    }

    #[test]
    fn system_tools_use_full_paths() {
        // Paths given in full are left alone everywhere.
        assert_eq!(program_path("/sbin/ping"), PathBuf::from("/sbin/ping"));
        if cfg!(windows) {
            for tool in ["powershell.exe", "mstsc", "explorer.exe", "query", "ping", "arp", "route"] {
                assert!(program_path(tool).is_absolute(), "{tool} must not be found by search order");
            }
        }
    }

    #[test]
    fn port_probe_tells_open_from_closed() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let open = listener.local_addr().unwrap().port();
        // A port that was just released is closed (refused on loopback).
        let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let (ports, answered) = probe_ports(Ipv4Addr::LOCALHOST, &[open, closed], Duration::from_millis(1000));
        assert_eq!(ports, vec![open]);
        assert!(answered);
        let (ports, answered) = probe_ports(Ipv4Addr::LOCALHOST, &[closed], Duration::from_millis(1000));
        assert!(ports.is_empty() && answered, "a refused connection still proves the host is up");
    }

    #[test]
    fn more_ports_than_one_batch() {
        let ports: Vec<u16> = (20_000..20_150).collect();
        let (open, answered) = probe_ports(Ipv4Addr::LOCALHOST, &ports, Duration::from_millis(500));
        assert!(open.len() < ports.len() && answered);
    }

    #[test]
    fn ping_parsing() {
        assert_eq!(number_after("64 bytes: ttl=64 time=3.21 ms", "time="), Some(3.21));
        assert_eq!(number_after("reply from x: bytes=32 time<1ms ttl=128", "ttl="), Some(128.0));
    }
}
