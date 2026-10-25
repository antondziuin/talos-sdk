//! What this machine can say about itself, read without spawning anything.
//!
//! `wmic`, `ioreg` and `dmidecode` draw antivirus attention, fail in sandboxes
//! and are slow, and none of them is worth a licensing call that hangs. So every
//! probe here is a file read, a registry read or a single system call, and every
//! one of them treats failure as "unavailable": a missing component costs a
//! little matching weight, while an error escaping into a licensing call would
//! cost the user their session.

/// The raw component values, before hashing. `None` is "not readable here".
pub(crate) struct RawComponents {
    pub machine_guid: Option<String>,
    pub smbios_uuid: Option<String>,
    pub disk_serial: Option<String>,
    pub mac_set: Option<String>,
    pub cpu: Option<String>,
    pub mem_bucket: Option<String>,
    pub os_install: Option<String>,
    pub hostname: Option<String>,
}

pub(crate) fn collect() -> RawComponents {
    RawComponents {
        machine_guid: imp::machine_guid(),
        smbios_uuid: imp::smbios_uuid(),
        disk_serial: imp::disk_serial(),
        mac_set: imp::mac_set(),
        cpu: imp::cpu_model().map(|model| format!("{model}|{}", cpu_count())),
        mem_bucket: imp::total_memory().and_then(mem_bucket),
        os_install: imp::os_install(),
        hostname: hostname(),
    }
}

/// The machine name: what the portal shows for a seat, and one (weak)
/// fingerprint component.
pub(crate) fn hostname() -> Option<String> {
    imp::hostname()
        .map(|h| h.trim().to_string())
        .filter(|h| !h.is_empty())
}

/// The `os` string reported on activation and heartbeat. Descriptive only.
pub(crate) fn os_description() -> String {
    match imp::os_version() {
        Some(v) => format!("{} {v}", platform()),
        None => platform().to_string(),
    }
}

/// The platform name artifacts are published under: `windows`, `macos`, `linux`.
///
/// Rust's own names are already the manifest's spelling for all three — unlike
/// Node's `win32` and `darwin` — so there is nothing to translate.
pub(crate) fn platform() -> &'static str {
    std::env::consts::OS
}

/// The arch name artifacts are published under — the same spelling the other
/// SDKs report (`x64`, `arm64`, `x86`), so one manifest serves all three.
pub(crate) fn arch() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "x64",
        "aarch64" => "arm64",
        "x86" => "x86",
        other => other,
    }
}

fn cpu_count() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
}

/// Installed RAM rounded down to a power of two GiB. Coarse on purpose: exact
/// byte counts shift when firmware reserves memory, which would look like drift
/// on a machine nobody touched.
fn mem_bucket(bytes: u64) -> Option<String> {
    let gib = bytes / (1024 * 1024 * 1024);
    if gib < 1 {
        return None;
    }
    let mut bucket = 1u64;
    while bucket * 2 <= gib {
        bucket *= 2;
    }
    Some(bucket.to_string())
}

/// A file's trimmed contents, or `None` when it is absent, unreadable or empty.
#[allow(dead_code)]
fn read_file(path: &str) -> Option<String> {
    let text = std::fs::read_to_string(path).ok()?;
    let text = text.trim();
    (!text.is_empty()).then(|| text.to_string())
}

/// Install time, approximated by a system directory's creation time.
/// Filesystems that record no birth time report nothing rather than the epoch:
/// a constant every host agrees on would be worse than no component.
#[allow(dead_code)]
fn birth_time(path: &str) -> Option<String> {
    let created = std::fs::metadata(path).ok()?.created().ok()?;
    let secs = created
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs();
    (secs > 0).then(|| secs.to_string())
}

fn format_mac(bytes: &[u8]) -> Option<String> {
    if bytes.len() != 6 || bytes.iter().all(|b| *b == 0) {
        return None;
    }
    Some(
        bytes
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(":"),
    )
}

fn join_macs(mut macs: Vec<String>) -> Option<String> {
    macs.sort();
    macs.dedup();
    (!macs.is_empty()).then(|| macs.join(","))
}

#[cfg(windows)]
mod imp {
    use std::mem::{size_of, zeroed};
    use std::ptr::{null, null_mut};

    use windows_sys::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, ERROR_SUCCESS};
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetAdaptersAddresses, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER,
        GAA_FLAG_SKIP_MULTICAST, IP_ADAPTER_ADDRESSES_LH,
    };
    use windows_sys::Win32::Networking::WinSock::AF_UNSPEC;
    use windows_sys::Win32::Storage::FileSystem::GetVolumeInformationW;
    use windows_sys::Win32::System::Registry::{
        RegGetValueW, HKEY_LOCAL_MACHINE, REG_DWORD, REG_SZ, RRF_RT_REG_DWORD, RRF_RT_REG_SZ,
        RRF_SUBKEY_WOW6464KEY,
    };
    use windows_sys::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};

    const CRYPTOGRAPHY: &str = r"SOFTWARE\Microsoft\Cryptography";
    const CURRENT_VERSION: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion";

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(Some(0)).collect()
    }

    /// A string or DWORD value under HKLM, always from the 64-bit view: a
    /// 32-bit build of the host must report the same machine as a 64-bit one.
    fn registry(path: &str, name: &str) -> Option<String> {
        let path = wide(path);
        let name = wide(name);
        let mut kind = 0u32;
        let mut buf = [0u16; 512];
        let mut len = (buf.len() * 2) as u32;
        // SAFETY: both strings are NUL-terminated and outlive the call; `buf`
        // is writable for `len` bytes, which the call reduces to what it wrote.
        let rc = unsafe {
            RegGetValueW(
                HKEY_LOCAL_MACHINE,
                path.as_ptr(),
                name.as_ptr(),
                RRF_RT_REG_SZ | RRF_RT_REG_DWORD | RRF_SUBKEY_WOW6464KEY,
                &mut kind,
                buf.as_mut_ptr().cast(),
                &mut len,
            )
        };
        if rc != ERROR_SUCCESS {
            return None;
        }
        let value = match kind {
            REG_DWORD if len >= 4 => (u32::from(buf[0]) | (u32::from(buf[1]) << 16)).to_string(),
            REG_SZ => {
                let units = &buf[..(len as usize / 2).min(buf.len())];
                let end = units.iter().position(|u| *u == 0).unwrap_or(units.len());
                String::from_utf16_lossy(&units[..end])
            }
            _ => return None,
        };
        let value = value.trim();
        (!value.is_empty()).then(|| value.to_string())
    }

    pub(super) fn machine_guid() -> Option<String> {
        registry(CRYPTOGRAPHY, "MachineGuid")
    }

    pub(super) fn smbios_uuid() -> Option<String> {
        None
    }

    /// The system volume's serial — what `vol C:` prints, and stable until the
    /// volume is reformatted.
    pub(super) fn disk_serial() -> Option<String> {
        let root = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".into());
        let root = wide(&format!("{}\\", root.trim_end_matches('\\')));
        let mut serial = 0u32;
        // SAFETY: `root` is NUL-terminated; every optional out-parameter is
        // null with a zero size, which the API documents as "not wanted".
        let ok = unsafe {
            GetVolumeInformationW(
                root.as_ptr(),
                null_mut(),
                0,
                &mut serial,
                null_mut(),
                null_mut(),
                null_mut(),
                0,
            )
        };
        (ok != 0 && serial != 0).then(|| format!("{serial:08x}"))
    }

    /// Physical adapters' MACs. Loopback and tunnels are skipped: they churn
    /// with every VPN connection and would report drift on a machine nobody
    /// touched.
    pub(super) fn mac_set() -> Option<String> {
        const IF_TYPE_SOFTWARE_LOOPBACK: u32 = 24;
        const IF_TYPE_TUNNEL: u32 = 131;
        let flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
        let mut size = 16 * 1024u32;
        for _ in 0..3 {
            // u64 elements, so the buffer is aligned for the structures the
            // call writes into it.
            let mut buf = vec![0u64; (size as usize).div_ceil(8)];
            let head = buf.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
            // SAFETY: `buf` is writable for `size` bytes and aligned for the
            // adapter structures; the call reports the size it needs instead
            // of writing past it.
            let rc = unsafe {
                GetAdaptersAddresses(u32::from(AF_UNSPEC), flags, null(), head, &mut size)
            };
            if rc == ERROR_BUFFER_OVERFLOW {
                continue;
            }
            if rc != ERROR_SUCCESS {
                return None;
            }
            let mut macs = Vec::new();
            let mut cur = head.cast_const();
            while !cur.is_null() {
                // SAFETY: a linked list the call built inside `buf`, which is
                // still alive; `Next` is null at the end.
                let adapter = unsafe { &*cur };
                if adapter.IfType != IF_TYPE_SOFTWARE_LOOPBACK && adapter.IfType != IF_TYPE_TUNNEL {
                    let len =
                        (adapter.PhysicalAddressLength as usize).min(adapter.PhysicalAddress.len());
                    if let Some(mac) = super::format_mac(&adapter.PhysicalAddress[..len]) {
                        macs.push(mac);
                    }
                }
                cur = adapter.Next;
            }
            return super::join_macs(macs);
        }
        None
    }

    pub(super) fn cpu_model() -> Option<String> {
        std::env::var("PROCESSOR_IDENTIFIER")
            .ok()
            .filter(|s| !s.trim().is_empty())
    }

    pub(super) fn total_memory() -> Option<u64> {
        // SAFETY: a plain-data structure; `dwLength` is set as the API requires.
        let mut status: MEMORYSTATUSEX = unsafe { zeroed() };
        status.dwLength = size_of::<MEMORYSTATUSEX>() as u32;
        // SAFETY: `status` is a valid, writable MEMORYSTATUSEX.
        let ok = unsafe { GlobalMemoryStatusEx(&mut status) };
        (ok != 0 && status.ullTotalPhys > 0).then_some(status.ullTotalPhys)
    }

    pub(super) fn os_install() -> Option<String> {
        registry(CURRENT_VERSION, "InstallDate")
    }

    pub(super) fn hostname() -> Option<String> {
        std::env::var("COMPUTERNAME").ok()
    }

    pub(super) fn os_version() -> Option<String> {
        let major = registry(CURRENT_VERSION, "CurrentMajorVersionNumber")?;
        let minor =
            registry(CURRENT_VERSION, "CurrentMinorVersionNumber").unwrap_or_else(|| "0".into());
        match registry(CURRENT_VERSION, "CurrentBuildNumber") {
            Some(build) => Some(format!("{major}.{minor}.{build}")),
            None => Some(format!("{major}.{minor}")),
        }
    }
}

#[cfg(unix)]
mod unix {
    /// `gethostname(2)`, which both Linux and macOS have.
    pub(super) fn hostname() -> Option<String> {
        let mut buf = [0u8; 256];
        // SAFETY: `buf` is writable for its length; the result is checked
        // before anything is read from it.
        let rc = unsafe { libc::gethostname(buf.as_mut_ptr().cast(), buf.len()) };
        if rc != 0 {
            return None;
        }
        let end = buf.iter().position(|b| *b == 0).unwrap_or(buf.len());
        Some(String::from_utf8_lossy(&buf[..end]).into_owned())
    }
}

#[cfg(target_os = "linux")]
mod imp {
    use super::{birth_time, read_file};

    /// Per-install OS identity; survives hardware changes.
    pub(super) fn machine_guid() -> Option<String> {
        read_file("/etc/machine-id").or_else(|| read_file("/var/lib/dbus/machine-id"))
    }

    /// Root-only on most distributions; absent is a normal outcome.
    pub(super) fn smbios_uuid() -> Option<String> {
        read_file("/sys/class/dmi/id/product_uuid")
    }

    pub(super) fn disk_serial() -> Option<String> {
        read_file("/sys/class/dmi/id/board_serial")
    }

    /// MACs of interfaces backed by a device. Bridges, veths, tunnels and
    /// whatever a container runtime raises have no `device` link, and they come
    /// and go with every `docker run`.
    pub(super) fn mac_set() -> Option<String> {
        let mut macs = Vec::new();
        for entry in std::fs::read_dir("/sys/class/net").ok()?.flatten() {
            let path = entry.path();
            if !path.join("device").exists() {
                continue;
            }
            let Ok(text) = std::fs::read_to_string(path.join("address")) else {
                continue;
            };
            let bytes: Vec<u8> = text
                .trim()
                .split(':')
                .filter_map(|p| u8::from_str_radix(p, 16).ok())
                .collect();
            if let Some(mac) = super::format_mac(&bytes) {
                macs.push(mac);
            }
        }
        super::join_macs(macs)
    }

    pub(super) fn cpu_model() -> Option<String> {
        let text = std::fs::read_to_string("/proc/cpuinfo").ok()?;
        text.lines()
            .find(|l| l.starts_with("model name"))
            .and_then(|l| l.split_once(':'))
            .map(|(_, v)| v.trim().to_string())
            .filter(|v| !v.is_empty())
    }

    pub(super) fn total_memory() -> Option<u64> {
        let text = std::fs::read_to_string("/proc/meminfo").ok()?;
        let line = text.lines().find(|l| l.starts_with("MemTotal:"))?;
        let kb: u64 = line.split_whitespace().nth(1)?.parse().ok()?;
        Some(kb * 1024)
    }

    pub(super) fn os_install() -> Option<String> {
        birth_time("/etc")
    }

    pub(super) fn hostname() -> Option<String> {
        super::unix::hostname()
    }

    pub(super) fn os_version() -> Option<String> {
        read_file("/proc/sys/kernel/osrelease")
    }
}

#[cfg(target_os = "macos")]
mod imp {
    use std::ffi::CStr;

    use super::birth_time;

    fn sysctl_string(name: &CStr) -> Option<String> {
        let mut len = 0usize;
        // SAFETY: a size query — null output buffer, `len` receives the size.
        let rc = unsafe {
            libc::sysctlbyname(
                name.as_ptr(),
                std::ptr::null_mut(),
                &mut len,
                std::ptr::null_mut(),
                0,
            )
        };
        if rc != 0 || len == 0 {
            return None;
        }
        let mut buf = vec![0u8; len];
        // SAFETY: `buf` is writable for `len` bytes, the size just reported.
        let rc = unsafe {
            libc::sysctlbyname(
                name.as_ptr(),
                buf.as_mut_ptr().cast(),
                &mut len,
                std::ptr::null_mut(),
                0,
            )
        };
        if rc != 0 {
            return None;
        }
        let end = buf
            .iter()
            .position(|b| *b == 0)
            .unwrap_or(len.min(buf.len()));
        let s = String::from_utf8_lossy(&buf[..end]).trim().to_string();
        (!s.is_empty()).then_some(s)
    }

    pub(super) fn machine_guid() -> Option<String> {
        None
    }

    pub(super) fn smbios_uuid() -> Option<String> {
        None
    }

    pub(super) fn disk_serial() -> Option<String> {
        None
    }

    /// The built-in `en*` interfaces. `awdl`, `llw`, `utun`, `bridge` and `ap`
    /// are raised and dropped by the OS on its own schedule, and some of them
    /// randomise their address.
    pub(super) fn mac_set() -> Option<String> {
        let mut macs = Vec::new();
        let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
        // SAFETY: on success `ifap` is a list owned by libc until freed below.
        if unsafe { libc::getifaddrs(&mut ifap) } != 0 {
            return None;
        }
        let mut cur = ifap;
        while !cur.is_null() {
            // SAFETY: a node of the list getifaddrs returned, not yet freed.
            let ifa = unsafe { &*cur };
            cur = ifa.ifa_next;
            if ifa.ifa_addr.is_null() || ifa.ifa_name.is_null() {
                continue;
            }
            // SAFETY: both pointers were checked non-null and point into the list.
            let (family, name) = unsafe {
                (
                    i32::from((*ifa.ifa_addr).sa_family),
                    CStr::from_ptr(ifa.ifa_name),
                )
            };
            if family != libc::AF_LINK || !name.to_bytes().starts_with(b"en") {
                continue;
            }
            let sdl = ifa.ifa_addr.cast::<libc::sockaddr_dl>();
            // SAFETY: an AF_LINK address is a sockaddr_dl; the link-layer
            // address follows the interface name inside `sdl_data`.
            let bytes = unsafe {
                let nlen = usize::from((*sdl).sdl_nlen);
                let alen = usize::from((*sdl).sdl_alen);
                if alen != 6 {
                    continue;
                }
                let start = (*sdl).sdl_data.as_ptr().cast::<u8>().add(nlen);
                std::slice::from_raw_parts(start, alen).to_vec()
            };
            if let Some(mac) = super::format_mac(&bytes) {
                macs.push(mac);
            }
        }
        // SAFETY: the list getifaddrs returned, freed exactly once.
        unsafe { libc::freeifaddrs(ifap) };
        super::join_macs(macs)
    }

    pub(super) fn cpu_model() -> Option<String> {
        sysctl_string(c"machdep.cpu.brand_string")
    }

    pub(super) fn total_memory() -> Option<u64> {
        let mut value = 0u64;
        let mut len = std::mem::size_of::<u64>();
        // SAFETY: `hw.memsize` is a 64-bit integer and `value` is 8 writable bytes.
        let rc = unsafe {
            libc::sysctlbyname(
                c"hw.memsize".as_ptr(),
                (&mut value as *mut u64).cast(),
                &mut len,
                std::ptr::null_mut(),
                0,
            )
        };
        (rc == 0 && value > 0).then_some(value)
    }

    pub(super) fn os_install() -> Option<String> {
        birth_time("/etc")
    }

    pub(super) fn hostname() -> Option<String> {
        super::unix::hostname()
    }

    pub(super) fn os_version() -> Option<String> {
        sysctl_string(c"kern.osproductversion")
    }
}

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
mod imp {
    pub(super) fn machine_guid() -> Option<String> {
        None
    }
    pub(super) fn smbios_uuid() -> Option<String> {
        None
    }
    pub(super) fn disk_serial() -> Option<String> {
        None
    }
    pub(super) fn mac_set() -> Option<String> {
        None
    }
    pub(super) fn cpu_model() -> Option<String> {
        None
    }
    pub(super) fn total_memory() -> Option<u64> {
        None
    }
    pub(super) fn os_install() -> Option<String> {
        None
    }
    pub(super) fn hostname() -> Option<String> {
        #[cfg(unix)]
        {
            super::unix::hostname()
        }
        #[cfg(not(unix))]
        {
            None
        }
    }
    pub(super) fn os_version() -> Option<String> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_is_bucketed_down_to_a_power_of_two() {
        let gib = 1024 * 1024 * 1024;
        assert_eq!(mem_bucket(gib / 2), None);
        assert_eq!(mem_bucket(gib).as_deref(), Some("1"));
        assert_eq!(mem_bucket(15 * gib).as_deref(), Some("8"));
        assert_eq!(mem_bucket(16 * gib).as_deref(), Some("16"));
    }

    #[test]
    fn an_all_zero_or_short_address_is_not_a_mac() {
        assert_eq!(format_mac(&[0; 6]), None);
        assert_eq!(format_mac(&[1, 2, 3]), None);
        assert_eq!(
            format_mac(&[0xaa, 0xbb, 0xcc, 0x01, 0x02, 0x03]).as_deref(),
            Some("aa:bb:cc:01:02:03")
        );
    }

    #[test]
    fn the_arch_and_platform_are_spelled_as_manifests_spell_them() {
        assert!(["windows", "macos", "linux"].contains(&platform()) || !platform().is_empty());
        assert_ne!(arch(), "x86_64");
        assert_ne!(arch(), "aarch64");
    }
}
