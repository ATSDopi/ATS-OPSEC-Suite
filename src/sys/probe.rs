//! Sonde de capacités de l'hôte — exécutée pendant la séquence de boot.
//! Chaque résultat est affiché dans le checklist et le dashboard ; les
//! options incompatibles seront grisées (jamais cachées) dans le TUI.

use super::memlock::{self, LockStatus};
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct CpuFeatures {
    pub aes_ni: bool,
    pub avx2: bool,
    pub sse42: bool,
    pub hypervisor: Option<bool>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SystemProfile {
    pub os: &'static str,
    pub arch: &'static str,
    pub cpu: CpuFeatures,
    pub total_ram_mb: Option<u64>,
    pub memlock: LockStatus,
    /// Type de FS du répertoire courant ("NTFS", "ext4", "apfs", …).
    pub fs_type: Option<String>,
    /// getrandom() fonctionnel — condition sine qua non de toute la crypto.
    pub rng_ok: bool,
    /// Debugger/tracer détecté au lancement (avertissement, pas un blocage).
    pub tracer_detected: Option<bool>,
    /// Swap activé détecté (Linux) — risque de fuite de secrets.
    pub swap_present: Option<bool>,
}

/// Lance toutes les sondes. Conçu pour rester < ~50 ms.
pub fn probe() -> SystemProfile {
    let mut rng_buf = [0u8; 32];
    let rng_ok = getrandom::getrandom(&mut rng_buf).is_ok();

    SystemProfile {
        os: std::env::consts::OS,
        arch: std::env::consts::ARCH,
        cpu: probe_cpu(),
        total_ram_mb: probe_ram(),
        memlock: memlock::probe_lock(),
        fs_type: probe_fs(),
        rng_ok,
        tracer_detected: probe_tracer(),
        swap_present: probe_swap(),
    }
}

fn probe_cpu() -> CpuFeatures {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        CpuFeatures {
            aes_ni: std::arch::is_x86_feature_detected!("aes"),
            avx2: std::arch::is_x86_feature_detected!("avx2"),
            sse42: std::arch::is_x86_feature_detected!("sse4.2"),
            hypervisor: Some(cpuid_hypervisor()),
        }
    }
    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
    {
        CpuFeatures {
            aes_ni: false,
            avx2: false,
            sse42: false,
            hypervisor: None,
        }
    }
}

/// Bit 31 de ECX (CPUID leaf 1) = invité sous hyperviseur.
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn cpuid_hypervisor() -> bool {
    core::arch::x86_64::__cpuid(1).ecx & (1 << 31) != 0
}

fn probe_ram() -> Option<u64> {
    #[cfg(windows)]
    {
        windows_ram()
    }
    #[cfg(unix)]
    {
        unix_ram()
    }
    #[cfg(not(any(windows, unix)))]
    {
        None
    }
}

#[cfg(windows)]
fn windows_ram() -> Option<u64> {
    use windows_sys::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};
    let mut st = MEMORYSTATUSEX {
        dwLength: std::mem::size_of::<MEMORYSTATUSEX>() as u32,
        dwMemoryLoad: 0,
        ullTotalPhys: 0,
        ullAvailPhys: 0,
        ullTotalPageFile: 0,
        ullAvailPageFile: 0,
        ullTotalVirtual: 0,
        ullAvailVirtual: 0,
        ullAvailExtendedVirtual: 0,
    };
    // SAFETY: structure initialisée avec sa taille, appel Win32 standard.
    let ok = unsafe { GlobalMemoryStatusEx(&mut st) };
    (ok != 0).then_some(st.ullTotalPhys / (1024 * 1024))
}

#[cfg(unix)]
fn unix_ram() -> Option<u64> {
    // SAFETY: sysconf sans effet de bord.
    let pages = unsafe { libc::sysconf(libc::_SC_PHYS_PAGES) };
    let page_sz = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if pages <= 0 || page_sz <= 0 {
        return None;
    }
    Some((pages as u64 * page_sz as u64) / (1024 * 1024))
}

/// Type de filesystem du répertoire courant.
fn probe_fs() -> Option<String> {
    let cwd = std::env::current_dir().ok()?;
    #[cfg(windows)]
    {
        windows_fs(&cwd)
    }
    #[cfg(target_os = "linux")]
    {
        linux_fs(&cwd)
    }
    #[cfg(target_os = "macos")]
    {
        macos_fs(&cwd)
    }
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        let _ = cwd;
        None
    }
}

#[cfg(windows)]
fn windows_fs(path: &std::path::Path) -> Option<String> {
    use windows_sys::Win32::Storage::FileSystem::GetVolumeInformationW;

    // Racine du volume ("C:\", "\\?\…", etc.) depuis le préfixe du chemin.
    let root = match path.components().next() {
        Some(std::path::Component::Prefix(p)) => p.as_os_str().to_string_lossy().into_owned(),
        _ => path.to_string_lossy().into_owned(),
    };
    let root = format!("{}\\", root.trim_end_matches(['\\', '/']));
    let wide: Vec<u16> = root.encode_utf16().chain(std::iter::once(0)).collect();

    let mut name_buf = [0u16; 64];
    // SAFETY: buffers valides dimensionnés, appel Win32 lecture seule.
    let ok = unsafe {
        GetVolumeInformationW(
            wide.as_ptr(),
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            name_buf.as_mut_ptr(),
            name_buf.len() as u32,
        )
    };
    if ok == 0 {
        return None;
    }
    let end = name_buf
        .iter()
        .position(|&c| c == 0)
        .unwrap_or(name_buf.len());
    Some(String::from_utf16_lossy(&name_buf[..end]).to_uppercase())
}

#[cfg(target_os = "linux")]
fn linux_fs(path: &std::path::Path) -> Option<String> {
    use std::os::unix::ffi::OsStrExt;
    let c_path = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
    let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
    // SAFETY: statfs remplit la structure pointée.
    if unsafe { libc::statfs(c_path.as_ptr(), &mut stat) } != 0 {
        return None;
    }
    let name = match stat.f_type as u64 {
        0xEF53 => "ext2/3/4",
        0x9123_683E => "btrfs",
        0x5846_5342 => "xfs",
        0x0102_1994 => "tmpfs",
        0x5346_544E => "ntfs",
        0x794C_7630 => "overlayfs",
        0x6573_5546 => "fuse",
        0xA501_FCF5 => "apfs",
        other => return Some(format!("unknown(0x{other:x})")),
    };
    Some(name.to_uppercase())
}

#[cfg(target_os = "macos")]
fn macos_fs(path: &std::path::Path) -> Option<String> {
    use std::os::unix::ffi::OsStrExt;
    let c_path = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
    let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statfs(c_path.as_ptr(), &mut stat) } != 0 {
        return None;
    }
    let end = stat
        .f_fstypename
        .iter()
        .position(|&c| c == 0)
        .unwrap_or(stat.f_fstypename.len());
    Some(
        stat.f_fstypename[..end]
            .iter()
            .map(|&c| c as u8 as char)
            .collect::<String>()
            .to_uppercase(),
    )
}

fn probe_tracer() -> Option<bool> {
    #[cfg(windows)]
    {
        use windows_sys::Win32::System::Diagnostics::Debug::IsDebuggerPresent;
        // SAFETY: appel Win32 sans paramètre.
        Some(unsafe { IsDebuggerPresent() } != 0)
    }
    #[cfg(target_os = "linux")]
    {
        let status = std::fs::read_to_string("/proc/self/status").ok()?;
        let pid: u32 = status
            .lines()
            .find_map(|l| l.strip_prefix("TracerPid:"))
            .and_then(|v| v.trim().parse().ok())?;
        Some(pid != 0)
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        None
    }
}

fn probe_swap() -> Option<bool> {
    #[cfg(target_os = "linux")]
    {
        let swaps = std::fs::read_to_string("/proc/swaps").ok()?;
        Some(swaps.lines().count() > 1)
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}
