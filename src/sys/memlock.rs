//! Verrouillage de mémoire sensible — `mlock` (Unix) / `VirtualLock` (Windows).
//! Probe non destructif d'une page ; le verrouillage des secrets arrive en v0.2.

/// État de capacité du verrouillage mémoire sur l'hôte.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum LockStatus {
    /// Verrouillage d'une page de test réussi.
    Available,
    /// API absente ou refusée (quota, privilèges).
    Unavailable,
}

impl LockStatus {
    pub fn label(self) -> &'static str {
        match self {
            LockStatus::Available => {
                if cfg!(windows) {
                    "VIRTUALLOCK"
                } else {
                    "MLOCK"
                }
            }
            LockStatus::Unavailable => "UNAVAILABLE",
        }
    }

    pub fn ok(self) -> bool {
        matches!(self, LockStatus::Available)
    }
}

/// Tente de verrouiller puis déverrouiller une page de test.
pub fn probe_lock() -> LockStatus {
    #[cfg(windows)]
    {
        probe_windows()
    }
    #[cfg(unix)]
    {
        probe_unix()
    }
    #[cfg(not(any(windows, unix)))]
    {
        LockStatus::Unavailable
    }
}

#[cfg(windows)]
fn probe_windows() -> LockStatus {
    use windows_sys::Win32::System::Memory::{VirtualLock, VirtualUnlock};
    let mut page = [0u8; 4096];
    let ok = unsafe {
        VirtualLock(page.as_mut_ptr().cast(), page.len()) != 0
            && VirtualUnlock(page.as_mut_ptr().cast(), page.len()) != 0
    };
    if ok {
        LockStatus::Available
    } else {
        LockStatus::Unavailable
    }
}

#[cfg(unix)]
fn probe_unix() -> LockStatus {
    let mut page = [0u8; 4096];
    let ok = unsafe {
        libc::mlock(page.as_mut_ptr().cast(), page.len()) == 0
            && libc::munlock(page.as_mut_ptr().cast(), page.len()) == 0
    };
    if ok {
        LockStatus::Available
    } else {
        LockStatus::Unavailable
    }
}
