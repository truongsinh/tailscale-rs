//! Detect the free-disk summary for this node, formatted as a `disk=…` token
//! folded into the `HostInfo.ipn_version` (and `app`) reported to control.
//!
//! The admin console surfaces `clientVersion` but not `app`, so folding the
//! disk summary into the version string is the only way an operator can see
//! *how much room a node has* — e.g. catching a fleet box that is about to run
//! out of disk before the updater fails to stage a new binary.
//!
//! Format: `disk=<free%>/<freeGB>` where `<free%>` is the percentage of total
//! bytes that are free (rounded down) and `<freeGB>` is the free bytes divided
//! by 1024³ (rounded to the nearest whole gigabyte). Example: `disk=29%/169GB`.
//!
//! The probe target is platform-specific:
//!
//! - **Windows** always probes `C:\`. Most fleet boxes install under
//!   `C:\Program Files\…` or similar, so `C:` is the disk that matters for
//!   updater staging.
//! - **Unix** probes the filesystem holding the running binary's install dir
//!   (parent of `current_exe()`). That matches where the updater writes the
//!   new binary + rollback stack, so the free figure reflects the disk the
//!   updater actually consumes.
//!
//! Detection is deliberately **fail-open**: it never panics and never blocks
//! startup. If the platform lookup fails for any reason, the token degrades to
//! `disk=unknown` rather than taking the process down.

use std::sync::OnceLock;

/// The cached `disk=…` summary for this process.
///
/// Computed once on first use and memoised for the lifetime of the process;
/// the underlying free space snapshot is taken at startup and intentionally
/// not refreshed — the admin console already polls nodes on an interval, and
/// a fresh probe per MapRequest would add I/O to the hot registration path
/// for no operational benefit (if disk is genuinely low, the updater's own
/// pre-stage check catches it before this value would matter).
pub(crate) fn disk_identity() -> &'static str {
    static CACHE: OnceLock<String> = OnceLock::new();
    CACHE.get_or_init(detect).as_str()
}

#[cfg(unix)]
fn detect() -> String {
    use std::os::unix::ffi::OsStrExt;

    // Probe the filesystem holding the running binary's install dir. The
    // parent of current_exe() matches the default install_dir computed in
    // ssh_shell::main — i.e. the disk the updater actually stages into.
    let target_bytes: Vec<u8> = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|parent| parent.as_os_str().as_bytes().to_vec()))
        .unwrap_or_else(|| b"/".to_vec());

    // `CString::new` fails if the path contains an interior NUL — vanishingly
    // rare for a real install path, but fall back to "/" so we never panic.
    let path = std::ffi::CString::new(target_bytes)
        .unwrap_or_else(|_| std::ffi::CString::new("/").expect("\"/\" has no NUL"));

    // SAFETY: `path` is a NUL-terminated C string pointing to a valid path
    // buffer we own for the duration of the call. `statvfs` writes into a
    // `statvfs` struct on the stack.
    let mut buf = unsafe { std::mem::zeroed::<libc::statvfs>() };
    let rc = unsafe { libc::statvfs(path.as_ptr(), &mut buf) };
    if rc != 0 {
        return "disk=unknown".to_owned();
    }

    // f_bavail = blocks available to unprivileged user (excludes root reserve).
    // f_blocks = total data blocks in the filesystem. f_frsize = fragment size
    // (the true block size for size calculations; f_bsize is for I/O, not totals).
    let block_size = buf.f_frsize.max(1) as u64;
    let free_bytes = buf.f_bavail.saturating_mul(block_size);
    let total_bytes = buf.f_blocks.saturating_mul(block_size);

    format_summary(free_bytes, total_bytes)
}

#[cfg(windows)]
fn detect() -> String {
    use windows::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;
    use windows::core::PCWSTR;

    // Always probe `C:\` on Windows: fleet boxes install under `C:\Program
    // Files\…` (or similar) and the updater stages in the install dir, so the
    // free space on `C:` is the operationally meaningful figure. A multi-disk
    // box with the binary on `D:\` is a deployment we don't ship today; if that
    // changes, switch this to resolve the drive from `current_exe()` like the
    // unix branch does.
    let mut wide: Vec<u16> = "C:\\".encode_utf16().chain(std::iter::once(0)).collect();

    let mut free_to_caller: u64 = 0;
    let mut total_bytes: u64 = 0;
    let mut total_free: u64 = 0;
    // SAFETY: `wide` is a NUL-terminated UTF-16 string. The three out-pointers
    // are valid stack storage for `u64` each.
    let ok = unsafe {
        GetDiskFreeSpaceExW(
            PCWSTR(wide.as_mut_ptr()),
            Some(&mut free_to_caller as *mut u64),
            Some(&mut total_bytes as *mut u64),
            Some(&mut total_free as *mut u64),
        )
        .is_ok()
    };
    if !ok {
        return "disk=unknown".to_owned();
    }

    // `free_to_caller` reflects the user-quota-aware free bytes; `total_free`
    // reflects the real free bytes (ignoring quota). For a fleet service
    // running as SYSTEM (no quota), they are identical. Use `total_free` so
    // the figure is stable regardless of which principal launched the process.
    format_summary(total_free, total_bytes)
}

#[cfg(not(any(unix, windows)))]
fn detect() -> String {
    "disk=unknown".to_owned()
}

/// Format the `disk=<free%>/<freeGB>` token from raw byte counts.
///
/// Returns `disk=unknown` when `total_bytes == 0` (division by zero would
/// otherwise panic).
fn format_summary(free_bytes: u64, total_bytes: u64) -> String {
    const BYTES_PER_GB: u64 = 1024 * 1024 * 1024;

    if total_bytes == 0 {
        return "disk=unknown".to_owned();
    }

    // Free percentage: floor of (free / total * 100), so a disk with 0.9 GB
    // free out of 1 TB reports `0%`, not `1%`. Operators reading the value
    // want to know "is this about to fill up?" — floor is the conservative
    // choice; the absolute GB figure carries the precision.
    let free_pct = (free_bytes as u128 * 100 / total_bytes as u128) as u64;
    let free_gb = free_bytes.div_ceil(BYTES_PER_GB);

    format!("disk={free_pct}%/{free_gb}GB")
}

#[cfg(test)]
mod tests {
    use super::format_summary;

    #[test]
    fn formats_free_fraction_and_absolute_gigabytes() {
        struct Case {
            desc: &'static str,
            free: u64,
            total: u64,
            expected: &'static str,
        }
        let cases = [
            Case {
                desc: "exactly half free rounds to 50%",
                free: 500 * 1024 * 1024 * 1024,
                total: 1024 * 1024 * 1024 * 1024,
                expected: "disk=50%/500GB",
            },
            Case {
                desc: "sub-GB remainder rounds up to 1GB (div_ceil)",
                free: 1024 * 1024 * 1024 + 1,
                total: 10 * 1024 * 1024 * 1024,
                expected: "disk=10%/2GB",
            },
            Case {
                desc: "zero free bytes reports 0%",
                free: 0,
                total: 1024 * 1024 * 1024,
                expected: "disk=0%/0GB",
            },
            Case {
                desc: "free under one GB still rounds up to 1GB",
                free: 1,
                total: 1024 * 1024 * 1024 * 1024,
                expected: "disk=0%/1GB",
            },
        ];
        for case in cases {
            assert_eq!(
                format_summary(case.free, case.total),
                case.expected,
                "{}",
                case.desc,
            );
        }
    }

    #[test]
    fn returns_unknown_when_total_is_zero() {
        assert_eq!(format_summary(0, 0), "disk=unknown");
    }
}
