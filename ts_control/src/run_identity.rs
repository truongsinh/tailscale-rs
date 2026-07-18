//! Detect the identity this node runs as, formatted as a `run=…` token folded into the
//! `HostInfo.ipn_version` (and `app`) reported to control.
//!
//! The admin console surfaces `clientVersion` but not `app`, so folding the identity into
//! the version string is the only way an operator can see *who* a node is running as —
//! e.g. distinguishing a `run=SYSTEM` service from a `run=user:sinh` foreground session.
//!
//! Detection is deliberately **fail-open**: it never panics and never blocks startup. If
//! the platform lookup fails for any reason, the token degrades to `run=user:<uid>` (unix)
//! or `run=unknown` (windows / other) rather than taking the process down.

use std::sync::OnceLock;

/// The cached `run=…` identity token for this process.
///
/// Computed once on first use and memoised for the lifetime of the process; the underlying
/// identity cannot change without a re-exec, so caching is safe.
pub(crate) fn run_identity() -> &'static str {
    static CACHE: OnceLock<String> = OnceLock::new();
    CACHE.get_or_init(detect).as_str()
}

#[cfg(unix)]
fn detect() -> String {
    let uid = nix::unistd::geteuid();
    let name = nix::unistd::User::from_uid(uid)
        .ok()
        .flatten()
        .map(|user| user.name)
        .unwrap_or_default();

    format_unix(uid.as_raw() as u32, &name)
}

#[cfg(windows)]
fn detect() -> String {
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::Security::{
        GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    use windows::Win32::System::WindowsProgramming::GetUserNameW;
    use windows::core::PWSTR;

    // Resolve the principal (account) name via GetUserNameW. The first call, with a null
    // buffer, fails and reports the required size in `size`; the second call fills the buffer.
    let name = unsafe {
        let mut size: u32 = 0;
        // Intentionally ignore the "insufficient buffer" error from the sizing call (null
        // buffer -> the required length is written back into `size`).
        let _ = GetUserNameW(None, &mut size).ok();
        if size == 0 {
            String::new()
        } else {
            let mut buf = vec![0u16; size as usize];
            match GetUserNameW(Some(PWSTR(buf.as_mut_ptr())), &mut size) {
                // `size` now counts the characters written, including the trailing NUL.
                Ok(()) => String::from_utf16_lossy(&buf[..size.saturating_sub(1) as usize]),
                Err(_) => String::new(),
            }
        }
    };

    // Resolve elevation via the process token's TokenElevation info class.
    let elevated = unsafe {
        let mut token = HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_ok() {
            let mut elevation = TOKEN_ELEVATION::default();
            let mut ret_len: u32 = 0;
            let result = GetTokenInformation(
                token,
                TokenElevation,
                Some(&mut elevation as *mut TOKEN_ELEVATION as *mut core::ffi::c_void),
                core::mem::size_of::<TOKEN_ELEVATION>() as u32,
                &mut ret_len,
            );
            let _ = CloseHandle(token).ok();
            match result {
                Ok(()) => Some(elevation.TokenIsElevated != 0),
                Err(_) => None,
            }
        } else {
            None
        }
    };

    format_windows(&name, elevated)
}

#[cfg(not(any(unix, windows)))]
fn detect() -> String {
    "run=unknown".to_owned()
}

/// Format a unix `run=…` token from an effective uid and (possibly empty) account name.
///
/// root (uid 0) is reported as `run=root`; a resolvable name as `run=user:<name>`; and a
/// bare uid with no name as `run=user:<uid>`.
#[cfg(any(unix, test))]
fn format_unix(uid: u32, name: &str) -> String {
    if uid == 0 {
        "run=root".to_owned()
    } else if !name.is_empty() {
        format!("run=user:{name}")
    } else {
        format!("run=user:{uid}")
    }
}

/// Format a windows `run=…` token from an account name and optional elevation state.
///
/// The `LocalSystem` principal is reported as `run=SYSTEM`; an elevated named user as
/// `run=admin:<name>`; any other named user as `run=user:<name>`; and an unresolvable
/// identity as `run=unknown`.
#[cfg(any(windows, test))]
fn format_windows(name: &str, elevated: Option<bool>) -> String {
    if name.eq_ignore_ascii_case("SYSTEM") {
        "run=SYSTEM".to_owned()
    } else if !name.is_empty() && elevated == Some(true) {
        format!("run=admin:{name}")
    } else if !name.is_empty() {
        format!("run=user:{name}")
    } else {
        "run=unknown".to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::{format_unix, format_windows};

    #[test]
    fn unix_identity_reflects_uid_and_name() {
        struct Case {
            desc: &'static str,
            uid: u32,
            name: &'static str,
            expected: &'static str,
        }
        let cases = [
            Case {
                desc: "root reports run=root regardless of name",
                uid: 0,
                name: "root",
                expected: "run=root",
            },
            Case {
                desc: "a named non-root user reports run=user:<name>",
                uid: 1000,
                name: "sinh",
                expected: "run=user:sinh",
            },
            Case {
                desc: "a non-root user with no resolvable name falls back to the uid",
                uid: 1000,
                name: "",
                expected: "run=user:1000",
            },
        ];

        for case in cases {
            assert_eq!(format_unix(case.uid, case.name), case.expected, "{}", case.desc);
        }
    }

    #[test]
    fn windows_identity_reflects_principal_and_elevation() {
        struct Case {
            desc: &'static str,
            name: &'static str,
            elevated: Option<bool>,
            expected: &'static str,
        }
        let cases = [
            Case {
                desc: "the LocalSystem principal reports run=SYSTEM (case-insensitive)",
                name: "system",
                elevated: Some(false),
                expected: "run=SYSTEM",
            },
            Case {
                desc: "an elevated named user reports run=admin:<name>",
                name: "Administrator",
                elevated: Some(true),
                expected: "run=admin:Administrator",
            },
            Case {
                desc: "a non-elevated named user reports run=user:<name>",
                name: "sinh",
                elevated: Some(false),
                expected: "run=user:sinh",
            },
            Case {
                desc: "an unknown elevation for a named user reports run=user:<name>",
                name: "sinh",
                elevated: None,
                expected: "run=user:sinh",
            },
            Case {
                desc: "an unresolvable identity reports run=unknown",
                name: "",
                elevated: None,
                expected: "run=unknown",
            },
        ];

        for case in cases {
            assert_eq!(
                format_windows(case.name, case.elevated),
                case.expected,
                "{}",
                case.desc
            );
        }
    }
}
