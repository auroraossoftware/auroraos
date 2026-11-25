//! Strict ordered capability purging and security lock enforcement.

use crate::LauncherError;
use std::fs;

// Linux capability constants
const LINUX_CAPABILITY_VERSION_3: u32 = 0x20080522;
const CAP_SETPCAP: u32 = 8;
const CAP_SYS_CHROOT: u32 = 18;
const CAP_SYS_ADMIN: u32 = 21;

#[repr(C)]
struct CapHeader {
    version: u32,
    pid: i32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

/// Verifies that user-namespace setup capabilities (CAP_SYS_ADMIN, CAP_SYS_CHROOT, CAP_SETPCAP)
/// remain effective before privileged rootfs operations commence.
pub fn verify_setup_capabilities_effective() -> Result<(), LauncherError> {
    let mut hdr = CapHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let mut data = [CapData::default(); 2];

    let ret = unsafe { libc::syscall(libc::SYS_capget, &mut hdr, data.as_mut_ptr()) };
    if ret != 0 {
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        return Err(LauncherError::Os("capget", errno));
    }

    let eff_low = data[0].effective;
    let cap_admin_ok = (eff_low & (1 << CAP_SYS_ADMIN)) != 0;
    let cap_chroot_ok = (eff_low & (1 << CAP_SYS_CHROOT)) != 0;
    let cap_setpcap_ok = (eff_low & (1 << CAP_SETPCAP)) != 0;

    if !cap_admin_ok || !cap_chroot_ok || !cap_setpcap_ok {
        return Err(LauncherError::SetupCapsMissing(format!(
            "Missing required setup capabilities: CAP_SYS_ADMIN={cap_admin_ok}, CAP_SYS_CHROOT={cap_chroot_ok}, CAP_SETPCAP={cap_setpcap_ok} (effective: 0x{eff_low:08x})"
        )));
    }

    Ok(())
}

/// Reads the last valid capability index from `/proc/sys/kernel/cap_last_cap`.
/// Must be called before `pivot_root` + procfs `subset=pid` hides `/proc/sys`.
pub fn get_cap_last_cap() -> u32 {
    if let Ok(content) = fs::read_to_string("/proc/sys/kernel/cap_last_cap") {
        if let Ok(val) = content.trim().parse::<u32>() {
            return val;
        }
    }
    63 // Safe fallback covering all modern 64-bit capability bitmasks
}

/// Purges all 5 capability sets with CAP_SETPCAP retained until bounding set drop is complete.
///
/// Order of operations:
/// 1. Assert CAP_SETPCAP is effective in user namespace.
/// 2. Clear ambient capabilities: `prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0)`.
/// 3. Drop all capabilities from bounding set (0..=cap_last) while CAP_SETPCAP is still effective.
/// 4. Clear permitted, effective, and inheritable sets via `capset()` with zeroed 64-bit masks.
/// 5. Verify all 5 sets are completely zeroed.
pub fn purge_all_capabilities(cap_last: u32) -> Result<(), LauncherError> {
    // 1. Verify CAP_SETPCAP is effective for bounding set modifications
    let mut hdr = CapHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let mut data = [CapData::default(); 2];
    let ret = unsafe { libc::syscall(libc::SYS_capget, &mut hdr, data.as_mut_ptr()) };
    if ret != 0 {
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        return Err(LauncherError::Os("capget", errno));
    }
    if (data[0].effective & (1 << CAP_SETPCAP)) == 0 {
        return Err(LauncherError::CapsPurge(
            "CAP_SETPCAP not effective; cannot drop bounding capability set".to_string(),
        ));
    }

    // 2. Clear ambient capabilities
    let ret = unsafe {
        libc::prctl(
            libc::PR_CAP_AMBIENT,
            libc::PR_CAP_AMBIENT_CLEAR_ALL,
            0,
            0,
            0,
        )
    };
    if ret != 0 {
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        return Err(LauncherError::Os("prctl(PR_CAP_AMBIENT_CLEAR_ALL)", errno));
    }

    // 3. Drop bounding set while retaining CAP_SETPCAP
    for cap in 0..=cap_last {
        let ret = unsafe { libc::prctl(libc::PR_CAPBSET_DROP, cap, 0, 0, 0) };
        if ret != 0 {
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            if errno != libc::EINVAL {
                return Err(LauncherError::Os("prctl(PR_CAPBSET_DROP)", errno));
            }
        }
    }

    // 4. Clear effective, permitted, and inheritable sets via capset
    let zero_data = [CapData::default(); 2];
    let ret = unsafe { libc::syscall(libc::SYS_capset, &hdr, zero_data.as_ptr()) };
    if ret != 0 {
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        return Err(LauncherError::Os("capset(zeroed)", errno));
    }

    // 5. Verification: Check capget returns zeroes
    let mut verify_data = [CapData::default(); 2];
    let ret = unsafe { libc::syscall(libc::SYS_capget, &mut hdr, verify_data.as_mut_ptr()) };
    if ret != 0 {
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        return Err(LauncherError::Os("capget(verify)", errno));
    }

    if verify_data[0].effective != 0
        || verify_data[1].effective != 0
        || verify_data[0].permitted != 0
        || verify_data[1].permitted != 0
        || verify_data[0].inheritable != 0
        || verify_data[1].inheritable != 0
    {
        return Err(LauncherError::CapsPurge(format!(
            "Capability set not zeroed after capset: eff={:08x}{:08x}, prm={:08x}{:08x}, inh={:08x}{:08x}",
            verify_data[1].effective, verify_data[0].effective,
            verify_data[1].permitted, verify_data[0].permitted,
            verify_data[1].inheritable, verify_data[0].inheritable,
        )));
    }

    // Verify bounding set is empty (must return 0, or -1 with EINVAL if beyond kernel max)
    for cap in 0..=cap_last {
        let ret = unsafe { libc::prctl(libc::PR_CAPBSET_READ, cap, 0, 0, 0) };
        if ret == 1 {
            return Err(LauncherError::CapsPurge(format!(
                "Bounding capability {cap} still present after purge"
            )));
        } else if ret < 0 {
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            if errno != libc::EINVAL {
                return Err(LauncherError::Os("prctl(PR_CAPBSET_READ)", errno));
            }
        }
    }

    // Verify ambient set is empty (must return 0, or -1 with EINVAL if beyond kernel max)
    for cap in 0..=cap_last {
        let ret =
            unsafe { libc::prctl(libc::PR_CAP_AMBIENT, libc::PR_CAP_AMBIENT_IS_SET, cap, 0, 0) };
        if ret == 1 {
            return Err(LauncherError::CapsPurge(format!(
                "Ambient capability {cap} still present after purge"
            )));
        } else if ret < 0 {
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            if errno != libc::EINVAL {
                return Err(LauncherError::Os("prctl(PR_CAP_AMBIENT_IS_SET)", errno));
            }
        }
    }

    Ok(())
}

/// Applies privilege lock (`PR_SET_NO_NEW_PRIVS`) and disables memory dumpability (`PR_SET_DUMPABLE(0)`),
/// immediately verifying both settings pre-exec.
///
/// Note: Under Linux `execve()`, executing a regular binary resets `mm->dumpable` to 1;
/// therefore `PR_GET_DUMPABLE == 0` must be verified here pre-exec in Phase 1, and re-applied
/// and re-verified post-exec in Phase 4 bootstrap.
pub fn apply_security_locks() -> Result<(), LauncherError> {
    // 1. Permanent privilege escalation block
    let ret = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if ret != 0 {
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        return Err(LauncherError::Os("prctl(PR_SET_NO_NEW_PRIVS)", errno));
    }

    let nnp = unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) };
    if nnp != 1 {
        return Err(LauncherError::SecurityLock(format!(
            "PR_GET_NO_NEW_PRIVS returned {nnp}, expected 1"
        )));
    }

    // 2. Disable dumpability (prevents same-UID ptrace attachment and core dump leaks pre-exec)
    let ret = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };
    if ret != 0 {
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        return Err(LauncherError::Os("prctl(PR_SET_DUMPABLE, 0)", errno));
    }

    let dumpable = unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) };
    if dumpable != 0 {
        return Err(LauncherError::SecurityLock(format!(
            "PR_GET_DUMPABLE returned {dumpable} after PR_SET_DUMPABLE(0), expected 0"
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pre_exec_security_locks_verified_in_forked_child() {
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed");
        if pid == 0 {
            if let Err(e) = apply_security_locks() {
                eprintln!("apply_security_locks failed: {e}");
                unsafe { libc::_exit(1) };
            }
            let dumpable = unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) };
            let nnp = unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) };
            if dumpable == 0 && nnp == 1 {
                unsafe { libc::_exit(0) };
            }
            unsafe { libc::_exit(2) };
        } else {
            let mut status: libc::c_int = 0;
            let res = unsafe { libc::waitpid(pid, &mut status, 0) };
            assert_eq!(res, pid);
            assert!(libc::WIFEXITED(status));
            assert_eq!(libc::WEXITSTATUS(status), 0);
        }
    }
}
