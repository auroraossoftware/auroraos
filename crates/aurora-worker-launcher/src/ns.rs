//! Namespace unsharing primitives for rootless sandboxing.

use crate::LauncherError;
use std::ffi::CString;

/// Unshares the user namespace (CLONE_NEWUSER).
pub fn unshare_user_ns() -> Result<(), LauncherError> {
    let ret = unsafe { libc::unshare(libc::CLONE_NEWUSER) };
    if ret != 0 {
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        if errno == libc::EPERM || errno == libc::ENOSYS {
            return Err(LauncherError::UserNsUnsupported);
        }
        return Err(LauncherError::Os("unshare(CLONE_NEWUSER)", errno));
    }
    Ok(())
}

/// Unshares the network namespace (CLONE_NEWNET).
/// Loopback interface `lo` is left DOWN by default.
pub fn unshare_net_ns() -> Result<(), LauncherError> {
    let ret = unsafe { libc::unshare(libc::CLONE_NEWNET) };
    if ret != 0 {
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        return Err(LauncherError::Os("unshare(CLONE_NEWNET)", errno));
    }
    Ok(())
}

/// Unshares the PID namespace (CLONE_NEWPID).
/// The next child created via fork() will become PID 1 in the new namespace.
pub fn unshare_pid_ns() -> Result<(), LauncherError> {
    let ret = unsafe { libc::unshare(libc::CLONE_NEWPID) };
    if ret != 0 {
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        return Err(LauncherError::Os("unshare(CLONE_NEWPID)", errno));
    }
    Ok(())
}

/// Unshares the mount namespace (CLONE_NEWNS) and sets private propagation.
pub fn unshare_mount_ns() -> Result<(), LauncherError> {
    let ret = unsafe { libc::unshare(libc::CLONE_NEWNS) };
    if ret != 0 {
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        return Err(LauncherError::Os("unshare(CLONE_NEWNS)", errno));
    }

    // Set private propagation on root
    let root = CString::new("/").unwrap();
    let ret = unsafe {
        libc::mount(
            std::ptr::null(),
            root.as_ptr(),
            std::ptr::null(),
            libc::MS_REC | libc::MS_PRIVATE,
            std::ptr::null(),
        )
    };
    if ret != 0 {
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        return Err(LauncherError::Os(
            "mount(NULL, '/', MS_REC | MS_PRIVATE)",
            errno,
        ));
    }

    Ok(())
}
