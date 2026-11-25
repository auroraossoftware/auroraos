//! UID/GID mapping and setgroups denial in rootless user namespaces.

use crate::{LauncherError, CONTAINER_GID, CONTAINER_UID};
use std::fs::OpenOptions;
use std::io::Write;

/// Configures rootless user namespace ID mappings and disables group manipulation.
///
/// Order of operations required by the Linux kernel:
/// 1. Write UID mapping to `/proc/self/uid_map`.
/// 2. Write "deny" to `/proc/self/setgroups` (disables supplementary group elevation).
/// 3. Write GID mapping to `/proc/self/gid_map`.
pub fn configure_idmap(
    host_uid: libc::uid_t,
    host_gid: libc::gid_t,
    target_uid: libc::uid_t,
    target_gid: libc::gid_t,
) -> Result<(), LauncherError> {
    // 1. Write uid_map: "<target_uid> <host_uid> 1\n"
    let mut uid_map = OpenOptions::new()
        .write(true)
        .open("/proc/self/uid_map")
        .map_err(LauncherError::Io)?;
    let uid_line = format!("{target_uid} {host_uid} 1\n");
    uid_map
        .write_all(uid_line.as_bytes())
        .map_err(LauncherError::Io)?;
    drop(uid_map);

    // 2. Write "deny" to /proc/self/setgroups
    let mut setgroups_file = OpenOptions::new()
        .write(true)
        .open("/proc/self/setgroups")
        .map_err(LauncherError::Io)?;
    setgroups_file
        .write_all(b"deny\n")
        .map_err(LauncherError::Io)?;
    drop(setgroups_file);

    // 3. Write gid_map: "<target_gid> <host_gid> 1\n"
    let mut gid_map = OpenOptions::new()
        .write(true)
        .open("/proc/self/gid_map")
        .map_err(LauncherError::Io)?;
    let gid_line = format!("{target_gid} {host_gid} 1\n");
    gid_map
        .write_all(gid_line.as_bytes())
        .map_err(LauncherError::Io)?;
    drop(gid_map);

    Ok(())
}

/// Convenience helper to map current host UID/GID to container UID/GID 1000.
/// Must be passed the host UID and GID captured *prior* to unsharing CLONE_NEWUSER.
pub fn configure_default_idmap(
    host_uid: libc::uid_t,
    host_gid: libc::gid_t,
) -> Result<(), LauncherError> {
    configure_idmap(host_uid, host_gid, CONTAINER_UID, CONTAINER_GID)
}
