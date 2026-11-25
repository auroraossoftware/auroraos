//! Minimal root filesystem construction, read-only bind mounts, procfs subset=pid, and atomic pivot_root.

use crate::LauncherError;
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{CStr, CString, OsString};
use std::fs;
use std::mem;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};

#[repr(C)]
struct MountAttr {
    attr_set: u64,
    attr_clr: u64,
    propagation: u64,
    userns_fd: u64,
}

const SYS_MOUNT_SETATTR: libc::c_long = 442;
const MOUNT_ATTR_RDONLY: u64 = 0x0000_0001;
const MOUNT_ATTR_NOSUID: u64 = 0x0000_0002;
const MOUNT_ATTR_NODEV: u64 = 0x0000_0004;
const AT_RECURSIVE: libc::c_int = 0x8000;

const MS_NOSYMFOLLOW_FLAG: libc::c_ulong = 256;
const MS_NOATIME_FLAG: libc::c_ulong = 1024;
const MS_NODIRATIME_FLAG: libc::c_ulong = 2048;
const MS_RELATIME_FLAG: libc::c_ulong = 1 << 21;
const MS_STRICTATIME_FLAG: libc::c_ulong = 1 << 24;

const ST_NOEXEC_FLAG: libc::c_ulong = 8;
const ST_NOSYMFOLLOW_FLAG: libc::c_ulong = 8192;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AtimeMode {
    Relatime,
    Noatime,
    Strict,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SuperblockOptions {
    pub raw: String,
    pub synchronous: bool,
    pub dirsync: bool,
    pub mandlock: bool,
    pub lazytime: bool,
}

impl SuperblockOptions {
    /// Parses superblock options from `/proc/self/mountinfo` after the ` - ` separator
    /// (tracking `sync`, `dirsync`, `mand`, `lazytime` separately from Field 6 per-mount flags).
    pub fn parse(raw: &str) -> Self {
        let mut synchronous = false;
        let mut dirsync = false;
        let mut mandlock = false;
        let mut lazytime = false;
        for token in raw.split(',') {
            match token {
                "sync" => synchronous = true,
                "dirsync" => dirsync = true,
                "mand" => mandlock = true,
                "lazytime" => lazytime = true,
                _ => {}
            }
        }
        Self {
            raw: raw.to_string(),
            synchronous,
            dirsync,
            mandlock,
            lazytime,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MountOptions {
    pub read_only: bool,
    pub nosuid: bool,
    pub nodev: bool,
    pub noexec: bool,
    pub nodiratime: bool,
    pub nosymfollow: bool,
    pub atime: AtimeMode,
}

impl MountOptions {
    /// Parses per-mount options from `/proc/self/mountinfo` Field 6.
    /// Rejects superblock-only or unknown/unpreservable options (such as `idmapped`).
    pub fn parse(raw: &str, mount_point: &Path) -> Result<Self, LauncherError> {
        let mut opts = Self {
            read_only: false,
            nosuid: false,
            nodev: false,
            noexec: false,
            nodiratime: false,
            nosymfollow: false,
            atime: AtimeMode::Strict,
        };
        let mut seen_rw_or_ro = false;
        let mut seen_atime: Option<AtimeMode> = None;

        for token in raw.split(',') {
            if token.is_empty() {
                return Err(LauncherError::RootfsAssembly(format!(
                    "Empty mount option token on {}",
                    mount_point.display()
                )));
            }
            match token {
                "ro" => {
                    opts.read_only = true;
                    seen_rw_or_ro = true;
                }
                "rw" => {
                    opts.read_only = false;
                    seen_rw_or_ro = true;
                }
                "nosuid" => opts.nosuid = true,
                "nodev" => opts.nodev = true,
                "noexec" => opts.noexec = true,
                "nodiratime" => opts.nodiratime = true,
                "nosymfollow" => opts.nosymfollow = true,
                "relatime" => {
                    if let Some(prev) = seen_atime {
                        if prev != AtimeMode::Relatime {
                            return Err(LauncherError::RootfsAssembly(format!(
                                "Conflicting atime options on {}",
                                mount_point.display()
                            )));
                        }
                    }
                    seen_atime = Some(AtimeMode::Relatime);
                    opts.atime = AtimeMode::Relatime;
                }
                "noatime" => {
                    if let Some(prev) = seen_atime {
                        if prev != AtimeMode::Noatime {
                            return Err(LauncherError::RootfsAssembly(format!(
                                "Conflicting atime options on {}",
                                mount_point.display()
                            )));
                        }
                    }
                    seen_atime = Some(AtimeMode::Noatime);
                    opts.atime = AtimeMode::Noatime;
                }
                "strictatime" => {
                    if let Some(prev) = seen_atime {
                        if prev != AtimeMode::Strict {
                            return Err(LauncherError::RootfsAssembly(format!(
                                "Conflicting atime options on {}",
                                mount_point.display()
                            )));
                        }
                    }
                    seen_atime = Some(AtimeMode::Strict);
                    opts.atime = AtimeMode::Strict;
                }
                other => {
                    return Err(LauncherError::RootfsAssembly(format!(
                        "Unknown or unpreservable mount option '{other}' on {}",
                        mount_point.display()
                    )));
                }
            }
        }

        if !seen_rw_or_ro {
            return Err(LauncherError::RootfsAssembly(format!(
                "Mountinfo options missing ro/rw on {}: '{raw}'",
                mount_point.display()
            )));
        }

        Ok(opts)
    }

    /// Builds `MS_BIND | MS_REMOUNT` flags enforcing read-only and `nosuid` (and `MS_NODEV`
    /// when `enforce_nodev` is true) while preserving all existing non-conflicting per-mount
    /// attributes. Never includes superblock flags or `MS_REC`.
    pub fn to_remount_flags(&self, enforce_nodev: bool) -> libc::c_ulong {
        let mut flags = libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY | libc::MS_NOSUID;
        if enforce_nodev {
            flags |= libc::MS_NODEV;
        }
        if self.noexec {
            flags |= libc::MS_NOEXEC;
        }
        if self.nodiratime {
            flags |= MS_NODIRATIME_FLAG;
        }
        if self.nosymfollow {
            flags |= MS_NOSYMFOLLOW_FLAG;
        }
        flags |= match self.atime {
            AtimeMode::Relatime => MS_RELATIME_FLAG,
            AtimeMode::Noatime => MS_NOATIME_FLAG,
            AtimeMode::Strict => MS_STRICTATIME_FLAG,
        };
        flags
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MountInfoEntry {
    pub mount_id: u64,
    pub parent_id: u64,
    pub mount_point: PathBuf,
    pub options: MountOptions,
    pub super_options: SuperblockOptions,
    pub fs_type: String,
}

/// Decodes `/proc/self/mountinfo` octal path escapes (such as `\040`, `\011`, `\012`, `\134`).
pub fn decode_mountinfo_path(raw: &str) -> Result<PathBuf, LauncherError> {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' {
            if i + 3 >= bytes.len() {
                return Err(LauncherError::RootfsAssembly(format!(
                    "Truncated octal escape in mountinfo path '{raw}'"
                )));
            }
            let d0 = bytes[i + 1];
            let d1 = bytes[i + 2];
            let d2 = bytes[i + 3];
            if !(b'0'..=b'7').contains(&d0)
                || !(b'0'..=b'7').contains(&d1)
                || !(b'0'..=b'7').contains(&d2)
            {
                return Err(LauncherError::RootfsAssembly(format!(
                    "Invalid octal escape in mountinfo path '{raw}'"
                )));
            }
            let decoded = (d0 - b'0') * 64 + (d1 - b'0') * 8 + (d2 - b'0');
            if decoded == 0 {
                return Err(LauncherError::RootfsAssembly(format!(
                    "Interior NUL byte decoded in mountinfo path '{raw}'"
                )));
            }
            out.push(decoded);
            i += 4;
        } else {
            if bytes[i] == 0 {
                return Err(LauncherError::RootfsAssembly(format!(
                    "Interior NUL byte in mountinfo path '{raw}'"
                )));
            }
            out.push(bytes[i]);
            i += 1;
        }
    }
    Ok(PathBuf::from(OsString::from_vec(out)))
}

/// Parses complete `/proc/self/mountinfo` contents, failing closed on any malformed entry
/// or unrecognized per-mount option.
pub fn parse_mountinfo(content: &str) -> Result<Vec<MountInfoEntry>, LauncherError> {
    let mut entries = Vec::new();
    for line in content.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let (left, right) = line.split_once(" - ").ok_or_else(|| {
            LauncherError::RootfsAssembly(format!("Malformed mountinfo line: '{line}'"))
        })?;
        let pre: Vec<&str> = left.split(' ').collect();
        let post: Vec<&str> = right.split(' ').collect();
        if pre.len() < 6 || post.len() < 3 || post[0].is_empty() {
            return Err(LauncherError::RootfsAssembly(format!(
                "Incomplete mountinfo fields in line: '{line}'"
            )));
        }
        let mount_id = pre[0].parse::<u64>().map_err(|_| {
            LauncherError::RootfsAssembly(format!("Invalid mount_id '{}' in mountinfo", pre[0]))
        })?;
        let parent_id = pre[1].parse::<u64>().map_err(|_| {
            LauncherError::RootfsAssembly(format!("Invalid parent_id '{}' in mountinfo", pre[1]))
        })?;
        let mount_point = decode_mountinfo_path(pre[4])?;
        let options = MountOptions::parse(pre[5], &mount_point)?;
        let super_options = SuperblockOptions::parse(post[2]);
        entries.push(MountInfoEntry {
            mount_id,
            parent_id,
            mount_point,
            options,
            super_options,
            fs_type: post[0].to_string(),
        });
    }
    Ok(entries)
}

fn strip_trailing_slash(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for comp in path.components() {
        normalized.push(comp);
    }
    normalized
}

/// Enumerates all mounts within `target` (matching path component boundaries via `Path::starts_with`),
/// verifying `target` itself exists and detecting duplicate/stacked mountpoints.
pub fn enumerate_subtree_mounts(
    entries: &[MountInfoEntry],
    target: &Path,
    recursive: bool,
) -> Result<Vec<MountInfoEntry>, LauncherError> {
    let norm_target = strip_trailing_slash(target);
    let mut subtree = Vec::new();
    let mut seen_paths = BTreeSet::new();
    let mut seen_root = false;

    for entry in entries {
        let norm_mp = strip_trailing_slash(&entry.mount_point);
        let in_subtree = if norm_mp == norm_target {
            seen_root = true;
            true
        } else {
            recursive && norm_mp.starts_with(&norm_target)
        };

        if in_subtree {
            if !seen_paths.insert(norm_mp.clone()) {
                return Err(LauncherError::RootfsAssembly(format!(
                    "Ambiguous stacked or duplicate mountpoint detected at {}",
                    norm_mp.display()
                )));
            }
            let mut normalized = entry.clone();
            normalized.mount_point = norm_mp;
            subtree.push(normalized);
        }
    }

    if !seen_root || subtree.is_empty() {
        return Err(LauncherError::RootfsAssembly(format!(
            "Target mountpoint {} not found in /proc/self/mountinfo",
            norm_target.display()
        )));
    }

    Ok(subtree)
}

/// Abstraction over kernel mount syscalls and verification checks to allow deterministic unit
/// testing of error injection, mount-tree mutation, and fallback paths alongside real execution.
pub trait MountOps {
    fn read_mountinfo(&self) -> Result<String, LauncherError>;
    fn mount_setattr_ro(
        &self,
        target: &Path,
        recursive: bool,
        nodev: bool,
    ) -> Result<(), (i32, String)>;
    fn remount_bind_single(&self, target: &Path, flags: libc::c_ulong)
        -> Result<(), LauncherError>;
    fn verify_statvfs(
        &self,
        target: &Path,
        expect_nodev: bool,
        expect_noexec: bool,
        expect_nosymfollow: bool,
    ) -> Result<(), LauncherError>;
    fn verify_write_rejected(&self, target: &Path) -> Result<(), LauncherError>;
}

pub struct RealMountOps;

impl MountOps for RealMountOps {
    fn read_mountinfo(&self) -> Result<String, LauncherError> {
        fs::read_to_string("/proc/self/mountinfo").map_err(|e| {
            LauncherError::RootfsAssembly(format!("Failed to read /proc/self/mountinfo: {e}"))
        })
    }

    fn mount_setattr_ro(
        &self,
        target: &Path,
        recursive: bool,
        nodev: bool,
    ) -> Result<(), (i32, String)> {
        let target_c = path_to_cstring(target).map_err(|e| (libc::EINVAL, e.to_string()))?;
        let mut attr_set = MOUNT_ATTR_RDONLY | MOUNT_ATTR_NOSUID;
        if nodev {
            attr_set |= MOUNT_ATTR_NODEV;
        }
        let attr = MountAttr {
            attr_set,
            attr_clr: 0,
            propagation: 0,
            userns_fd: 0,
        };
        let flags = if recursive { AT_RECURSIVE } else { 0 };
        let ret = unsafe {
            libc::syscall(
                SYS_MOUNT_SETATTR,
                libc::AT_FDCWD,
                target_c.as_ptr(),
                flags as libc::c_uint,
                &attr as *const MountAttr,
                mem::size_of::<MountAttr>(),
            )
        };
        if ret == 0 {
            return Ok(());
        }
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        Err((
            errno,
            format!("mount_setattr({}) failed: errno {errno}", target.display()),
        ))
    }

    fn remount_bind_single(
        &self,
        target: &Path,
        flags: libc::c_ulong,
    ) -> Result<(), LauncherError> {
        let target_c = path_to_cstring(target)?;
        let ret = unsafe {
            libc::mount(
                std::ptr::null(),
                target_c.as_ptr(),
                std::ptr::null(),
                flags,
                std::ptr::null(),
            )
        };
        if ret != 0 {
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            return Err(LauncherError::RootfsAssembly(format!(
                "Read-only remount of {} failed (flags 0x{flags:x}): errno {errno}",
                target.display()
            )));
        }
        Ok(())
    }

    fn verify_statvfs(
        &self,
        target: &Path,
        expect_nodev: bool,
        expect_noexec: bool,
        expect_nosymfollow: bool,
    ) -> Result<(), LauncherError> {
        verify_mount_flags(
            target,
            true,
            true,
            expect_nodev,
            expect_noexec,
            expect_nosymfollow,
        )
    }

    fn verify_write_rejected(&self, target: &Path) -> Result<(), LauncherError> {
        if target.is_dir() {
            let probe_file = target.join(".probe_ro_check");
            let probe_c = path_to_cstring(&probe_file)?;
            let fd = unsafe {
                libc::open(
                    probe_c.as_ptr(),
                    libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC,
                    0o644,
                )
            };
            if fd >= 0 {
                unsafe {
                    libc::close(fd);
                    libc::unlink(probe_c.as_ptr());
                }
                return Err(LauncherError::RootfsAssembly(format!(
                    "Write succeeded on supposedly read-only directory mount at {}",
                    target.display()
                )));
            }
        } else {
            let target_c = path_to_cstring(target)?;
            let fd = unsafe { libc::open(target_c.as_ptr(), libc::O_WRONLY | libc::O_NONBLOCK) };
            if fd >= 0 {
                unsafe { libc::close(fd) };
                return Err(LauncherError::RootfsAssembly(format!(
                    "Write open succeeded on supposedly read-only mount at {}",
                    target.display()
                )));
            }
        }
        Ok(())
    }
}

fn path_to_cstring(path: &Path) -> Result<CString, LauncherError> {
    let s = path.to_str().ok_or_else(|| {
        LauncherError::RootfsAssembly(format!("Non-UTF-8 path: {}", path.display()))
    })?;
    CString::new(s).map_err(|_| {
        LauncherError::RootfsAssembly(format!("Path contains interior NUL: {}", path.display()))
    })
}

fn should_fallback_from_mount_setattr(errno: i32) -> bool {
    errno == libc::ENOSYS || errno == libc::EOPNOTSUPP
}

/// Applies read-only, `nosuid`, and optional `nodev` across `target` (and all descendant mounts
/// when `recursive` is true), either via `mount_setattr(AT_RECURSIVE)` or via per-mount
/// enumeration and individual remounting without `MS_REC`, then re-reads `/proc/self/mountinfo`
/// and verifies every mount in the subtree.
pub fn apply_ro_bind_subtree(
    ops: &dyn MountOps,
    target: &Path,
    recursive: bool,
    nodev: bool,
    write_check: bool,
    force_fallback: bool,
) -> Result<(), LauncherError> {
    let pre_raw = ops.read_mountinfo()?;
    let pre_entries = parse_mountinfo(&pre_raw)?;
    let pre_subtree = enumerate_subtree_mounts(&pre_entries, target, recursive)?;

    let mut run_fallback = force_fallback;
    if !force_fallback {
        if let Err((errno, msg)) = ops.mount_setattr_ro(target, recursive, nodev) {
            if should_fallback_from_mount_setattr(errno) {
                run_fallback = true;
            } else {
                return Err(LauncherError::RootfsAssembly(msg));
            }
        }
    }

    if run_fallback {
        for mount in &pre_subtree {
            let remount_flags = mount.options.to_remount_flags(nodev);
            ops.remount_bind_single(&mount.mount_point, remount_flags)?;
        }
    }

    let post_raw = ops.read_mountinfo()?;
    let post_entries = parse_mountinfo(&post_raw)?;
    let post_subtree = enumerate_subtree_mounts(&post_entries, target, recursive)?;

    if pre_subtree.len() != post_subtree.len() {
        return Err(LauncherError::RootfsAssembly(format!(
            "Mount-tree changed under {} during read-only enforcement (pre={}, post={})",
            target.display(),
            pre_subtree.len(),
            post_subtree.len()
        )));
    }

    let post_by_id: BTreeMap<u64, &MountInfoEntry> =
        post_subtree.iter().map(|m| (m.mount_id, m)).collect();

    for pre in &pre_subtree {
        let Some(post) = post_by_id.get(&pre.mount_id) else {
            return Err(LauncherError::RootfsAssembly(format!(
                "Mount ID {} ({}) missing from post-modification mountinfo",
                pre.mount_id,
                pre.mount_point.display()
            )));
        };

        if post.parent_id != pre.parent_id || post.mount_point != pre.mount_point {
            return Err(LauncherError::RootfsAssembly(format!(
                "Mount ID {} topology changed under {}: pre=({}, {}), post=({}, {})",
                pre.mount_id,
                target.display(),
                pre.parent_id,
                pre.mount_point.display(),
                post.parent_id,
                post.mount_point.display()
            )));
        }

        if !post.options.read_only
            || !post.options.nosuid
            || post.options.nodev != nodev
            || post.options.noexec != pre.options.noexec
            || post.options.nosymfollow != pre.options.nosymfollow
            || post.options.nodiratime != pre.options.nodiratime
            || post.options.atime != pre.options.atime
        {
            return Err(LauncherError::RootfsAssembly(format!(
                "Post-modification mount flags mismatch on {} (pre={:?}, post={:?}, expected_nodev={nodev})",
                post.mount_point.display(),
                pre.options,
                post.options
            )));
        }

        if post.super_options != pre.super_options {
            return Err(LauncherError::RootfsAssembly(format!(
                "Superblock options changed unexpectedly on {} (pre='{}', post='{}')",
                post.mount_point.display(),
                pre.super_options.raw,
                post.super_options.raw
            )));
        }

        ops.verify_statvfs(
            &post.mount_point,
            nodev,
            post.options.noexec,
            post.options.nosymfollow,
        )?;
        if write_check {
            ops.verify_write_rejected(&post.mount_point)?;
        }
    }

    Ok(())
}

/// Sets a mount (and subtree when `recursive`) read-only and verifies all resulting mounts.
fn set_mount_readonly(
    target: &Path,
    recursive: bool,
    nodev: bool,
    write_check: bool,
    force_fallback: bool,
) -> Result<(), LauncherError> {
    apply_ro_bind_subtree(
        &RealMountOps,
        target,
        recursive,
        nodev,
        write_check,
        force_fallback,
    )
}

/// Verifies mount flags via `statvfs` (`ST_RDONLY`, `ST_NOSUID`, `ST_NODEV`, `ST_NOEXEC`, `ST_NOSYMFOLLOW`).
fn verify_mount_flags(
    target: &Path,
    expect_ro: bool,
    expect_nosuid: bool,
    expect_nodev: bool,
    expect_noexec: bool,
    expect_nosymfollow: bool,
) -> Result<(), LauncherError> {
    let target_c = path_to_cstring(target)?;
    let mut st: libc::statvfs = unsafe { mem::zeroed() };
    let ret = unsafe { libc::statvfs(target_c.as_ptr(), &mut st) };
    if ret != 0 {
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        return Err(LauncherError::Os("statvfs", errno));
    }

    if expect_ro && (st.f_flag & libc::ST_RDONLY as libc::c_ulong) == 0 {
        return Err(LauncherError::RootfsAssembly(format!(
            "Mount at {} missing ST_RDONLY (flags: 0x{:x})",
            target.display(),
            st.f_flag
        )));
    }
    if expect_nosuid && (st.f_flag & libc::ST_NOSUID as libc::c_ulong) == 0 {
        return Err(LauncherError::RootfsAssembly(format!(
            "Mount at {} missing ST_NOSUID (flags: 0x{:x})",
            target.display(),
            st.f_flag
        )));
    }
    if expect_nodev && (st.f_flag & libc::ST_NODEV as libc::c_ulong) == 0 {
        return Err(LauncherError::RootfsAssembly(format!(
            "Mount at {} missing ST_NODEV (flags: 0x{:x})",
            target.display(),
            st.f_flag
        )));
    }
    if !expect_nodev && (st.f_flag & libc::ST_NODEV as libc::c_ulong) != 0 {
        return Err(LauncherError::RootfsAssembly(format!(
            "Mount at {} unexpectedly has ST_NODEV set (flags: 0x{:x})",
            target.display(),
            st.f_flag
        )));
    }
    if expect_noexec && (st.f_flag & ST_NOEXEC_FLAG) == 0 {
        return Err(LauncherError::RootfsAssembly(format!(
            "Mount at {} missing ST_NOEXEC (flags: 0x{:x})",
            target.display(),
            st.f_flag
        )));
    }
    if expect_nosymfollow && (st.f_flag & ST_NOSYMFOLLOW_FLAG) == 0 {
        return Err(LauncherError::RootfsAssembly(format!(
            "Mount at {} missing ST_NOSYMFOLLOW (flags: 0x{:x})",
            target.display(),
            st.f_flag
        )));
    }

    Ok(())
}

/// Mounts a host directory read-only at `dst` and validates every mount in the resulting subtree.
fn mount_bind_readonly(src: &Path, dst: &Path, force_fallback: bool) -> Result<(), LauncherError> {
    let src_c = path_to_cstring(src)?;
    let dst_c = path_to_cstring(dst)?;

    // 1. Initial recursive bind mount
    let ret = unsafe {
        libc::mount(
            src_c.as_ptr(),
            dst_c.as_ptr(),
            std::ptr::null(),
            libc::MS_BIND | libc::MS_REC,
            std::ptr::null(),
        )
    };
    if ret != 0 {
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        return Err(LauncherError::RootfsAssembly(format!(
            "Initial bind mount of {} -> {} failed: errno {errno}",
            src.display(),
            dst.display()
        )));
    }

    // 2. Enforce and verify ro, nosuid, nodev across entire bound subtree
    set_mount_readonly(dst, true, true, true, force_fallback)
}

/// Creates a unique temporary directory under /tmp using mkdtemp.
pub fn create_unique_sandbox_root() -> Result<PathBuf, LauncherError> {
    let template = CString::new("/tmp/aurora_root_XXXXXX")
        .map_err(|e| LauncherError::RootfsAssembly(e.to_string()))?;
    let raw = template.into_raw();
    let ptr = unsafe { libc::mkdtemp(raw) };
    if ptr.is_null() {
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        unsafe { drop(CString::from_raw(raw)) };
        return Err(LauncherError::Os("mkdtemp", errno));
    }
    let cstr = unsafe { CStr::from_ptr(ptr) };
    let path_str = cstr
        .to_str()
        .map_err(|e| LauncherError::RootfsAssembly(e.to_string()))?;
    let path = PathBuf::from(path_str);
    unsafe {
        drop(CString::from_raw(raw));
    }
    Ok(path)
}

/// Assembles the minimal root filesystem with default fallback selection.
pub fn construct_and_pivot_rootfs(
    strict_mode: bool,
    sandbox_path: &Path,
    app_dir: Option<&Path>,
    probe_exe: Option<&Path>,
) -> Result<(), LauncherError> {
    construct_and_pivot_rootfs_with_options(strict_mode, sandbox_path, app_dir, probe_exe, false)
}

/// Assembles the minimal root filesystem, procfs, minimal /dev, private /tmp,
/// executes pivot_root, detaches the old root, and purges setup file descriptors >= 10.
pub fn construct_and_pivot_rootfs_with_options(
    strict_mode: bool,
    sandbox_path: &Path,
    app_dir: Option<&Path>,
    probe_exe: Option<&Path>,
    force_mount_fallback: bool,
) -> Result<(), LauncherError> {
    // 1. Ensure private mount propagation on "/"
    let slash = CString::new("/").map_err(|e| LauncherError::RootfsAssembly(e.to_string()))?;
    let ret = unsafe {
        libc::mount(
            std::ptr::null(),
            slash.as_ptr(),
            std::ptr::null(),
            libc::MS_REC | libc::MS_PRIVATE,
            std::ptr::null(),
        )
    };
    if ret != 0 {
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        return Err(LauncherError::RootfsAssembly(format!(
            "mount(NULL, '/', MS_REC | MS_PRIVATE) failed: errno {errno}"
        )));
    }

    // 2. Mount tmpfs on sandbox root (size=64M, mode=0755, nosuid, nodev)
    let root_c = path_to_cstring(sandbox_path)?;
    let tmpfs_c =
        CString::new("tmpfs").map_err(|e| LauncherError::RootfsAssembly(e.to_string()))?;
    let root_opts = CString::new("size=64M,mode=0755")
        .map_err(|e| LauncherError::RootfsAssembly(e.to_string()))?;
    let ret = unsafe {
        libc::mount(
            tmpfs_c.as_ptr(),
            root_c.as_ptr(),
            tmpfs_c.as_ptr(),
            libc::MS_NODEV | libc::MS_NOSUID,
            root_opts.as_ptr() as *const libc::c_void,
        )
    };
    if ret != 0 {
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        return Err(LauncherError::RootfsAssembly(format!(
            "Mount tmpfs on sandbox root failed: errno {errno}"
        )));
    }
    verify_mount_flags(sandbox_path, false, true, true, false, false)?;

    // 3. Create approved directory skeleton
    for dir in &["usr", "dev", "proc", "tmp", "app", "put_old"] {
        fs::create_dir_all(sandbox_path.join(dir)).map_err(LauncherError::Io)?;
    }

    // 4. Bind-mount /usr read-only
    let host_usr = Path::new("/usr");
    if !host_usr.exists() {
        return Err(LauncherError::RootfsAssembly(
            "Host /usr directory does not exist".to_string(),
        ));
    }
    mount_bind_readonly(host_usr, &sandbox_path.join("usr"), force_mount_fallback)?;

    // Handle /bin, /lib, /lib64 (symlinks on merged-usr hosts, read-only bind mounts otherwise)
    for link_name in &["bin", "lib", "lib64"] {
        let host_p = Path::new("/").join(link_name);
        let target_p = sandbox_path.join(link_name);
        if host_p.is_symlink() {
            let dest = fs::read_link(&host_p).map_err(LauncherError::Io)?;
            symlink(&dest, &target_p).map_err(LauncherError::Io)?;
        } else if host_p.is_dir() {
            fs::create_dir_all(&target_p).map_err(LauncherError::Io)?;
            mount_bind_readonly(&host_p, &target_p, force_mount_fallback)?;
        } else {
            return Err(LauncherError::RootfsAssembly(format!(
                "Required system path {} missing on host",
                host_p.display()
            )));
        }
    }

    // 5. Bind-mount application directory if provided or exists on host
    if let Some(app) = app_dir {
        if !app.exists() {
            return Err(LauncherError::RootfsAssembly(format!(
                "Configured app_dir {} does not exist",
                app.display()
            )));
        }
        mount_bind_readonly(app, &sandbox_path.join("app"), force_mount_fallback)?;
    } else {
        let host_app = Path::new("/app");
        if host_app.exists() {
            mount_bind_readonly(host_app, &sandbox_path.join("app"), force_mount_fallback)?;
        }
    }

    // 6. Bind-mount controlled Phase 1 dummy probe binary if in test-probe mode
    if let Some(p_exe) = probe_exe {
        if !p_exe.exists() {
            return Err(LauncherError::RootfsAssembly(format!(
                "Probe executable {} does not exist",
                p_exe.display()
            )));
        }
        let probe_dir = sandbox_path.join("probe_bin");
        fs::create_dir_all(&probe_dir).map_err(LauncherError::Io)?;
        let target_dest = probe_dir.join("probe_target");
        fs::File::create(&target_dest).map_err(LauncherError::Io)?;
        let src_c = path_to_cstring(p_exe)?;
        let dst_c = path_to_cstring(&target_dest)?;
        let ret = unsafe {
            libc::mount(
                src_c.as_ptr(),
                dst_c.as_ptr(),
                std::ptr::null(),
                libc::MS_BIND,
                std::ptr::null(),
            )
        };
        if ret != 0 {
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            return Err(LauncherError::RootfsAssembly(format!(
                "Bind mount of probe_exe failed: errno {errno}"
            )));
        }
        set_mount_readonly(&target_dest, false, true, true, force_mount_fallback)?;
    }

    // 7. Minimal /dev tmpfs (no MS_NODEV so character devices /dev/null, /dev/zero, /dev/urandom work)
    let dev_path = sandbox_path.join("dev");
    let dev_c = path_to_cstring(&dev_path)?;
    let dev_opts = CString::new("size=64k,mode=0755")
        .map_err(|e| LauncherError::RootfsAssembly(e.to_string()))?;
    let ret = unsafe {
        libc::mount(
            tmpfs_c.as_ptr(),
            dev_c.as_ptr(),
            tmpfs_c.as_ptr(),
            libc::MS_NOSUID | libc::MS_NOEXEC,
            dev_opts.as_ptr() as *const libc::c_void,
        )
    };
    if ret != 0 {
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        return Err(LauncherError::RootfsAssembly(format!(
            "Mount tmpfs on /dev failed: errno {errno}"
        )));
    }
    verify_mount_flags(&dev_path, false, true, false, true, false)?;

    // Bind-mount character devices: /dev/null (RW), /dev/zero (RO, dev allowed), /dev/urandom (RO, dev allowed)
    for (dev_name, ro) in &[("null", false), ("zero", true), ("urandom", true)] {
        let host_dev = format!("/dev/{dev_name}");
        let target_dev = dev_path.join(dev_name);
        fs::File::create(&target_dev).map_err(LauncherError::Io)?;

        let h_c = CString::new(host_dev.as_str())
            .map_err(|e| LauncherError::RootfsAssembly(e.to_string()))?;
        let t_c = path_to_cstring(&target_dev)?;
        let ret = unsafe {
            libc::mount(
                h_c.as_ptr(),
                t_c.as_ptr(),
                std::ptr::null(),
                libc::MS_BIND,
                std::ptr::null(),
            )
        };
        if ret != 0 {
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            return Err(LauncherError::RootfsAssembly(format!(
                "Bind mount of /dev/{dev_name} failed: errno {errno}"
            )));
        }

        if *ro {
            // Preserve read-only and nosuid, while NOT setting nodev on character device bind mounts
            set_mount_readonly(&target_dev, false, false, false, force_mount_fallback)?;
        }
    }
    // Symlink /dev/random -> urandom
    symlink("urandom", dev_path.join("random")).map_err(LauncherError::Io)?;

    // 8. Dedicated scratch storage at /tmp (size=128M, mode=0700, nosuid, nodev, noexec)
    let tmp_path = sandbox_path.join("tmp");
    let tmp_c = path_to_cstring(&tmp_path)?;
    let tmp_opts = CString::new("size=128M,mode=0700")
        .map_err(|e| LauncherError::RootfsAssembly(e.to_string()))?;
    let ret = unsafe {
        libc::mount(
            tmpfs_c.as_ptr(),
            tmp_c.as_ptr(),
            tmpfs_c.as_ptr(),
            libc::MS_NODEV | libc::MS_NOSUID | libc::MS_NOEXEC,
            tmp_opts.as_ptr() as *const libc::c_void,
        )
    };
    if ret != 0 {
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        return Err(LauncherError::RootfsAssembly(format!(
            "Mount scratch tmpfs on /tmp failed: errno {errno}"
        )));
    }
    verify_mount_flags(&tmp_path, false, true, true, true, false)?;

    // 9. Mount private procfs with subset=pid
    let proc_path = sandbox_path.join("proc");
    let proc_c = path_to_cstring(&proc_path)?;
    let proc_type =
        CString::new("proc").map_err(|e| LauncherError::RootfsAssembly(e.to_string()))?;
    let proc_flags = libc::MS_NODEV | libc::MS_NOSUID | libc::MS_NOEXEC;
    let subset_pid_data =
        CString::new("subset=pid").map_err(|e| LauncherError::RootfsAssembly(e.to_string()))?;

    let ret = unsafe {
        libc::mount(
            proc_type.as_ptr(),
            proc_c.as_ptr(),
            proc_type.as_ptr(),
            proc_flags,
            subset_pid_data.as_ptr() as *const libc::c_void,
        )
    };

    if ret != 0 {
        if strict_mode {
            return Err(LauncherError::ProcfsSubsetPidUnsupported);
        }

        // Permissive fallback: mount standard procfs and mask telemetry files read-only with /dev/null
        let ret_fallback = unsafe {
            libc::mount(
                proc_type.as_ptr(),
                proc_c.as_ptr(),
                proc_type.as_ptr(),
                proc_flags,
                std::ptr::null(),
            )
        };
        if ret_fallback != 0 {
            let fallback_errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            return Err(LauncherError::RootfsAssembly(format!(
                "Fallback mount of procfs failed: errno {fallback_errno}"
            )));
        }

        // Bind-mount /dev/null over /proc/stat, /proc/meminfo, /proc/cpuinfo and lock read-only
        let dev_null =
            CString::new("/dev/null").map_err(|e| LauncherError::RootfsAssembly(e.to_string()))?;
        for file in &["stat", "meminfo", "cpuinfo"] {
            let target_file = proc_path.join(file);
            if target_file.exists() {
                let tf_c = path_to_cstring(&target_file)?;
                let ret = unsafe {
                    libc::mount(
                        dev_null.as_ptr(),
                        tf_c.as_ptr(),
                        std::ptr::null(),
                        libc::MS_BIND,
                        std::ptr::null(),
                    )
                };
                if ret != 0 {
                    let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
                    return Err(LauncherError::RootfsAssembly(format!(
                        "Failed to mask /proc/{file} in permissive fallback: errno {errno}"
                    )));
                }
                set_mount_readonly(&target_file, false, true, false, force_mount_fallback)?;
            }
        }
    }
    verify_mount_flags(&proc_path, false, true, true, true, false)?;

    // 10. Atomic pivot_root
    let put_old_path = sandbox_path.join("put_old");
    let put_old_c = path_to_cstring(&put_old_path)?;

    let ret = unsafe { libc::syscall(libc::SYS_pivot_root, root_c.as_ptr(), put_old_c.as_ptr()) };
    if ret != 0 {
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        return Err(LauncherError::RootfsAssembly(format!(
            "pivot_root failed: errno {errno}"
        )));
    }

    // chdir to new root "/"
    let ret = unsafe { libc::chdir(slash.as_ptr()) };
    if ret != 0 {
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        return Err(LauncherError::RootfsAssembly(format!(
            "chdir('/') failed: errno {errno}"
        )));
    }

    // Detach and remove /put_old
    let old_root_c =
        CString::new("/put_old").map_err(|e| LauncherError::RootfsAssembly(e.to_string()))?;
    let ret = unsafe { libc::umount2(old_root_c.as_ptr(), libc::MNT_DETACH) };
    if ret != 0 {
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        return Err(LauncherError::RootfsAssembly(format!(
            "umount2('/put_old', MNT_DETACH) failed: errno {errno}"
        )));
    }
    fs::remove_dir("/put_old").map_err(LauncherError::Io)?;

    // 11. Purge intermediate setup file descriptors >= 10
    purge_setup_fds(10);

    Ok(())
}

/// Closes all file descriptors >= `min_fd` using `close_range(2)` with fallback loop.
pub fn purge_setup_fds(min_fd: u32) {
    let ret = unsafe { libc::syscall(libc::SYS_close_range, min_fd, u32::MAX, 0) };
    if ret != 0 {
        let max_fd = unsafe { libc::sysconf(libc::_SC_OPEN_MAX) };
        let limit = if max_fd > 0 && max_fd < 65536 {
            max_fd as u32
        } else {
            4096
        };
        for fd in min_fd..limit {
            unsafe { libc::close(fd as libc::c_int) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    struct MockMountOps {
        pre_mountinfo: String,
        post_mountinfo: RefCell<String>,
        mount_setattr_res: Result<(), (i32, String)>,
        remount_calls: RefCell<Vec<(PathBuf, libc::c_ulong)>>,
        fail_remount_on: Option<PathBuf>,
        fail_statvfs_on: Option<PathBuf>,
        fail_write_check_on: Option<PathBuf>,
        fail_read_count: Option<usize>,
        read_counter: RefCell<usize>,
    }

    impl MockMountOps {
        fn new(pre: &str, post: &str) -> Self {
            Self {
                pre_mountinfo: pre.to_string(),
                post_mountinfo: RefCell::new(post.to_string()),
                mount_setattr_res: Ok(()),
                remount_calls: RefCell::new(Vec::new()),
                fail_remount_on: None,
                fail_statvfs_on: None,
                fail_write_check_on: None,
                fail_read_count: None,
                read_counter: RefCell::new(0),
            }
        }
    }

    impl MountOps for MockMountOps {
        fn read_mountinfo(&self) -> Result<String, LauncherError> {
            let mut cnt = self.read_counter.borrow_mut();
            *cnt += 1;
            if self.fail_read_count == Some(*cnt) {
                return Err(LauncherError::RootfsAssembly(
                    "Injected mountinfo enumeration failure".to_string(),
                ));
            }
            if *cnt == 1 {
                Ok(self.pre_mountinfo.clone())
            } else {
                Ok(self.post_mountinfo.borrow().clone())
            }
        }

        fn mount_setattr_ro(
            &self,
            _target: &Path,
            _recursive: bool,
            _nodev: bool,
        ) -> Result<(), (i32, String)> {
            self.mount_setattr_res.clone()
        }

        fn remount_bind_single(
            &self,
            target: &Path,
            flags: libc::c_ulong,
        ) -> Result<(), LauncherError> {
            assert_eq!(
                flags & libc::MS_REC,
                0,
                "MS_REC must NEVER be passed to MS_BIND | MS_REMOUNT"
            );
            self.remount_calls
                .borrow_mut()
                .push((target.to_path_buf(), flags));
            if self.fail_remount_on.as_deref() == Some(target) {
                return Err(LauncherError::RootfsAssembly(format!(
                    "Injected remount failure on {}",
                    target.display()
                )));
            }
            Ok(())
        }

        fn verify_statvfs(
            &self,
            target: &Path,
            _expect_nodev: bool,
            _expect_noexec: bool,
            _expect_nosymfollow: bool,
        ) -> Result<(), LauncherError> {
            if self.fail_statvfs_on.as_deref() == Some(target) {
                return Err(LauncherError::RootfsAssembly(format!(
                    "Injected statvfs verification failure on {}",
                    target.display()
                )));
            }
            Ok(())
        }

        fn verify_write_rejected(&self, target: &Path) -> Result<(), LauncherError> {
            if self.fail_write_check_on.as_deref() == Some(target) {
                return Err(LauncherError::RootfsAssembly(format!(
                    "Injected write rejection failure on {}",
                    target.display()
                )));
            }
            Ok(())
        }
    }

    #[test]
    fn test_decode_mountinfo_escapes_and_rejects_malformed() {
        let p = decode_mountinfo_path(r"/app/dir\040name\011tab\012nl\134slash").unwrap();
        assert_eq!(p, PathBuf::from("/app/dir name\ttab\nnl\\slash"));

        assert!(decode_mountinfo_path(r"/app/bad\999").is_err());
        assert!(decode_mountinfo_path(r"/app/trunc\04").is_err());
        assert!(decode_mountinfo_path(r"/app/nul\000byte").is_err());
    }

    #[test]
    fn test_component_boundary_matching_and_stacked_detection() {
        let mi = "\
10 1 0:1 / /sandbox/usr rw,relatime - tmpfs tmpfs rw
11 10 0:2 / /sandbox/usr/lib rw,noexec,noatime,nosymfollow - tmpfs tmpfs rw
12 1 0:3 / /sandbox/usr2 rw,relatime - tmpfs tmpfs rw
";
        let entries = parse_mountinfo(mi).unwrap();
        let sub = enumerate_subtree_mounts(&entries, Path::new("/sandbox/usr"), true).unwrap();
        assert_eq!(sub.len(), 2);
        assert!(sub
            .iter()
            .all(|e| e.mount_point != Path::new("/sandbox/usr2")));

        // Stacked duplicate mountpoint must fail closed
        let stacked_mi = "\
10 1 0:1 / /sandbox/app rw,relatime - tmpfs tmpfs rw
11 10 0:2 / /sandbox/app/sub rw,relatime - tmpfs tmpfs rw
12 11 0:3 / /sandbox/app/sub rw,noexec,relatime - tmpfs tmpfs rw
";
        let stacked_entries = parse_mountinfo(stacked_mi).unwrap();
        let err = enumerate_subtree_mounts(&stacked_entries, Path::new("/sandbox/app"), true)
            .unwrap_err();
        assert!(err.to_string().contains("stacked"));
    }

    #[test]
    fn test_unknown_and_misplaced_mount_options_fail_closed() {
        let idmapped = "10 1 0:1 / /sandbox/app rw,relatime,idmapped - tmpfs tmpfs rw\n";
        let err = parse_mountinfo(idmapped).unwrap_err();
        assert!(err.to_string().contains("Unknown or unpreservable"));

        // Superblock flags must not be accepted in Field 6 per-mount options
        for sb_flag in ["sync", "dirsync", "mand", "lazytime"] {
            let line = format!("10 1 0:1 / /sandbox/app rw,relatime,{sb_flag} - tmpfs tmpfs rw\n");
            let err = parse_mountinfo(&line).unwrap_err();
            assert!(
                err.to_string().contains("Unknown or unpreservable"),
                "Expected Field 6 rejection for superblock flag {sb_flag}: {err}"
            );
        }
    }

    #[test]
    fn test_superblock_options_separated_from_per_mount_remount_flags() {
        const MS_SYNCHRONOUS: libc::c_ulong = 16;
        const MS_MANDLOCK: libc::c_ulong = 64;
        const MS_DIRSYNC: libc::c_ulong = 128;
        const MS_LAZYTIME: libc::c_ulong = 1 << 25;

        let pre = "\
10 1 0:1 / /sandbox/app rw,relatime - ext4 /dev/sda1 rw,sync,dirsync,mand,lazytime
11 10 0:2 / /sandbox/app/sub rw,noexec,noatime,nosymfollow - tmpfs tmpfs rw,lazytime,size=1024k
";
        let post = "\
10 1 0:1 / /sandbox/app ro,nosuid,nodev,relatime - ext4 /dev/sda1 rw,sync,dirsync,mand,lazytime
11 10 0:2 / /sandbox/app/sub ro,nosuid,nodev,noexec,noatime,nosymfollow - tmpfs tmpfs rw,lazytime,size=1024k
";
        let entries = parse_mountinfo(pre).unwrap();
        assert!(entries[0].super_options.synchronous);
        assert!(entries[0].super_options.dirsync);
        assert!(entries[0].super_options.mandlock);
        assert!(entries[0].super_options.lazytime);
        assert_eq!(
            entries[0].super_options.raw,
            "rw,sync,dirsync,mand,lazytime"
        );
        assert!(entries[1].super_options.lazytime);
        assert!(!entries[1].super_options.synchronous);

        let mut ops = MockMountOps::new(pre, post);
        ops.mount_setattr_res = Err((libc::ENOSYS, "ENOSYS".to_string()));
        apply_ro_bind_subtree(&ops, Path::new("/sandbox/app"), true, true, true, false).unwrap();

        let calls = ops.remount_calls.borrow();
        assert_eq!(calls.len(), 2);
        for (_path, flags) in calls.iter() {
            assert_eq!(
                flags & (MS_SYNCHRONOUS | MS_DIRSYNC | MS_MANDLOCK | MS_LAZYTIME),
                0,
                "Superblock flags must never be emitted in MS_BIND | MS_REMOUNT flags: 0x{flags:x}"
            );
            assert_eq!(flags & libc::MS_REC, 0);
        }

        // Verify post-modification superblock option mutation fails closed
        let post_sb_changed = "\
10 1 0:1 / /sandbox/app ro,nosuid,nodev,relatime - ext4 /dev/sda1 rw,dirsync,mand,lazytime
11 10 0:2 / /sandbox/app/sub ro,nosuid,nodev,noexec,noatime,nosymfollow - tmpfs tmpfs rw,lazytime,size=1024k
";
        let mut ops_sb_changed = MockMountOps::new(pre, post_sb_changed);
        ops_sb_changed.mount_setattr_res = Err((libc::ENOSYS, "ENOSYS".to_string()));
        let err = apply_ro_bind_subtree(
            &ops_sb_changed,
            Path::new("/sandbox/app"),
            true,
            true,
            true,
            false,
        )
        .unwrap_err();
        assert!(err.to_string().contains("Superblock options changed"));
    }

    #[test]
    fn test_mount_setattr_unexpected_error_does_not_fallback() {
        let pre = "10 1 0:1 / /sandbox/app rw,relatime - tmpfs tmpfs rw\n";
        let mut ops = MockMountOps::new(pre, pre);
        ops.mount_setattr_res = Err((libc::EPERM, "mount_setattr EPERM".to_string()));
        let err = apply_ro_bind_subtree(&ops, Path::new("/sandbox/app"), true, true, true, false)
            .unwrap_err();
        assert!(err.to_string().contains("EPERM"));
        assert!(ops.remount_calls.borrow().is_empty());
    }

    #[test]
    fn test_enosys_fallback_individually_remounts_and_preserves_flags_without_ms_rec() {
        let pre = "\
10 1 0:1 / /sandbox/app rw,relatime - tmpfs tmpfs rw
11 10 0:2 / /sandbox/app/sub\\040dir rw,noexec,nodiratime,noatime,nosymfollow - tmpfs tmpfs rw
";
        let post = "\
10 1 0:1 / /sandbox/app ro,nosuid,nodev,relatime - tmpfs tmpfs rw
11 10 0:2 / /sandbox/app/sub\\040dir ro,nosuid,nodev,noexec,nodiratime,noatime,nosymfollow - tmpfs tmpfs rw
";
        let mut ops = MockMountOps::new(pre, post);
        ops.mount_setattr_res = Err((libc::ENOSYS, "ENOSYS".to_string()));

        apply_ro_bind_subtree(&ops, Path::new("/sandbox/app"), true, true, true, false).unwrap();

        let calls = ops.remount_calls.borrow();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].0, PathBuf::from("/sandbox/app"));
        assert_eq!(calls[1].0, PathBuf::from("/sandbox/app/sub dir"));

        let child_flags = calls[1].1;
        assert_ne!(child_flags & libc::MS_BIND, 0);
        assert_ne!(child_flags & libc::MS_REMOUNT, 0);
        assert_ne!(child_flags & libc::MS_RDONLY, 0);
        assert_ne!(child_flags & libc::MS_NOSUID, 0);
        assert_ne!(child_flags & libc::MS_NODEV, 0);
        assert_ne!(child_flags & libc::MS_NOEXEC, 0);
        assert_ne!(child_flags & MS_NOSYMFOLLOW_FLAG, 0);
        assert_ne!(child_flags & MS_NOATIME_FLAG, 0);
        assert_ne!(child_flags & MS_NODIRATIME_FLAG, 0);
        assert_eq!(child_flags & libc::MS_REC, 0);
    }

    #[test]
    fn test_failure_injections_enumeration_remount_verification_and_tree_mutation() {
        let pre = "\
10 1 0:1 / /sandbox/app rw,relatime - tmpfs tmpfs rw
11 10 0:2 / /sandbox/app/sub rw,noexec,noatime,nosymfollow - tmpfs tmpfs rw
";
        let post_ok = "\
10 1 0:1 / /sandbox/app ro,nosuid,nodev,relatime - tmpfs tmpfs rw
11 10 0:2 / /sandbox/app/sub ro,nosuid,nodev,noexec,noatime,nosymfollow - tmpfs tmpfs rw
";

        // 1. Enumeration failure
        let mut ops_enum = MockMountOps::new(pre, post_ok);
        ops_enum.fail_read_count = Some(1);
        assert!(apply_ro_bind_subtree(
            &ops_enum,
            Path::new("/sandbox/app"),
            true,
            true,
            true,
            true
        )
        .is_err());

        // 2. Remount failure on child mount
        let mut ops_remount = MockMountOps::new(pre, post_ok);
        ops_remount.mount_setattr_res = Err((libc::ENOSYS, "ENOSYS".to_string()));
        ops_remount.fail_remount_on = Some(PathBuf::from("/sandbox/app/sub"));
        assert!(apply_ro_bind_subtree(
            &ops_remount,
            Path::new("/sandbox/app"),
            true,
            true,
            true,
            false
        )
        .is_err());

        // 3. Statvfs verification failure
        let mut ops_statvfs = MockMountOps::new(pre, post_ok);
        ops_statvfs.fail_statvfs_on = Some(PathBuf::from("/sandbox/app/sub"));
        assert!(apply_ro_bind_subtree(
            &ops_statvfs,
            Path::new("/sandbox/app"),
            true,
            true,
            true,
            false
        )
        .is_err());

        // 4. Write rejection verification failure
        let mut ops_write = MockMountOps::new(pre, post_ok);
        ops_write.fail_write_check_on = Some(PathBuf::from("/sandbox/app/sub"));
        assert!(apply_ro_bind_subtree(
            &ops_write,
            Path::new("/sandbox/app"),
            true,
            true,
            true,
            false
        )
        .is_err());

        // 5. Preserved flag weakened (noexec dropped) in post mountinfo
        let post_weakened = "\
10 1 0:1 / /sandbox/app ro,nosuid,nodev,relatime - tmpfs tmpfs rw
11 10 0:2 / /sandbox/app/sub ro,nosuid,nodev,noatime,nosymfollow - tmpfs tmpfs rw
";
        let ops_weak = MockMountOps::new(pre, post_weakened);
        assert!(apply_ro_bind_subtree(
            &ops_weak,
            Path::new("/sandbox/app"),
            true,
            true,
            true,
            false
        )
        .is_err());

        // 6. Mount-tree mutation / missing mount ID / new child mount appeared
        let post_missing_id = "\
10 1 0:1 / /sandbox/app ro,nosuid,nodev,relatime - tmpfs tmpfs rw
99 10 0:2 / /sandbox/app/sub ro,nosuid,nodev,noexec,noatime,nosymfollow - tmpfs tmpfs rw
";
        let ops_mutated = MockMountOps::new(pre, post_missing_id);
        let err = apply_ro_bind_subtree(
            &ops_mutated,
            Path::new("/sandbox/app"),
            true,
            true,
            true,
            false,
        )
        .unwrap_err();
        assert!(err.to_string().contains("missing from post-modification"));
    }
}
