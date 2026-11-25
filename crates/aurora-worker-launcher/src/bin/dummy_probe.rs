//! Controlled dummy probe binary for verifying Phase 1 launcher isolation invariants.

use std::env;
use std::ffi::CString;
use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::net::TcpStream;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{self, Command};
use std::thread;
use std::time::Duration;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: aurora-dummy-probe <probe_name>");
        process::exit(1);
    }

    let probe_name = &args[1];
    match probe_name.as_str() {
        "pid1" => probe_pid1(),
        "id" => probe_id(),
        "caps" => probe_caps(),
        "locks" => probe_locks(),
        "procfs" => probe_procfs(),
        "rootfs" => probe_rootfs(),
        "rootfs-nested" => probe_rootfs_nested(),
        "devices" => probe_devices(),
        "network" => probe_network(),
        "sigterm" => probe_sigterm(),
        "sleep-forever" => probe_sleep_forever(),
        other => {
            eprintln!("Unknown probe: {other}");
            process::exit(2);
        }
    }
}

/// Asserts process is PID 1 in its namespace and has no parent.
fn probe_pid1() {
    let pid = unsafe { libc::getpid() };
    let ppid = unsafe { libc::getppid() };
    if pid == 1 && ppid == 0 {
        println!("PROBE_PID1_OK: pid=1, ppid=0");
        process::exit(0);
    } else {
        eprintln!("PROBE_PID1_FAIL: pid={pid}, ppid={ppid}");
        process::exit(1);
    }
}

/// Asserts UID and GID are mapped to 1000.
fn probe_id() {
    let uid = unsafe { libc::getuid() };
    let gid = unsafe { libc::getgid() };
    if uid == 1000 && gid == 1000 {
        println!("PROBE_ID_OK: uid=1000, gid=1000");
        process::exit(0);
    } else {
        eprintln!("PROBE_ID_FAIL: uid={uid}, gid={gid}");
        process::exit(1);
    }
}

/// Verifies that all 5 capability sets in /proc/self/status are zeroed.
fn probe_caps() {
    let status = fs::read_to_string("/proc/self/status").expect("Failed to read /proc/self/status");
    let mut cap_inh = None;
    let mut cap_prm = None;
    let mut cap_eff = None;
    let mut cap_bnd = None;
    let mut cap_amb = None;

    for line in status.lines() {
        if let Some(val) = line.strip_prefix("CapInh:\t") {
            cap_inh = Some(val.trim().to_string());
        } else if let Some(val) = line.strip_prefix("CapPrm:\t") {
            cap_prm = Some(val.trim().to_string());
        } else if let Some(val) = line.strip_prefix("CapEff:\t") {
            cap_eff = Some(val.trim().to_string());
        } else if let Some(val) = line.strip_prefix("CapBnd:\t") {
            cap_bnd = Some(val.trim().to_string());
        } else if let Some(val) = line.strip_prefix("CapAmb:\t") {
            cap_amb = Some(val.trim().to_string());
        }
    }

    let is_zero = |s: &Option<String>| match s {
        Some(val) => !val.is_empty() && val.chars().all(|c| c == '0'),
        None => false,
    };

    if is_zero(&cap_inh)
        && is_zero(&cap_prm)
        && is_zero(&cap_eff)
        && is_zero(&cap_bnd)
        && is_zero(&cap_amb)
    {
        println!("PROBE_CAPS_OK: all 5 capability sets zeroed");
        process::exit(0);
    } else {
        eprintln!(
            "PROBE_CAPS_FAIL: Inh={cap_inh:?}, Prm={cap_prm:?}, Eff={cap_eff:?}, Bnd={cap_bnd:?}, Amb={cap_amb:?}"
        );
        process::exit(1);
    }
}

/// Verifies `NoNewPrivs: 1` persists post-exec in `/proc/self/status`.
///
/// Note: Under Linux `execve()`, `mm->dumpable` is reset to 1 for non-SUID binaries;
/// pre-exec `PR_SET_DUMPABLE(0)` verification occurs before `execve()` in `caps::apply_security_locks()`.
fn probe_locks() {
    let status = fs::read_to_string("/proc/self/status").expect("Failed to read /proc/self/status");
    let mut no_new_privs = None;

    for line in status.lines() {
        if let Some(val) = line.strip_prefix("NoNewPrivs:\t") {
            no_new_privs = Some(val.trim() == "1");
        }
    }

    if no_new_privs == Some(true) {
        println!("PROBE_LOCKS_OK: NoNewPrivs=1");
        process::exit(0);
    } else {
        eprintln!("PROBE_LOCKS_FAIL: NoNewPrivs={no_new_privs:?}");
        process::exit(1);
    }
}

/// Verifies private procfs mounted with `subset=pid` hides host telemetry.
fn probe_procfs() {
    let self_exists = Path::new("/proc/self").exists();
    let one_exists = Path::new("/proc/1").exists();

    let stat_exists = Path::new("/proc/stat").exists();
    let meminfo_exists = Path::new("/proc/meminfo").exists();
    let cpuinfo_exists = Path::new("/proc/cpuinfo").exists();

    if self_exists && one_exists && !stat_exists && !meminfo_exists && !cpuinfo_exists {
        println!("PROBE_PROCFS_OK: subset=pid active, /proc/stat returns ENOENT");
        process::exit(0);
    } else {
        eprintln!(
            "PROBE_PROCFS_FAIL: self={self_exists}, 1={one_exists}, stat={stat_exists}, meminfo={meminfo_exists}, cpuinfo={cpuinfo_exists}"
        );
        process::exit(1);
    }
}

/// Verifies `/proc/self/mountinfo`, read-only enforcement on `/usr` and `/app`, `/tmp` `noexec`,
/// absence of host paths, and zero unexpected inherited FDs.
fn probe_rootfs() {
    // 1. Parse /proc/self/mountinfo
    let mountinfo =
        fs::read_to_string("/proc/self/mountinfo").expect("Failed to read /proc/self/mountinfo");

    let mut seen_root = false;
    let mut seen_usr_ro = false;
    let mut seen_app_ro = false;
    let mut seen_tmp_noexec = false;
    let mut seen_dev_noexec = false;
    let mut seen_proc_noexec = false;

    for line in mountinfo.lines() {
        let parts: Vec<&str> = line.split(" - ").collect();
        if parts.len() != 2 {
            eprintln!("PROBE_ROOTFS_FAIL: malformed mountinfo line: {line}");
            process::exit(1);
        }
        let pre: Vec<&str> = parts[0].split_whitespace().collect();
        let post: Vec<&str> = parts[1].split_whitespace().collect();
        if pre.len() < 6 || post.is_empty() {
            eprintln!("PROBE_ROOTFS_FAIL: short mountinfo line: {line}");
            process::exit(1);
        }
        let mount_point = pre[4];
        let opts = pre[5];
        let fs_type = post[0];

        let has_opt = |needle: &str| opts.split(',').any(|o| o == needle);

        // Ensure no host-root /put_old or unexpected host paths remain mounted
        if mount_point == "/put_old"
            || mount_point.starts_with("/home")
            || mount_point.starts_with("/workspaces")
            || mount_point.starts_with("/var")
            || mount_point.starts_with("/etc")
            || mount_point.starts_with("/sys")
        {
            eprintln!("PROBE_ROOTFS_FAIL: unexpected mount exposed: {mount_point} ({fs_type})");
            process::exit(1);
        }

        match mount_point {
            "/" => {
                if fs_type != "tmpfs" || !has_opt("nosuid") || !has_opt("nodev") {
                    eprintln!("PROBE_ROOTFS_FAIL: invalid root mount: {line}");
                    process::exit(1);
                }
                seen_root = true;
            }
            "/usr" => {
                if !has_opt("ro") || !has_opt("nosuid") || !has_opt("nodev") {
                    eprintln!("PROBE_ROOTFS_FAIL: /usr not ro,nosuid,nodev: {line}");
                    process::exit(1);
                }
                seen_usr_ro = true;
            }
            "/app" => {
                if !has_opt("ro") || !has_opt("nosuid") || !has_opt("nodev") {
                    eprintln!("PROBE_ROOTFS_FAIL: /app not ro,nosuid,nodev: {line}");
                    process::exit(1);
                }
                seen_app_ro = true;
            }
            "/tmp" => {
                if fs_type != "tmpfs"
                    || !has_opt("rw")
                    || !has_opt("nosuid")
                    || !has_opt("nodev")
                    || !has_opt("noexec")
                {
                    eprintln!(
                        "PROBE_ROOTFS_FAIL: /tmp missing tmpfs/rw/nosuid/nodev/noexec: {line}"
                    );
                    process::exit(1);
                }
                seen_tmp_noexec = true;
            }
            "/dev" => {
                if fs_type != "tmpfs" || !has_opt("rw") || !has_opt("nosuid") || !has_opt("noexec")
                {
                    eprintln!("PROBE_ROOTFS_FAIL: /dev missing tmpfs/rw/nosuid/noexec: {line}");
                    process::exit(1);
                }
                seen_dev_noexec = true;
            }
            "/proc" => {
                if fs_type != "proc"
                    || !has_opt("nosuid")
                    || !has_opt("nodev")
                    || !has_opt("noexec")
                {
                    eprintln!("PROBE_ROOTFS_FAIL: /proc missing proc/nosuid/nodev/noexec: {line}");
                    process::exit(1);
                }
                seen_proc_noexec = true;
            }
            _ => {}
        }
    }

    if !seen_root
        || !seen_usr_ro
        || !seen_app_ro
        || !seen_tmp_noexec
        || !seen_dev_noexec
        || !seen_proc_noexec
    {
        eprintln!(
            "PROBE_ROOTFS_FAIL: missing expected mounts: root={seen_root}, usr={seen_usr_ro}, app={seen_app_ro}, tmp={seen_tmp_noexec}, dev={seen_dev_noexec}, proc={seen_proc_noexec}\n{mountinfo}"
        );
        process::exit(1);
    }

    // 2. Verify writes to /usr and /app fail with EROFS or EACCES
    for ro_dir in &["/usr", "/app"] {
        let test_path = format!("{ro_dir}/.probe_write_deny");
        match OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&test_path)
        {
            Ok(_) => {
                let _ = fs::remove_file(&test_path);
                eprintln!("PROBE_ROOTFS_FAIL: write unexpectedly succeeded on {ro_dir}");
                process::exit(1);
            }
            Err(e) => {
                let raw = e.raw_os_error();
                if raw != Some(libc::EROFS) && raw != Some(libc::EACCES) {
                    eprintln!("PROBE_ROOTFS_FAIL: expected EROFS/EACCES on {ro_dir}, got {e:?}");
                    process::exit(1);
                }
            }
        }
    }

    // 3. Verify /tmp is writable, but execution from /tmp is denied (EACCES via noexec)
    let tmp_exec_path = "/tmp/probe_noexec_test";
    {
        let mut f = fs::File::create(tmp_exec_path).expect("Failed to write to /tmp");
        f.write_all(b"#!/bin/sh\necho PWNED\n")
            .expect("Failed to write bytes to /tmp");
    }
    fs::set_permissions(tmp_exec_path, fs::Permissions::from_mode(0o755))
        .expect("Failed to chmod /tmp/probe_noexec_test");

    match Command::new(tmp_exec_path).status() {
        Ok(s) => {
            let _ = fs::remove_file(tmp_exec_path);
            eprintln!("PROBE_ROOTFS_FAIL: execution from /tmp unexpectedly succeeded: {s}");
            process::exit(1);
        }
        Err(e) => {
            let _ = fs::remove_file(tmp_exec_path);
            if e.raw_os_error() != Some(libc::EACCES) {
                eprintln!("PROBE_ROOTFS_FAIL: expected EACCES executing from /tmp, got {e:?}");
                process::exit(1);
            }
        }
    }

    // 4. Verify host paths are inaccessible (ENOENT)
    for absent in &["/put_old", "/home", "/etc/shadow", "/root", "/sys"] {
        if Path::new(absent).exists() {
            eprintln!("PROBE_ROOTFS_FAIL: host path {absent} unexpectedly exists");
            process::exit(1);
        }
    }

    // 5. Verify no unexpected inherited FDs exist in /proc/self/fd (only 0, 1, 2 allowed)
    verify_clean_fd_table();

    println!(
        "PROBE_ROOTFS_OK: mountinfo verified, /usr & /app RO, /tmp noexec, host paths absent, FDs clean"
    );
    process::exit(0);
}

/// Verifies nested child mounts under `/app`, octal-escaped path decoding,
/// `ro,nosuid,nodev` enforcement, and preservation of `noexec`, `nosymfollow`, and `noatime`.
fn probe_rootfs_nested() {
    use aurora_worker_launcher::rootfs::{enumerate_subtree_mounts, parse_mountinfo, AtimeMode};

    let mountinfo =
        fs::read_to_string("/proc/self/mountinfo").expect("Failed to read /proc/self/mountinfo");
    let entries = parse_mountinfo(&mountinfo).expect("Failed to parse /proc/self/mountinfo");
    let app_subtree = enumerate_subtree_mounts(&entries, Path::new("/app"), true)
        .expect("Failed to enumerate /app subtree");

    let app_root = app_subtree
        .iter()
        .find(|m| m.mount_point == Path::new("/app"))
        .expect("Missing /app mount");
    if !app_root.options.read_only || !app_root.options.nosuid || !app_root.options.nodev {
        eprintln!("PROBE_ROOTFS_NESTED_FAIL: /app missing ro/nosuid/nodev: {app_root:?}");
        process::exit(1);
    }

    let nested_path = Path::new("/app/nested ro data");
    let nested = app_subtree
        .iter()
        .find(|m| m.mount_point == nested_path)
        .expect("Missing /app/nested ro data mount");

    if !nested.options.read_only
        || !nested.options.nosuid
        || !nested.options.nodev
        || !nested.options.noexec
        || !nested.options.nosymfollow
        || nested.options.atime != AtimeMode::Noatime
    {
        eprintln!("PROBE_ROOTFS_NESTED_FAIL: nested mount options mismatch: {nested:?}");
        process::exit(1);
    }

    // Verify statvfs independently on nested child mount
    let nested_c = CString::new("/app/nested ro data").unwrap();
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(nested_c.as_ptr(), &mut st) } != 0 {
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        eprintln!("PROBE_ROOTFS_NESTED_FAIL: statvfs failed: errno {errno}");
        process::exit(1);
    }
    const ST_NOEXEC_FLAG: libc::c_ulong = 8;
    const ST_NOSYMFOLLOW_FLAG: libc::c_ulong = 8192;
    let required = libc::ST_RDONLY as libc::c_ulong
        | libc::ST_NOSUID as libc::c_ulong
        | libc::ST_NODEV as libc::c_ulong
        | ST_NOEXEC_FLAG
        | ST_NOSYMFOLLOW_FLAG;
    if (st.f_flag & required) != required {
        eprintln!(
            "PROBE_ROOTFS_NESTED_FAIL: nested statvfs missing flags: got=0x{:x}, expected=0x{:x}",
            st.f_flag, required
        );
        process::exit(1);
    }

    // Verify writes fail with EROFS or EACCES on both /app and /app/nested ro data
    for dir in &["/app", "/app/nested ro data"] {
        let test_path = format!("{dir}/.probe_nested_ro");
        match OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&test_path)
        {
            Ok(_) => {
                let _ = fs::remove_file(&test_path);
                eprintln!("PROBE_ROOTFS_NESTED_FAIL: write unexpectedly succeeded on {dir}");
                process::exit(1);
            }
            Err(e) => {
                let raw = e.raw_os_error();
                if raw != Some(libc::EROFS) && raw != Some(libc::EACCES) {
                    eprintln!(
                        "PROBE_ROOTFS_NESTED_FAIL: expected EROFS/EACCES on {dir}, got {e:?}"
                    );
                    process::exit(1);
                }
            }
        }
    }

    verify_clean_fd_table();

    println!(
        "PROBE_ROOTFS_NESTED_OK: /app and nested child mount verified with ro,nosuid,nodev,noexec,nosymfollow,noatime"
    );
    process::exit(0);
}

/// Scans `/proc/self/fd` using `opendir`/`dirfd` so the directory stream FD itself can be excluded,
/// verifying that only FDs 0, 1, and 2 remain open.
fn verify_clean_fd_table() {
    let dir_c = CString::new("/proc/self/fd").unwrap();
    let dirp = unsafe { libc::opendir(dir_c.as_ptr()) };
    if dirp.is_null() {
        eprintln!("PROBE_ROOTFS_FAIL: failed to opendir /proc/self/fd");
        process::exit(1);
    }
    let dir_fd = unsafe { libc::dirfd(dirp) };
    let mut extra_fds = Vec::new();

    loop {
        let entry = unsafe { libc::readdir(dirp) };
        if entry.is_null() {
            break;
        }
        let name_c = unsafe { std::ffi::CStr::from_ptr((*entry).d_name.as_ptr()) };
        if let Ok(name) = name_c.to_str() {
            if name == "." || name == ".." {
                continue;
            }
            if let Ok(fd) = name.parse::<libc::c_int>() {
                if fd != dir_fd && fd > 2 {
                    extra_fds.push(fd);
                }
            }
        }
    }
    unsafe { libc::closedir(dirp) };

    if !extra_fds.is_empty() {
        eprintln!("PROBE_ROOTFS_FAIL: unexpected open FDs crossed execve: {extra_fds:?}");
        process::exit(1);
    }
}

/// Verifies device open/read/write invariants and mount flags:
/// - `/dev/null` is read-write (writable, lacks `ST_RDONLY` and `ST_NODEV`)
/// - `/dev/zero`, `/dev/urandom`, and `/dev/random` are readable
/// - `/dev/zero` and `/dev/urandom` bind mounts enforce `ST_RDONLY | ST_NOSUID` without `ST_NODEV`,
///   and metadata writes (`utimensat`) on `/dev/zero`, `/dev/urandom`, and `/dev/random` fail with
///   `EROFS` (Linux `may_open` exempts `S_ISCHR` `open(O_WRONLY)` from `EROFS`; Phase 2 Landlock
///   enforces `WRITE_FILE` denial on device nodes).
fn probe_devices() {
    // 1. /dev/null must be read-write and lack ST_RDONLY / ST_NODEV
    match OpenOptions::new().read(true).write(true).open("/dev/null") {
        Ok(mut f) => {
            if let Err(e) = f.write_all(b"aurora-null-test") {
                eprintln!("PROBE_DEVICES_FAIL: write to /dev/null failed: {e}");
                process::exit(1);
            }
        }
        Err(e) => {
            eprintln!("PROBE_DEVICES_FAIL: open /dev/null for r/w failed: {e}");
            process::exit(1);
        }
    }

    // 2. /dev/zero must be readable (all zeros)
    {
        let mut f = match OpenOptions::new().read(true).open("/dev/zero") {
            Ok(f) => f,
            Err(e) => {
                eprintln!("PROBE_DEVICES_FAIL: open /dev/zero for read failed: {e}");
                process::exit(1);
            }
        };
        let mut buf = [0xAAu8; 16];
        if let Err(e) = f.read_exact(&mut buf) {
            eprintln!("PROBE_DEVICES_FAIL: read /dev/zero failed: {e}");
            process::exit(1);
        }
        if buf != [0u8; 16] {
            eprintln!("PROBE_DEVICES_FAIL: /dev/zero returned non-zero bytes");
            process::exit(1);
        }
    }

    // 3. /dev/urandom and /dev/random must be readable
    for dev in &["/dev/urandom", "/dev/random"] {
        let mut f = match OpenOptions::new().read(true).open(dev) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("PROBE_DEVICES_FAIL: open {dev} for read failed: {e}");
                process::exit(1);
            }
        };
        let mut buf = [0u8; 16];
        if let Err(e) = f.read_exact(&mut buf) {
            eprintln!("PROBE_DEVICES_FAIL: read {dev} failed: {e}");
            process::exit(1);
        }
    }

    // 4. Verify statvfs flags and EROFS on metadata write (utimensat) for /dev/zero, /dev/urandom, /dev/random
    for ro_dev in &["/dev/zero", "/dev/urandom", "/dev/random"] {
        let dev_c = CString::new(*ro_dev).unwrap();
        let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
        if unsafe { libc::statvfs(dev_c.as_ptr(), &mut st) } != 0 {
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            eprintln!("PROBE_DEVICES_FAIL: statvfs({ro_dev}) failed: errno {errno}");
            process::exit(1);
        }
        if (st.f_flag & libc::ST_RDONLY as libc::c_ulong) == 0
            || (st.f_flag & libc::ST_NOSUID as libc::c_ulong) == 0
            || (st.f_flag & libc::ST_NODEV as libc::c_ulong) != 0
        {
            eprintln!(
                "PROBE_DEVICES_FAIL: unexpected statvfs flags on {ro_dev}: 0x{:x}",
                st.f_flag
            );
            process::exit(1);
        }

        let ret = unsafe { libc::utimensat(libc::AT_FDCWD, dev_c.as_ptr(), std::ptr::null(), 0) };
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        if ret == 0 || errno != libc::EROFS {
            eprintln!(
                "PROBE_DEVICES_FAIL: expected EROFS from utimensat({ro_dev}), got ret={ret}, errno={errno}"
            );
            process::exit(1);
        }
    }

    println!(
        "PROBE_DEVICES_OK: /dev/null RW; /dev/zero, /dev/urandom, /dev/random readable & RO mount verified"
    );
    process::exit(0);
}

/// Verifies network namespace: loopback `lo` exists but is DOWN, zero non-loopback interfaces,
/// and no usable connectivity (`ENETUNREACH`).
fn probe_network() {
    // 1. Inspect interfaces via standard POSIX libc::if_nameindex()
    let mut ifaces = Vec::new();
    unsafe {
        let idx_ptr = libc::if_nameindex();
        if idx_ptr.is_null() {
            eprintln!("PROBE_NETWORK_FAIL: if_nameindex() returned null");
            process::exit(1);
        }
        let mut curr = idx_ptr;
        while (*curr).if_index != 0 {
            if let Ok(name) = std::ffi::CStr::from_ptr((*curr).if_name).to_str() {
                ifaces.push(name.to_string());
            }
            curr = curr.add(1);
        }
        libc::if_freenameindex(idx_ptr);
    }

    // Must have only "lo", no non-loopback interfaces
    if ifaces.len() != 1 || ifaces[0] != "lo" {
        eprintln!("PROBE_NETWORK_FAIL: unexpected interfaces via if_nameindex: {ifaces:?}");
        process::exit(1);
    }

    // 2. Verify loopback 'lo' is DOWN using SIOCGIFFLAGS (fail on any socket/ioctl error)
    unsafe {
        let sock = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
        if sock < 0 {
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            eprintln!("PROBE_NETWORK_FAIL: socket(AF_INET, SOCK_DGRAM) failed: errno {errno}");
            process::exit(1);
        }
        let mut ifr: libc::ifreq = std::mem::zeroed();
        let lo_bytes = b"lo\0";
        std::ptr::copy_nonoverlapping(
            lo_bytes.as_ptr() as *const libc::c_char,
            ifr.ifr_name.as_mut_ptr(),
            lo_bytes.len(),
        );
        let ret = libc::ioctl(sock, libc::SIOCGIFFLAGS, &mut ifr);
        let ioctl_errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        libc::close(sock);
        if ret != 0 {
            eprintln!("PROBE_NETWORK_FAIL: ioctl(SIOCGIFFLAGS) failed: errno {ioctl_errno}");
            process::exit(1);
        }
        let flags = ifr.ifr_ifru.ifru_flags;
        let is_up = (flags & libc::IFF_UP as libc::c_short) != 0;
        if is_up {
            eprintln!("PROBE_NETWORK_FAIL: loopback 'lo' is UP (flags: 0x{flags:x})");
            process::exit(1);
        }
    }

    // 3. Verify socket connections fail with ENETUNREACH
    for addr in &["127.0.0.1:80", "192.0.2.1:80"] {
        match TcpStream::connect(addr) {
            Ok(_) => {
                eprintln!("PROBE_NETWORK_FAIL: unexpected network connectivity to {addr}");
                process::exit(1);
            }
            Err(e) => {
                if e.raw_os_error() != Some(libc::ENETUNREACH)
                    && e.kind() != ErrorKind::NetworkUnreachable
                {
                    eprintln!(
                        "PROBE_NETWORK_FAIL: expected ENETUNREACH connecting to {addr}, got {e:?}"
                    );
                    process::exit(1);
                }
            }
        }
    }

    println!("PROBE_NETWORK_OK: lo is DOWN, zero non-loopback interfaces, ENETUNREACH enforced");
    process::exit(0);
}

/// Registers SIGTERM handler, flushes PROBE_SIGTERM_READY, and exits with 143 upon receiving SIGTERM.
fn probe_sigterm() {
    extern "C" fn handle_sigterm(_sig: libc::c_int) {
        unsafe { libc::_exit(143) };
    }

    unsafe {
        libc::signal(libc::SIGTERM, handle_sigterm as *const () as usize);
    }

    println!("PROBE_SIGTERM_READY");
    let _ = std::io::stdout().flush();
    loop {
        thread::sleep(Duration::from_millis(50));
    }
}

/// Flushes PROBE_SLEEPING and sleeps indefinitely to test parent-death SIGKILL termination.
fn probe_sleep_forever() {
    println!("PROBE_SLEEPING");
    let _ = std::io::stdout().flush();
    loop {
        thread::sleep(Duration::from_millis(100));
    }
}
