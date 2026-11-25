//! Standalone trusted launcher binary entry point.
//!
//! Sequential execution flow:
//! 1. CLI parsing (strict mode default, startup gate FD, controlled test-probe mode).
//! 2. Capture supervisor PPID, install `PR_SET_PDEATHSIG(SIGKILL)`, verify PPID unchanged.
//! 3. Initialize signal context via signalfd (relocated to FD >= 10).
//! 4. Pause at Cgroup startup gate (mandatory in strict mode).
//! 5. Redirect FD 1 to `/dev/null` in normal mode (stdout preserved only in controlled Phase 1 test mode).
//! 6. Capture host UID/GID, unshare user namespace, and configure UID/GID mapping with setgroups denial.
//! 7. Unshare network namespace (loopback remains DOWN).
//! 8. Unshare PID namespace (prepares worker child to become PID 1).
//! 9. Establish two-way parent-death pipes (staged >= 10, relocated to FDs 6..=9).
//! 10. fork() worker child:
//!    - Launcher: closes FD 0, executes Stage 1 early handshake & Stage 2 final handshake
//!      (polling signalfd alongside c2l_r and reaping via blocking waitpid on pipe EOF),
//!      then enters proxy reaping loop.
//!    - Child (PID 1): installs PR_SET_PDEATHSIG(SIGKILL) immediately post-fork, restores signal mask,
//!      completes Stage 1 early handshake before potentially blocking setup, unshares mount ns,
//!      verifies setup caps, captures cap_last_cap, builds rootfs (with full subtree ro/nosuid/nodev
//!      verification), purges caps, locks security posture + verifies PR_GET_DUMPABLE == 0,
//!      re-arms PDEATHSIG and completes Stage 2 handshake, purges FDs >= 3, restores SIGPIPE, and execs.

use aurora_worker_launcher::caps::{
    apply_security_locks, get_cap_last_cap, purge_all_capabilities,
    verify_setup_capabilities_effective,
};
use aurora_worker_launcher::idmap::configure_default_idmap;
use aurora_worker_launcher::ns::{
    unshare_mount_ns, unshare_net_ns, unshare_pid_ns, unshare_user_ns,
};
use aurora_worker_launcher::pdeath::{
    create_pdeath_pipes, ensure_sigpipe_ignored, install_pdeathsig_sigkill, HandshakeOutcome,
    PdeathChild, PdeathLauncher, PdeathPausePoint, PdeathTestHook,
};
use aurora_worker_launcher::reaper::SignalContext;
use aurora_worker_launcher::rootfs::{
    construct_and_pivot_rootfs_with_options, create_unique_sandbox_root, purge_setup_fds,
};
use aurora_worker_launcher::{LauncherError, ERR_PDEATH_FAILED};
use std::env;
use std::ffi::{CString, OsStr};
use std::fs;
use std::os::unix::io::RawFd;
use std::path::PathBuf;
use std::process;

struct LauncherConfig {
    strict_mode: bool,
    cgroup_gate_fd: Option<RawFd>,
    gate_ready_fd: Option<RawFd>,
    app_dir: Option<PathBuf>,
    probe_exe: Option<PathBuf>,
    probe_args: Vec<String>,
    force_mount_fallback: bool,
    pdeath_hook: Option<PdeathTestHook>,
}

fn parse_fd_arg(flag: &str, val: Option<String>) -> Result<RawFd, LauncherError> {
    let s = val.ok_or_else(|| LauncherError::InvalidArgs(format!("Missing value for {flag}")))?;
    let fd = s.parse::<RawFd>().map_err(|_| {
        LauncherError::InvalidArgs(format!("Invalid file descriptor '{s}' for {flag}"))
    })?;
    if fd < 0 {
        return Err(LauncherError::InvalidArgs(format!(
            "Negative file descriptor {fd} for {flag}"
        )));
    }
    Ok(fd)
}

fn parse_cli_args() -> Result<LauncherConfig, LauncherError> {
    let mut args = env::args().skip(1);
    let mut strict_mode = true;
    let mut cgroup_gate_fd = None;
    let mut gate_ready_fd = None;
    let mut app_dir = None;
    let mut probe_exe = None;
    let mut probe_args = Vec::new();
    let mut force_mount_fallback = false;
    let mut pdeath_pause: Option<PdeathPausePoint> = None;
    let mut pdeath_ack_fd: Option<RawFd> = None;
    let mut pdeath_go_fd: Option<RawFd> = None;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--permissive" => strict_mode = false,
            "--strict" => strict_mode = true,
            "--cgroup-gate-fd" => {
                cgroup_gate_fd = Some(parse_fd_arg("--cgroup-gate-fd", args.next())?);
            }
            "--gate-ready-fd" => {
                gate_ready_fd = Some(parse_fd_arg("--gate-ready-fd", args.next())?);
            }
            "--app-dir" => {
                let p = args.next().ok_or_else(|| {
                    LauncherError::InvalidArgs("Missing path for --app-dir".to_string())
                })?;
                app_dir = Some(PathBuf::from(p));
            }
            "--test-probe-exe" => {
                let p = args.next().ok_or_else(|| {
                    LauncherError::InvalidArgs("Missing path for --test-probe-exe".to_string())
                })?;
                let pb = PathBuf::from(p);
                // Strictly restrict test-probe mode to the controlled aurora-dummy-probe binary
                if pb.file_name() != Some(OsStr::new("aurora-dummy-probe")) {
                    return Err(LauncherError::InvalidArgs(format!(
                        "--test-probe-exe is restricted strictly to 'aurora-dummy-probe', got: {}",
                        pb.display()
                    )));
                }
                probe_exe = Some(pb);
            }
            "--test-force-mount-fallback" => {
                force_mount_fallback = true;
            }
            "--test-pdeath-pause" => {
                let s = args.next().ok_or_else(|| {
                    LauncherError::InvalidArgs("Missing stage for --test-pdeath-pause".to_string())
                })?;
                pdeath_pause = Some(PdeathPausePoint::parse(&s)?);
            }
            "--test-pdeath-ack-fd" => {
                pdeath_ack_fd = Some(parse_fd_arg("--test-pdeath-ack-fd", args.next())?);
            }
            "--test-pdeath-go-fd" => {
                pdeath_go_fd = Some(parse_fd_arg("--test-pdeath-go-fd", args.next())?);
            }
            "--test-probe-args" => {
                if probe_exe.is_none() {
                    return Err(LauncherError::InvalidArgs(
                        "--test-probe-args requires --test-probe-exe".to_string(),
                    ));
                }
                for remaining in args.by_ref() {
                    probe_args.push(remaining);
                }
                break;
            }
            other => {
                return Err(LauncherError::InvalidArgs(format!(
                    "Unrecognized or unsupported argument: '{other}'"
                )));
            }
        }
    }

    if (force_mount_fallback
        || pdeath_pause.is_some()
        || pdeath_ack_fd.is_some()
        || pdeath_go_fd.is_some())
        && probe_exe.is_none()
    {
        return Err(LauncherError::InvalidArgs(
            "Test-only flags require --test-probe-exe".to_string(),
        ));
    }

    if (pdeath_ack_fd.is_some() || pdeath_go_fd.is_some()) && pdeath_pause.is_none() {
        return Err(LauncherError::InvalidArgs(
            "--test-pdeath-ack-fd / --test-pdeath-go-fd require --test-pdeath-pause".to_string(),
        ));
    }

    let pdeath_hook = pdeath_pause.map(|pause_point| PdeathTestHook {
        pause_point,
        ack_fd: pdeath_ack_fd,
        go_fd: pdeath_go_fd,
    });

    // In strict mode, if no gate FD was explicitly passed, default to FD 4 (supervisor convention)
    if strict_mode && cgroup_gate_fd.is_none() {
        cgroup_gate_fd = Some(4);
    }

    Ok(LauncherConfig {
        strict_mode,
        cgroup_gate_fd,
        gate_ready_fd,
        app_dir,
        probe_exe,
        probe_args,
        force_mount_fallback,
        pdeath_hook,
    })
}

/// Redirects FD 1 (stdout) to `/dev/null` in production worker mode.
fn redirect_stdout_dev_null() -> Result<(), LauncherError> {
    let dev_null = CString::new("/dev/null").map_err(|e| LauncherError::Io(e.into()))?;
    let fd = unsafe { libc::open(dev_null.as_ptr(), libc::O_WRONLY) };
    if fd < 0 {
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        return Err(LauncherError::Os("open(/dev/null, O_WRONLY)", errno));
    }
    if fd != 1 {
        let ret = unsafe { libc::dup2(fd, 1) };
        unsafe { libc::close(fd) };
        if ret < 0 {
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            return Err(LauncherError::Os("dup2(/dev/null, 1)", errno));
        }
    }
    Ok(())
}

fn handle_launcher_handshake_result(
    res: Result<HandshakeOutcome, LauncherError>,
    signal_ctx: SignalContext,
    child_pid: libc::pid_t,
    sandbox_host_dir: &PathBuf,
) -> ! {
    match res {
        Ok(HandshakeOutcome::ChildTerminated(Some(status))) => {
            let _ = fs::remove_dir(sandbox_host_dir);
            signal_ctx.mirror_exit_status(status);
        }
        Ok(HandshakeOutcome::ChildTerminated(None)) => {
            signal_ctx.reap_blocking_and_mirror(child_pid, sandbox_host_dir);
        }
        Ok(HandshakeOutcome::Completed) => unreachable!(),
        Err(e) => {
            eprintln!("aurora-worker-launcher: parent-death handshake failed: {e}");
            unsafe { libc::kill(child_pid, libc::SIGKILL) };
            let mut status: libc::c_int = 0;
            loop {
                let r = unsafe { libc::waitpid(child_pid, &mut status, 0) };
                if r == child_pid {
                    break;
                }
                let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
                if errno != libc::EINTR {
                    break;
                }
            }
            let _ = fs::remove_dir(sandbox_host_dir);
            process::exit(ERR_PDEATH_FAILED);
        }
    }
}

fn main() {
    let config = match parse_cli_args() {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("aurora-worker-launcher: {e}");
            process::exit(e.exit_code());
        }
    };

    // 1. Launcher-to-supervisor PDEATHSIG with PPID capture before & after to close the install race
    let expected_supervisor_ppid = unsafe { libc::getppid() };
    if let Err(e) = install_pdeathsig_sigkill() {
        eprintln!("aurora-worker-launcher: {e}");
        process::exit(ERR_PDEATH_FAILED);
    }
    let verified_supervisor_ppid = unsafe { libc::getppid() };
    if verified_supervisor_ppid != expected_supervisor_ppid {
        eprintln!(
            "aurora-worker-launcher: parent changed during PDEATHSIG setup ({expected_supervisor_ppid} -> {verified_supervisor_ppid})"
        );
        process::exit(ERR_PDEATH_FAILED);
    }

    // Explicitly set SIGPIPE=SIG_IGN rather than relying on Rust runtime behavior
    if let Err(e) = ensure_sigpipe_ignored() {
        eprintln!("aurora-worker-launcher: {e}");
        process::exit(ERR_PDEATH_FAILED);
    }

    // 2. Initialize signalfd context at FD >= 10 (blocking SIGTERM, SIGINT, SIGCHLD)
    let signal_ctx = match SignalContext::new() {
        Ok(ctx) => ctx,
        Err(e) => {
            eprintln!("aurora-worker-launcher: signal setup failed: {e}");
            process::exit(e.exit_code());
        }
    };

    // 3. Pause at Cgroup startup gate (mandatory in strict mode)
    if let Err(e) = signal_ctx.wait_at_startup_gate(
        config.cgroup_gate_fd,
        config.gate_ready_fd,
        config.strict_mode,
    ) {
        eprintln!("aurora-worker-launcher: startup gate error: {e}");
        match e {
            LauncherError::SignalTerminated(sig) => signal_ctx.raise_and_exit_signal(sig),
            other => process::exit(other.exit_code()),
        }
    }

    // 4. Redirect stdout (FD 1) to /dev/null unless running in controlled Phase 1 test-probe mode
    if config.probe_exe.is_none() {
        if let Err(e) = redirect_stdout_dev_null() {
            eprintln!("aurora-worker-launcher: stdout redirect failed: {e}");
            process::exit(e.exit_code());
        }
    }

    // 5. Capture host UID/GID prior to unsharing user namespace
    let host_uid = unsafe { libc::getuid() };
    let host_gid = unsafe { libc::getgid() };

    if let Err(e) = unshare_user_ns() {
        eprintln!("aurora-worker-launcher: userns unshare failed: {e}");
        process::exit(e.exit_code());
    }
    if let Err(e) = configure_default_idmap(host_uid, host_gid) {
        eprintln!("aurora-worker-launcher: idmap configuration failed: {e}");
        process::exit(e.exit_code());
    }

    // 6. Unshare network namespace
    if let Err(e) = unshare_net_ns() {
        eprintln!("aurora-worker-launcher: netns unshare failed: {e}");
        process::exit(e.exit_code());
    }

    // 7. Unshare PID namespace
    if let Err(e) = unshare_pid_ns() {
        eprintln!("aurora-worker-launcher: pidns unshare failed: {e}");
        process::exit(e.exit_code());
    }

    // 8. Create unique sandbox root mountpoint on host so launcher can clean it up post-exit
    let sandbox_host_dir = match create_unique_sandbox_root() {
        Ok(dir) => dir,
        Err(e) => {
            eprintln!("aurora-worker-launcher: sandbox root creation failed: {e}");
            process::exit(e.exit_code());
        }
    };

    // 9. Establish parent-death synchronization pipes (staged >= 10, relocated to 6..=9)
    let (pdeath_launcher, pdeath_child) = match create_pdeath_pipes() {
        Ok(pipes) => pipes,
        Err(e) => {
            let _ = fs::remove_dir(&sandbox_host_dir);
            eprintln!("aurora-worker-launcher: pdeath pipe creation failed: {e}");
            process::exit(e.exit_code());
        }
    };

    // 10. Fork worker child (becomes PID 1 in new PID namespace)
    let child_pid = unsafe { libc::fork() };
    if child_pid < 0 {
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        let _ = fs::remove_dir(&sandbox_host_dir);
        eprintln!("aurora-worker-launcher: fork failed: errno {errno}");
        process::exit(1);
    }

    if child_pid > 0 {
        // --- LAUNCHER PARENT PROCESS ---
        PdeathLauncher::close_child_ends();

        // Close worker-side IPC stream (FD 0) reference post-fork
        unsafe {
            libc::close(0);
        }

        // Release child-only hook descriptors in launcher if hook belongs to child
        let launcher_hook = config
            .pdeath_hook
            .as_ref()
            .and_then(|h| match h.pause_point {
                PdeathPausePoint::LauncherBeforeEarlyContinue
                | PdeathPausePoint::LauncherBeforeFinalContinue => Some(h),
                _ => {
                    h.close_fds();
                    None
                }
            });

        let sfd = signal_ctx.raw_fd();

        // Stage 1: Early liveness handshake before child begins setup
        match pdeath_launcher.handshake_early(sfd, child_pid, launcher_hook) {
            Ok(HandshakeOutcome::Completed) => {}
            other => {
                if let Some(h) = launcher_hook {
                    h.close_fds();
                }
                handle_launcher_handshake_result(other, signal_ctx, child_pid, &sandbox_host_dir);
            }
        }

        // Stage 2: Authoritative post-credential/capability handshake
        match pdeath_launcher.handshake(sfd, child_pid, launcher_hook) {
            Ok(HandshakeOutcome::Completed) => {}
            other => {
                if let Some(h) = launcher_hook {
                    h.close_fds();
                }
                handle_launcher_handshake_result(other, signal_ctx, child_pid, &sandbox_host_dir);
            }
        }

        if let Some(h) = launcher_hook {
            h.close_fds();
        }

        // Enter proxy reaping and signal mirroring loop
        signal_ctx.proxy_reap_and_mirror(child_pid, &sandbox_host_dir);
    } else {
        // --- WORKER CHILD PROCESS (PID 1 in ns) ---
        PdeathChild::close_launcher_ends();

        let child_hook = config
            .pdeath_hook
            .as_ref()
            .and_then(|h| match h.pause_point {
                PdeathPausePoint::BeforeFirstPdeathsig
                | PdeathPausePoint::AfterFirstPdeathsig
                | PdeathPausePoint::BeforeEarlyContinue => Some(h),
                _ => {
                    h.close_fds();
                    None
                }
            });

        if let Some(h) = child_hook {
            if let Err(e) = h.trigger(PdeathPausePoint::BeforeFirstPdeathsig) {
                eprintln!("aurora-worker-child: pre-pdeathsig test hook failed: {e}");
                process::exit(e.exit_code());
            }
        }

        // 1. Install PR_SET_PDEATHSIG(SIGKILL) immediately after fork, before mountns or rootfs
        if let Err(e) = install_pdeathsig_sigkill() {
            eprintln!("aurora-worker-child: initial PR_SET_PDEATHSIG failed: {e}");
            process::exit(ERR_PDEATH_FAILED);
        }

        // Restore default signal handling and unblock all signals (closes signalfd >= 10)
        // so launcher-forwarded SIGTERM kills child promptly during early setup/handshake.
        if let Err(e) = signal_ctx.restore_for_child() {
            eprintln!("aurora-worker-child: signal restore failed: {e}");
            process::exit(e.exit_code());
        }

        if let Some(h) = child_hook {
            if let Err(e) = h.trigger(PdeathPausePoint::AfterFirstPdeathsig) {
                eprintln!("aurora-worker-child: post-pdeathsig test hook failed: {e}");
                process::exit(e.exit_code());
            }
        }

        // 2. Stage 1 early parent-liveness handshake before mount namespace / rootfs setup
        if let Err(e) = pdeath_child.early_arm_and_handshake(child_hook) {
            eprintln!("aurora-worker-child: early pdeath handshake failed: {e}");
            process::exit(e.exit_code());
        }

        if let Some(h) = child_hook {
            h.close_fds();
        }

        // Capture cap_last_cap before pivot_root + procfs subset=pid hides /proc/sys
        let cap_last_cap = get_cap_last_cap();

        // Unshare independent mount namespace with private propagation
        if let Err(e) = unshare_mount_ns() {
            eprintln!("aurora-worker-child: mountns unshare failed: {e}");
            process::exit(e.exit_code());
        }

        // Verify setup capabilities remain effective before rootfs construction
        if let Err(e) = verify_setup_capabilities_effective() {
            eprintln!("aurora-worker-child: setup caps missing: {e}");
            process::exit(e.exit_code());
        }

        // Construct minimal rootfs, procfs subset=pid, pivot_root, and purge FDs >= 10
        if let Err(e) = construct_and_pivot_rootfs_with_options(
            config.strict_mode,
            &sandbox_host_dir,
            config.app_dir.as_deref(),
            config.probe_exe.as_deref(),
            config.force_mount_fallback,
        ) {
            eprintln!("aurora-worker-child: rootfs construction failed: {e}");
            process::exit(e.exit_code());
        }

        // Purge all 5 capability sets with CAP_SETPCAP dropped last
        if let Err(e) = purge_all_capabilities(cap_last_cap) {
            eprintln!("aurora-worker-child: capability purge failed: {e}");
            process::exit(e.exit_code());
        }

        // Apply permanent security locks (NoNewPrivs, Dumpable=0) and verify pre-exec
        if let Err(e) = apply_security_locks() {
            eprintln!("aurora-worker-child: security locks failed: {e}");
            process::exit(e.exit_code());
        }

        // 3. Stage 2 authoritative re-arm of PR_SET_PDEATHSIG(SIGKILL) and final handshake (closes FDs 7, 8)
        if let Err(e) = pdeath_child.arm_and_handshake() {
            eprintln!("aurora-worker-child: pdeath handshake failed: {e}");
            process::exit(e.exit_code());
        }

        // Explicitly close any remaining unintended inherited descriptors >= 3 before execve
        purge_setup_fds(3);

        // Restore SIGPIPE to SIG_DFL immediately before execve
        if let Err(e) = SignalContext::restore_sigpipe_default() {
            eprintln!("aurora-worker-child: {e}");
            process::exit(e.exit_code());
        }

        // Determine executable path inside sandbox
        let exec_path = if config.probe_exe.is_some() {
            "/probe_bin/probe_target"
        } else {
            "/usr/bin/python3"
        };

        let mut exec_args = Vec::new();
        let Ok(exec_c) = CString::new(exec_path) else {
            process::exit(LauncherError::ExecFailed("invalid exec path".to_string()).exit_code());
        };
        exec_args.push(exec_c.clone());
        for arg in &config.probe_args {
            match CString::new(arg.as_str()) {
                Ok(c) => exec_args.push(c),
                Err(_) => {
                    process::exit(
                        LauncherError::ExecFailed("arg contains interior NUL".to_string())
                            .exit_code(),
                    );
                }
            }
        }

        let mut exec_argv: Vec<*const libc::c_char> =
            exec_args.iter().map(|s| s.as_ptr()).collect();
        exec_argv.push(std::ptr::null());

        let env_clean = [
            CString::new("PYTHONUNBUFFERED=1").unwrap(),
            CString::new("LC_ALL=C.UTF-8").unwrap(),
            CString::new("LANG=C.UTF-8").unwrap(),
        ];
        let mut envp: Vec<*const libc::c_char> = env_clean.iter().map(|s| s.as_ptr()).collect();
        envp.push(std::ptr::null());

        unsafe {
            libc::execve(exec_c.as_ptr(), exec_argv.as_ptr(), envp.as_ptr());
        }

        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        eprintln!("aurora-worker-child: execve failed for {exec_path}: errno {errno}");
        process::exit(LauncherError::ExecFailed(format!("errno {errno}")).exit_code());
    }
}
