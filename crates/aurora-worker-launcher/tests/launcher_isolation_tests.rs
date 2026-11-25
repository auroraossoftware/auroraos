//! Milestone 10c Phase 1 Integration Tests: Native Trusted Launcher Isolation.
//!
//! Verifies:
//! - SEC-REQ-01: Pre-execution isolation (User, Net, Mount, PID namespaces).
//! - SEC-REQ-02: Root filesystem partitioning, read-only bind mounts, `/tmp` noexec, device nodes,
//!   procfs `subset=pid`, and `pivot_root`.
//! - SEC-REQ-03: Descriptor hygiene (FD 6..=9 collision safety, `signalfd` >= 10, no inherited FDs crossing execve).
//! - SEC-REQ-04: Network disconnection (loopback `lo` exists but is DOWN, 0 non-loopback interfaces, `ENETUNREACH`).
//! - SEC-REQ-07: Process isolation (PID 1 in ns, 5 capability sets zeroed, `NoNewPrivs: 1`).
//! - Startup gate: Deterministic pause via gate-readiness acknowledgement; gate termination handling.
//! - Parent-death containment: Actual kernel termination of child via `PR_SET_PDEATHSIG(SIGKILL)`.
//! - Signal forwarding & proxy reaping: Explicit SIGTERM forwarding and exit status mirroring (code 143).

use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

fn get_launcher_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_aurora-worker-launcher"))
}

fn get_dummy_probe_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_aurora-dummy-probe"))
}

/// Helper to create an OS pipe pair returning (reader, writer).
fn create_pipe() -> (File, File) {
    let mut fds = [-1; 2];
    let ret = unsafe { libc::pipe(fds.as_mut_ptr()) };
    assert_eq!(ret, 0, "pipe() failed");
    unsafe { (File::from_raw_fd(fds[0]), File::from_raw_fd(fds[1])) }
}

/// Clears FD_CLOEXEC on specified file descriptors in `pre_exec`.
unsafe fn clear_cloexec(fd: RawFd) {
    let flags = libc::fcntl(fd, libc::F_GETFD);
    if flags >= 0 {
        libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC);
    }
}

/// Spawns `aurora-worker-launcher` in controlled test-probe mode, completes deterministic
/// startup gate acknowledgement, and returns the running child handle.
fn spawn_probe_with_gate(
    probe_name: &str,
    app_dir: Option<&Path>,
    piped_stdout: bool,
) -> (Child, File) {
    let launcher_bin = get_launcher_bin();
    let probe_bin = get_dummy_probe_bin();

    let (gate_r, gate_w) = create_pipe();
    let (mut ready_r, ready_w) = create_pipe();

    let gate_r_fd = gate_r.as_raw_fd();
    let ready_w_fd = ready_w.as_raw_fd();

    let mut cmd = Command::new(&launcher_bin);
    cmd.arg("--strict");
    cmd.arg("--cgroup-gate-fd").arg(gate_r_fd.to_string());
    cmd.arg("--gate-ready-fd").arg(ready_w_fd.to_string());
    if let Some(dir) = app_dir {
        cmd.arg("--app-dir").arg(dir);
    }
    cmd.arg("--test-probe-exe").arg(&probe_bin);
    cmd.arg("--test-probe-args").arg(probe_name);

    if piped_stdout {
        cmd.stdout(Stdio::piped());
    }
    cmd.stderr(Stdio::piped());

    unsafe {
        cmd.pre_exec(move || {
            clear_cloexec(gate_r_fd);
            clear_cloexec(ready_w_fd);
            Ok(())
        });
    }

    let child = cmd.spawn().expect("Failed to spawn launcher");
    drop(gate_r);
    drop(ready_w);

    // Deterministic acknowledgement that launcher is paused at the gate
    let mut ready_buf = [0u8; 1];
    ready_r
        .read_exact(&mut ready_buf)
        .expect("Failed to read GATE_READY acknowledgement from launcher");
    assert_eq!(
        ready_buf[0], 0x01,
        "Expected GATE_READY (0x01) from launcher"
    );

    (child, gate_w)
}

/// Helper to run a dummy probe through the launcher with deterministic startup gate coordination.
fn run_launcher_probe(probe_name: &str, app_dir: Option<&Path>) -> (i32, String) {
    let (child, mut gate_w) = spawn_probe_with_gate(probe_name, app_dir, true);

    gate_w
        .write_all(&[0x01])
        .expect("Failed to write GATE_CONTINUE token to launcher");
    drop(gate_w);

    let output = child
        .wait_with_output()
        .expect("Failed to wait on launcher");
    let stdout_str = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr_str = String::from_utf8_lossy(&output.stderr).to_string();
    let combined = format!("{stdout_str}\n{stderr_str}");
    let exit_code = output.status.code().unwrap_or(-1);

    (exit_code, combined)
}

// ============================================================================
// 1. Startup Gate: Deterministic Pause and Release
// ============================================================================
#[test]
fn test_startup_gate_deterministic_pause_and_release() {
    let (mut child, mut gate_w) = spawn_probe_with_gate("pid1", None, true);

    // Verify launcher is paused waiting for gate token
    assert!(
        child.try_wait().unwrap().is_none(),
        "Launcher should be paused waiting for gate token"
    );

    // Release gate
    gate_w.write_all(&[0x01]).unwrap();
    drop(gate_w);

    // Launcher resumes, executes probe, and exits with 0
    let status = child.wait().expect("wait failed");
    assert!(status.success(), "Expected launcher exit 0, got {status:?}");
}

// ============================================================================
// 2. Startup Gate: Termination Signal Handling while Paused
// ============================================================================
#[test]
fn test_startup_gate_termination_signal_handling() {
    let (mut child, _gate_w) = spawn_probe_with_gate("pid1", None, false);
    let launcher_pid = child.id() as libc::pid_t;

    // Send SIGTERM to launcher while paused at gate
    unsafe { libc::kill(launcher_pid, libc::SIGTERM) };

    // Launcher must exit promptly due to SIGTERM without deadlocking or spawning a child
    let status = child.wait().expect("wait failed");
    assert!(!status.success());
    assert!(find_child_pid_of(launcher_pid).is_none());
}

// ============================================================================
// 3. PID Namespace: Worker Child is PID 1
// ============================================================================
#[test]
fn test_isolation_worker_child_is_pid_1() {
    let (exit_code, output) = run_launcher_probe("pid1", None);
    assert_eq!(
        exit_code, 0,
        "Worker child must be PID 1 in new PID ns. Output: {output}"
    );
    assert!(output.contains("PROBE_PID1_OK"));
}

// ============================================================================
// 4. User Namespace: UID/GID Mapped to 1000
// ============================================================================
#[test]
fn test_isolation_uid_gid_mapped_to_1000() {
    let (exit_code, output) = run_launcher_probe("id", None);
    assert_eq!(
        exit_code, 0,
        "Worker child UID/GID must map to 1000. Output: {output}"
    );
    assert!(output.contains("PROBE_ID_OK"));
}

// ============================================================================
// 5. Capability Purge: All 5 Capability Sets Zeroed
// ============================================================================
#[test]
fn test_isolation_all_five_capability_sets_zeroed() {
    let (exit_code, output) = run_launcher_probe("caps", None);
    assert_eq!(
        exit_code, 0,
        "All 5 capability sets must be 0000000000000000. Output: {output}"
    );
    assert!(output.contains("PROBE_CAPS_OK"));
}

// ============================================================================
// 6. Security Locks: NoNewPrivs=1 Post-Exec
// ============================================================================
#[test]
fn test_isolation_nonewprivs_locked_post_exec() {
    let (exit_code, output) = run_launcher_probe("locks", None);
    assert_eq!(
        exit_code, 0,
        "NoNewPrivs must be 1 post-exec. Output: {output}"
    );
    assert!(output.contains("PROBE_LOCKS_OK"));
}

// ============================================================================
// 7. Private Procfs: subset=pid Hides Host Telemetry
// ============================================================================
#[test]
fn test_isolation_private_procfs_subset_pid() {
    let (exit_code, output) = run_launcher_probe("procfs", None);
    assert_eq!(
        exit_code, 0,
        "Private procfs must expose subset=pid and hide /proc/stat. Output: {output}"
    );
    assert!(output.contains("PROBE_PROCFS_OK"));
}

// ============================================================================
// 8. Root Filesystem: Mountinfo, RO Enforcement, /tmp noexec, Clean FDs
// ============================================================================
#[test]
fn test_isolation_rootfs_pivot_root_detached() {
    let temp_app = std::env::temp_dir().join(format!("aurora-test-app-{}", std::process::id()));
    fs::create_dir_all(&temp_app).expect("Failed to create temp app dir");

    let (exit_code, output) = run_launcher_probe("rootfs", Some(&temp_app));
    let _ = fs::remove_dir_all(&temp_app);

    assert_eq!(
        exit_code, 0,
        "Rootfs confinement checks failed. Output: {output}"
    );
    assert!(output.contains("PROBE_ROOTFS_OK"));
}

// ============================================================================
// 9. Device Mounts: /dev/null RW; /dev/zero, /dev/urandom, /dev/random RO & Readable
// ============================================================================
#[test]
fn test_isolation_device_mounts_rw_and_ro() {
    let (exit_code, output) = run_launcher_probe("devices", None);
    assert_eq!(exit_code, 0, "Device mount checks failed. Output: {output}");
    assert!(output.contains("PROBE_DEVICES_OK"));
}

// ============================================================================
// 10. Network Isolation: Loopback lo is DOWN; 0 Non-Loopback; ENETUNREACH
// ============================================================================
#[test]
fn test_isolation_network_disconnected_and_lo_down() {
    let (exit_code, output) = run_launcher_probe("network", None);
    assert_eq!(
        exit_code, 0,
        "Network namespace must contain only 'lo' in DOWN state. Output: {output}"
    );
    assert!(output.contains("PROBE_NETWORK_OK"));
}

// ============================================================================
// 11. Signal Forwarding & Proxy Reaping: Deterministic Readiness + Status 143
// ============================================================================
#[test]
fn test_signal_forwarding_and_exit_mirroring() {
    let (mut child, mut gate_w) = spawn_probe_with_gate("sigterm", None, true);
    let launcher_pid = child.id() as libc::pid_t;

    gate_w.write_all(&[0x01]).unwrap();
    drop(gate_w);

    // Wait deterministically for probe child to emit PROBE_SIGTERM_READY
    let stdout = child.stdout.take().expect("stdout piped");
    let mut reader = BufReader::new(stdout);
    let mut ready_line = String::new();
    reader
        .read_line(&mut ready_line)
        .expect("Failed to read PROBE_SIGTERM_READY from child");
    assert!(
        ready_line.contains("PROBE_SIGTERM_READY"),
        "Child did not reach ready state before SIGTERM: '{ready_line}'"
    );

    // Send SIGTERM to the launcher process
    unsafe { libc::kill(launcher_pid, libc::SIGTERM) };

    // Launcher forwards SIGTERM to child; child exits 143; launcher mirrors 143
    let status = child.wait().expect("Failed to wait on launcher");
    let exit_code = status.code().unwrap_or(-1);

    assert_eq!(
        exit_code, 143,
        "Launcher must mirror child's clean SIGTERM exit status 143 (got {exit_code})"
    );
}

// ============================================================================
// 12. Strict Mode: Mandatory Cgroup Startup Gate (Explicit Invalid & Default FD 4)
// ============================================================================
#[test]
fn test_strict_mode_cgroup_gate_mandatory() {
    let launcher_bin = get_launcher_bin();
    let probe_bin = get_dummy_probe_bin();

    // 1. Explicit invalid gate FD (999)
    let output = Command::new(&launcher_bin)
        .arg("--strict")
        .arg("--cgroup-gate-fd")
        .arg("999")
        .arg("--test-probe-exe")
        .arg(&probe_bin)
        .arg("--test-probe-args")
        .arg("pid1")
        .output()
        .expect("Failed to execute launcher");

    assert_eq!(
        output.status.code(),
        Some(72), // ERR_CGROUP_GATE_MISSING
        "Launcher must refuse startup with ERR_CGROUP_GATE_MISSING (72) if gate FD is invalid"
    );

    // 2. Default FD 4 closed in strict mode
    let output_default = Command::new(&launcher_bin)
        .arg("--strict")
        .arg("--test-probe-exe")
        .arg(&probe_bin)
        .arg("--test-probe-args")
        .arg("pid1")
        .output()
        .expect("Failed to execute launcher");

    assert_eq!(
        output_default.status.code(),
        Some(72), // ERR_CGROUP_GATE_MISSING
        "Launcher must refuse startup when default FD 4 is absent in strict mode"
    );
}

// ============================================================================
// 13. Actual Parent-Death Termination: Deterministic Readiness + Non-Vacuous Check
// ============================================================================
#[test]
fn test_actual_parent_death_termination() {
    let (mut child, mut gate_w) = spawn_probe_with_gate("sleep-forever", None, true);
    let launcher_pid = child.id() as libc::pid_t;

    gate_w.write_all(&[0x01]).unwrap();
    drop(gate_w);

    // Wait deterministically for child to complete setup, pdeath handshake, and exec
    let stdout = child.stdout.take().expect("stdout piped");
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    let n = reader
        .read_line(&mut line)
        .expect("Failed to read PROBE_SLEEPING from child");
    assert!(
        n > 0 && line.contains("PROBE_SLEEPING"),
        "Child never reached PROBE_SLEEPING (read {n} bytes: '{line}')"
    );

    // Child must actually exist under launcher before killing launcher
    let cp = find_child_pid_of(launcher_pid)
        .expect("Expected active worker child process under launcher before SIGKILL");

    // Send abrupt SIGKILL to launcher
    unsafe { libc::kill(launcher_pid, libc::SIGKILL) };
    let _ = child.wait();

    // Verify actual child process terminated via PR_SET_PDEATHSIG(SIGKILL) within <= 1.0s
    let deadline = Instant::now() + Duration::from_millis(1000);
    let mut terminated = false;
    while Instant::now() < deadline {
        if !PathBuf::from(format!("/proc/{cp}")).exists() {
            terminated = true;
            break;
        }
        thread::sleep(Duration::from_millis(20));
    }
    assert!(
        terminated,
        "Child process {cp} must be terminated by PDEATHSIG after launcher SIGKILL"
    );
}

// ============================================================================
// 14. Regression: Occupied FDs 6..=9 and 11 Do Not Break signalfd / pdeath / execve
// ============================================================================
#[test]
fn test_fd_collision_regression_occupying_fds_6_to_9() {
    let launcher_bin = get_launcher_bin();
    let probe_bin = get_dummy_probe_bin();

    // Case A: Occupy FDs 6, 7, 8, 9, 11 and run sigterm probe (tests signalfd + pdeath + mirroring)
    let (gate_r, mut gate_w) = create_pipe();
    let (mut ready_r, ready_w) = create_pipe();
    let (dummy_r, dummy_w) = create_pipe();

    let gate_r_fd = gate_r.as_raw_fd();
    let ready_w_fd = ready_w.as_raw_fd();
    let dummy_r_fd = dummy_r.as_raw_fd();
    let dummy_w_fd = dummy_w.as_raw_fd();

    let mut cmd = Command::new(&launcher_bin);
    cmd.arg("--strict");
    cmd.arg("--cgroup-gate-fd").arg("4");
    cmd.arg("--gate-ready-fd").arg("5");
    cmd.arg("--test-probe-exe").arg(&probe_bin);
    cmd.arg("--test-probe-args").arg("sigterm");
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    unsafe {
        cmd.pre_exec(move || {
            // Stage source descriptors >= 20 so dup2 targets 4..=11 cannot collide with sources
            let s_gate = libc::fcntl(gate_r_fd, libc::F_DUPFD_CLOEXEC, 20);
            let s_ready = libc::fcntl(ready_w_fd, libc::F_DUPFD_CLOEXEC, 20);
            let s_dr = libc::fcntl(dummy_r_fd, libc::F_DUPFD_CLOEXEC, 20);
            let s_dw = libc::fcntl(dummy_w_fd, libc::F_DUPFD_CLOEXEC, 20);
            if s_gate < 0 || s_ready < 0 || s_dr < 0 || s_dw < 0 {
                return Err(std::io::Error::last_os_error());
            }

            libc::dup2(s_gate, 4);
            libc::dup2(s_ready, 5);
            clear_cloexec(4);
            clear_cloexec(5);

            // Deliberately occupy FDs 3, 6, 7, 8, 9 and 11 with inherited descriptors
            for target_fd in [3, 6, 7, 8, 9, 11] {
                let src = if target_fd % 2 == 0 { s_dr } else { s_dw };
                libc::dup2(src, target_fd);
                clear_cloexec(target_fd);
            }
            Ok(())
        });
    }

    let mut child = cmd.spawn().expect("Failed to spawn launcher");
    let launcher_pid = child.id() as libc::pid_t;
    drop(gate_r);
    drop(ready_w);
    drop(dummy_r);
    drop(dummy_w);

    let mut ready_buf = [0u8; 1];
    ready_r.read_exact(&mut ready_buf).unwrap();
    assert_eq!(ready_buf[0], 0x01);

    gate_w.write_all(&[0x01]).unwrap();
    drop(gate_w);

    // Wait for child readiness (proves pdeath handshake succeeded despite FDs 6..=9 being occupied)
    let stdout = child.stdout.take().expect("stdout piped");
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    let n = reader
        .read_line(&mut line)
        .expect("Failed to read PROBE_SIGTERM_READY");
    assert!(
        n > 0 && line.contains("PROBE_SIGTERM_READY"),
        "Probe failed with occupied FDs 6..=9: '{line}'"
    );

    // Send SIGTERM (proves signalfd was NOT clobbered by pdeath relocation to 6..=9)
    unsafe { libc::kill(launcher_pid, libc::SIGTERM) };
    let status = child.wait().expect("wait failed");
    assert_eq!(status.code(), Some(143));

    // Case B: Occupy FDs 3, 6..=9, 11 and run rootfs probe (verifies none cross execve)
    let temp_app = std::env::temp_dir().join(format!("aurora-test-fd-app-{}", std::process::id()));
    fs::create_dir_all(&temp_app).expect("Failed to create temp app dir");

    let (gate_r2, mut gate_w2) = create_pipe();
    let (mut ready_r2, ready_w2) = create_pipe();
    let (dummy_r2, dummy_w2) = create_pipe();
    let g2 = gate_r2.as_raw_fd();
    let r2 = ready_w2.as_raw_fd();
    let dr2 = dummy_r2.as_raw_fd();
    let dw2 = dummy_w2.as_raw_fd();

    let mut cmd2 = Command::new(&launcher_bin);
    cmd2.arg("--strict");
    cmd2.arg("--cgroup-gate-fd").arg("4");
    cmd2.arg("--gate-ready-fd").arg("5");
    cmd2.arg("--app-dir").arg(&temp_app);
    cmd2.arg("--test-probe-exe").arg(&probe_bin);
    cmd2.arg("--test-probe-args").arg("rootfs");
    cmd2.stdout(Stdio::piped());
    cmd2.stderr(Stdio::piped());

    unsafe {
        cmd2.pre_exec(move || {
            let s_gate = libc::fcntl(g2, libc::F_DUPFD_CLOEXEC, 20);
            let s_ready = libc::fcntl(r2, libc::F_DUPFD_CLOEXEC, 20);
            let s_dr = libc::fcntl(dr2, libc::F_DUPFD_CLOEXEC, 20);
            let s_dw = libc::fcntl(dw2, libc::F_DUPFD_CLOEXEC, 20);
            if s_gate < 0 || s_ready < 0 || s_dr < 0 || s_dw < 0 {
                return Err(std::io::Error::last_os_error());
            }
            libc::dup2(s_gate, 4);
            libc::dup2(s_ready, 5);
            clear_cloexec(4);
            clear_cloexec(5);
            for target_fd in [3, 6, 7, 8, 9, 11] {
                let src = if target_fd % 2 == 0 { s_dr } else { s_dw };
                libc::dup2(src, target_fd);
                clear_cloexec(target_fd);
            }
            Ok(())
        });
    }

    let child2 = cmd2.spawn().expect("Failed to spawn launcher case B");
    drop(gate_r2);
    drop(ready_w2);
    drop(dummy_r2);
    drop(dummy_w2);

    let mut rb2 = [0u8; 1];
    ready_r2.read_exact(&mut rb2).unwrap();
    gate_w2.write_all(&[0x01]).unwrap();
    drop(gate_w2);

    let out2 = child2.wait_with_output().expect("wait case B failed");
    let _ = fs::remove_dir_all(&temp_app);
    assert_eq!(
        out2.status.code(),
        Some(0),
        "Occupied FDs leaked or broke rootfs probe: stdout={}, stderr={}",
        String::from_utf8_lossy(&out2.stdout),
        String::from_utf8_lossy(&out2.stderr)
    );
}

// ============================================================================
// 15. CLI Hardening: Arbitrary Executables & Malformed FD Arguments Rejected
// ============================================================================
#[test]
fn test_cli_rejects_arbitrary_executables_and_malformed_fds() {
    let launcher_bin = get_launcher_bin();

    // 1. Reject arbitrary binary passed via --test-probe-exe
    let out_arb = Command::new(&launcher_bin)
        .arg("--test-probe-exe")
        .arg("/bin/sh")
        .output()
        .expect("Failed to run launcher");
    assert_eq!(out_arb.status.code(), Some(2));

    // 2. Reject positional executable argument
    let out_pos = Command::new(&launcher_bin)
        .arg("/bin/sh")
        .output()
        .expect("Failed to run launcher");
    assert_eq!(out_pos.status.code(), Some(2));

    // 3. Reject malformed --cgroup-gate-fd
    let out_fd = Command::new(&launcher_bin)
        .arg("--cgroup-gate-fd")
        .arg("not_an_fd")
        .output()
        .expect("Failed to run launcher");
    assert_eq!(out_fd.status.code(), Some(2));

    // 4. Reject test-only flags without --test-probe-exe
    let out_fb = Command::new(&launcher_bin)
        .arg("--test-force-mount-fallback")
        .output()
        .expect("Failed to run launcher");
    assert_eq!(out_fb.status.code(), Some(2));

    let out_hook = Command::new(&launcher_bin)
        .arg("--test-pdeath-pause")
        .arg("before-first-pdeathsig")
        .output()
        .expect("Failed to run launcher");
    assert_eq!(out_hook.status.code(), Some(2));
}

/// Spawns `aurora-worker-launcher` configured with a `--test-pdeath-pause` barrier,
/// releases the cgroup startup gate deterministically, waits for the hook acknowledgement byte,
/// and returns `(launcher_child, ack_r, go_w)` so the caller controls exact continuation timing.
fn spawn_with_pdeath_barrier(stage: &str, probe_name: &str) -> (Child, File, File) {
    let launcher_bin = get_launcher_bin();
    let probe_bin = get_dummy_probe_bin();

    let (gate_r, mut gate_w) = create_pipe();
    let (mut ready_r, ready_w) = create_pipe();
    let (mut ack_r, ack_w) = create_pipe();
    let (go_r, go_w) = create_pipe();

    let gate_r_fd = gate_r.as_raw_fd();
    let ready_w_fd = ready_w.as_raw_fd();
    let ack_w_fd = ack_w.as_raw_fd();
    let go_r_fd = go_r.as_raw_fd();

    let mut cmd = Command::new(&launcher_bin);
    cmd.arg("--strict");
    cmd.arg("--cgroup-gate-fd").arg(gate_r_fd.to_string());
    cmd.arg("--gate-ready-fd").arg(ready_w_fd.to_string());
    cmd.arg("--test-pdeath-pause").arg(stage);
    cmd.arg("--test-pdeath-ack-fd").arg(ack_w_fd.to_string());
    cmd.arg("--test-pdeath-go-fd").arg(go_r_fd.to_string());
    cmd.arg("--test-probe-exe").arg(&probe_bin);
    cmd.arg("--test-probe-args").arg(probe_name);
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    unsafe {
        cmd.pre_exec(move || {
            clear_cloexec(gate_r_fd);
            clear_cloexec(ready_w_fd);
            clear_cloexec(ack_w_fd);
            clear_cloexec(go_r_fd);
            Ok(())
        });
    }

    let child = cmd.spawn().expect("Failed to spawn launcher with barrier");
    drop(gate_r);
    drop(ready_w);
    drop(ack_w);
    drop(go_r);

    let mut ready_buf = [0u8; 1];
    ready_r
        .read_exact(&mut ready_buf)
        .expect("Failed to read GATE_READY");
    assert_eq!(ready_buf[0], 0x01);

    gate_w
        .write_all(&[0x01])
        .expect("Failed to release startup gate");
    drop(gate_w);

    let mut ack_buf = [0u8; 1];
    ack_r
        .read_exact(&mut ack_buf)
        .expect("Failed to read barrier ack from launcher/child");
    assert_eq!(ack_buf[0], 0x01);

    (child, ack_r, go_w)
}

fn assert_pid_terminates(pid: libc::pid_t, context: &str) {
    let deadline = Instant::now() + Duration::from_millis(1500);
    while Instant::now() < deadline {
        if !PathBuf::from(format!("/proc/{pid}")).exists() {
            return;
        }
        thread::sleep(Duration::from_millis(10));
    }
    panic!("Child PID {pid} survived unexpectedly: {context}");
}

// ============================================================================
// 16. Deterministic Parent-Death Race Tests (All Early & Late Windows)
// ============================================================================
#[test]
fn test_pdeath_launcher_death_before_first_pdeathsig() {
    let (mut launcher, _ack_r, mut go_w) =
        spawn_with_pdeath_barrier("before-first-pdeathsig", "sleep-forever");
    let launcher_pid = launcher.id() as libc::pid_t;
    let child_pid =
        find_child_pid_of(launcher_pid).expect("Expected worker child paused before PDEATHSIG");

    // Kill launcher BEFORE child installs its first PR_SET_PDEATHSIG(SIGKILL)
    unsafe { libc::kill(launcher_pid, libc::SIGKILL) };
    let _ = launcher.wait();

    // Release child barrier so it attempts first PDEATHSIG + early handshake; EPIPE/EOF must fail closed
    let _ = go_w.write_all(&[0x01]);
    drop(go_w);

    assert_pid_terminates(child_pid, "launcher killed before child first PDEATHSIG");
}

#[test]
fn test_pdeath_launcher_death_immediately_after_first_pdeathsig() {
    let (mut launcher, _ack_r, go_w) =
        spawn_with_pdeath_barrier("after-first-pdeathsig", "sleep-forever");
    let launcher_pid = launcher.id() as libc::pid_t;
    let child_pid = find_child_pid_of(launcher_pid)
        .expect("Expected worker child paused after first PDEATHSIG");

    // Keep go_w OPEN so child stays blocked unless kernel PR_SET_PDEATHSIG(SIGKILL) kills it
    unsafe { libc::kill(launcher_pid, libc::SIGKILL) };
    let _ = launcher.wait();

    assert_pid_terminates(
        child_pid,
        "launcher killed immediately after child first PDEATHSIG",
    );
    drop(go_w);
}

#[test]
fn test_pdeath_launcher_death_before_early_continuation() {
    let (mut launcher, _ack_r, go_w) =
        spawn_with_pdeath_barrier("launcher-before-early-continue", "sleep-forever");
    let launcher_pid = launcher.id() as libc::pid_t;
    let child_pid = find_child_pid_of(launcher_pid)
        .expect("Expected worker child blocked awaiting TOKEN_EARLY_CONTINUE");

    // Kill launcher while it holds off sending TOKEN_EARLY_CONTINUE
    unsafe { libc::kill(launcher_pid, libc::SIGKILL) };
    let _ = launcher.wait();
    drop(go_w);

    assert_pid_terminates(
        child_pid,
        "launcher killed before early-handshake continuation",
    );
}

#[test]
fn test_pdeath_launcher_death_during_later_handshake() {
    let (mut launcher, _ack_r, go_w) =
        spawn_with_pdeath_barrier("launcher-before-final-continue", "sleep-forever");
    let launcher_pid = launcher.id() as libc::pid_t;
    let child_pid = find_child_pid_of(launcher_pid)
        .expect("Expected worker child blocked awaiting final TOKEN_CONTINUE");

    // Kill launcher during Stage 2 post-caps/locks handshake
    unsafe { libc::kill(launcher_pid, libc::SIGKILL) };
    let _ = launcher.wait();
    drop(go_w);

    assert_pid_terminates(child_pid, "launcher killed during Stage 2 handshake");
}

#[test]
fn test_pdeath_sigterm_while_child_handshake_waiting() {
    // Child pauses before TOKEN_EARLY_ARMED with go_w held open; launcher polls [c2l_r, signalfd]
    let (mut launcher, _ack_r, go_w) =
        spawn_with_pdeath_barrier("after-first-pdeathsig", "sleep-forever");
    let launcher_pid = launcher.id() as libc::pid_t;
    let child_pid = find_child_pid_of(launcher_pid)
        .expect("Expected worker child paused while launcher handshake waits");

    // Send SIGTERM to launcher while PdeathLauncher::handshake_early() is waiting
    unsafe { libc::kill(launcher_pid, libc::SIGTERM) };
    let status = launcher.wait().expect("wait on launcher failed");

    assert_eq!(
        status.code(),
        Some(143),
        "Launcher must forward SIGTERM from handshake poll to PID 1 child and mirror status 143 (status={status:?})"
    );
    assert_pid_terminates(
        child_pid,
        "child killed by launcher-forwarded SIGTERM during handshake",
    );
    drop(go_w);
}

// ============================================================================
// 17. Recursive Subtree Mount & Forced Compatibility Fallback Tests (User+Mount NS)
// ============================================================================
fn run_nested_mount_scenario(
    force_fallback: bool,
    stacked_duplicate: bool,
    probe_name: &str,
) -> (i32, String) {
    use std::ffi::CString;

    let launcher_bin = get_launcher_bin();
    let probe_bin = get_dummy_probe_bin();
    let (mut out_r, mut out_w) = create_pipe();

    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork failed");
    if pid == 0 {
        drop(out_r);
        let run = || -> Result<(i32, String), String> {
            let host_uid = unsafe { libc::getuid() };
            let host_gid = unsafe { libc::getgid() };
            if unsafe { libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNS) } != 0 {
                return Err(format!(
                    "unshare(NEWUSER|NEWNS) failed: {}",
                    std::io::Error::last_os_error()
                ));
            }
            fs::write("/proc/self/uid_map", format!("1000 {host_uid} 1\n"))
                .map_err(|e| format!("uid_map: {e}"))?;
            fs::write("/proc/self/setgroups", "deny\n").map_err(|e| format!("setgroups: {e}"))?;
            fs::write("/proc/self/gid_map", format!("1000 {host_gid} 1\n"))
                .map_err(|e| format!("gid_map: {e}"))?;

            let slash = CString::new("/").unwrap();
            if unsafe {
                libc::mount(
                    std::ptr::null(),
                    slash.as_ptr(),
                    std::ptr::null(),
                    libc::MS_REC | libc::MS_PRIVATE,
                    std::ptr::null(),
                )
            } != 0
            {
                return Err(format!(
                    "MS_PRIVATE on / failed: {}",
                    std::io::Error::last_os_error()
                ));
            }

            let app_root = std::env::temp_dir().join(format!(
                "aurora-nested-app-{}-{force_fallback}-{stacked_duplicate}",
                std::process::id()
            ));
            fs::create_dir_all(&app_root).map_err(|e| format!("mkdir app_root: {e}"))?;
            let tmpfs = CString::new("tmpfs").unwrap();
            let app_c = CString::new(app_root.to_str().unwrap()).unwrap();
            if unsafe {
                libc::mount(
                    tmpfs.as_ptr(),
                    app_c.as_ptr(),
                    tmpfs.as_ptr(),
                    0,
                    std::ptr::null(),
                )
            } != 0
            {
                return Err(format!(
                    "mount tmpfs app_root failed: {}",
                    std::io::Error::last_os_error()
                ));
            }

            if stacked_duplicate {
                let stacked = app_root.join("stacked");
                fs::create_dir_all(&stacked).map_err(|e| format!("mkdir stacked: {e}"))?;
                let st_c = CString::new(stacked.to_str().unwrap()).unwrap();
                for _ in 0..2 {
                    if unsafe {
                        libc::mount(
                            tmpfs.as_ptr(),
                            st_c.as_ptr(),
                            tmpfs.as_ptr(),
                            libc::MS_NOEXEC,
                            std::ptr::null(),
                        )
                    } != 0
                    {
                        return Err(format!(
                            "stacked tmpfs mount failed: {}",
                            std::io::Error::last_os_error()
                        ));
                    }
                }
            } else {
                // Include a space in mountpoint name so octal path decoding (\040) is exercised
                let nested = app_root.join("nested ro data");
                fs::create_dir_all(&nested).map_err(|e| format!("mkdir nested: {e}"))?;
                let nested_c = CString::new(nested.to_str().unwrap()).unwrap();
                const MS_NOSYMFOLLOW_FLAG: libc::c_ulong = 256;
                const MS_NOATIME_FLAG: libc::c_ulong = 1024;
                if unsafe {
                    libc::mount(
                        tmpfs.as_ptr(),
                        nested_c.as_ptr(),
                        tmpfs.as_ptr(),
                        libc::MS_NOEXEC | MS_NOSYMFOLLOW_FLAG | MS_NOATIME_FLAG,
                        std::ptr::null(),
                    )
                } != 0
                {
                    return Err(format!(
                        "nested tmpfs mount failed: {}",
                        std::io::Error::last_os_error()
                    ));
                }
            }

            let (gate_r, mut gate_w) = create_pipe();
            let (mut ready_r, ready_w) = create_pipe();
            let gate_r_fd = gate_r.as_raw_fd();
            let ready_w_fd = ready_w.as_raw_fd();

            let mut cmd = Command::new(&launcher_bin);
            cmd.arg("--strict");
            cmd.arg("--cgroup-gate-fd").arg(gate_r_fd.to_string());
            cmd.arg("--gate-ready-fd").arg(ready_w_fd.to_string());
            if force_fallback {
                cmd.arg("--test-force-mount-fallback");
            }
            cmd.arg("--app-dir").arg(&app_root);
            cmd.arg("--test-probe-exe").arg(&probe_bin);
            cmd.arg("--test-probe-args").arg(probe_name);
            cmd.stdout(Stdio::piped());
            cmd.stderr(Stdio::piped());

            unsafe {
                cmd.pre_exec(move || {
                    clear_cloexec(gate_r_fd);
                    clear_cloexec(ready_w_fd);
                    Ok(())
                });
            }

            let child = cmd.spawn().map_err(|e| format!("spawn launcher: {e}"))?;
            drop(gate_r);
            drop(ready_w);

            let mut ready_buf = [0u8; 1];
            ready_r
                .read_exact(&mut ready_buf)
                .map_err(|e| format!("ready_r: {e}"))?;
            gate_w
                .write_all(&[0x01])
                .map_err(|e| format!("gate_w: {e}"))?;
            drop(gate_w);

            let output = child.wait_with_output().map_err(|e| format!("wait: {e}"))?;
            let code = output.status.code().unwrap_or(-1);
            let combined = format!(
                "{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            let _ = unsafe { libc::umount2(app_c.as_ptr(), libc::MNT_DETACH) };
            let _ = fs::remove_dir_all(&app_root);
            Ok((code, combined))
        };

        match run() {
            Ok((code, text)) => {
                let payload = format!("{code}\n{text}");
                let _ = out_w.write_all(payload.as_bytes());
                drop(out_w);
                unsafe { libc::_exit(0) };
            }
            Err(err) => {
                let payload = format!("-99\nFIXTURE_ERR: {err}");
                let _ = out_w.write_all(payload.as_bytes());
                drop(out_w);
                unsafe { libc::_exit(1) };
            }
        }
    }

    drop(out_w);
    let mut raw = String::new();
    out_r.read_to_string(&mut raw).unwrap();
    let mut status: libc::c_int = 0;
    unsafe { libc::waitpid(pid, &mut status, 0) };

    let mut lines = raw.splitn(2, '\n');
    let code = lines
        .next()
        .and_then(|s| s.trim().parse::<i32>().ok())
        .unwrap_or(-1);
    let text = lines.next().unwrap_or("").to_string();
    (code, text)
}

#[test]
fn test_recursive_mount_nested_child_preferred_mount_setattr() {
    let (code, output) = run_nested_mount_scenario(false, false, "rootfs-nested");
    assert_eq!(
        code, 0,
        "Preferred mount_setattr(AT_RECURSIVE) nested mount check failed: {output}"
    );
    assert!(output.contains("PROBE_ROOTFS_NESTED_OK"));
}

#[test]
fn test_recursive_mount_nested_child_forced_compatibility_fallback() {
    let (code, output) = run_nested_mount_scenario(true, false, "rootfs-nested");
    assert_eq!(
        code, 0,
        "Forced compatibility fallback nested mount check failed: {output}"
    );
    assert!(output.contains("PROBE_ROOTFS_NESTED_OK"));
}

#[test]
fn test_recursive_mount_stacked_duplicate_mountpoint_refuses_startup_and_mirrors_code() {
    // Tests both stacked-mount detection (ERR_ROOTFS_FAILED = 74) AND child-reaping race fix
    // (launcher waits via blocking waitpid on pipe EOF and mirrors 74 instead of 77).
    for force_fallback in [false, true] {
        let (code, output) = run_nested_mount_scenario(force_fallback, true, "rootfs");
        assert_eq!(
            code, 74,
            "Stacked duplicate mountpoint must fail closed with ERR_ROOTFS_FAILED (74) (force_fallback={force_fallback}): {output}"
        );
    }
}

/// Helper to inspect `/proc/<parent_pid>/task/<tid>/children` or `/proc` to find child PID.
fn find_child_pid_of(parent_pid: libc::pid_t) -> Option<libc::pid_t> {
    let children_path = format!("/proc/{parent_pid}/task/{parent_pid}/children");
    if let Ok(content) = fs::read_to_string(&children_path) {
        if let Some(first_pid) = content.split_whitespace().next() {
            if let Ok(p) = first_pid.parse::<libc::pid_t>() {
                return Some(p);
            }
        }
    }

    if let Ok(entries) = fs::read_dir("/proc") {
        for entry in entries.flatten() {
            if let Ok(name) = entry.file_name().into_string() {
                if let Ok(pid) = name.parse::<libc::pid_t>() {
                    let status_path = format!("/proc/{pid}/status");
                    if let Ok(status) = fs::read_to_string(status_path) {
                        for line in status.lines() {
                            if let Some(ppid_str) = line.strip_prefix("PPid:\t") {
                                if ppid_str.trim() == parent_pid.to_string() {
                                    return Some(pid);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    None
}
