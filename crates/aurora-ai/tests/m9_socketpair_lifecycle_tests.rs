//! Milestone 9 Socketpair IPC & Worker Lifecycle Management Integration Tests.
//!
//! Pursuant to ADR-003 and Milestone 9 specifications, this suite verifies:
//! - M9-IPC-01: Nominal socketpair handshake over FD 0; diskless operation (0 files on disk).
//! - M9-IPC-02: 512 KiB framing limit over socketpair (+1 byte drops connection).
//! - M9-RECOV-01: Idle worker crash detection via poll_status().
//! - M9-RECOV-02: Active turn crash returns WorkerTerminatedDuringTurn; 0 capabilities replayed.
//! - M9-RECOV-03: Lazy recovery on next request succeeds with fresh socketpair.
//! - M9-RECOV-04: Idle crash followed immediately by execute_turn() triggers lazy recovery.
//! - M9-LIMIT-01: Exactly 3 consecutive failed replacement attempts latch supervisor into Degraded.
//! - M9-LIMIT-02: Flapping worker counter resets strictly after healthy window.
//! - M9-SHUT-01: Orderly signal shutdown (EOF -> clean worker exit -> child reaped).
//! - M9-SHUT-02: Escalation to SIGTERM/SIGKILL for unresponsive worker.
//! - M9-SHUT-03: Abrupt daemon SIGKILL terminates worker via PR_SET_PDEATHSIG(SIGKILL) within <= 1.0s.
//! - M9-SIGINT-01: Active turn interruption via SIGINT cancels turn, reaps worker, no hang.
//! - M9-LEAK-01: Descriptor leak invariance across 10 restart cycles.
//! - M9-REG-01: All 4 MVP capabilities regression over socketpair.

use aurora_ai::ipc::IpcError;
use aurora_ai::provider::MockCpuProvider;
use aurora_ai::{
    CallerIdentity, CapabilityDispatcher, PolicyEngine, SupervisorConfig, SupervisorError,
    WorkerState, WorkerStatus, WorkerSupervisor,
};
use aurora_protocol::TurnStatus;
use std::collections::HashSet;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

static SERIALIZE_TESTS: Mutex<()> = Mutex::new(());

fn lock_test_guard() -> std::sync::MutexGuard<'static, ()> {
    SERIALIZE_TESTS.lock().unwrap_or_else(|e| e.into_inner())
}

fn get_workspace_root() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .map(|p| p.to_path_buf())
        .unwrap_or(manifest_dir)
}

fn create_test_config() -> SupervisorConfig {
    let unique_id = std::process::id();
    let thread_id = format!("{:?}", std::thread::current().id());
    let sanitized_thread_id = thread_id.replace(|c: char| !c.is_alphanumeric(), "");
    let dummy_socket_path = std::env::temp_dir().join(format!(
        "aurora-m9-dummy-{unique_id}-{sanitized_thread_id}.sock"
    ));
    let mut config = SupervisorConfig::default().with_socket_path(dummy_socket_path);
    config.working_dir = Some(get_workspace_root());
    config.handshake_timeout = Duration::from_secs(5);
    config.socket_timeout = Duration::from_secs(5);
    config.restart_backoff_base = Duration::from_millis(20);
    config
}

/// Helper to read all persistent open file descriptors for a given process (or self).
fn get_process_persistent_fds(pid: Option<u32>) -> Result<HashSet<(u32, String)>, String> {
    let proc_fd_dir = match pid {
        Some(p) => format!("/proc/{p}/fd"),
        None => "/proc/self/fd".to_string(),
    };

    if !std::path::Path::new(&proc_fd_dir).exists() {
        return Err(format!(
            "Environment limitation: {proc_fd_dir} does not exist"
        ));
    }

    let entries = match fs::read_dir(&proc_fd_dir) {
        Ok(e) => e,
        Err(e) => return Err(format!("Failed to read {proc_fd_dir}: {e}")),
    };

    let mut fds = HashSet::new();
    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        let file_name = entry.file_name();
        let name_str = match file_name.to_str() {
            Some(s) => s,
            None => continue,
        };
        let fd_num: u32 = match name_str.parse() {
            Ok(n) => n,
            Err(_) => continue,
        };

        let link_path = format!("{proc_fd_dir}/{fd_num}");
        let link_target = match fs::read_link(&link_path) {
            Ok(p) => p.to_string_lossy().to_string(),
            Err(_) => continue,
        };

        if link_target.contains("/proc/") && link_target.contains("/fd") {
            continue;
        }

        fds.insert((fd_num, link_target));
    }

    Ok(fds)
}

// ============================================================================
// M9-IPC-01: Nominal socketpair handshake over FD 0; diskless operation
// ============================================================================
#[test]
fn test_m9_ipc_01_nominal_socketpair_handshake_and_disklessness() {
    let _guard = lock_test_guard();
    let config = create_test_config();
    let dummy_path = config.socket_path.clone();

    let mut supervisor = WorkerSupervisor::new(config);
    supervisor.start().expect("Supervisor start failed");

    // 1. Handshake verified
    assert_eq!(supervisor.state(), WorkerState::Ready);
    assert_eq!(supervisor.worker_version(), Some("0.1.0"));
    assert!(supervisor.worker_pid().is_some());

    // 2. Poll status shows running
    let status = supervisor.poll_status().expect("poll_status failed");
    assert_eq!(status, WorkerStatus::Running);

    // 3. Diskless invariance: socketpair operates in kernel memory, never creating socket files
    assert!(!supervisor.owns_socket());
    assert!(
        !dummy_path.exists(),
        "Socketpair transport must never create socket files on disk"
    );

    // 4. Clean shutdown
    supervisor.shutdown();
    assert_eq!(supervisor.state(), WorkerState::Terminated);
    assert!(!dummy_path.exists());
}

// ============================================================================
// M9-IPC-02: 512 KiB framing limit over socketpair (+1 byte drops connection)
// ============================================================================
#[test]
fn test_m9_ipc_02_framing_limit_512k_over_socketpair() {
    let _guard = lock_test_guard();
    let (daemon_stream, mut worker_stream) = UnixStream::pair().expect("socketpair failed");
    let mut reader = BufReader::new(daemon_stream);

    // 1. Frame exactly at limit (512 KiB = 524,288 bytes including trailing newline)
    let boundary_size = 524_288;
    let mut exact_frame = vec![b'a'; boundary_size - 1];
    exact_frame.push(b'\n');
    assert_eq!(exact_frame.len(), boundary_size);

    // Write in background thread to avoid deadlocking on kernel socket buffer capacity (~208 KiB)
    let handle = std::thread::spawn(move || {
        worker_stream.write_all(&exact_frame).expect("write failed");
        worker_stream
    });

    let line = aurora_ai::ipc::read_bounded_line(&mut reader, boundary_size)
        .expect("read failed")
        .expect("expected line");
    assert_eq!(line.len(), boundary_size);
    let mut worker_stream = handle.join().unwrap();

    // 2. Frame exceeding limit by 1 byte (524,289 bytes)
    let mut oversized_frame = vec![b'b'; boundary_size];
    oversized_frame.push(b'\n');
    assert_eq!(oversized_frame.len(), boundary_size + 1);

    let handle2 = std::thread::spawn(move || {
        let _ = worker_stream.write_all(&oversized_frame);
    });

    let err = aurora_ai::ipc::read_bounded_line(&mut reader, boundary_size).unwrap_err();
    match err {
        IpcError::FrameTooLarge => {}
        other => panic!("Expected FrameTooLarge, got: {other:?}"),
    }
    let _ = handle2.join();
}

// ============================================================================
// M9-RECOV-01: Idle worker crash detection via poll_status()
// ============================================================================
#[test]
fn test_m9_recov_01_idle_worker_crash_detection_via_poll_status() {
    let _guard = lock_test_guard();
    let config = create_test_config();
    let mut supervisor = WorkerSupervisor::new(config);
    supervisor.start().expect("Supervisor start failed");

    let pid = supervisor.worker_pid().expect("Worker PID must exist");
    assert_eq!(supervisor.poll_status().unwrap(), WorkerStatus::Running);

    // Kill idle worker child with SIGKILL
    unsafe {
        libc::kill(pid as libc::pid_t, libc::SIGKILL);
    }
    std::thread::sleep(Duration::from_millis(50));

    // poll_status() detects termination and reaps zombie child
    let status = supervisor.poll_status().expect("poll_status failed");
    assert!(
        matches!(
            status,
            WorkerStatus::Terminated(_) | WorkerStatus::Disconnected
        ),
        "Expected Terminated or Disconnected status, got: {status:?}"
    );

    // State transitions to Recovering
    assert_eq!(supervisor.state(), WorkerState::Recovering);
    supervisor.shutdown();
}

// ============================================================================
// M9-RECOV-02: Active turn crash returns WorkerTerminatedDuringTurn; 0 proposals replayed
// ============================================================================
#[test]
fn test_m9_recov_02_active_turn_crash_no_replay() {
    let _guard = lock_test_guard();
    let mut config = create_test_config();

    // Custom worker script: performs handshake, accepts RequestTurn, proposes sys.cpu.read,
    // receives CapabilityResult, then immediately exits with status 42 (crash mid-turn).
    config.worker_command = vec![
        "python3".to_string(),
        "-c".to_string(),
        r#"
import socket, sys, json, os

s = socket.fromfd(0, socket.AF_UNIX, socket.SOCK_STREAM)
os.close(0)
sf = s.makefile('rwb')

# 1. Handshake
line = sf.readline()
msg = json.loads(line)
sf.write(json.dumps({
    "type": "handshake_response",
    "protocol_version": 1,
    "worker_version": "0.1.0",
    "status": "ready"
}).encode('utf-8') + b'\n')
sf.flush()

# 2. Receive RequestTurn
line = sf.readline()
req = json.loads(line)
turn_id = req["turn_id"]

# 3. Propose sys.cpu.read
sf.write(json.dumps({
    "type": "propose_capability",
    "protocol_version": 1,
    "turn_id": turn_id,
    "call_id": "call-1",
    "capability_name": "sys.cpu.read",
    "parameters": {}
}).encode('utf-8') + b'\n')
sf.flush()

# 4. Receive CapabilityResult
res_line = sf.readline()

# 5. Crash immediately mid-turn without sending CompleteTurn
os._exit(42)
"#
        .to_string(),
    ];

    let mock_cpu = std::sync::Arc::new(MockCpuProvider::with_success(serde_json::json!({
        "cpu_count": 4,
        "usage_percent": 12.5
    })));

    let mut policy_engine = PolicyEngine::new_mvp(config.demo_sandbox_path.clone());
    let caller = CallerIdentity::principal("test-user");
    policy_engine.grant(caller.clone(), "sys.cpu.read");
    let dispatcher = CapabilityDispatcher::new(policy_engine, mock_cpu.clone());

    let mut supervisor = WorkerSupervisor::with_dispatcher(config, dispatcher);
    supervisor.start().expect("Supervisor start failed");

    let result = supervisor.execute_turn(&caller, "Analyze CPU metrics");
    assert!(result.is_err(), "Expected turn failure on worker crash");

    match result {
        Err(SupervisorError::WorkerTerminatedDuringTurn {
            turn_id,
            completed_proposals,
            exit_code,
        }) => {
            assert_eq!(turn_id, "turn-1");
            assert_eq!(completed_proposals, vec!["sys.cpu.read"]);
            assert_eq!(exit_code, Some(42));
        }
        other => panic!("Expected WorkerTerminatedDuringTurn, got: {other:?}"),
    }

    // Invariant: mock provider was executed exactly once; zero silent replays occurred
    assert_eq!(mock_cpu.invocation_count(), 1);
    assert_eq!(supervisor.state(), WorkerState::Recovering);

    supervisor.shutdown();
}

// ============================================================================
// M9-RECOV-03: Lazy recovery on next request succeeds
// ============================================================================
#[test]
fn test_m9_recov_03_lazy_recovery_on_next_request() {
    let _guard = lock_test_guard();
    let config = create_test_config();
    let mut supervisor = WorkerSupervisor::new(config);
    let caller = CallerIdentity::principal("user");
    supervisor
        .policy_engine_mut()
        .grant(caller.clone(), "sys.cpu.read");

    supervisor.start().expect("Supervisor start failed");
    let pid1 = supervisor.worker_pid().expect("Worker PID 1 must exist");

    // Execute first turn successfully
    let turn1 = supervisor
        .execute_turn(&caller, "Check CPU usage")
        .expect("Turn 1 failed");
    assert_eq!(turn1.status, TurnStatus::Success);

    // Crash the worker process abruptly
    unsafe {
        libc::kill(pid1 as libc::pid_t, libc::SIGKILL);
    }
    std::thread::sleep(Duration::from_millis(50));

    // Poll status triggers detection and transitions to Recovering
    let status = supervisor.poll_status().expect("poll_status failed");
    assert!(matches!(
        status,
        WorkerStatus::Terminated(_) | WorkerStatus::Disconnected
    ));
    assert_eq!(supervisor.state(), WorkerState::Recovering);

    // Next turn transparently triggers lazy recovery (new socketpair + child spawn + handshake)
    let turn2 = supervisor
        .execute_turn(&caller, "Check CPU usage again")
        .expect("Turn 2 lazy recovery failed");
    assert_eq!(turn2.status, TurnStatus::Success);
    assert_eq!(supervisor.state(), WorkerState::Ready);

    let pid2 = supervisor.worker_pid().expect("Worker PID 2 must exist");
    assert_ne!(pid1, pid2, "Replacement worker must have a distinct PID");

    supervisor.shutdown();
}

// ============================================================================
// M9-RECOV-04: Idle crash followed immediately by execute_turn() triggers lazy recovery
// ============================================================================
#[test]
fn test_m9_recov_04_idle_crash_followed_by_execute_turn_recovers() {
    let _guard = lock_test_guard();
    let config = create_test_config();
    let mut supervisor = WorkerSupervisor::new(config);
    let caller = CallerIdentity::principal("user");
    supervisor
        .policy_engine_mut()
        .grant(caller.clone(), "sys.cpu.read");

    supervisor.start().expect("Supervisor start failed");
    let pid1 = supervisor.worker_pid().expect("Worker PID 1 must exist");

    // Kill idle worker child without calling poll_status()
    unsafe {
        libc::kill(pid1 as libc::pid_t, libc::SIGKILL);
    }
    std::thread::sleep(Duration::from_millis(50));

    // Immediate execute_turn() detects dead worker in pre-turn check and performs lazy restart
    let turn = supervisor
        .execute_turn(&caller, "Check CPU metrics")
        .expect("Turn recovery failed");
    assert_eq!(turn.status, TurnStatus::Success);
    assert_eq!(supervisor.state(), WorkerState::Ready);

    let pid2 = supervisor.worker_pid().expect("Worker PID 2 must exist");
    assert_ne!(pid1, pid2);

    supervisor.shutdown();
}

// ============================================================================
// M9-LIMIT-01: Exactly 3 consecutive failed replacement attempts latch supervisor into Degraded
// ============================================================================
#[test]
fn test_m9_limit_01_three_consecutive_failed_replacements_transitions_to_degraded() {
    let _guard = lock_test_guard();
    let mut config = create_test_config();
    // Use short healthy window and short backoff for fast deterministic test
    config.healthy_reset_window = Duration::from_millis(100);
    config.restart_backoff_base = Duration::from_millis(10);
    config.max_consecutive_restarts = 3;

    let mut supervisor = WorkerSupervisor::new(config);
    let caller = CallerIdentity::principal("user");
    supervisor
        .policy_engine_mut()
        .grant(caller.clone(), "sys.cpu.read");

    supervisor.start().expect("Supervisor start failed");
    // Wait past healthy window so initial worker failure is not penalized as replacement failure
    std::thread::sleep(Duration::from_millis(120));

    let pid = supervisor.worker_pid().expect("Worker PID must exist");
    unsafe {
        libc::kill(pid as libc::pid_t, libc::SIGKILL);
    }
    std::thread::sleep(Duration::from_millis(50));

    let _ = supervisor.poll_status();
    assert_eq!(supervisor.state(), WorkerState::Recovering);
    assert_eq!(supervisor.consecutive_restarts(), 0);

    // Reconfigure command to a failing command to simulate failed replacement attempts
    supervisor.config_mut().worker_command = vec![
        "python3".to_string(),
        "-c".to_string(),
        "import sys; sys.exit(1)".to_string(),
    ];

    // Replacement Attempt 1/3 fails
    let res1 = supervisor.execute_turn(&caller, "prompt 1");
    assert!(res1.is_err());
    assert_eq!(supervisor.consecutive_restarts(), 1);
    assert_eq!(supervisor.state(), WorkerState::Recovering);

    // Replacement Attempt 2/3 fails
    let res2 = supervisor.execute_turn(&caller, "prompt 2");
    assert!(res2.is_err());
    assert_eq!(supervisor.consecutive_restarts(), 2);
    assert_eq!(supervisor.state(), WorkerState::Recovering);

    // Replacement Attempt 3/3 fails -> transitions strictly into Degraded
    let res3 = supervisor.execute_turn(&caller, "prompt 3");
    assert!(res3.is_err());
    assert_eq!(supervisor.consecutive_restarts(), 3);
    assert_eq!(supervisor.state(), WorkerState::Degraded);

    // Subsequent turn attempts fail closed immediately without spawning child
    let res4 = supervisor.execute_turn(&caller, "prompt 4");
    match res4 {
        Err(SupervisorError::WorkerRestartLimitExceeded) => {}
        other => panic!("Expected WorkerRestartLimitExceeded, got: {other:?}"),
    }
    assert_eq!(supervisor.poll_status().unwrap(), WorkerStatus::Degraded);

    // Reset API restores supervisor when valid command is re-supplied
    supervisor.config_mut().worker_command = vec![
        "python3".to_string(),
        "-m".to_string(),
        "worker.main".to_string(),
    ];
    supervisor.reset().expect("Operator reset must succeed");
    assert_eq!(supervisor.state(), WorkerState::Ready);
    assert_eq!(supervisor.consecutive_restarts(), 0);

    supervisor.shutdown();
}

// ============================================================================
// M9-LIMIT-02: Flapping worker counter reset strictly after 10s healthy window
// ============================================================================
#[test]
fn test_m9_limit_02_flapping_worker_healthy_window_reset() {
    let _guard = lock_test_guard();
    let mut config = create_test_config();
    // Test with 200ms healthy window for deterministic test speed
    config.healthy_reset_window = Duration::from_millis(200);
    config.restart_backoff_base = Duration::from_millis(10);
    config.max_consecutive_restarts = 3;

    let mut supervisor = WorkerSupervisor::new(config);
    let caller = CallerIdentity::principal("user");
    supervisor
        .policy_engine_mut()
        .grant(caller.clone(), "sys.cpu.read");

    supervisor.start().expect("Supervisor start failed");
    // Initial worker crashes immediately (within 200ms)
    let pid1 = supervisor.worker_pid().expect("PID 1 must exist");
    unsafe {
        libc::kill(pid1 as libc::pid_t, libc::SIGKILL);
    }
    std::thread::sleep(Duration::from_millis(20));

    // Recovery replaces worker -> Attempt 1
    let turn1 = supervisor
        .execute_turn(&caller, "turn 1")
        .expect("turn 1 failed");
    assert_eq!(turn1.status, TurnStatus::Success);
    assert_eq!(supervisor.consecutive_restarts(), 1);

    // Worker remains healthy past healthy_reset_window (250ms > 200ms)
    std::thread::sleep(Duration::from_millis(250));

    // Next turn or status check observes healthy window elapsed and resets consecutive_restarts to 0
    let status = supervisor.poll_status().expect("poll_status failed");
    assert_eq!(status, WorkerStatus::Running);
    assert_eq!(supervisor.consecutive_restarts(), 0);

    supervisor.shutdown();
}

// ============================================================================
// M9-SHUT-01: Orderly signal shutdown (EOF -> clean worker exit -> child reaped)
// ============================================================================
#[test]
fn test_m9_shut_01_orderly_eof_shutdown_and_reap() {
    let _guard = lock_test_guard();
    let config = create_test_config();
    let mut supervisor = WorkerSupervisor::new(config);
    supervisor.start().expect("Supervisor start failed");

    let pid = supervisor.worker_pid().expect("PID must exist");

    // Invocate shutdown: drops socket endpoint, closing stream (EOF)
    supervisor.shutdown();
    assert_eq!(supervisor.state(), WorkerState::Terminated);

    // Verify child process was reaped and no zombie remains
    unsafe {
        let res = libc::kill(pid as libc::pid_t, 0);
        assert_eq!(
            res, -1,
            "Reaped process must not accept signals; expected ESRCH"
        );
        let err = std::io::Error::last_os_error();
        assert_eq!(err.raw_os_error(), Some(libc::ESRCH));
    }
}

// ============================================================================
// M9-SHUT-02: Escalation to SIGTERM/SIGKILL for unresponsive worker
// ============================================================================
#[test]
fn test_m9_shut_02_escalation_to_sigterm_and_sigkill() {
    let _guard = lock_test_guard();
    let mut config = create_test_config();

    // Worker script that ignores SIGTERM and loops indefinitely on EOF
    config.worker_command = vec![
        "python3".to_string(),
        "-c".to_string(),
        r#"
import socket, sys, json, time, signal, os

signal.signal(signal.SIGTERM, signal.SIG_IGN)
s = socket.fromfd(0, socket.AF_UNIX, socket.SOCK_STREAM)
os.close(0)
sf = s.makefile('rwb')

line = sf.readline()
sf.write(json.dumps({
    "type": "handshake_response",
    "protocol_version": 1,
    "worker_version": "stub-unresponsive",
    "status": "ready"
}).encode('utf-8') + b'\n')
sf.flush()

# Stubborn loop: ignores EOF, ignores SIGTERM
while True:
    try:
        data = sf.readline()
        if not data:
            time.sleep(0.05)
    except Exception:
        time.sleep(0.05)
"#
        .to_string(),
    ];

    let mut supervisor = WorkerSupervisor::new(config);
    supervisor.start().expect("Supervisor start failed");
    let pid = supervisor.worker_pid().expect("PID must exist");

    let shutdown_start = Instant::now();
    // shutdown() escalates: EOF (200ms) -> SIGTERM (300ms) -> SIGKILL -> mandatory wait()
    supervisor.shutdown();
    let elapsed = shutdown_start.elapsed();

    // Verify escalation completed within expected time window (~500ms to 2s)
    assert!(
        elapsed >= Duration::from_millis(500),
        "Shutdown must give graceful stages opportunity before SIGKILL"
    );
    assert!(
        elapsed < Duration::from_secs(3),
        "Shutdown escalation must complete within bounded deadline"
    );

    // Verify stubborn worker child was terminated and reaped
    unsafe {
        let res = libc::kill(pid as libc::pid_t, 0);
        assert_eq!(res, -1);
        let err = std::io::Error::last_os_error();
        assert_eq!(err.raw_os_error(), Some(libc::ESRCH));
    }
}

// ============================================================================
// M9-SHUT-03: Abrupt daemon SIGKILL terminates worker via PR_SET_PDEATHSIG
// ============================================================================
#[test]
fn test_m9_shut_03_abrupt_daemon_sigkill_terminates_worker_via_pdeathsig() {
    let _guard = lock_test_guard();
    let workspace_root = get_workspace_root();
    let binary_path = env!("CARGO_BIN_EXE_aurora-ai");

    // Spawn daemon process running supervision loop for 60 seconds
    let mut daemon_cmd = Command::new(binary_path);
    daemon_cmd
        .current_dir(&workspace_root)
        .arg("--duration")
        .arg("60")
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());

    let mut daemon_child = daemon_cmd
        .spawn()
        .expect("Failed to spawn aurora-ai daemon");
    let daemon_pid = daemon_child.id() as libc::pid_t;

    let stdout = daemon_child.stdout.take().expect("Child stdout missing");
    let mut reader = BufReader::new(stdout);

    // Read lines until daemon reports worker child PID
    let mut worker_pid: Option<u32> = None;
    let start_wait = Instant::now();
    while start_wait.elapsed() < Duration::from_secs(5) {
        let mut line = String::new();
        if let Ok(n) = reader.read_line(&mut line) {
            if n == 0 {
                break;
            }
            if line.contains("Worker child PID:") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if let Some(last) = parts.last() {
                    if let Ok(pid) = last.parse::<u32>() {
                        worker_pid = Some(pid);
                        break;
                    }
                }
            }
        }
    }

    let worker_pid = worker_pid.expect("Failed to capture worker PID from daemon stdout");

    // Verify worker child is currently running
    unsafe {
        let check = libc::kill(worker_pid as libc::pid_t, 0);
        assert_eq!(check, 0, "Worker must be alive before daemon SIGKILL");
    }

    // Abruptly kill the daemon process with SIGKILL (no clean supervisor shutdown)
    unsafe {
        libc::kill(daemon_pid, libc::SIGKILL);
    }
    let _ = daemon_child.wait();

    // Verify worker process terminates via PR_SET_PDEATHSIG within bounded deadline (<= 1.0s)
    let pdeath_start = Instant::now();
    let mut worker_dead = false;
    while pdeath_start.elapsed() < Duration::from_secs(1) {
        unsafe {
            if libc::kill(worker_pid as libc::pid_t, 0) != 0 {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::ESRCH) {
                    worker_dead = true;
                    break;
                }
            }
        }
        std::thread::sleep(Duration::from_millis(20));
    }

    assert!(
        worker_dead,
        "Worker child must terminate via PR_SET_PDEATHSIG within 1.0s of daemon SIGKILL"
    );
}

// ============================================================================
// M9-SIGINT-01: Active turn interruption via SIGINT cancels turn, reaps worker, no hang
// ============================================================================
#[test]
fn test_m9_sigint_01_active_turn_sigint_interruption_no_hang() {
    let _guard = lock_test_guard();
    let mut config = create_test_config();
    config.socket_timeout = Duration::from_millis(300);

    // Worker that sleeps during turn execution
    config.worker_command = vec![
        "python3".to_string(),
        "-c".to_string(),
        r#"
import socket, sys, json, time, os

s = socket.fromfd(0, socket.AF_UNIX, socket.SOCK_STREAM)
os.close(0)
sf = s.makefile('rwb')

line = sf.readline()
sf.write(json.dumps({
    "type": "handshake_response",
    "protocol_version": 1,
    "worker_version": "stub-sleep",
    "status": "ready"
}).encode('utf-8') + b'\n')
sf.flush()

line = sf.readline()
time.sleep(5)
"#
        .to_string(),
    ];

    let mut supervisor = WorkerSupervisor::new(config);
    let caller = CallerIdentity::principal("user");
    supervisor.start().expect("Supervisor start failed");

    let pid = supervisor.worker_pid().expect("PID must exist");
    let owner_pthread = unsafe { libc::pthread_self() };

    // Spawn a background sender to deliver SIGINT to the supervisor thread
    let bg_sender = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(50));
        unsafe {
            libc::pthread_kill(owner_pthread, libc::SIGINT);
        }
    });

    let turn_start = Instant::now();
    let res = supervisor.execute_turn(&caller, "prompt");
    let elapsed = turn_start.elapsed();
    let _ = bg_sender.join();

    assert!(res.is_err());
    match res {
        Err(SupervisorError::Interrupted) => {}
        other => panic!("Expected SupervisorError::Interrupted, got: {other:?}"),
    }
    assert!(
        elapsed < Duration::from_secs(2),
        "Signal-interrupted turn must fail within bounded deadline: {elapsed:?}"
    );

    // Verify supervisor shuts down and cleans up worker without hanging
    supervisor.shutdown();
    unsafe {
        let check = libc::kill(pid as libc::pid_t, 0);
        assert_eq!(check, -1);
    }
}

// ============================================================================
// M9-DESC-01: Low-descriptor safety edge case (allocations <= 2 moved to >= 3)
// ============================================================================
#[test]
fn test_m9_low_descriptor_safety_edge_case() {
    let _guard = lock_test_guard();
    let (s1, _s2) = UnixStream::pair().expect("socketpair failed");
    let above_stdio = aurora_ai::supervisor::ensure_fd_above_stdio(s1).expect("ensure failed");
    assert!(
        above_stdio.as_raw_fd() >= 3,
        "Descriptor must be >= 3, got: {}",
        above_stdio.as_raw_fd()
    );
}

// ============================================================================
// M9-LEAK-01: Descriptor leak invariance across 10 restart cycles
// ============================================================================
#[test]
fn test_m9_leak_01_descriptor_leak_invariance_across_10_restart_cycles() {
    let _guard = lock_test_guard();
    let mut config = create_test_config();
    config.max_consecutive_restarts = 15;
    config.healthy_reset_window = Duration::from_millis(10);
    let mut supervisor = WorkerSupervisor::new(config);
    let caller = CallerIdentity::principal("user");
    supervisor
        .policy_engine_mut()
        .grant(caller.clone(), "sys.cpu.read");

    supervisor.start().expect("Supervisor start failed");

    // Warm up initial turn
    let _ = supervisor
        .execute_turn(&caller, "warmup turn")
        .expect("warmup failed");

    // Baseline descriptor snapshot
    let baseline_fds = get_process_persistent_fds(None).expect("Failed to read baseline FDs");
    let baseline_fd_nums: HashSet<u32> = baseline_fds.iter().map(|(fd, _)| *fd).collect();

    // Execute 10 crash and lazy restart cycles
    for i in 0..10 {
        let pid = supervisor.worker_pid().expect("Worker PID must exist");
        unsafe {
            libc::kill(pid as libc::pid_t, libc::SIGKILL);
        }
        std::thread::sleep(Duration::from_millis(30));

        let turn = supervisor
            .execute_turn(&caller, &format!("turn cycle {i}"))
            .unwrap_or_else(|e| panic!("Cycle {i} failed: {e:?}"));
        assert_eq!(turn.status, TurnStatus::Success);
    }

    // Final descriptor snapshot: open descriptor numbers must remain invariant
    let final_fds = get_process_persistent_fds(None).expect("Failed to read final FDs");
    let final_fd_nums: HashSet<u32> = final_fds.iter().map(|(fd, _)| *fd).collect();

    assert_eq!(
        final_fd_nums,
        baseline_fd_nums,
        "Descriptor set grew across 10 restart cycles (leak detected): new FDs: {:?}",
        final_fd_nums.difference(&baseline_fd_nums)
    );

    supervisor.shutdown();
}

// ============================================================================
// M9-REG-01: All 4 MVP capabilities regression over socketpair
// ============================================================================
#[test]
fn test_m9_reg_01_all_four_mvp_capabilities_regression_over_socketpair() {
    let _guard = lock_test_guard();
    let config = create_test_config();
    let mut supervisor = WorkerSupervisor::new(config);
    let caller = CallerIdentity::principal("test-user");

    // Grant all 4 MVP capabilities
    supervisor
        .policy_engine_mut()
        .grant(caller.clone(), "sys.cpu.read");
    supervisor
        .policy_engine_mut()
        .grant(caller.clone(), "sys.memory.read");
    supervisor
        .policy_engine_mut()
        .grant(caller.clone(), "proc.list");
    supervisor
        .policy_engine_mut()
        .grant(caller.clone(), "fs.file.read");

    supervisor.start().expect("Supervisor start failed");

    // 1. sys.cpu.read
    let turn_cpu = supervisor
        .execute_turn(&caller, "Report current host CPU telemetry metrics")
        .expect("CPU capability failed");
    assert_eq!(turn_cpu.status, TurnStatus::Success);
    assert!(
        turn_cpu.response_text.contains("cpu")
            || turn_cpu.response_text.contains("CPU")
            || turn_cpu.response_text.contains("%"),
        "CPU response text: {}",
        turn_cpu.response_text
    );

    // 2. sys.memory.read
    let turn_mem = supervisor
        .execute_turn(&caller, "Report current system memory metrics")
        .expect("Memory capability failed");
    assert_eq!(turn_mem.status, TurnStatus::Success);
    assert!(
        turn_mem.response_text.contains("Memory")
            || turn_mem.response_text.contains("memory")
            || turn_mem.response_text.contains("MB"),
        "Memory response text: {}",
        turn_mem.response_text
    );

    // 3. proc.list
    let turn_proc = supervisor
        .execute_turn(&caller, "list running processes limit 5")
        .expect("Process capability failed");
    assert_eq!(turn_proc.status, TurnStatus::Success);
    assert!(
        turn_proc.response_text.contains("Process")
            || turn_proc.response_text.contains("process")
            || turn_proc.response_text.contains("PID"),
        "Process response text: {}",
        turn_proc.response_text
    );

    // 4. fs.file.read
    let demo_sandbox = supervisor.config().demo_sandbox_path.clone();
    fs::create_dir_all(&demo_sandbox).expect("create demo sandbox failed");
    let test_file = demo_sandbox.join("sample.txt");
    fs::write(&test_file, "AURORA_DEMO_CONTENT_M9").expect("write test file failed");

    let turn_fs = supervisor
        .execute_turn(&caller, "read sample.txt")
        .expect("File capability failed");
    assert_eq!(turn_fs.status, TurnStatus::Success);
    assert!(
        turn_fs.response_text.contains("AURORA_DEMO_CONTENT_M9"),
        "FS response text: {}",
        turn_fs.response_text
    );

    let _ = fs::remove_file(&test_file);
    supervisor.shutdown();
}
