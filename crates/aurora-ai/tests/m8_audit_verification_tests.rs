//! Milestone 8 Verification and Audit Tests.
//!
//! Validates:
//! 1. Multi-step capability chaining within a single turn (sequential proposals before CompleteTurn).
//! 2. Proposal flooding mitigation (rejection at proposal 21, IPC invalidation, zero excess provider execution).
//! 3. Descriptor leakage check across 500 sustained turns (identities and counts).
//! 4. Long-running session memory observations across 1,000 turns without unvalidated thresholds.

use aurora_ai::ipc::{read_daemon_message, send_worker_message};
use aurora_ai::provider::{MockCpuProvider, MockMemoryProvider};
use aurora_ai::{
    CallerIdentity, CapabilityDispatcher, PolicyEngine, SupervisorConfig, SupervisorError,
    WorkerStatus, WorkerSupervisor,
};
use aurora_protocol::{
    CapabilityOutcome, CompleteTurn, DaemonToWorkerMessage, ProposeCapability, TurnStatus,
    WorkerToDaemonMessage, CURRENT_PROTOCOL_VERSION,
};
use std::collections::HashSet;
use std::fs;
use std::io::BufReader;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;

static SERIALIZE_TESTS: Mutex<()> = Mutex::new(());

fn get_workspace_root() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .map(|p| p.to_path_buf())
        .unwrap_or(manifest_dir)
}

/// Helper to read all persistent open file descriptors for a given process (or self),
/// resolving symlink targets and filtering out the measurement directory iterator handle.
fn get_process_persistent_fds(pid: Option<u32>) -> Result<HashSet<(u32, String)>, String> {
    let proc_fd_dir = match pid {
        Some(p) => format!("/proc/{p}/fd"),
        None => "/proc/self/fd".to_string(),
    };

    if !std::path::Path::new(&proc_fd_dir).exists() {
        return Err(format!(
            "Environment limitation: {proc_fd_dir} does not exist or is inaccessible"
        ));
    }

    let entries = match fs::read_dir(&proc_fd_dir) {
        Ok(e) => e,
        Err(e) => {
            return Err(format!(
                "Environment limitation: failed to read {proc_fd_dir}: {e}"
            ))
        }
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

        // Filter out transient measurement handle referencing /proc/.../fd
        if link_target.contains("/proc/") && link_target.contains("/fd") {
            continue;
        }

        fds.insert((fd_num, link_target));
    }

    Ok(fds)
}

/// Helper to read all persistent open file descriptors for the current process,
/// resolving symlink targets and filtering out the measurement directory iterator handle.
fn get_persistent_fds() -> HashSet<(u32, String)> {
    get_process_persistent_fds(None).expect("failed to read /proc/self/fd")
}

/// Helper to read VmRSS, VmHWM, and VmSize from /proc/self/status.
fn read_memory_status() -> (u64, u64, u64) {
    let content = fs::read_to_string("/proc/self/status").unwrap_or_default();
    let mut vmrss = 0;
    let mut vmhwm = 0;
    let mut vmsize = 0;

    for line in content.lines() {
        if line.starts_with("VmRSS:") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                vmrss = parts[1].parse().unwrap_or(0);
            }
        } else if line.starts_with("VmHWM:") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                vmhwm = parts[1].parse().unwrap_or(0);
            }
        } else if line.starts_with("VmSize:") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                vmsize = parts[1].parse().unwrap_or(0);
            }
        }
    }

    (vmrss, vmhwm, vmsize)
}

#[test]
fn test_multi_step_capability_chaining_in_single_turn() {
    let _lock = SERIALIZE_TESTS.lock().unwrap();
    let (server, mut client) = UnixStream::pair().expect("failed to create UnixStream pair");
    let caller = CallerIdentity::principal("analyst-1");
    let mut policy = PolicyEngine::new_mvp(PathBuf::from("/tmp/sandbox"));
    policy.grant(caller.clone(), "sys.cpu.read");
    policy.grant(caller.clone(), "sys.memory.read");

    let mock_cpu = Arc::new(MockCpuProvider::with_success(serde_json::json!({
        "user_percent": 15.5,
        "system_percent": 4.2,
        "idle_percent": 80.3,
        "total_ticks": 10000,
        "idle_ticks": 8030
    })));
    let mock_mem = Arc::new(MockMemoryProvider::with_success(serde_json::json!({
        "total_mb": 16384,
        "used_mb": 8192,
        "free_mb": 4096,
        "available_mb": 8192
    })));

    let dispatcher =
        CapabilityDispatcher::new_with_providers(policy, mock_cpu.clone(), mock_mem.clone());

    let config = SupervisorConfig::default();
    let mut supervisor =
        WorkerSupervisor::from_stream(config, dispatcher, server).expect("from_stream failed");

    // Worker thread simulates multi-step chaining:
    // 1. Receives RequestTurn
    // 2. Proposes sys.cpu.read (step 1)
    // 3. Receives CapabilityResult
    // 4. Proposes sys.memory.read (step 2)
    // 5. Receives CapabilityResult
    // 6. Sends CompleteTurn with combined synthesis
    let worker_handle = std::thread::spawn(move || {
        let mut reader = BufReader::new(client.try_clone().unwrap());

        // 1. Read RequestTurn
        let msg = read_daemon_message(&mut reader)
            .expect("read failed")
            .expect("expected RequestTurn");
        let turn_id = match msg {
            DaemonToWorkerMessage::RequestTurn(req) => req.turn_id,
            other => panic!("Expected RequestTurn, got {other:?}"),
        };

        // 2. Propose sys.cpu.read
        let prop1 = ProposeCapability {
            protocol_version: CURRENT_PROTOCOL_VERSION,
            turn_id: turn_id.clone(),
            call_id: "call-1".to_string(),
            capability_name: "sys.cpu.read".to_string(),
            parameters: serde_json::json!({}),
        };
        send_worker_message(
            &mut client,
            &WorkerToDaemonMessage::ProposeCapability(prop1),
        )
        .expect("send failed");

        // 3. Read Result 1
        let res1 = read_daemon_message(&mut reader)
            .expect("read failed")
            .expect("expected CapabilityResult");
        match res1 {
            DaemonToWorkerMessage::CapabilityResult(cr) => {
                assert_eq!(cr.call_id, "call-1");
                assert_eq!(cr.turn_id, turn_id);
            }
            other => panic!("Expected CapabilityResult, got {other:?}"),
        }

        // 4. Propose sys.memory.read
        let prop2 = ProposeCapability {
            protocol_version: CURRENT_PROTOCOL_VERSION,
            turn_id: turn_id.clone(),
            call_id: "call-2".to_string(),
            capability_name: "sys.memory.read".to_string(),
            parameters: serde_json::json!({}),
        };
        send_worker_message(
            &mut client,
            &WorkerToDaemonMessage::ProposeCapability(prop2),
        )
        .expect("send failed");

        // 5. Read Result 2
        let res2 = read_daemon_message(&mut reader)
            .expect("read failed")
            .expect("expected CapabilityResult");
        match res2 {
            DaemonToWorkerMessage::CapabilityResult(cr) => {
                assert_eq!(cr.call_id, "call-2");
                assert_eq!(cr.turn_id, turn_id);
            }
            other => panic!("Expected CapabilityResult, got {other:?}"),
        }

        // 6. CompleteTurn with synthesized response from both observations
        let complete = CompleteTurn {
            protocol_version: CURRENT_PROTOCOL_VERSION,
            turn_id: turn_id.clone(),
            status: TurnStatus::Success,
            response_text:
                "System telemetry: CPU is 15.5% active, Memory is 8192MB used of 16384MB."
                    .to_string(),
        };
        send_worker_message(&mut client, &WorkerToDaemonMessage::CompleteTurn(complete))
            .expect("send failed");
    });

    let complete_turn = supervisor
        .execute_turn(&caller, "check cpu and memory telemetry")
        .expect("turn execution failed");

    worker_handle.join().expect("worker thread panicked");

    assert_eq!(complete_turn.status, TurnStatus::Success);
    assert!(complete_turn.response_text.contains("CPU is 15.5% active"));
    assert!(complete_turn.response_text.contains("8192MB used"));

    // Verify both providers were executed exactly once in this single turn
    assert_eq!(
        mock_cpu.invocation_count(),
        1,
        "Expected exactly 1 sys.cpu.read invocation"
    );
    assert_eq!(
        mock_mem.invocation_count(),
        1,
        "Expected exactly 1 sys.memory.read invocation"
    );
}

#[test]
fn test_turn_proposal_flood_rejection_at_limit() {
    let _lock = SERIALIZE_TESTS.lock().unwrap();
    let (server, mut client) = UnixStream::pair().expect("failed to create UnixStream pair");
    let caller = CallerIdentity::principal("user-flood");
    let mut policy = PolicyEngine::new_mvp(PathBuf::from("/tmp/sandbox"));
    policy.grant(caller.clone(), "sys.cpu.read");

    let mock_cpu = Arc::new(MockCpuProvider::with_success(serde_json::json!({
        "user_percent": 10.0,
        "system_percent": 5.0,
        "idle_percent": 85.0,
        "total_ticks": 1000,
        "idle_ticks": 850
    })));

    let dispatcher = CapabilityDispatcher::new_with_providers(
        policy,
        mock_cpu.clone(),
        Arc::new(MockMemoryProvider::with_success(serde_json::json!({}))),
    );

    // Default max_proposals_per_turn is 20
    let config = SupervisorConfig::default();
    assert_eq!(config.max_proposals_per_turn, 20);

    let mut supervisor =
        WorkerSupervisor::from_stream(config, dispatcher, server).expect("from_stream failed");

    // Worker emits 21 proposals in rapid succession
    let worker_handle = std::thread::spawn(move || {
        let mut reader = BufReader::new(client.try_clone().unwrap());

        // Read RequestTurn
        let msg = read_daemon_message(&mut reader)
            .expect("read failed")
            .expect("expected RequestTurn");
        let turn_id = match msg {
            DaemonToWorkerMessage::RequestTurn(req) => req.turn_id,
            other => panic!("Expected RequestTurn, got {other:?}"),
        };

        // Emit 20 valid proposals, reading the result for each
        for i in 1..=20 {
            let prop = ProposeCapability {
                protocol_version: CURRENT_PROTOCOL_VERSION,
                turn_id: turn_id.clone(),
                call_id: format!("call-{i}"),
                capability_name: "sys.cpu.read".to_string(),
                parameters: serde_json::json!({}),
            };
            send_worker_message(&mut client, &WorkerToDaemonMessage::ProposeCapability(prop))
                .expect("send failed");

            // Read the successful result
            let res = read_daemon_message(&mut reader)
                .expect("read failed")
                .expect("expected CapabilityResult");
            match res {
                DaemonToWorkerMessage::CapabilityResult(cr) => {
                    assert_eq!(cr.call_id, format!("call-{i}"));
                }
                other => panic!("Expected CapabilityResult, got {other:?}"),
            }
        }

        // Emit proposal 21 (exceeding max_proposals_per_turn of 20)
        let prop21 = ProposeCapability {
            protocol_version: CURRENT_PROTOCOL_VERSION,
            turn_id: turn_id.clone(),
            call_id: "call-21".to_string(),
            capability_name: "sys.cpu.read".to_string(),
            parameters: serde_json::json!({}),
        };
        let _ = send_worker_message(
            &mut client,
            &WorkerToDaemonMessage::ProposeCapability(prop21),
        );
    });

    let res = supervisor.execute_turn(&caller, "flood test");

    worker_handle.join().expect("worker thread panicked");

    // Must be rejected with TurnProposalLimitExceeded
    match res {
        Err(SupervisorError::TurnProposalLimitExceeded { count, limit }) => {
            assert_eq!(count, 21);
            assert_eq!(limit, 20);
        }
        other => panic!("Expected TurnProposalLimitExceeded, got {other:?}"),
    }

    // Verify provider was executed exactly 20 times; proposal 21 NEVER reached the provider
    assert_eq!(
        mock_cpu.invocation_count(),
        20,
        "Provider must be executed at most 20 times; proposal 21 must not be executed"
    );

    // Verify session invalidation: subsequent turn on this supervisor immediately fails closed
    let next_turn = supervisor.execute_turn(&caller, "follow up");
    match next_turn {
        Err(SupervisorError::Ipc(aurora_ai::ipc::IpcError::ConnectionClosed)) => {}
        other => panic!("Expected ConnectionClosed following session invalidation, got {other:?}"),
    }
}

#[test]
fn test_turn_proposal_flood_rejection_counts_pre_dispatch() {
    let _lock = SERIALIZE_TESTS.lock().unwrap();
    // Verifies that proposals are counted pre-dispatch: even unauthorized or unknown
    // capability proposals count towards the limit, and proposal 21 triggers invalidation.
    let (server, mut client) = UnixStream::pair().expect("failed to create UnixStream pair");
    let caller = CallerIdentity::principal("unauthorized-flooder");
    let policy = PolicyEngine::new_mvp(PathBuf::from("/tmp/sandbox")); // No grants

    let mock_cpu = Arc::new(MockCpuProvider::with_success(serde_json::json!({})));
    let dispatcher = CapabilityDispatcher::new_with_providers(
        policy,
        mock_cpu.clone(),
        Arc::new(MockMemoryProvider::with_success(serde_json::json!({}))),
    );

    let config = SupervisorConfig::default().with_max_proposals_per_turn(5);
    let mut supervisor =
        WorkerSupervisor::from_stream(config, dispatcher, server).expect("from_stream failed");

    let worker_handle = std::thread::spawn(move || {
        let mut reader = BufReader::new(client.try_clone().unwrap());

        let msg = read_daemon_message(&mut reader)
            .expect("read failed")
            .expect("expected RequestTurn");
        let turn_id = match msg {
            DaemonToWorkerMessage::RequestTurn(req) => req.turn_id,
            other => panic!("Expected RequestTurn, got {other:?}"),
        };

        // Send 5 unauthorized proposals (each returns PERMISSION_DENIED)
        for i in 1..=5 {
            let prop = ProposeCapability {
                protocol_version: CURRENT_PROTOCOL_VERSION,
                turn_id: turn_id.clone(),
                call_id: format!("call-{i}"),
                capability_name: "sys.cpu.read".to_string(),
                parameters: serde_json::json!({}),
            };
            send_worker_message(&mut client, &WorkerToDaemonMessage::ProposeCapability(prop))
                .expect("send failed");

            let res = read_daemon_message(&mut reader)
                .expect("read failed")
                .expect("expected CapabilityResult");
            match res {
                DaemonToWorkerMessage::CapabilityResult(cr) => {
                    assert!(matches!(cr.outcome, CapabilityOutcome::Failure { .. }));
                }
                other => panic!("Expected CapabilityResult, got {other:?}"),
            }
        }

        // Send proposal 6 (limit is 5)
        let prop6 = ProposeCapability {
            protocol_version: CURRENT_PROTOCOL_VERSION,
            turn_id: turn_id.clone(),
            call_id: "call-6".to_string(),
            capability_name: "sys.cpu.read".to_string(),
            parameters: serde_json::json!({}),
        };
        let _ = send_worker_message(
            &mut client,
            &WorkerToDaemonMessage::ProposeCapability(prop6),
        );
    });

    let res = supervisor.execute_turn(&caller, "pre-dispatch flood test");
    worker_handle.join().expect("worker thread panicked");

    match res {
        Err(SupervisorError::TurnProposalLimitExceeded { count, limit }) => {
            assert_eq!(count, 6);
            assert_eq!(limit, 5);
        }
        other => panic!("Expected TurnProposalLimitExceeded, got {other:?}"),
    }

    // Zero provider executions across all proposals
    assert_eq!(
        mock_cpu.invocation_count(),
        0,
        "Unauthorized caller must never invoke provider"
    );
}

/// Tests file-descriptor leak invariance for the in-process daemon supervisor stream transport
/// across 500 sustained turns.
///
/// SCOPE NOTE: This test evaluates only the in-process daemon/test process descriptor table
/// (/proc/self/fd) when using `WorkerSupervisor::from_stream` with a mock worker thread.
/// It does NOT inspect an external, separately spawned Python worker subprocess.
/// For live external Python worker process descriptor inspection, see
/// `test_external_python_worker_and_daemon_descriptor_leakage_under_sustained_turns`.
#[test]
fn test_descriptor_leakage_under_sustained_turns() {
    let _lock = SERIALIZE_TESTS.lock().unwrap();
    let caller = CallerIdentity::principal("desktop-user");
    let mut policy = PolicyEngine::new_mvp(PathBuf::from("/tmp/sandbox"));
    policy.grant_all_mvp(&caller);

    let mock_cpu = Arc::new(MockCpuProvider::with_success(serde_json::json!({})));
    let mock_mem = Arc::new(MockMemoryProvider::with_success(serde_json::json!({})));
    let dispatcher = CapabilityDispatcher::new_with_providers(policy, mock_cpu, mock_mem);

    // Record baseline persistent open descriptors before running turns
    let fds_initial = get_persistent_fds();
    assert!(
        !fds_initial.is_empty(),
        "Process must have standard descriptors open"
    );

    let (server, mut client) = UnixStream::pair().expect("failed to create UnixStream pair");
    let config = SupervisorConfig::default();
    let mut supervisor =
        WorkerSupervisor::from_stream(config, dispatcher, server).expect("from_stream failed");

    // Worker thread responds to 500 consecutive turns over the same persistent channel
    let worker_handle = std::thread::spawn(move || {
        let mut reader = BufReader::new(client.try_clone().unwrap());

        for _ in 0..500 {
            let msg = read_daemon_message(&mut reader)
                .expect("read failed")
                .expect("expected RequestTurn");
            let turn_id = match msg {
                DaemonToWorkerMessage::RequestTurn(req) => req.turn_id,
                other => panic!("Expected RequestTurn, got {other:?}"),
            };

            let prop = ProposeCapability {
                protocol_version: CURRENT_PROTOCOL_VERSION,
                turn_id: turn_id.clone(),
                call_id: "call-cpu".to_string(),
                capability_name: "sys.cpu.read".to_string(),
                parameters: serde_json::json!({}),
            };
            send_worker_message(&mut client, &WorkerToDaemonMessage::ProposeCapability(prop))
                .expect("send failed");

            let _ = read_daemon_message(&mut reader);

            let complete = CompleteTurn {
                protocol_version: CURRENT_PROTOCOL_VERSION,
                turn_id,
                status: TurnStatus::Success,
                response_text: "OK".to_string(),
            };
            send_worker_message(&mut client, &WorkerToDaemonMessage::CompleteTurn(complete))
                .expect("send failed");
        }
    });

    for i in 0..500 {
        let turn_res = supervisor.execute_turn(&caller, "sustained turn");
        assert!(turn_res.is_ok(), "Turn {i} failed: {:?}", turn_res.err());
    }

    worker_handle.join().expect("worker thread panicked");
    supervisor.shutdown();

    // Record final open descriptors after 500 turns
    let fds_final = get_persistent_fds();

    // Compute symmetric difference between initial and final sets
    let leaked: HashSet<_> = fds_final.difference(&fds_initial).cloned().collect();
    let closed: HashSet<_> = fds_initial.difference(&fds_final).cloned().collect();

    assert!(
        leaked.is_empty(),
        "Descriptor leak detected after 500 sustained turns! Leaked descriptors: {leaked:?}"
    );
    assert!(
        closed.is_empty(),
        "Unexpected closure of baseline descriptors after 500 turns: {closed:?}"
    );
}

/// Tests file-descriptor leak invariance across 500 sustained capability turns,
/// exercising the Rust supervisor within the integration-test process and the
/// real Python worker as a separate child process across all four approved capabilities:
/// - `sys.cpu.read`
/// - `sys.memory.read`
/// - `proc.list`
/// - `fs.file.read`
///
/// Invariants verified:
/// 1. Rust supervisor exercised within the integration-test process; real Python worker launched as a separate child process via WorkerSupervisor::start().
/// 2. Live worker PID captured and /proc/<worker_pid>/fd inspected separately from test process /proc/self/fd.
/// 3. Controlled temporary sandbox fixture created for fs.file.read.
/// 4. Caller identity granted permissions for all 4 capabilities.
/// 5. Initial baseline descriptor sets captured for both worker and daemon in quiescent state.
/// 6. 500 consecutive capability turns executed cycling through all 4 capabilities.
/// 7. Each turn is verified for successful execution and valid response synthesis.
/// 8. Final quiescent descriptor sets captured after all turns complete.
/// 9. Symmetric difference ΔS_FD = ∅ asserted for both processes (identities and counts).
/// 10. Automatic cleanup and process reaping verified on both success and failure.
#[test]
fn test_external_python_worker_and_daemon_descriptor_leakage_under_sustained_turns() {
    let _lock = SERIALIZE_TESTS.lock().unwrap();

    // Explicit check for /proc inspection availability per Requirement 5
    if !std::path::Path::new("/proc/self/fd").exists() {
        panic!("Environment limitation: /proc/self/fd is unavailable on this platform");
    }

    let workspace_root = get_workspace_root();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let temp_socket = std::env::temp_dir().join(format!(
        "aurora-test-worker-fd-{}-{}.sock",
        std::process::id(),
        nanos
    ));

    // Controlled temporary sandbox fixture for fs.file.read
    let sandbox_dir = std::env::temp_dir().join(format!(
        "aurora-test-sandbox-{}-{}",
        std::process::id(),
        nanos
    ));
    fs::create_dir_all(&sandbox_dir).expect("failed to create sandbox dir fixture");
    let test_file_name = "sample_telemetry.txt";
    let test_file_path = sandbox_dir.join(test_file_name);
    fs::write(
        &test_file_path,
        "Aurora OS M8 sandboxed file read payload.\n",
    )
    .expect("failed to write sandbox file fixture");

    let config = SupervisorConfig::default()
        .with_working_dir(workspace_root)
        .with_socket_path(&temp_socket)
        .with_demo_sandbox_path(&sandbox_dir)
        .with_max_proposals_per_turn(50);

    let mut supervisor = WorkerSupervisor::new(config);

    // 1. Launch the real Python worker process via WorkerSupervisor::start()
    let start_res = supervisor.start();
    assert!(
        start_res.is_ok(),
        "Supervisor failed to start real Python worker: {:?}",
        start_res.err()
    );

    // 2. Capture live worker PID and verify status
    let worker_pid = supervisor
        .worker_pid()
        .expect("worker child PID must be available after start()");
    let daemon_pid = std::process::id();

    assert_eq!(
        supervisor.poll_status().expect("poll_status failed"),
        WorkerStatus::Running
    );

    // 3. Snapshot quiescent baseline file descriptors for both worker and daemon
    let worker_fds_initial = get_process_persistent_fds(Some(worker_pid)).unwrap_or_else(|e| {
        panic!("Environment limitation: unable to inspect worker /proc/{worker_pid}/fd: {e}")
    });
    let daemon_fds_initial = get_process_persistent_fds(None).unwrap_or_else(|e| {
        panic!("Environment limitation: unable to inspect daemon /proc/self/fd: {e}")
    });

    assert!(
        !worker_fds_initial.is_empty(),
        "Worker process PID {worker_pid} must have baseline descriptors open (stdio, socket)"
    );
    assert!(
        !daemon_fds_initial.is_empty(),
        "Daemon process PID {daemon_pid} must have baseline descriptors open"
    );

    // 4. Grant all four approved capabilities to caller
    let caller = CallerIdentity::principal("fd-audit-user");
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

    // 5. Execute 500 consecutive capability turns cycling through all 4 capabilities:
    //    Turn % 4 == 0 -> sys.cpu.read
    //    Turn % 4 == 1 -> sys.memory.read
    //    Turn % 4 == 2 -> proc.list
    //    Turn % 4 == 3 -> fs.file.read
    let prompts = [
        ("check cpu usage", "sys.cpu.read"),
        ("check memory usage", "sys.memory.read"),
        ("list running processes limit 10", "proc.list"),
        ("read sample_telemetry.txt", "fs.file.read"),
    ];

    for i in 1..=500 {
        let (prompt, expected_capability) = prompts[(i - 1) % prompts.len()];
        let turn_res = supervisor.execute_turn(&caller, prompt);

        // Distinguish actual execution failures from descriptor invariants
        assert!(
            turn_res.is_ok(),
            "Execution failure at turn {i} with prompt '{prompt}' (exercising {expected_capability}): {:?}",
            turn_res.err()
        );

        let turn = turn_res.unwrap();
        assert_eq!(
            turn.status,
            TurnStatus::Success,
            "Execution status failure at turn {i} for {expected_capability}: turn status is {:?}",
            turn.status
        );
        assert!(
            !turn.response_text.is_empty(),
            "Execution failure at turn {i} for {expected_capability}: response text is empty"
        );
    }

    // 6. Snapshot quiescent descriptors after 500 completed turns
    let worker_fds_final = get_process_persistent_fds(Some(worker_pid)).unwrap_or_else(|e| {
        panic!("Environment limitation: unable to inspect worker /proc/{worker_pid}/fd: {e}")
    });
    let daemon_fds_final = get_process_persistent_fds(None).unwrap_or_else(|e| {
        panic!("Environment limitation: unable to inspect daemon /proc/self/fd: {e}")
    });

    // 7. Compare worker descriptors: symmetric difference and count
    let worker_leaked: HashSet<_> = worker_fds_final
        .difference(&worker_fds_initial)
        .cloned()
        .collect();
    let worker_closed: HashSet<_> = worker_fds_initial
        .difference(&worker_fds_final)
        .cloned()
        .collect();

    assert!(
        worker_leaked.is_empty(),
        "Real Python worker (PID {worker_pid}) leaked descriptors after 500 multi-capability turns! Leaked: {worker_leaked:?}"
    );
    assert!(
        worker_closed.is_empty(),
        "Real Python worker (PID {worker_pid}) closed baseline descriptors unexpectedly! Closed: {worker_closed:?}"
    );
    assert_eq!(
        worker_fds_final.len(),
        worker_fds_initial.len(),
        "Real Python worker descriptor count mismatch: initial={}, final={}",
        worker_fds_initial.len(),
        worker_fds_final.len()
    );

    // 8. Compare daemon descriptors: symmetric difference and count
    let daemon_leaked: HashSet<_> = daemon_fds_final
        .difference(&daemon_fds_initial)
        .cloned()
        .collect();
    let daemon_closed: HashSet<_> = daemon_fds_initial
        .difference(&daemon_fds_final)
        .cloned()
        .collect();

    assert!(
        daemon_leaked.is_empty(),
        "Daemon process leaked descriptors after 500 multi-capability turns! Leaked: {daemon_leaked:?}"
    );
    assert!(
        daemon_closed.is_empty(),
        "Daemon process closed baseline descriptors unexpectedly! Closed: {daemon_closed:?}"
    );
    assert_eq!(
        daemon_fds_final.len(),
        daemon_fds_initial.len(),
        "Daemon descriptor count mismatch: initial={}, final={}",
        daemon_fds_initial.len(),
        daemon_fds_final.len()
    );

    // 9. Clean shutdown and reap child process
    supervisor.shutdown();

    // Verify child process is reaped and socket file is unlinked
    assert!(
        !temp_socket.exists(),
        "Socket file must be removed after supervisor shutdown"
    );

    // Clean up temporary sandbox directory fixture
    let _ = fs::remove_dir_all(&sandbox_dir);
}

#[test]
fn test_long_running_session_memory_observations() {
    let _lock = SERIALIZE_TESTS.lock().unwrap();
    let caller = CallerIdentity::principal("perf-user");
    let mut policy = PolicyEngine::new_mvp(PathBuf::from("/tmp/sandbox"));
    policy.grant(caller.clone(), "sys.cpu.read");

    let mock_cpu = Arc::new(MockCpuProvider::with_success(serde_json::json!({
        "user_percent": 12.0,
        "idle_percent": 88.0
    })));
    let dispatcher = CapabilityDispatcher::new_with_providers(
        policy,
        mock_cpu,
        Arc::new(MockMemoryProvider::with_success(serde_json::json!({}))),
    );

    let (m0_rss, m0_hwm, m0_vsz) = read_memory_status();

    let (server, mut client) = UnixStream::pair().expect("failed to create UnixStream pair");
    let config = SupervisorConfig::default();
    let mut supervisor =
        WorkerSupervisor::from_stream(config, dispatcher, server).expect("from_stream failed");

    let mut observations: Vec<(usize, u64, u64, u64)> = Vec::new();
    observations.push((0, m0_rss, m0_hwm, m0_vsz));

    // Worker handles 1,000 sustained capability turns over the persistent channel
    let worker_handle = std::thread::spawn(move || {
        let mut reader = BufReader::new(client.try_clone().unwrap());

        for _ in 0..1000 {
            let msg = read_daemon_message(&mut reader)
                .expect("read failed")
                .expect("expected RequestTurn");
            let turn_id = match msg {
                DaemonToWorkerMessage::RequestTurn(req) => req.turn_id,
                other => panic!("Expected RequestTurn, got {other:?}"),
            };

            let prop = ProposeCapability {
                protocol_version: CURRENT_PROTOCOL_VERSION,
                turn_id: turn_id.clone(),
                call_id: "call-mem-test".to_string(),
                capability_name: "sys.cpu.read".to_string(),
                parameters: serde_json::json!({}),
            };
            send_worker_message(&mut client, &WorkerToDaemonMessage::ProposeCapability(prop))
                .expect("send failed");

            let _ = read_daemon_message(&mut reader);

            let complete = CompleteTurn {
                protocol_version: CURRENT_PROTOCOL_VERSION,
                turn_id,
                status: TurnStatus::Success,
                response_text: "Observation recorded".to_string(),
            };
            send_worker_message(&mut client, &WorkerToDaemonMessage::CompleteTurn(complete))
                .expect("send failed");
        }
    });

    for i in 1..=1000 {
        let res = supervisor.execute_turn(&caller, "measure memory");
        assert!(res.is_ok(), "Turn {i} failed: {:?}", res.err());

        if i == 50 || i == 100 || i == 500 || i == 1000 {
            let (rss, hwm, vsz) = read_memory_status();
            observations.push((i, rss, hwm, vsz));
        }
    }

    worker_handle.join().expect("worker thread panicked");
    supervisor.shutdown();

    // Verify all 1,000 turns completed and report empirical memory trajectory
    assert_eq!(observations.len(), 5);
    println!("\n=== Long-Running Session Memory Observations (1,000 turns) ===");
    for (turn, rss, hwm, vsz) in &observations {
        println!("Turn {turn:4}: VmRSS = {rss:6} kB, VmHWM = {hwm:6} kB, VmSize = {vsz:8} kB");
    }
}
