//! Milestone 5 Integration Tests: Complete End-to-End Request Flow
//!
//! Validates the entire vertical slice through the existing Aurora architecture:
//! Caller/Client -> aurora-ai daemon -> Python worker -> ProposeCapability
//! -> Deterministic Policy -> Capability Provider -> Result -> Python worker
//! -> Caller.
//!
//! Architectural invariants enforced:
//! 1. `aurora-ai` is the policy enforcement point.
//! 2. The worker is untrusted and cannot execute capabilities directly.
//! 3. Every capability proposal passes through the policy boundary.
//! 4. Capability execution occurs ONLY AFTER authorization.
//! 5. Bypassing CapabilityDispatcher is impossible.
//! 6. Denied requests NEVER invoke the provider (invocation count == 0).
//! 7. Provider execution failures propagate as execution errors, not permission errors.
//! 8. Worker crashes/disconnects are handled safely without daemon crashes.
//! 9. Protocol framing/deserialization violations cannot bypass policy or trigger execution.

use std::io::Write;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use aurora_ai::{
    CapabilityDispatcher, CapabilityExecutionError, CallerIdentity, MockCpuProvider,
    PolicyEngine, SupervisorConfig, SupervisorError, WorkerStatus, WorkerSupervisor,
};
use aurora_protocol::{
    CURRENT_PROTOCOL_VERSION, TurnStatus,
};

fn get_workspace_root() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .map(|p| p.to_path_buf())
        .unwrap_or(manifest_dir)
}

fn create_test_config(test_name: &str) -> SupervisorConfig {
    let temp_socket = std::env::temp_dir().join(format!(
        "aurora-m5-{test_name}-{}.sock",
        std::process::id()
    ));
    let mut config = SupervisorConfig::default()
        .with_socket_path(temp_socket)
        .with_handshake_timeout(Duration::from_secs(5));
    config.working_dir = Some(get_workspace_root());
    config
}

/// Test 1: Complete authorized end-to-end request:
/// caller -> worker -> proposal -> policy -> provider -> result -> worker -> caller.
#[test]
fn test_authorized_end_to_end_request_flow() {
    let config = create_test_config("authorized_e2e");
    let caller = CallerIdentity::principal("desktop-user");

    let mut policy = PolicyEngine::new_mvp(PathBuf::from("/tmp/sandbox"));
    policy.grant(caller.clone(), "sys.cpu.read");

    let mock_provider = Arc::new(MockCpuProvider::with_success(serde_json::json!({
        "user_percent": 16.5,
        "system_percent": 4.5,
        "idle_percent": 79.0,
    })));

    let dispatcher = CapabilityDispatcher::new(policy, mock_provider.clone());
    let mut supervisor = WorkerSupervisor::with_dispatcher(config, dispatcher);

    supervisor.start().expect("Supervisor failed to start");

    // Execute first turn
    let turn1 = supervisor
        .execute_turn(&caller, "check cpu")
        .expect("Turn 1 execution failed");

    assert_eq!(turn1.protocol_version, CURRENT_PROTOCOL_VERSION);
    assert_eq!(turn1.status, TurnStatus::Success);
    assert!(
        turn1.response_text.contains("16.5%"),
        "Response should include user CPU percentage: {}",
        turn1.response_text
    );
    assert_eq!(mock_provider.invocation_count(), 1);

    // Multi-turn verification on the same connected session
    let turn2 = supervisor
        .execute_turn(&caller, "inspect cpu again")
        .expect("Turn 2 execution failed");

    assert_eq!(turn2.status, TurnStatus::Success);
    assert_eq!(mock_provider.invocation_count(), 2);

    supervisor.shutdown();
}

/// Test 2 (CRITICAL SECURITY INVARIANT): Unauthorized caller:
/// proposal reaches policy; policy denies; provider invocation count remains zero; denial reaches caller.
#[test]
fn test_unauthorized_caller_proposal_denied_provider_invocation_count_zero() {
    let config = create_test_config("unauthorized_e2e");
    let caller = CallerIdentity::principal("unauthorized-agent");

    // Policy has NO grants for unauthorized-agent
    let policy = PolicyEngine::new_mvp(PathBuf::from("/tmp/sandbox"));

    let mock_provider = Arc::new(MockCpuProvider::with_success(serde_json::json!({
        "user_percent": 50.0,
    })));

    let dispatcher = CapabilityDispatcher::new(policy, mock_provider.clone());
    let mut supervisor = WorkerSupervisor::with_dispatcher(config, dispatcher);

    supervisor.start().expect("Supervisor start failed");

    let complete_turn = supervisor
        .execute_turn(&caller, "check cpu")
        .expect("Turn should complete gracefully with error status");

    // 1. CRITICAL PROPERTY: Capability provider must NEVER be invoked
    assert_eq!(
        mock_provider.invocation_count(),
        0,
        "SECURITY VIOLATION: Provider was invoked for unauthorized caller!"
    );

    // 2. Denial must reach caller
    assert_eq!(complete_turn.status, TurnStatus::Error);
    assert!(
        complete_turn.response_text.contains("PERMISSION_DENIED"),
        "Response should indicate PERMISSION_DENIED: {}",
        complete_turn.response_text
    );
    assert!(
        complete_turn.response_text.contains("not permitted"),
        "Response should explain permission denial: {}",
        complete_turn.response_text
    );

    supervisor.shutdown();
}

/// Test 2b: Unauthenticated anonymous caller denied and provider invocation count is zero.
#[test]
fn test_anonymous_caller_proposal_denied_provider_invocation_count_zero() {
    let config = create_test_config("anonymous_e2e");
    let anon = CallerIdentity::anonymous();

    let policy = PolicyEngine::new_mvp(PathBuf::from("/tmp/sandbox"));
    let mock_provider = Arc::new(MockCpuProvider::with_success(serde_json::json!({})));
    let dispatcher = CapabilityDispatcher::new(policy, mock_provider.clone());
    let mut supervisor = WorkerSupervisor::with_dispatcher(config, dispatcher);

    supervisor.start().expect("Supervisor start failed");

    let complete_turn = supervisor
        .execute_turn(&anon, "check cpu")
        .expect("Turn should complete with error status");

    assert_eq!(mock_provider.invocation_count(), 0);
    assert_eq!(complete_turn.status, TurnStatus::Error);
    assert!(complete_turn.response_text.contains("PERMISSION_DENIED"));
    assert!(complete_turn.response_text.contains("unauthenticated"));

    supervisor.shutdown();
}

/// Test 3: Invalid capability proposal: rejected before provider execution.
#[test]
fn test_invalid_capability_name_rejected_before_provider_execution() {
    let config = create_test_config("invalid_name_e2e");
    let caller = CallerIdentity::principal("desktop-user");

    let mut policy = PolicyEngine::new_mvp(PathBuf::from("/tmp/sandbox"));
    policy.grant(caller.clone(), "sys.cpu.read");

    let mock_provider = Arc::new(MockCpuProvider::with_success(serde_json::json!({})));
    let dispatcher = CapabilityDispatcher::new(policy, mock_provider.clone());
    let mut supervisor = WorkerSupervisor::with_dispatcher(config, dispatcher);

    supervisor.start().expect("Supervisor start failed");

    // Worker test seam: "invalid_proposal_name" triggers worker to emit proposal "sys..cpu.read"
    let complete_turn = supervisor
        .execute_turn(&caller, "invalid_proposal_name")
        .expect("Turn should complete with error");

    // Provider must NEVER be called
    assert_eq!(
        mock_provider.invocation_count(),
        0,
        "Provider invoked despite invalid capability proposal!"
    );

    assert_eq!(complete_turn.status, TurnStatus::Error);
    assert!(
        complete_turn.response_text.contains("INVALID_ARGUMENT"),
        "Expected INVALID_ARGUMENT error, got: {}",
        complete_turn.response_text
    );

    supervisor.shutdown();
}

/// Test 3b: Invalid parameters in proposal rejected before provider execution.
#[test]
fn test_invalid_parameters_rejected_before_provider_execution() {
    let config = create_test_config("invalid_params_e2e");
    let caller = CallerIdentity::principal("desktop-user");

    let mut policy = PolicyEngine::new_mvp(PathBuf::from("/tmp/sandbox"));
    policy.grant(caller.clone(), "sys.cpu.read");

    let mock_provider = Arc::new(MockCpuProvider::with_success(serde_json::json!({})));
    let dispatcher = CapabilityDispatcher::new(policy, mock_provider.clone());
    let mut supervisor = WorkerSupervisor::with_dispatcher(config, dispatcher);

    supervisor.start().expect("Supervisor start failed");

    // Worker test seam: "invalid_params" causes worker to propose sys.cpu.read with extra parameters
    let complete_turn = supervisor
        .execute_turn(&caller, "invalid_params")
        .expect("Turn should complete with error");

    assert_eq!(mock_provider.invocation_count(), 0);
    assert_eq!(complete_turn.status, TurnStatus::Error);
    assert!(
        complete_turn.response_text.contains("PERMISSION_DENIED"),
        "Expected PERMISSION_DENIED for invalid parameter scope: {}",
        complete_turn.response_text
    );
    assert!(
        complete_turn
            .response_text
            .contains("Parameter or scope validation failed"),
        "Expected parameter validation error message: {}",
        complete_turn.response_text
    );

    supervisor.shutdown();
}

/// Test 3c: Unknown capability proposal rejected before provider execution.
#[test]
fn test_unknown_capability_rejected_before_provider_execution() {
    let config = create_test_config("unknown_cap_e2e");
    let caller = CallerIdentity::principal("desktop-user");

    let mut policy = PolicyEngine::new_mvp(PathBuf::from("/tmp/sandbox"));
    policy.grant(caller.clone(), "sys.cpu.read");

    let mock_provider = Arc::new(MockCpuProvider::with_success(serde_json::json!({})));
    let dispatcher = CapabilityDispatcher::new(policy, mock_provider.clone());
    let mut supervisor = WorkerSupervisor::with_dispatcher(config, dispatcher);

    supervisor.start().expect("Supervisor start failed");

    // Worker test seam: "unknown_capability" causes worker to propose "sys.quantum_core.read"
    let complete_turn = supervisor
        .execute_turn(&caller, "unknown_capability")
        .expect("Turn should complete with error");

    assert_eq!(mock_provider.invocation_count(), 0);
    assert_eq!(complete_turn.status, TurnStatus::Error);
    assert!(complete_turn.response_text.contains("Unknown or unregistered"));

    supervisor.shutdown();
}

/// Test 4: Worker disconnect/crash during a request: daemon handles failure without crashing.
#[test]
fn test_worker_crash_during_request_handled_without_daemon_crash() {
    let config = create_test_config("worker_crash_turn");
    let caller = CallerIdentity::principal("desktop-user");

    let mut policy = PolicyEngine::new_mvp(PathBuf::from("/tmp/sandbox"));
    policy.grant(caller.clone(), "sys.cpu.read");

    let mock_provider = Arc::new(MockCpuProvider::with_success(serde_json::json!({})));
    let dispatcher = CapabilityDispatcher::new(policy, mock_provider.clone());
    let mut supervisor = WorkerSupervisor::with_dispatcher(config, dispatcher);

    supervisor.start().expect("Supervisor start failed");

    // Worker test seam: "simulate_crash" causes worker to exit immediately with status 137
    let result = supervisor.execute_turn(&caller, "simulate_crash");

    // Daemon must not panic or crash; returns IPC error
    assert!(result.is_err(), "Expected turn execution to fail on worker crash");
    match result {
        Err(SupervisorError::Ipc(_)) => {}
        Err(other) => panic!("Expected IPC error on crash, got: {other:?}"),
        Ok(_) => panic!("Turn unexpectedly succeeded on crashed worker"),
    }

    // Polling status reflects worker disconnect or termination
    // Allow OS scheduler a moment to reap child process
    let mut status = supervisor.poll_status().expect("poll_status failed");
    for _ in 0..20 {
        if matches!(status, WorkerStatus::Terminated(_) | WorkerStatus::Disconnected) {
            break;
        }
        std::thread::sleep(Duration::from_millis(25));
        status = supervisor.poll_status().expect("poll_status failed");
    }
    assert!(
        matches!(status, WorkerStatus::Terminated(_) | WorkerStatus::Disconnected),
        "Expected Terminated or Disconnected status, got {status:?}"
    );

    // Clean shutdown must succeed and clean up socket file
    supervisor.shutdown();
    assert!(!supervisor.socket_path().exists());
}

/// Test 5: Capability provider failure: execution error propagates as an execution error, not a permission error.
#[test]
fn test_capability_provider_failure_propagates_as_execution_error_not_permission_error() {
    let config = create_test_config("provider_failure_e2e");
    let caller = CallerIdentity::principal("desktop-user");

    let mut policy = PolicyEngine::new_mvp(PathBuf::from("/tmp/sandbox"));
    policy.grant(caller.clone(), "sys.cpu.read");

    // Provider is authorized, but simulates a host hardware/kernel read failure
    let mock_provider = Arc::new(MockCpuProvider::with_failure(CapabilityExecutionError::new(
        "IO_ERROR",
        "Failed to read /proc/stat: input/output error",
    )));

    let dispatcher = CapabilityDispatcher::new(policy, mock_provider.clone());
    let mut supervisor = WorkerSupervisor::with_dispatcher(config, dispatcher);

    supervisor.start().expect("Supervisor start failed");

    let complete_turn = supervisor
        .execute_turn(&caller, "check cpu")
        .expect("Turn should complete gracefully reporting execution failure");

    // Provider was authorized and invoked once
    assert_eq!(mock_provider.invocation_count(), 1);

    // Outcome must report IO_ERROR, NOT PERMISSION_DENIED
    assert_eq!(complete_turn.status, TurnStatus::Error);
    assert!(
        complete_turn.response_text.contains("IO_ERROR"),
        "Response should preserve error code IO_ERROR: {}",
        complete_turn.response_text
    );
    assert!(
        !complete_turn.response_text.contains("PERMISSION_DENIED"),
        "Execution failure must NOT be masked as PERMISSION_DENIED: {}",
        complete_turn.response_text
    );
    assert!(complete_turn.response_text.contains("/proc/stat"));

    supervisor.shutdown();
}

/// Test 6: Protocol validation: malformed or incompatible messages cannot bypass policy/execution boundary.
#[test]
fn test_malformed_worker_message_cannot_trigger_capability_execution() {
    let (mut client_stream, server_stream) = UnixStream::pair().expect("Failed to create socket pair");
    client_stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();

    let caller = CallerIdentity::principal("desktop-user");
    let mut policy = PolicyEngine::new_mvp(PathBuf::from("/tmp/sandbox"));
    policy.grant(caller.clone(), "sys.cpu.read");

    let mock_provider = Arc::new(MockCpuProvider::with_success(serde_json::json!({})));
    let dispatcher = CapabilityDispatcher::new(policy, mock_provider.clone());

    let config = create_test_config("malformed_wire");
    let mut supervisor =
        WorkerSupervisor::from_stream(config, dispatcher, server_stream).expect("from_stream failed");

    // Spawn a mock worker thread that sends raw malformed JSON
    std::thread::spawn(move || {
        let mut reader = std::io::BufReader::new(client_stream.try_clone().unwrap());
        let mut line = String::new();
        // Read RequestTurn from daemon
        std::io::BufRead::read_line(&mut reader, &mut line).unwrap();

        // Respond with completely malformed JSON
        client_stream.write_all(b"{ malformed syntax ::: not json }\n").unwrap();
        client_stream.flush().unwrap();
    });

    let result = supervisor.execute_turn(&caller, "test prompt");

    // Daemon parser rejects malformed JSON
    assert!(result.is_err(), "Expected deserialization error on malformed message");
    match result {
        Err(SupervisorError::Ipc(aurora_ai::ipc::IpcError::Serialization(_))) => {}
        Err(other) => panic!("Expected Serialization error, got: {other:?}"),
        Ok(_) => panic!("Turn unexpectedly succeeded on malformed frame"),
    }

    // Provider was NEVER executed
    assert_eq!(mock_provider.invocation_count(), 0);
}

/// Test 6b: Forged message direction (worker sending DaemonToWorker message) rejected and provider not executed.
#[test]
fn test_forged_daemon_message_from_worker_rejected() {
    let (mut client_stream, server_stream) = UnixStream::pair().expect("Failed to create socket pair");
    let caller = CallerIdentity::principal("desktop-user");
    let mut policy = PolicyEngine::new_mvp(PathBuf::from("/tmp/sandbox"));
    policy.grant(caller.clone(), "sys.cpu.read");

    let mock_provider = Arc::new(MockCpuProvider::with_success(serde_json::json!({})));
    let dispatcher = CapabilityDispatcher::new(policy, mock_provider.clone());

    let config = create_test_config("forged_msg");
    let mut supervisor =
        WorkerSupervisor::from_stream(config, dispatcher, server_stream).expect("from_stream failed");

    std::thread::spawn(move || {
        let mut reader = std::io::BufReader::new(client_stream.try_clone().unwrap());
        let mut line = String::new();
        std::io::BufRead::read_line(&mut reader, &mut line).unwrap();

        // Worker attempts to forge a DaemonToWorker message: CapabilityResult
        let forged = r#"{"type": "capability_result", "protocol_version": 1, "turn_id": "turn-1", "call_id": "c1", "outcome": {"status": "success", "data": {}}}"#;
        client_stream.write_all(format!("{forged}\n").as_bytes()).unwrap();
        client_stream.flush().unwrap();
    });

    let result = supervisor.execute_turn(&caller, "test prompt");
    assert!(result.is_err());
    assert_eq!(mock_provider.invocation_count(), 0);
}

/// Test 7: Worker cannot directly trigger capability execution without going through daemon authorization path.
#[test]
fn test_worker_cannot_bypass_daemon_authorization_path() {
    let config = create_test_config("bypass_prevention");
    let ungranted_caller = CallerIdentity::principal("unauthorized-user");

    let policy = PolicyEngine::new_mvp(PathBuf::from("/tmp/sandbox"));
    let mock_provider = Arc::new(MockCpuProvider::with_success(serde_json::json!({})));
    let dispatcher = CapabilityDispatcher::new(policy, mock_provider.clone());
    let mut supervisor = WorkerSupervisor::with_dispatcher(config, dispatcher);

    supervisor.start().expect("Supervisor start failed");

    // Worker attempts to propose capability without caller grant
    let turn = supervisor
        .execute_turn(&ungranted_caller, "check cpu")
        .expect("Turn execution should complete with error");

    // Invariant: Provider count MUST remain 0; daemon policy gate blocks execution
    assert_eq!(
        mock_provider.invocation_count(),
        0,
        "Security boundary breached: provider executed without authorization!"
    );
    assert_eq!(turn.status, TurnStatus::Error);
    assert!(turn.response_text.contains("PERMISSION_DENIED"));

    supervisor.shutdown();
}

/// Test 8: Real Linux /proc/stat telemetry integration test end-to-end with live worker.
#[test]
fn test_authorized_caller_real_proc_stat_end_to_end() {
    let config = create_test_config("real_proc_stat_e2e");
    let caller = CallerIdentity::principal("desktop-user");

    // Use default supervisor which wires real LinuxProcStatCpuProvider
    let mut supervisor = WorkerSupervisor::new(config);
    supervisor
        .policy_engine_mut()
        .grant(caller.clone(), "sys.cpu.read");

    supervisor.start().expect("Supervisor start failed");

    let turn = supervisor
        .execute_turn(&caller, "check cpu usage")
        .expect("Real end-to-end turn failed");

    assert_eq!(turn.status, TurnStatus::Success);
    assert!(
        turn.response_text.contains("user="),
        "Response should include real user percentage: {}",
        turn.response_text
    );
    assert!(
        turn.response_text.contains("idle="),
        "Response should include real idle percentage: {}",
        turn.response_text
    );

    supervisor.shutdown();
}
