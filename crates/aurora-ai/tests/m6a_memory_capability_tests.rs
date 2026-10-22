//! Milestone 6a Integration Tests: sys.memory.read Capability Execution Boundary
//!
//! Pursuant to ADR-001, ADR-002, and Vertical Slice Prototype Design:
//! - `aurora-ai` is the policy enforcement point for memory telemetry.
//! - The worker is untrusted and proposes actions; the daemon validates and authorizes.
//! - Authorization MUST strictly occur BEFORE capability provider execution.
//! - Denied requests must NEVER invoke the provider (proven via mock counter test seam).
//! - Provider execution failures are cleanly distinguished from authorization denials (`PERMISSION_DENIED`).
//! - Real Linux `/proc/meminfo` provider accurately parses host memory metrics (total, used, free, available MB).
//! - Neither `proc.list` nor `fs.file.read` are implemented in Milestone 6a.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use aurora_ai::{
    CapabilityDispatcher, CapabilityExecutionError, CallerIdentity, LinuxProcMeminfoMemoryProvider,
    MemoryProvider, MockCpuProvider, MockMemoryProvider, PolicyEngine, SupervisorConfig,
    WorkerSupervisor,
};
use aurora_protocol::{
    CapabilityOutcome, ProposeCapability, TurnStatus, CURRENT_PROTOCOL_VERSION,
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
        "aurora-m6a-{test_name}-{}.sock",
        std::process::id()
    ));
    let mut config = SupervisorConfig::default()
        .with_socket_path(temp_socket)
        .with_handshake_timeout(Duration::from_secs(5));
    config.working_dir = Some(get_workspace_root());
    config
}

fn make_memory_proposal(params: serde_json::Value) -> ProposeCapability {
    ProposeCapability {
        protocol_version: CURRENT_PROTOCOL_VERSION,
        turn_id: "turn-m6a-001".to_string(),
        call_id: "call-mem-001".to_string(),
        capability_name: "sys.memory.read".to_string(),
        parameters: params,
    }
}

#[test]
fn test_authorized_caller_sys_memory_read_succeeds_with_structured_telemetry() {
    let caller = CallerIdentity::principal("desktop-user");
    let mut policy = PolicyEngine::new_mvp(PathBuf::from("/tmp/sandbox"));
    policy.grant(caller.clone(), "sys.memory.read");

    let mock_cpu = Arc::new(MockCpuProvider::with_success(serde_json::json!({})));
    let mock_mem = Arc::new(MockMemoryProvider::with_success(serde_json::json!({
        "total_mb": 16000,
        "used_mb": 4500,
        "free_mb": 3500,
        "available_mb": 11500,
    })));

    let dispatcher = CapabilityDispatcher::new_with_providers(
        policy,
        mock_cpu.clone(),
        mock_mem.clone(),
    );
    let proposal = make_memory_proposal(serde_json::json!({}));

    let result = dispatcher.execute_proposal(&caller, &proposal);

    // 1. Provider must be invoked exactly once
    assert_eq!(mock_mem.invocation_count(), 1);
    assert_eq!(mock_cpu.invocation_count(), 0);

    // 2. Correlation metadata preserved
    assert_eq!(result.protocol_version, CURRENT_PROTOCOL_VERSION);
    assert_eq!(result.turn_id, "turn-m6a-001");
    assert_eq!(result.call_id, "call-mem-001");

    // 3. Structured data outcome
    match result.outcome {
        CapabilityOutcome::Success { data } => {
            assert_eq!(data["total_mb"], 16000);
            assert_eq!(data["used_mb"], 4500);
            assert_eq!(data["free_mb"], 3500);
            assert_eq!(data["available_mb"], 11500);
        }
        CapabilityOutcome::Failure { error } => {
            panic!("Expected Success outcome, got Failure: {error:?}");
        }
    }
}

#[test]
fn test_unauthorized_caller_sys_memory_read_denied_and_never_invokes_provider() {
    let caller = CallerIdentity::principal("unauthorized-agent");
    let policy = PolicyEngine::new_mvp(PathBuf::from("/tmp/sandbox")); // No grants

    let mock_cpu = Arc::new(MockCpuProvider::with_success(serde_json::json!({})));
    let mock_mem = Arc::new(MockMemoryProvider::with_success(serde_json::json!({
        "total_mb": 16000,
    })));

    let dispatcher = CapabilityDispatcher::new_with_providers(
        policy,
        mock_cpu.clone(),
        mock_mem.clone(),
    );
    let proposal = make_memory_proposal(serde_json::json!({}));

    let result = dispatcher.execute_proposal(&caller, &proposal);

    // CRITICAL SECURITY INVARIANT: Provider must NEVER be invoked on unauthorized request
    assert_eq!(
        mock_mem.invocation_count(),
        0,
        "Security boundary violation: memory provider was invoked for unauthorized caller"
    );
    assert_eq!(mock_cpu.invocation_count(), 0);

    match result.outcome {
        CapabilityOutcome::Failure { error } => {
            assert_eq!(error.code, "PERMISSION_DENIED");
            assert!(
                error.message.contains("not permitted"),
                "Denial message should state permission issue: {}",
                error.message
            );
        }
        CapabilityOutcome::Success { .. } => {
            panic!("Security boundary violation: unauthorized request succeeded");
        }
    }
}

#[test]
fn test_anonymous_caller_sys_memory_read_denied_and_never_invokes_provider() {
    let anon_caller = CallerIdentity::anonymous();
    let mut policy = PolicyEngine::new_mvp(PathBuf::from("/tmp/sandbox"));
    policy.grant(anon_caller.clone(), "sys.memory.read");

    let mock_cpu = Arc::new(MockCpuProvider::with_success(serde_json::json!({})));
    let mock_mem = Arc::new(MockMemoryProvider::with_success(serde_json::json!({})));
    let dispatcher = CapabilityDispatcher::new_with_providers(
        policy,
        mock_cpu.clone(),
        mock_mem.clone(),
    );

    let proposal = make_memory_proposal(serde_json::json!({}));
    let result = dispatcher.execute_proposal(&anon_caller, &proposal);

    assert_eq!(mock_mem.invocation_count(), 0);
    assert_eq!(mock_cpu.invocation_count(), 0);

    match result.outcome {
        CapabilityOutcome::Failure { error } => {
            assert_eq!(error.code, "PERMISSION_DENIED");
            assert!(error.message.contains("unauthenticated"));
        }
        CapabilityOutcome::Success { .. } => panic!("Anonymous request succeeded unexpectedly"),
    }
}

#[test]
fn test_invalid_parameters_for_sys_memory_read_rejected_and_never_invokes_provider() {
    let caller = CallerIdentity::principal("desktop-user");
    let mut policy = PolicyEngine::new_mvp(PathBuf::from("/tmp/sandbox"));
    policy.grant(caller.clone(), "sys.memory.read");

    let mock_cpu = Arc::new(MockCpuProvider::with_success(serde_json::json!({})));
    let mock_mem = Arc::new(MockMemoryProvider::with_success(serde_json::json!({})));
    let dispatcher = CapabilityDispatcher::new_with_providers(
        policy,
        mock_cpu.clone(),
        mock_mem.clone(),
    );

    // sys.memory.read accepts null or empty object {}, unexpected arguments must fail
    let invalid_param_proposal = make_memory_proposal(serde_json::json!({
        "unexpected_extra_argument": 999,
    }));

    let result = dispatcher.execute_proposal(&caller, &invalid_param_proposal);

    assert_eq!(
        mock_mem.invocation_count(),
        0,
        "Provider invoked despite invalid parameters"
    );

    match result.outcome {
        CapabilityOutcome::Failure { error } => {
            assert_eq!(error.code, "PERMISSION_DENIED");
            assert!(error.message.contains("Parameter or scope validation failed"));
        }
        CapabilityOutcome::Success { .. } => panic!("Invalid parameters succeeded unexpectedly"),
    }
}

#[test]
fn test_memory_provider_execution_failure_distinguished_from_permission_denied() {
    let caller = CallerIdentity::principal("desktop-user");
    let mut policy = PolicyEngine::new_mvp(PathBuf::from("/tmp/sandbox"));
    policy.grant(caller.clone(), "sys.memory.read");

    // Provider simulates a host I/O failure when reading /proc/meminfo
    let mock_cpu = Arc::new(MockCpuProvider::with_success(serde_json::json!({})));
    let mock_mem = Arc::new(MockMemoryProvider::with_failure(
        CapabilityExecutionError::new("IO_ERROR", "Failed to open /proc/meminfo: No such file or directory"),
    ));
    let dispatcher = CapabilityDispatcher::new_with_providers(
        policy,
        mock_cpu.clone(),
        mock_mem.clone(),
    );

    let proposal = make_memory_proposal(serde_json::json!({}));
    let result = dispatcher.execute_proposal(&caller, &proposal);

    // Provider WAS invoked because caller was authorized
    assert_eq!(mock_mem.invocation_count(), 1);

    // Error must be categorized as execution failure (IO_ERROR), NEVER authorization failure (PERMISSION_DENIED)
    match result.outcome {
        CapabilityOutcome::Failure { error } => {
            assert_eq!(error.code, "IO_ERROR");
            assert_ne!(
                error.code, "PERMISSION_DENIED",
                "Execution error must not be masked as PERMISSION_DENIED"
            );
            assert!(error.message.contains("Failed to open /proc/meminfo"));
        }
        CapabilityOutcome::Success { .. } => panic!("Expected failure outcome on provider error"),
    }
}

#[test]
fn test_real_linux_proc_meminfo_provider_reads_and_parses_real_system_metrics() {
    let provider = LinuxProcMeminfoMemoryProvider::new();
    assert_eq!(provider.path(), PathBuf::from("/proc/meminfo"));

    let telemetry = provider.read_memory().expect("Failed to read host /proc/meminfo");

    let total = telemetry["total_mb"].as_u64().expect("Missing total_mb");
    let used = telemetry["used_mb"].as_u64().expect("Missing used_mb");
    let free = telemetry["free_mb"].as_u64().expect("Missing free_mb");
    let available = telemetry["available_mb"].as_u64().expect("Missing available_mb");

    assert!(total > 0, "total_mb must be positive");
    assert!(available > 0, "available_mb must be positive");
    assert!(available <= total, "available_mb cannot exceed total_mb");
    assert!(free <= total, "free_mb cannot exceed total_mb");
    assert!(used <= total, "used_mb cannot exceed total_mb");
}

#[test]
fn test_supervisor_enforces_authorization_before_memory_execution() {
    let config = SupervisorConfig::default().with_demo_sandbox_path("/tmp/sandbox");
    let mock_cpu = Arc::new(MockCpuProvider::with_success(serde_json::json!({})));
    let mock_mem = Arc::new(MockMemoryProvider::with_success(serde_json::json!({
        "total_mb": 8192,
        "used_mb": 2048,
        "free_mb": 4096,
        "available_mb": 6144,
    })));
    let policy = PolicyEngine::new_mvp(PathBuf::from("/tmp/sandbox"));
    let dispatcher = CapabilityDispatcher::new_with_providers(
        policy,
        mock_cpu,
        mock_mem.clone(),
    );

    let mut supervisor = WorkerSupervisor::with_dispatcher(config, dispatcher);
    let caller = CallerIdentity::principal("client-app");
    let proposal = make_memory_proposal(serde_json::json!({}));

    // Step 1: Without grant -> DENY, provider not invoked
    let res1 = supervisor.execute_proposal(&caller, &proposal);
    assert_eq!(mock_mem.invocation_count(), 0);
    match res1.outcome {
        CapabilityOutcome::Failure { error } => assert_eq!(error.code, "PERMISSION_DENIED"),
        _ => panic!("Expected failure"),
    }

    // Step 2: Grant permission -> ALLOW, provider invoked
    supervisor
        .policy_engine_mut()
        .grant(caller.clone(), "sys.memory.read");

    let res2 = supervisor.execute_proposal(&caller, &proposal);
    assert_eq!(mock_mem.invocation_count(), 1);
    match res2.outcome {
        CapabilityOutcome::Success { data } => assert_eq!(data["total_mb"], 8192),
        _ => panic!("Expected success"),
    }
}

/// End-to-end integration test: caller -> worker -> proposal -> policy -> provider -> outcome -> worker synthesis -> caller.
#[test]
fn test_authorized_end_to_end_memory_request_flow() {
    let config = create_test_config("auth_mem_e2e");
    let caller = CallerIdentity::principal("desktop-user");

    let mut policy = PolicyEngine::new_mvp(PathBuf::from("/tmp/sandbox"));
    policy.grant(caller.clone(), "sys.memory.read");

    let mock_cpu = Arc::new(MockCpuProvider::with_success(serde_json::json!({})));
    let mock_mem = Arc::new(MockMemoryProvider::with_success(serde_json::json!({
        "total_mb": 16384,
        "used_mb": 4096,
        "free_mb": 4096,
        "available_mb": 12288,
    })));

    let dispatcher = CapabilityDispatcher::new_with_providers(
        policy,
        mock_cpu,
        mock_mem.clone(),
    );
    let mut supervisor = WorkerSupervisor::with_dispatcher(config, dispatcher);

    supervisor.start().expect("Supervisor failed to start");

    // "check memory" triggers worker to propose sys.memory.read
    let turn = supervisor
        .execute_turn(&caller, "check memory")
        .expect("Turn execution failed");

    assert_eq!(turn.status, TurnStatus::Success);
    assert!(
        turn.response_text.contains("16384MB"),
        "Response should include total memory: {}",
        turn.response_text
    );
    assert!(
        turn.response_text.contains("12288MB"),
        "Response should include available memory: {}",
        turn.response_text
    );
    assert_eq!(mock_mem.invocation_count(), 1);

    supervisor.shutdown();
}

/// End-to-end test proving: untrusted proposal -> policy DENY -> memory provider invocation count == 0.
#[test]
fn test_unauthorized_end_to_end_memory_request_denied_provider_count_zero() {
    let config = create_test_config("unauth_mem_e2e");
    let caller = CallerIdentity::principal("unauthorized-user");

    // No grant for caller
    let policy = PolicyEngine::new_mvp(PathBuf::from("/tmp/sandbox"));

    let mock_cpu = Arc::new(MockCpuProvider::with_success(serde_json::json!({})));
    let mock_mem = Arc::new(MockMemoryProvider::with_success(serde_json::json!({
        "total_mb": 8192,
    })));

    let dispatcher = CapabilityDispatcher::new_with_providers(
        policy,
        mock_cpu,
        mock_mem.clone(),
    );
    let mut supervisor = WorkerSupervisor::with_dispatcher(config, dispatcher);

    supervisor.start().expect("Supervisor failed to start");

    let turn = supervisor
        .execute_turn(&caller, "check memory")
        .expect("Turn should complete gracefully with error status");

    // CRITICAL PROPERTY: Provider must NEVER be called
    assert_eq!(
        mock_mem.invocation_count(),
        0,
        "Memory provider was invoked for unauthorized caller!"
    );

    assert_eq!(turn.status, TurnStatus::Error);
    assert!(turn.response_text.contains("PERMISSION_DENIED"));

    supervisor.shutdown();
}

/// End-to-end test with real Linux /proc/meminfo provider through live worker.
#[test]
fn test_real_proc_meminfo_end_to_end_request_flow() {
    let config = create_test_config("real_mem_e2e");
    let caller = CallerIdentity::principal("desktop-user");

    let mut supervisor = WorkerSupervisor::new(config);
    supervisor
        .policy_engine_mut()
        .grant(caller.clone(), "sys.memory.read");

    supervisor.start().expect("Supervisor failed to start");

    let turn = supervisor
        .execute_turn(&caller, "check memory usage")
        .expect("Turn failed");

    assert_eq!(turn.status, TurnStatus::Success);
    assert!(
        turn.response_text.contains("total="),
        "Response should include total memory: {}",
        turn.response_text
    );
    assert!(
        turn.response_text.contains("available="),
        "Response should include available memory: {}",
        turn.response_text
    );

    supervisor.shutdown();
}
