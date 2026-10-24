//! Milestone 6b Integration Tests: proc.list Capability Execution Boundary
//!
//! Pursuant to ADR-001, ADR-002, and Vertical Slice Prototype Design:
//! - `aurora-ai` daemon is the sole policy enforcement point for process listing.
//! - The Python worker is untrusted and can only propose actions over private IPC.
//! - Authorization MUST strictly occur BEFORE capability provider execution.
//! - Denied, anonymous, or invalid requests must NEVER invoke the provider (proven via mock counter).
//! - Limits are bounded: 1 <= limit <= 50; default is 10 when omitted.
//! - Parameter validation rejects invalid limits, non-integers, and unexpected fields.
//! - Process data exposes minimal fields: `pid`, `name`, `memory_mb` (binary MiB). No cmdline or environ.
//! - Pure Rust filesystem inspection without invoking shell commands or subprocesses.
//! - Provider execution failures are cleanly distinguished from authorization denials (`PERMISSION_DENIED`).
//! - Ephemeral and disappearing processes are handled gracefully without masking systemic `/proc` failures.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use aurora_ai::{
    CapabilityDispatcher, CapabilityExecutionError, CallerIdentity, LinuxProcFsProcessProvider,
    MockCpuProvider, MockMemoryProvider, MockProcessProvider, PolicyEngine, ProcessProvider,
    SupervisorConfig, WorkerSupervisor,
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
        "aurora-m6b-{test_name}-{}.sock",
        std::process::id()
    ));
    let mut config = SupervisorConfig::default()
        .with_socket_path(temp_socket)
        .with_handshake_timeout(Duration::from_secs(5));
    config.working_dir = Some(get_workspace_root());
    config
}

fn make_proc_proposal(params: serde_json::Value) -> ProposeCapability {
    ProposeCapability {
        protocol_version: CURRENT_PROTOCOL_VERSION,
        turn_id: "turn-m6b-001".to_string(),
        call_id: "call-proc-001".to_string(),
        capability_name: "proc.list".to_string(),
        parameters: params,
    }
}

fn create_sample_processes(count: usize) -> serde_json::Value {
    let mut procs = Vec::new();
    for i in 1..=count {
        procs.push(serde_json::json!({
            "pid": i as u32,
            "name": format!("proc_{i}"),
            "memory_mb": i as u64 * 4,
        }));
    }
    serde_json::Value::Array(procs)
}

#[test]
fn test_authorized_caller_proc_list_succeeds_with_bounded_results() {
    let caller = CallerIdentity::principal("desktop-user");
    let mut policy = PolicyEngine::new_mvp(PathBuf::from("/tmp/sandbox"));
    policy.grant(caller.clone(), "proc.list");

    let mock_cpu = Arc::new(MockCpuProvider::with_success(serde_json::json!({})));
    let mock_mem = Arc::new(MockMemoryProvider::with_success(serde_json::json!({})));
    let mock_proc = Arc::new(MockProcessProvider::with_success(create_sample_processes(20)));

    let dispatcher = CapabilityDispatcher::new_with_all_providers(
        policy,
        mock_cpu,
        mock_mem,
        mock_proc.clone(),
    );

    // Request limit of 5
    let proposal = make_proc_proposal(serde_json::json!({"limit": 5}));
    let result = dispatcher.execute_proposal(&caller, &proposal);

    // Provider invoked exactly once with limit 5
    assert_eq!(mock_proc.invocation_count(), 1);
    assert_eq!(mock_proc.last_limit(), 5);

    match result.outcome {
        CapabilityOutcome::Success { data } => {
            let arr = data.as_array().expect("Expected JSON array");
            assert_eq!(arr.len(), 5);
            assert_eq!(arr[0]["pid"], 1);
            assert_eq!(arr[0]["name"], "proc_1");
            assert_eq!(arr[0]["memory_mb"], 4);
            // Verify cpu_percent is not present
            assert!(arr[0].get("cpu_percent").is_none());
        }
        CapabilityOutcome::Failure { error } => panic!("Unexpected failure: {error:?}"),
    }
}

#[test]
fn test_default_limit_is_ten_when_parameter_omitted_or_empty() {
    let caller = CallerIdentity::principal("desktop-user");
    let mut policy = PolicyEngine::new_mvp(PathBuf::from("/tmp/sandbox"));
    policy.grant(caller.clone(), "proc.list");

    let mock_cpu = Arc::new(MockCpuProvider::with_success(serde_json::json!({})));
    let mock_mem = Arc::new(MockMemoryProvider::with_success(serde_json::json!({})));
    let mock_proc = Arc::new(MockProcessProvider::with_success(create_sample_processes(20)));

    let dispatcher = CapabilityDispatcher::new_with_all_providers(
        policy,
        mock_cpu,
        mock_mem,
        mock_proc.clone(),
    );

    // Empty object parameters {} -> default limit 10
    let proposal1 = make_proc_proposal(serde_json::json!({}));
    let res1 = dispatcher.execute_proposal(&caller, &proposal1);
    assert_eq!(mock_proc.invocation_count(), 1);
    assert_eq!(mock_proc.last_limit(), 10);
    match res1.outcome {
        CapabilityOutcome::Success { data } => {
            assert_eq!(data.as_array().unwrap().len(), 10);
        }
        _ => panic!("Expected success for proposal 1"),
    }

    // Null parameters -> default limit 10
    let proposal2 = make_proc_proposal(serde_json::Value::Null);
    let res2 = dispatcher.execute_proposal(&caller, &proposal2);
    assert_eq!(mock_proc.invocation_count(), 2);
    assert_eq!(mock_proc.last_limit(), 10);
    match res2.outcome {
        CapabilityOutcome::Success { data } => {
            assert_eq!(data.as_array().unwrap().len(), 10);
        }
        _ => panic!("Expected success for proposal 2"),
    }
}

#[test]
fn test_unauthorized_caller_proc_list_denied_provider_count_zero() {
    let caller = CallerIdentity::principal("unauthorized-agent");
    let policy = PolicyEngine::new_mvp(PathBuf::from("/tmp/sandbox")); // No grant

    let mock_cpu = Arc::new(MockCpuProvider::with_success(serde_json::json!({})));
    let mock_mem = Arc::new(MockMemoryProvider::with_success(serde_json::json!({})));
    let mock_proc = Arc::new(MockProcessProvider::with_success(create_sample_processes(10)));

    let dispatcher = CapabilityDispatcher::new_with_all_providers(
        policy,
        mock_cpu,
        mock_mem,
        mock_proc.clone(),
    );

    let proposal = make_proc_proposal(serde_json::json!({"limit": 5}));
    let result = dispatcher.execute_proposal(&caller, &proposal);

    // CRITICAL SECURITY INVARIANT: Provider must NEVER be called
    assert_eq!(
        mock_proc.invocation_count(),
        0,
        "Security boundary violation: process provider was invoked for unauthorized caller"
    );

    match result.outcome {
        CapabilityOutcome::Failure { error } => {
            assert_eq!(error.code, "PERMISSION_DENIED");
            assert!(error.message.contains("not permitted"));
        }
        CapabilityOutcome::Success { .. } => panic!("Unauthorized request unexpectedly succeeded"),
    }
}

#[test]
fn test_anonymous_caller_proc_list_denied_provider_count_zero() {
    let anon_caller = CallerIdentity::anonymous();
    let mut policy = PolicyEngine::new_mvp(PathBuf::from("/tmp/sandbox"));
    policy.grant(anon_caller.clone(), "proc.list");

    let mock_cpu = Arc::new(MockCpuProvider::with_success(serde_json::json!({})));
    let mock_mem = Arc::new(MockMemoryProvider::with_success(serde_json::json!({})));
    let mock_proc = Arc::new(MockProcessProvider::with_success(create_sample_processes(10)));

    let dispatcher = CapabilityDispatcher::new_with_all_providers(
        policy,
        mock_cpu,
        mock_mem,
        mock_proc.clone(),
    );

    let proposal = make_proc_proposal(serde_json::json!({}));
    let result = dispatcher.execute_proposal(&anon_caller, &proposal);

    assert_eq!(mock_proc.invocation_count(), 0);
    match result.outcome {
        CapabilityOutcome::Failure { error } => {
            assert_eq!(error.code, "PERMISSION_DENIED");
            assert!(error.message.contains("unauthenticated"));
        }
        CapabilityOutcome::Success { .. } => panic!("Anonymous request unexpectedly succeeded"),
    }
}

#[test]
fn test_invalid_limit_rejected_before_provider_execution() {
    let caller = CallerIdentity::principal("desktop-user");
    let mut policy = PolicyEngine::new_mvp(PathBuf::from("/tmp/sandbox"));
    policy.grant(caller.clone(), "proc.list");

    let mock_cpu = Arc::new(MockCpuProvider::with_success(serde_json::json!({})));
    let mock_mem = Arc::new(MockMemoryProvider::with_success(serde_json::json!({})));
    let mock_proc = Arc::new(MockProcessProvider::with_success(create_sample_processes(10)));

    let dispatcher = CapabilityDispatcher::new_with_all_providers(
        policy,
        mock_cpu,
        mock_mem,
        mock_proc.clone(),
    );

    let invalid_limits = vec![
        serde_json::json!({"limit": 0}),
        serde_json::json!({"limit": -1}),
        serde_json::json!({"limit": 51}),
        serde_json::json!({"limit": "ten"}),
        serde_json::json!({"limit": 10.5}),
        serde_json::json!({"limit": null}),
    ];

    for invalid_param in invalid_limits {
        let proposal = make_proc_proposal(invalid_param);
        let result = dispatcher.execute_proposal(&caller, &proposal);

        assert_eq!(
            mock_proc.invocation_count(),
            0,
            "Provider invoked despite invalid limit"
        );

        match result.outcome {
            CapabilityOutcome::Failure { error } => {
                assert_eq!(error.code, "PERMISSION_DENIED");
                assert!(error.message.contains("Parameter or scope validation failed"));
            }
            CapabilityOutcome::Success { .. } => panic!("Invalid limit succeeded unexpectedly"),
        }
    }
}

#[test]
fn test_unsupported_parameter_types_rejected_before_provider_execution() {
    let caller = CallerIdentity::principal("desktop-user");
    let mut policy = PolicyEngine::new_mvp(PathBuf::from("/tmp/sandbox"));
    policy.grant(caller.clone(), "proc.list");

    let mock_cpu = Arc::new(MockCpuProvider::with_success(serde_json::json!({})));
    let mock_mem = Arc::new(MockMemoryProvider::with_success(serde_json::json!({})));
    let mock_proc = Arc::new(MockProcessProvider::with_success(create_sample_processes(10)));

    let dispatcher = CapabilityDispatcher::new_with_all_providers(
        policy,
        mock_cpu,
        mock_mem,
        mock_proc.clone(),
    );

    let unsupported_types = vec![
        serde_json::json!([1, 2, 3]),
        serde_json::json!("string_parameter"),
        serde_json::json!(42),
        serde_json::json!(true),
    ];

    for invalid_type in unsupported_types {
        let proposal = make_proc_proposal(invalid_type);
        let result = dispatcher.execute_proposal(&caller, &proposal);

        assert_eq!(
            mock_proc.invocation_count(),
            0,
            "Provider invoked despite unsupported parameter type"
        );

        match result.outcome {
            CapabilityOutcome::Failure { error } => {
                assert_eq!(error.code, "PERMISSION_DENIED");
                assert!(error.message.contains("Parameter or scope validation failed"));
            }
            CapabilityOutcome::Success { .. } => panic!("Unsupported type succeeded unexpectedly"),
        }
    }
}

#[test]
fn test_unexpected_parameter_rejected_before_provider_execution() {
    let caller = CallerIdentity::principal("desktop-user");
    let mut policy = PolicyEngine::new_mvp(PathBuf::from("/tmp/sandbox"));
    policy.grant(caller.clone(), "proc.list");

    let mock_cpu = Arc::new(MockCpuProvider::with_success(serde_json::json!({})));
    let mock_mem = Arc::new(MockMemoryProvider::with_success(serde_json::json!({})));
    let mock_proc = Arc::new(MockProcessProvider::with_success(create_sample_processes(10)));

    let dispatcher = CapabilityDispatcher::new_with_all_providers(
        policy,
        mock_cpu,
        mock_mem,
        mock_proc.clone(),
    );

    let unexpected_params = vec![
        serde_json::json!({"unexpected_key": 123}),
        serde_json::json!({"limit": 10, "extra_arg": "forbidden"}),
    ];

    for params in unexpected_params {
        let proposal = make_proc_proposal(params);
        let result = dispatcher.execute_proposal(&caller, &proposal);

        assert_eq!(
            mock_proc.invocation_count(),
            0,
            "Provider invoked despite unexpected parameters"
        );

        match result.outcome {
            CapabilityOutcome::Failure { error } => {
                assert_eq!(error.code, "PERMISSION_DENIED");
                assert!(error.message.contains("Parameter or scope validation failed"));
            }
            CapabilityOutcome::Success { .. } => panic!("Unexpected param succeeded unexpectedly"),
        }
    }
}

#[test]
fn test_provider_failure_distinguished_from_permission_denied() {
    let caller = CallerIdentity::principal("desktop-user");
    let mut policy = PolicyEngine::new_mvp(PathBuf::from("/tmp/sandbox"));
    policy.grant(caller.clone(), "proc.list");

    let mock_cpu = Arc::new(MockCpuProvider::with_success(serde_json::json!({})));
    let mock_mem = Arc::new(MockMemoryProvider::with_success(serde_json::json!({})));
    let mock_proc = Arc::new(MockProcessProvider::with_failure(
        CapabilityExecutionError::new("IO_ERROR", "Failed to read process directory /proc: Permission denied"),
    ));

    let dispatcher = CapabilityDispatcher::new_with_all_providers(
        policy,
        mock_cpu,
        mock_mem,
        mock_proc.clone(),
    );

    let proposal = make_proc_proposal(serde_json::json!({"limit": 10}));
    let result = dispatcher.execute_proposal(&caller, &proposal);

    // Provider WAS invoked because caller was authorized
    assert_eq!(mock_proc.invocation_count(), 1);

    // Error must be categorized as execution failure (IO_ERROR), NEVER authorization failure (PERMISSION_DENIED)
    match result.outcome {
        CapabilityOutcome::Failure { error } => {
            assert_eq!(error.code, "IO_ERROR");
            assert_ne!(
                error.code, "PERMISSION_DENIED",
                "Execution error must not be masked as PERMISSION_DENIED"
            );
            assert!(error.message.contains("Failed to read process directory"));
        }
        CapabilityOutcome::Success { .. } => panic!("Expected failure outcome on provider error"),
    }
}

#[test]
fn test_supervisor_enforces_authorization_before_process_execution() {
    let config = SupervisorConfig::default().with_demo_sandbox_path("/tmp/sandbox");
    let mock_cpu = Arc::new(MockCpuProvider::with_success(serde_json::json!({})));
    let mock_mem = Arc::new(MockMemoryProvider::with_success(serde_json::json!({})));
    let mock_proc = Arc::new(MockProcessProvider::with_success(create_sample_processes(5)));

    let policy = PolicyEngine::new_mvp(PathBuf::from("/tmp/sandbox"));
    let dispatcher = CapabilityDispatcher::new_with_all_providers(
        policy,
        mock_cpu,
        mock_mem,
        mock_proc.clone(),
    );

    let mut supervisor = WorkerSupervisor::with_dispatcher(config, dispatcher);
    let caller = CallerIdentity::principal("client-app");
    let proposal = make_proc_proposal(serde_json::json!({"limit": 5}));

    // Step 1: Without grant -> DENY, provider not invoked
    let res1 = supervisor.execute_proposal(&caller, &proposal);
    assert_eq!(mock_proc.invocation_count(), 0);
    match res1.outcome {
        CapabilityOutcome::Failure { error } => assert_eq!(error.code, "PERMISSION_DENIED"),
        _ => panic!("Expected failure"),
    }

    // Step 2: Grant permission -> ALLOW, provider invoked
    supervisor
        .policy_engine_mut()
        .grant(caller.clone(), "proc.list");

    let res2 = supervisor.execute_proposal(&caller, &proposal);
    assert_eq!(mock_proc.invocation_count(), 1);
    assert_eq!(mock_proc.last_limit(), 5);
    match res2.outcome {
        CapabilityOutcome::Success { data } => {
            assert_eq!(data.as_array().unwrap().len(), 5);
        }
        _ => panic!("Expected success"),
    }
}

#[test]
fn test_real_linux_procfs_provider_reads_real_host_processes() {
    let provider = LinuxProcFsProcessProvider::new();
    assert_eq!(provider.path(), PathBuf::from("/proc"));

    // Request limit of 5
    let res = provider.list_processes(5).expect("Failed to read host /proc");
    let arr = res.as_array().expect("Expected JSON array");

    assert!(!arr.is_empty(), "Expected at least one running process on Linux host");
    assert!(arr.len() <= 5, "Result length must be <= limit (5)");

    let mut prev_pid = 0;
    for entry in arr {
        let pid = entry["pid"].as_u64().expect("Missing pid") as u32;
        let name = entry["name"].as_str().expect("Missing name");
        let _memory_mb = entry["memory_mb"].as_u64().expect("Missing memory_mb");

        assert!(pid > 0, "PID must be positive");
        assert!(!name.is_empty(), "Process name cannot be empty");
        // Verify deterministic sorting: ascending order by PID
        assert!(pid >= prev_pid, "Processes must be sorted ascending by PID");
        prev_pid = pid;

        // Verify cpu_percent is omitted
        assert!(entry.get("cpu_percent").is_none());
    }
}

/// End-to-end integration test: caller -> worker -> proposal -> policy -> provider -> outcome -> worker synthesis -> caller.
#[test]
fn test_authorized_end_to_end_proc_list_request_flow() {
    let config = create_test_config("auth_proc_e2e");
    let caller = CallerIdentity::principal("desktop-user");

    let mut policy = PolicyEngine::new_mvp(PathBuf::from("/tmp/sandbox"));
    policy.grant(caller.clone(), "proc.list");

    let mock_cpu = Arc::new(MockCpuProvider::with_success(serde_json::json!({})));
    let mock_mem = Arc::new(MockMemoryProvider::with_success(serde_json::json!({})));
    let mock_proc = Arc::new(MockProcessProvider::with_success(serde_json::json!([
        {"pid": 1, "name": "systemd", "memory_mb": 15},
        {"pid": 2, "name": "kthreadd", "memory_mb": 0},
        {"pid": 50, "name": "aurora-ai", "memory_mb": 25},
    ])));

    let dispatcher = CapabilityDispatcher::new_with_all_providers(
        policy,
        mock_cpu,
        mock_mem,
        mock_proc.clone(),
    );
    let mut supervisor = WorkerSupervisor::with_dispatcher(config, dispatcher);

    supervisor.start().expect("Supervisor failed to start");

    // "list processes" triggers worker to propose proc.list
    let turn = supervisor
        .execute_turn(&caller, "list processes")
        .expect("Turn execution failed");

    assert_eq!(turn.status, TurnStatus::Success);
    assert_eq!(mock_proc.invocation_count(), 1);
    assert!(
        turn.response_text.contains("systemd"),
        "Response should include process name: {}",
        turn.response_text
    );
    assert!(
        turn.response_text.contains("aurora-ai"),
        "Response should include process name: {}",
        turn.response_text
    );

    supervisor.shutdown();
}

/// End-to-end test proving: untrusted proposal -> policy DENY -> process provider invocation count == 0.
#[test]
fn test_unauthorized_end_to_end_proc_list_request_denied_provider_count_zero() {
    let config = create_test_config("unauth_proc_e2e");
    let caller = CallerIdentity::principal("unauthorized-user");

    // No grant for caller
    let policy = PolicyEngine::new_mvp(PathBuf::from("/tmp/sandbox"));

    let mock_cpu = Arc::new(MockCpuProvider::with_success(serde_json::json!({})));
    let mock_mem = Arc::new(MockMemoryProvider::with_success(serde_json::json!({})));
    let mock_proc = Arc::new(MockProcessProvider::with_success(create_sample_processes(5)));

    let dispatcher = CapabilityDispatcher::new_with_all_providers(
        policy,
        mock_cpu,
        mock_mem,
        mock_proc.clone(),
    );
    let mut supervisor = WorkerSupervisor::with_dispatcher(config, dispatcher);

    supervisor.start().expect("Supervisor failed to start");

    let turn = supervisor
        .execute_turn(&caller, "list processes")
        .expect("Turn should complete gracefully with error status");

    // CRITICAL SECURITY INVARIANT: Provider must NEVER be called
    assert_eq!(
        mock_proc.invocation_count(),
        0,
        "Process provider was invoked for unauthorized caller!"
    );

    assert_eq!(turn.status, TurnStatus::Error);
    assert!(turn.response_text.contains("PERMISSION_DENIED"));

    supervisor.shutdown();
}

/// End-to-end test with real Linux /proc provider through live worker.
#[test]
fn test_real_procfs_end_to_end_request_flow() {
    let config = create_test_config("real_proc_e2e");
    let caller = CallerIdentity::principal("desktop-user");

    let mut supervisor = WorkerSupervisor::new(config);
    supervisor
        .policy_engine_mut()
        .grant(caller.clone(), "proc.list");

    supervisor.start().expect("Supervisor failed to start");

    let turn = supervisor
        .execute_turn(&caller, "show running tasks")
        .expect("Turn failed");

    assert_eq!(turn.status, TurnStatus::Success);
    assert!(
        turn.response_text.contains("Running processes"),
        "Response should describe running processes: {}",
        turn.response_text
    );

    supervisor.shutdown();
}
