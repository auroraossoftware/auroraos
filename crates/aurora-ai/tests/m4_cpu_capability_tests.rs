//! Milestone 4 Integration Tests: sys.cpu.read Capability Execution Boundary
//!
//! Pursuant to ADR-001 and ADR-002:
//! - `aurora-ai` is the policy enforcement point for capabilities.
//! - The worker is untrusted and proposes actions; the daemon validates and authorizes.
//! - Authorization MUST strictly occur BEFORE capability provider execution.
//! - Denied requests must NEVER invoke the provider (proven via mock counter test seam).
//! - Provider execution failures are cleanly distinguished from authorization denials (`PERMISSION_DENIED`).
//! - Real Linux `/proc/stat` provider accurately parses host CPU telemetry.
//! - No other capabilities are implemented in Milestone 4.

use std::path::PathBuf;
use std::sync::Arc;

use aurora_ai::{
    CapabilityDispatcher, CapabilityExecutionError, CallerIdentity, CpuProvider,
    LinuxProcStatCpuProvider, MockCpuProvider, PolicyEngine, SupervisorConfig, WorkerSupervisor,
};
use aurora_protocol::{
    CapabilityOutcome, ProposeCapability, CURRENT_PROTOCOL_VERSION,
};

fn make_cpu_proposal(params: serde_json::Value) -> ProposeCapability {
    ProposeCapability {
        protocol_version: CURRENT_PROTOCOL_VERSION,
        turn_id: "turn-m4-001".to_string(),
        call_id: "call-cpu-001".to_string(),
        capability_name: "sys.cpu.read".to_string(),
        parameters: params,
    }
}

#[test]
fn test_authorized_caller_sys_cpu_read_succeeds_with_structured_telemetry() {
    let caller = CallerIdentity::principal("desktop-user");
    let mut policy = PolicyEngine::new_mvp(PathBuf::from("/tmp/sandbox"));
    policy.grant(caller.clone(), "sys.cpu.read");

    let mock_provider = Arc::new(MockCpuProvider::with_success(serde_json::json!({
        "user_percent": 18.5,
        "system_percent": 6.2,
        "idle_percent": 75.3,
        "total_ticks": 1000000,
        "idle_ticks": 753000,
    })));

    let dispatcher = CapabilityDispatcher::new(policy, mock_provider.clone());
    let proposal = make_cpu_proposal(serde_json::json!({}));

    let result = dispatcher.execute_proposal(&caller, &proposal);

    // 1. Provider must be invoked exactly once
    assert_eq!(mock_provider.invocation_count(), 1);

    // 2. Correlation metadata preserved
    assert_eq!(result.protocol_version, CURRENT_PROTOCOL_VERSION);
    assert_eq!(result.turn_id, "turn-m4-001");
    assert_eq!(result.call_id, "call-cpu-001");

    // 3. Structured data outcome
    match result.outcome {
        CapabilityOutcome::Success { data } => {
            assert_eq!(data["user_percent"], 18.5);
            assert_eq!(data["system_percent"], 6.2);
            assert_eq!(data["idle_percent"], 75.3);
            assert_eq!(data["total_ticks"], 1000000);
        }
        CapabilityOutcome::Failure { error } => {
            panic!("Expected Success outcome, got Failure: {error:?}");
        }
    }
}

#[test]
fn test_unauthorized_caller_denied_with_permission_denied_and_never_invokes_provider() {
    let caller = CallerIdentity::principal("unauthorized-agent");
    let policy = PolicyEngine::new_mvp(PathBuf::from("/tmp/sandbox")); // No grants

    let mock_provider = Arc::new(MockCpuProvider::with_success(serde_json::json!({
        "user_percent": 10.0,
    })));

    let dispatcher = CapabilityDispatcher::new(policy, mock_provider.clone());
    let proposal = make_cpu_proposal(serde_json::json!({}));

    let result = dispatcher.execute_proposal(&caller, &proposal);

    // CRITICAL SECURITY INVARIANT: Provider must NEVER be invoked on unauthorized request
    assert_eq!(
        mock_provider.invocation_count(),
        0,
        "Security boundary violation: capability provider was invoked for unauthorized caller"
    );

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
fn test_anonymous_caller_denied_and_never_invokes_provider() {
    let anon_caller = CallerIdentity::anonymous();
    let mut policy = PolicyEngine::new_mvp(PathBuf::from("/tmp/sandbox"));
    // Attempting to grant anonymous does nothing in policy engine
    policy.grant(anon_caller.clone(), "sys.cpu.read");

    let mock_provider = Arc::new(MockCpuProvider::with_success(serde_json::json!({})));
    let dispatcher = CapabilityDispatcher::new(policy, mock_provider.clone());

    let proposal = make_cpu_proposal(serde_json::json!({}));
    let result = dispatcher.execute_proposal(&anon_caller, &proposal);

    // CRITICAL SECURITY INVARIANT: Non-invocation
    assert_eq!(
        mock_provider.invocation_count(),
        0,
        "Provider invoked for anonymous caller"
    );

    match result.outcome {
        CapabilityOutcome::Failure { error } => {
            assert_eq!(error.code, "PERMISSION_DENIED");
            assert!(error.message.contains("unauthenticated"));
        }
        CapabilityOutcome::Success { .. } => panic!("Anonymous request succeeded unexpectedly"),
    }
}

#[test]
fn test_unknown_capability_denied_and_never_invokes_provider() {
    let caller = CallerIdentity::principal("desktop-user");
    let mut policy = PolicyEngine::new_mvp(PathBuf::from("/tmp/sandbox"));
    policy.grant(caller.clone(), "sys.cpu.read");

    let mock_provider = Arc::new(MockCpuProvider::with_success(serde_json::json!({})));
    let dispatcher = CapabilityDispatcher::new(policy, mock_provider.clone());

    let unknown_proposal = ProposeCapability {
        protocol_version: CURRENT_PROTOCOL_VERSION,
        turn_id: "turn-m4-002".to_string(),
        call_id: "call-unknown-001".to_string(),
        capability_name: "sys.quantum_core.read".to_string(),
        parameters: serde_json::json!({}),
    };

    let result = dispatcher.execute_proposal(&caller, &unknown_proposal);

    // CRITICAL SECURITY INVARIANT: Non-invocation
    assert_eq!(
        mock_provider.invocation_count(),
        0,
        "Provider invoked for unknown capability"
    );

    match result.outcome {
        CapabilityOutcome::Failure { error } => {
            assert_eq!(error.code, "PERMISSION_DENIED");
            assert!(error.message.contains("Unknown or unregistered"));
        }
        CapabilityOutcome::Success { .. } => panic!("Unknown capability succeeded unexpectedly"),
    }
}

#[test]
fn test_invalid_parameters_for_sys_cpu_read_rejected_and_never_invokes_provider() {
    let caller = CallerIdentity::principal("desktop-user");
    let mut policy = PolicyEngine::new_mvp(PathBuf::from("/tmp/sandbox"));
    policy.grant(caller.clone(), "sys.cpu.read");

    let mock_provider = Arc::new(MockCpuProvider::with_success(serde_json::json!({})));
    let dispatcher = CapabilityDispatcher::new(policy, mock_provider.clone());

    // sys.cpu.read accepts null or empty object {}, unexpected parameters must fail
    let invalid_param_proposal = make_cpu_proposal(serde_json::json!({
        "unexpected_extra_argument": 42,
        "raw_dump": true
    }));

    let result = dispatcher.execute_proposal(&caller, &invalid_param_proposal);

    // CRITICAL SECURITY INVARIANT: Non-invocation
    assert_eq!(
        mock_provider.invocation_count(),
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
fn test_provider_execution_failure_produces_execution_error_not_authorization_error() {
    let caller = CallerIdentity::principal("desktop-user");
    let mut policy = PolicyEngine::new_mvp(PathBuf::from("/tmp/sandbox"));
    policy.grant(caller.clone(), "sys.cpu.read");

    // Provider simulates a host I/O failure when reading /proc/stat
    let mock_provider = Arc::new(MockCpuProvider::with_failure(
        CapabilityExecutionError::new("IO_ERROR", "Failed to open /proc/stat: No such file or directory"),
    ));
    let dispatcher = CapabilityDispatcher::new(policy, mock_provider.clone());

    let proposal = make_cpu_proposal(serde_json::json!({}));
    let result = dispatcher.execute_proposal(&caller, &proposal);

    // Provider WAS invoked because caller was authorized
    assert_eq!(mock_provider.invocation_count(), 1);

    // Error must be categorized as execution failure (IO_ERROR), NEVER authorization failure (PERMISSION_DENIED)
    match result.outcome {
        CapabilityOutcome::Failure { error } => {
            assert_eq!(error.code, "IO_ERROR");
            assert_ne!(
                error.code, "PERMISSION_DENIED",
                "Execution error must not be masked as PERMISSION_DENIED"
            );
            assert!(error.message.contains("Failed to open /proc/stat"));
        }
        CapabilityOutcome::Success { .. } => panic!("Expected failure outcome on provider error"),
    }
}

#[test]
fn test_real_linux_proc_stat_provider_reads_and_parses_real_system_metrics() {
    let provider = LinuxProcStatCpuProvider::new();

    // Verify default path is indeed /proc/stat
    assert_eq!(provider.path(), PathBuf::from("/proc/stat"));

    // Execute provider against the host Linux system
    let telemetry = provider.read_cpu().expect("Failed to read host /proc/stat");

    // Validate structured fields
    let user = telemetry
        .get("user_percent")
        .and_then(|v| v.as_f64())
        .expect("Missing user_percent");
    let system = telemetry
        .get("system_percent")
        .and_then(|v| v.as_f64())
        .expect("Missing system_percent");
    let idle = telemetry
        .get("idle_percent")
        .and_then(|v| v.as_f64())
        .expect("Missing idle_percent");
    let total_ticks = telemetry
        .get("total_ticks")
        .and_then(|v| v.as_u64())
        .expect("Missing total_ticks");

    // CPU percentages must be in range [0.0, 100.0]
    assert!((0.0..=100.0).contains(&user), "user_percent out of range: {user}");
    assert!((0.0..=100.0).contains(&system), "system_percent out of range: {system}");
    assert!((0.0..=100.0).contains(&idle), "idle_percent out of range: {idle}");
    assert!(total_ticks > 0, "total_ticks must be non-zero on running system");

    // Integration check: real provider wired into CapabilityDispatcher
    let caller = CallerIdentity::principal("desktop-user");
    let mut policy = PolicyEngine::new_mvp(PathBuf::from("/tmp/sandbox"));
    policy.grant(caller.clone(), "sys.cpu.read");

    let dispatcher = CapabilityDispatcher::new(policy, Arc::new(provider));
    let proposal = make_cpu_proposal(serde_json::json!({}));
    let result = dispatcher.execute_proposal(&caller, &proposal);

    match result.outcome {
        CapabilityOutcome::Success { data } => {
            assert!(data.get("user_percent").is_some());
            assert!(data.get("idle_percent").is_some());
        }
        CapabilityOutcome::Failure { error } => {
            panic!("Real provider execution failed: {error:?}");
        }
    }
}

#[test]
fn test_supervisor_enforces_authorization_before_execution() {
    let config = SupervisorConfig::default().with_demo_sandbox_path("/tmp/sandbox");
    let mock_provider = Arc::new(MockCpuProvider::with_success(serde_json::json!({
        "user_percent": 12.0,
    })));
    let policy = PolicyEngine::new_mvp(PathBuf::from("/tmp/sandbox"));
    let dispatcher = CapabilityDispatcher::new(policy, mock_provider.clone());

    let mut supervisor = WorkerSupervisor::with_dispatcher(config, dispatcher);
    let caller = CallerIdentity::principal("client-app");
    let proposal = make_cpu_proposal(serde_json::json!({}));

    // Step 1: Without grant -> DENY, provider not invoked
    let res1 = supervisor.execute_proposal(&caller, &proposal);
    assert_eq!(mock_provider.invocation_count(), 0);
    match res1.outcome {
        CapabilityOutcome::Failure { error } => assert_eq!(error.code, "PERMISSION_DENIED"),
        _ => panic!("Expected failure"),
    }

    // Step 2: Grant permission -> ALLOW, provider invoked
    supervisor
        .policy_engine_mut()
        .grant(caller.clone(), "sys.cpu.read");

    let res2 = supervisor.execute_proposal(&caller, &proposal);
    assert_eq!(mock_provider.invocation_count(), 1);
    match res2.outcome {
        CapabilityOutcome::Success { data } => assert_eq!(data["user_percent"], 12.0),
        _ => panic!("Expected success"),
    }
}

#[test]
fn test_unimplemented_capabilities_return_not_implemented() {
    let caller = CallerIdentity::principal("client-app");
    let mut policy = PolicyEngine::new_mvp(PathBuf::from("/tmp/sandbox"));
    // Even if granted in policy, M4 has no provider for sys.memory.read
    policy.grant(caller.clone(), "sys.memory.read");

    let mock_provider = Arc::new(MockCpuProvider::with_success(serde_json::json!({})));
    let dispatcher = CapabilityDispatcher::new(policy, mock_provider.clone());

    let memory_proposal = ProposeCapability {
        protocol_version: CURRENT_PROTOCOL_VERSION,
        turn_id: "turn-m4-003".to_string(),
        call_id: "call-mem-001".to_string(),
        capability_name: "sys.memory.read".to_string(),
        parameters: serde_json::json!({}),
    };

    let result = dispatcher.execute_proposal(&caller, &memory_proposal);

    // CPU provider is NOT touched
    assert_eq!(mock_provider.invocation_count(), 0);

    match result.outcome {
        CapabilityOutcome::Failure { error } => {
            assert_eq!(error.code, "NOT_IMPLEMENTED");
            assert!(error.message.contains("not implemented in Milestone 4"));
        }
        CapabilityOutcome::Success { .. } => panic!("sys.memory.read unexpectedly succeeded in M4"),
    }
}
