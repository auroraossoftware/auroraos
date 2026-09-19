use aurora_ai::{
    CallerIdentity, PolicyDecision, PolicyEngine, SupervisorConfig, WorkerSupervisor,
};
use aurora_protocol::{CURRENT_PROTOCOL_VERSION, ProposeCapability};
use std::path::PathBuf;

fn create_test_engine() -> (PolicyEngine, CallerIdentity) {
    let sandbox = PathBuf::from("/demo");
    let mut engine = PolicyEngine::new_mvp(sandbox);
    let caller = CallerIdentity::principal("user-test");
    engine.grant_all_mvp(&caller);
    (engine, caller)
}

// ==========================================
// 1. Allowed Test Scenarios
// ==========================================

#[test]
fn test_allow_known_caller_sys_cpu_read() {
    let (engine, caller) = create_test_engine();
    let decision = engine.evaluate(&caller, "sys.cpu.read", &serde_json::json!({}));
    assert!(decision.is_allowed(), "Expected ALLOW for granted sys.cpu.read");
    assert_eq!(decision, PolicyDecision::Allow);
}

#[test]
fn test_allow_known_caller_sys_memory_read() {
    let (engine, caller) = create_test_engine();
    let decision = engine.evaluate(&caller, "sys.memory.read", &serde_json::json!({}));
    assert!(decision.is_allowed(), "Expected ALLOW for granted sys.memory.read");
    assert_eq!(decision, PolicyDecision::Allow);
}

#[test]
fn test_allow_known_caller_proc_list_with_and_without_limit() {
    let (engine, caller) = create_test_engine();

    // Default (no limit parameter)
    let d1 = engine.evaluate(&caller, "proc.list", &serde_json::json!({}));
    assert!(d1.is_allowed(), "Expected ALLOW for proc.list without limit");

    // Valid limits
    let d2 = engine.evaluate(&caller, "proc.list", &serde_json::json!({"limit": 10}));
    assert!(d2.is_allowed(), "Expected ALLOW for proc.list with limit=10");

    let d3 = engine.evaluate(&caller, "proc.list", &serde_json::json!({"limit": 50}));
    assert!(d3.is_allowed(), "Expected ALLOW for proc.list with limit=50");
}

#[test]
fn test_allow_known_caller_valid_demo_fs_file_read() {
    let (engine, caller) = create_test_engine();

    // Relative path inside sandbox
    let d1 = engine.evaluate(&caller, "fs.file.read", &serde_json::json!({"path": "sample.txt"}));
    assert!(d1.is_allowed(), "Expected ALLOW for relative sample.txt");

    // Nested relative path
    let d2 = engine.evaluate(
        &caller,
        "fs.file.read",
        &serde_json::json!({"path": "subdir/notes.md"}),
    );
    assert!(d2.is_allowed(), "Expected ALLOW for nested subdir/notes.md");

    // Absolute path within sandbox
    let d3 = engine.evaluate(
        &caller,
        "fs.file.read",
        &serde_json::json!({"path": "/demo/data.json"}),
    );
    assert!(d3.is_allowed(), "Expected ALLOW for absolute /demo/data.json");
}

// ==========================================
// 2. Denied Test Scenarios
// ==========================================

#[test]
fn test_deny_unknown_capability() {
    let (engine, caller) = create_test_engine();

    let decision = engine.evaluate(&caller, "fake.admin.tool", &serde_json::json!({}));
    assert!(decision.is_denied());
    assert!(
        decision.reason().unwrap().contains("Unknown or unregistered"),
        "Unexpected reason: {:?}",
        decision.reason()
    );
}

#[test]
fn test_deny_missing_or_anonymous_caller_identity() {
    let (engine, _caller) = create_test_engine();
    let anon = CallerIdentity::anonymous();

    let decision = engine.evaluate(&anon, "sys.cpu.read", &serde_json::json!({}));
    assert!(decision.is_denied());
    assert!(decision.reason().unwrap().contains("unauthenticated"));
}

#[test]
fn test_deny_malformed_capability_name() {
    let (engine, caller) = create_test_engine();

    let malformed_names = vec![
        "",
        "cpu",                    // missing dot namespace
        "sys..cpu.read",          // double dot
        "sys.CPU.read",           // uppercase
        "sys.cpu.read;rm -rf /",  // injection chars
        "sys/cpu/read",           // slash
    ];

    for name in malformed_names {
        let decision = engine.evaluate(&caller, name, &serde_json::json!({}));
        assert!(decision.is_denied(), "Expected denial for malformed name '{name}'");
        assert!(decision.reason().unwrap().contains("Malformed capability name"));
    }
}

#[test]
fn test_deny_invalid_proc_list_parameters() {
    let (engine, caller) = create_test_engine();

    // Limit <= 0
    let d1 = engine.evaluate(&caller, "proc.list", &serde_json::json!({"limit": 0}));
    assert!(d1.is_denied());
    assert!(d1.reason().unwrap().contains("must be between 1 and 50"));

    let d2 = engine.evaluate(&caller, "proc.list", &serde_json::json!({"limit": -10}));
    assert!(d2.is_denied());

    // Limit > 50
    let d3 = engine.evaluate(&caller, "proc.list", &serde_json::json!({"limit": 51}));
    assert!(d3.is_denied());
    assert!(d3.reason().unwrap().contains("must be between 1 and 50"));

    // Limit is wrong type
    let d4 = engine.evaluate(&caller, "proc.list", &serde_json::json!({"limit": "ten"}));
    assert!(d4.is_denied());
    assert!(d4.reason().unwrap().contains("must be an integer"));
}

#[test]
fn test_deny_invalid_fs_file_read_parameters() {
    let (engine, caller) = create_test_engine();

    // Missing 'path' parameter
    let d1 = engine.evaluate(&caller, "fs.file.read", &serde_json::json!({}));
    assert!(d1.is_denied());
    assert!(d1.reason().unwrap().contains("Missing required parameter 'path'"));

    // Empty 'path' parameter
    let d2 = engine.evaluate(&caller, "fs.file.read", &serde_json::json!({"path": ""}));
    assert!(d2.is_denied());
    assert!(d2.reason().unwrap().contains("cannot be empty"));

    // Non-string 'path'
    let d3 = engine.evaluate(&caller, "fs.file.read", &serde_json::json!({"path": 12345}));
    assert!(d3.is_denied());
    assert!(d3.reason().unwrap().contains("must be a string"));
}

#[test]
fn test_deny_filesystem_path_outside_demo_directory() {
    let (engine, caller) = create_test_engine();

    // Absolute system files
    let d1 = engine.evaluate(
        &caller,
        "fs.file.read",
        &serde_json::json!({"path": "/etc/passwd"}),
    );
    assert!(d1.is_denied());
    assert!(d1.reason().unwrap().contains("escapes demo sandbox"));

    let d2 = engine.evaluate(
        &caller,
        "fs.file.read",
        &serde_json::json!({"path": "/var/log/syslog"}),
    );
    assert!(d2.is_denied());
    assert!(d2.reason().unwrap().contains("escapes demo sandbox"));
}

#[test]
fn test_deny_filesystem_path_attempting_traversal() {
    let (engine, caller) = create_test_engine();

    // Parent directory traversal
    let d1 = engine.evaluate(
        &caller,
        "fs.file.read",
        &serde_json::json!({"path": "../../etc/shadow"}),
    );
    assert!(d1.is_denied());
    assert!(
        d1.reason().unwrap().contains("escape") || d1.reason().unwrap().contains("traversal"),
        "Unexpected reason: {:?}",
        d1.reason()
    );

    let d2 = engine.evaluate(
        &caller,
        "fs.file.read",
        &serde_json::json!({"path": "sub/../../etc/passwd"}),
    );
    assert!(d2.is_denied());
    assert!(
        d2.reason().unwrap().contains("escape") || d2.reason().unwrap().contains("traversal"),
        "Unexpected reason: {:?}",
        d2.reason()
    );
}

#[test]
fn test_deny_demo_secret_when_sandbox_is_demo() {
    let (engine, caller) = create_test_engine();

    // Sibling prefix matching vulnerability test:
    // A naive text starts_with("/demo") would mistakenly match "/demo-secret",
    // but component-aware validation MUST reject it.
    let d1 = engine.evaluate(
        &caller,
        "fs.file.read",
        &serde_json::json!({"path": "/demo-secret/secret.txt"}),
    );
    assert!(d1.is_denied(), "CRITICAL: /demo-secret must be rejected when sandbox is /demo");
    assert!(d1.reason().unwrap().contains("escapes demo sandbox"));

    let d2 = engine.evaluate(
        &caller,
        "fs.file.read",
        &serde_json::json!({"path": "../demo-secret/secret.txt"}),
    );
    assert!(d2.is_denied(), "CRITICAL: ../demo-secret must be rejected");
    assert!(d2.reason().unwrap().contains("escapes demo sandbox"));
}

#[test]
fn test_deny_ungranted_caller() {
    let sandbox = PathBuf::from("/demo");
    let mut engine = PolicyEngine::new_mvp(sandbox);
    let caller_alice = CallerIdentity::principal("alice");
    let caller_bob = CallerIdentity::principal("bob");

    // Alice is granted CPU, Bob is not granted anything
    engine.grant(caller_alice.clone(), "sys.cpu.read");

    let d_alice = engine.evaluate(&caller_alice, "sys.cpu.read", &serde_json::json!({}));
    assert!(d_alice.is_allowed());

    // Alice requests Memory without grant -> DENY
    let d_alice_mem = engine.evaluate(&caller_alice, "sys.memory.read", &serde_json::json!({}));
    assert!(d_alice_mem.is_denied());
    assert!(d_alice_mem.reason().unwrap().contains("is not permitted"));

    // Bob requests CPU without grant -> DENY
    let d_bob = engine.evaluate(&caller_bob, "sys.cpu.read", &serde_json::json!({}));
    assert!(d_bob.is_denied());
    assert!(d_bob.reason().unwrap().contains("is not permitted"));
}

#[test]
fn test_determinism_identical_inputs_yield_identical_decisions() {
    let (engine, caller) = create_test_engine();

    let allowed_params = serde_json::json!({"limit": 25});
    let first_allowed = engine.evaluate(&caller, "proc.list", &allowed_params);
    for _ in 0..100 {
        assert_eq!(engine.evaluate(&caller, "proc.list", &allowed_params), first_allowed);
    }

    let denied_params = serde_json::json!({"path": "/etc/shadow"});
    let first_denied = engine.evaluate(&caller, "fs.file.read", &denied_params);
    for _ in 0..100 {
        assert_eq!(engine.evaluate(&caller, "fs.file.read", &denied_params), first_denied);
    }
}

#[test]
fn test_supervisor_evaluates_untrusted_worker_proposal() {
    let config = SupervisorConfig::default().with_demo_sandbox_path("/demo");
    let mut supervisor = WorkerSupervisor::new(config);
    let caller = CallerIdentity::principal("client-app");

    // Grant client-app only CPU
    supervisor
        .policy_engine_mut()
        .grant(caller.clone(), "sys.cpu.read");

    // Worker proposes allowed capability
    let valid_proposal = ProposeCapability {
        protocol_version: CURRENT_PROTOCOL_VERSION,
        turn_id: "turn-1".to_string(),
        call_id: "call-1".to_string(),
        capability_name: "sys.cpu.read".to_string(),
        parameters: serde_json::json!({}),
    };
    let decision = supervisor.evaluate_proposal(&caller, &valid_proposal);
    assert!(decision.is_allowed());

    // Worker proposes unauthorized capability
    let unauthorized_proposal = ProposeCapability {
        protocol_version: CURRENT_PROTOCOL_VERSION,
        turn_id: "turn-1".to_string(),
        call_id: "call-2".to_string(),
        capability_name: "sys.memory.read".to_string(),
        parameters: serde_json::json!({}),
    };
    let decision2 = supervisor.evaluate_proposal(&caller, &unauthorized_proposal);
    assert!(decision2.is_denied());

    // Worker proposes path traversal escape
    let malicious_proposal = ProposeCapability {
        protocol_version: CURRENT_PROTOCOL_VERSION,
        turn_id: "turn-1".to_string(),
        call_id: "call-3".to_string(),
        capability_name: "fs.file.read".to_string(),
        parameters: serde_json::json!({"path": "../../etc/shadow"}),
    };
    let decision3 = supervisor.evaluate_proposal(&caller, &malicious_proposal);
    assert!(decision3.is_denied());
}
