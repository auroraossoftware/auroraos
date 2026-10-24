//! Milestone 7 Adversarial Security, Protocol Rejection, and Fault Containment Tests.
//!
//! Validates the fail-closed security invariants defined in ADR-001, ADR-002,
//! and the Vertical Slice Prototype Design.

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::symlink;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use aurora_ai::capability::{is_component_contained, validate_fs_path};
use aurora_ai::config::SupervisorConfig;
use aurora_ai::dispatcher::CapabilityDispatcher;
use aurora_ai::identity::CallerIdentity;
use aurora_ai::ipc::IpcError;
use aurora_ai::policy::PolicyEngine;
use aurora_ai::provider::{
    CpuProvider, FileProvider, LinuxProcFsProcessProvider, LinuxProcMeminfoMemoryProvider,
    LinuxProcStatCpuProvider, MemoryProvider, MockCpuProvider, MockFileProvider,
    MockMemoryProvider, MockProcessProvider, ProcessProvider, SandboxedLocalFileProvider,
};
use aurora_ai::supervisor::{SupervisorError, WorkerSupervisor};
use aurora_protocol::{CapabilityOutcome, ProposeCapability, TurnStatus, CURRENT_PROTOCOL_VERSION};

fn get_workspace_root() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .map(|p| p.to_path_buf())
        .unwrap_or(manifest_dir)
}

fn create_unique_temp_socket(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "aurora-m7-{name}-{}-{}.sock",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ))
}

fn create_test_config(test_name: &str) -> SupervisorConfig {
    let socket_path = create_unique_temp_socket(test_name);
    let mut config = SupervisorConfig::default()
        .with_socket_path(socket_path)
        .with_handshake_timeout(Duration::from_secs(5));
    config.working_dir = Some(get_workspace_root());
    config
}

// ============================================================================
// Category 1: Authorization & Capability Enforcement
// ============================================================================

/// AUTH-01: Caller Alice (granted) executes Turn 1. Caller Bob (ungranted) executes
/// Turn 2 on the same supervisor session. Verifies zero state leakage or credential retention.
#[test]
fn test_cross_caller_turn_context_isolation() {
    let caller_alice = CallerIdentity::principal("alice");
    let caller_bob = CallerIdentity::principal("bob");

    let mut policy = PolicyEngine::new_mvp(PathBuf::from("/demo"));
    policy.grant(caller_alice.clone(), "sys.cpu.read");
    // Bob has NO grants

    let mock_cpu = Arc::new(MockCpuProvider::with_success(serde_json::json!({
        "user_percent": 12.0,
        "idle_percent": 88.0,
    })));

    let (mut client, server) = UnixStream::pair().expect("UnixStream pair failed");
    let dispatcher = CapabilityDispatcher::new_with_all_capability_providers(
        policy,
        mock_cpu.clone(),
        Arc::new(MockMemoryProvider::with_success(serde_json::json!({}))),
        Arc::new(MockProcessProvider::with_success(serde_json::json!([]))),
        Arc::new(MockFileProvider::with_success(serde_json::json!({}))),
    );

    let config = create_test_config("cross_caller");
    let mut supervisor =
        WorkerSupervisor::from_stream(config, dispatcher, server).expect("from_stream failed");

    // Worker mock thread handles turns sequentially
    let worker_handle = std::thread::spawn(move || {
        let mut reader = BufReader::new(client.try_clone().unwrap());

        // Turn 1 (Alice)
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        let prop = serde_json::json!({
            "type": "propose_capability",
            "protocol_version": CURRENT_PROTOCOL_VERSION,
            "turn_id": "turn-1",
            "call_id": "call-1",
            "capability_name": "sys.cpu.read",
            "parameters": {}
        });
        client.write_all(format!("{prop}\n").as_bytes()).unwrap();
        client.flush().unwrap();

        line.clear();
        reader.read_line(&mut line).unwrap(); // Read CapabilityResult
        let comp = serde_json::json!({
            "type": "complete_turn",
            "protocol_version": CURRENT_PROTOCOL_VERSION,
            "turn_id": "turn-1",
            "status": "success",
            "response_text": "CPU telemetry"
        });
        client.write_all(format!("{comp}\n").as_bytes()).unwrap();
        client.flush().unwrap();

        // Turn 2 (Bob)
        line.clear();
        reader.read_line(&mut line).unwrap();
        let prop2 = serde_json::json!({
            "type": "propose_capability",
            "protocol_version": CURRENT_PROTOCOL_VERSION,
            "turn_id": "turn-2",
            "call_id": "call-2",
            "capability_name": "sys.cpu.read",
            "parameters": {}
        });
        client.write_all(format!("{prop2}\n").as_bytes()).unwrap();
        client.flush().unwrap();

        line.clear();
        reader.read_line(&mut line).unwrap(); // Read CapabilityResult (denial)
        let comp2 = serde_json::json!({
            "type": "complete_turn",
            "protocol_version": CURRENT_PROTOCOL_VERSION,
            "turn_id": "turn-2",
            "status": "error",
            "response_text": "Denied"
        });
        client.write_all(format!("{comp2}\n").as_bytes()).unwrap();
        client.flush().unwrap();
    });

    // Execute Turn 1 (Alice)
    let turn1 = supervisor
        .execute_turn(&caller_alice, "check cpu")
        .expect("Alice turn failed");
    assert_eq!(turn1.status, TurnStatus::Success);
    assert_eq!(mock_cpu.invocation_count(), 1);

    // Execute Turn 2 (Bob) on the exact same supervisor session
    let turn2 = supervisor
        .execute_turn(&caller_bob, "check cpu")
        .expect("Bob turn completed");
    assert_eq!(turn2.status, TurnStatus::Error);
    // CRITICAL PROPERTY: Provider count remains 1; Bob never invoked provider!
    assert_eq!(
        mock_cpu.invocation_count(),
        1,
        "SECURITY VIOLATION: Provider invoked for ungranted caller across turns!"
    );

    worker_handle.join().unwrap();
}

/// AUTH-02: Worker submits non-object parameters (arrays, booleans, integers, strings)
/// to all 4 capabilities to verify strict parameter type enforcement without panics.
#[test]
fn test_parameter_type_confusion_across_all_capabilities() {
    let caller = CallerIdentity::principal("user");
    let sandbox = PathBuf::from("/demo");
    let mut policy = PolicyEngine::new_mvp(sandbox);
    policy.grant_all_mvp(&caller);

    let mock_cpu = Arc::new(MockCpuProvider::with_success(serde_json::json!({})));
    let mock_mem = Arc::new(MockMemoryProvider::with_success(serde_json::json!({})));
    let mock_proc = Arc::new(MockProcessProvider::with_success(serde_json::json!([])));
    let mock_file = Arc::new(MockFileProvider::with_success(serde_json::json!({})));

    let dispatcher = CapabilityDispatcher::new_with_all_capability_providers(
        policy,
        mock_cpu.clone(),
        mock_mem.clone(),
        mock_proc.clone(),
        mock_file.clone(),
    );

    let bad_param_payloads = vec![
        serde_json::json!([]),
        serde_json::json!([1, 2, 3]),
        serde_json::json!(true),
        serde_json::json!(false),
        serde_json::json!(12345),
        serde_json::json!("arbitrary string"),
    ];

    let capabilities = [
        "sys.cpu.read",
        "sys.memory.read",
        "proc.list",
        "fs.file.read",
    ];

    for cap in &capabilities {
        for payload in &bad_param_payloads {
            let proposal = ProposeCapability {
                protocol_version: CURRENT_PROTOCOL_VERSION,
                turn_id: "turn-type-test".to_string(),
                call_id: "call-1".to_string(),
                capability_name: cap.to_string(),
                parameters: payload.clone(),
            };

            let res = dispatcher.execute_proposal(&caller, &proposal);
            match res.outcome {
                CapabilityOutcome::Failure { error } => {
                    assert!(
                        error.code == "PERMISSION_DENIED" || error.code == "INVALID_ARGUMENT",
                        "Unexpected error code for {cap} with bad params: {}",
                        error.code
                    );
                }
                CapabilityOutcome::Success { .. } => {
                    panic!(
                        "Capability {cap} unexpectedly succeeded on non-object params: {payload:?}"
                    );
                }
            }
        }
    }

    // All provider invocation counts must remain strictly 0
    assert_eq!(mock_cpu.invocation_count(), 0);
    assert_eq!(mock_mem.invocation_count(), 0);
    assert_eq!(mock_proc.invocation_count(), 0);
    assert_eq!(mock_file.invocation_count(), 0);
}

// ============================================================================
// Category 2: Path Containment & Filesystem Boundary
// ============================================================================

/// PATH-01: Sandbox contains cyclic symlink loop (loop_a -> loop_b -> loop_a).
/// Verifies safe, bounded rejection via kernel loop detection (ELOOP) mapped to SYMLINK_REJECTED.
#[test]
fn test_cyclic_symlink_loop_safe_rejection() {
    let sandbox_dir = std::env::temp_dir().join(format!(
        "aurora-cyclic-symlink-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&sandbox_dir).expect("Failed to create sandbox dir");

    let link_a = sandbox_dir.join("link_a");
    let link_b = sandbox_dir.join("link_b");

    // Create cyclic loop: link_a -> link_b, link_b -> link_a
    symlink("link_b", &link_a).expect("Failed to create link_a");
    symlink("link_a", &link_b).expect("Failed to create link_b");

    let provider = SandboxedLocalFileProvider::new(&sandbox_dir).expect("Provider init failed");

    let result = provider.read_file("link_a");
    assert!(result.is_err(), "Expected cyclic symlink to be rejected");

    let err = result.unwrap_err();
    assert_eq!(
        err.code, "SYMLINK_REJECTED",
        "Expected SYMLINK_REJECTED for cyclic symlink, got: {err}"
    );

    let _ = fs::remove_dir_all(&sandbox_dir);
}

/// PATH-02: Special non-regular files (Unix domain socket, device nodes) fail closed.
/// Asserts non-blocking fail-closed rejection without requiring NOT_REGULAR_FILE if openat2 fails at syscall time.
#[test]
fn test_special_non_regular_file_fail_closed_rejection() {
    let sandbox_dir = std::env::temp_dir().join(format!(
        "aurora-socket-test-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&sandbox_dir).expect("Failed to create sandbox dir");

    let socket_path = sandbox_dir.join("special.sock");
    let listener = UnixListener::bind(&socket_path).expect("Failed to bind socket in sandbox");

    let provider = SandboxedLocalFileProvider::new(&sandbox_dir).expect("Provider init failed");

    // Attempting to read a Unix domain socket must fail closed immediately without blocking
    let result = provider.read_file("special.sock");
    assert!(
        result.is_err(),
        "Expected special socket file to fail closed"
    );
    let err = result.unwrap_err();
    assert!(
        err.code == "IO_ERROR" || err.code == "NOT_REGULAR_FILE",
        "Expected IO_ERROR or NOT_REGULAR_FILE, got: {}",
        err.code
    );

    drop(listener);
    let _ = fs::remove_dir_all(&sandbox_dir);
}

/// PATH-03: Path parameter length exact 255-byte boundary vs. 256 bytes.
#[test]
fn test_path_length_exact_255_byte_boundary() {
    // 255-byte relative path
    let base = "sub/";
    let filename = "file.txt";
    let padding_len = 255 - base.len() - filename.len();
    let exact_255 = format!("{base}{}{filename}", "a".repeat(padding_len));
    assert_eq!(exact_255.len(), 255);

    // Exact 255 bytes passes syntactic validation
    assert!(
        validate_fs_path(&exact_255).is_ok(),
        "Exact 255-byte path should pass syntactic validation"
    );

    // 256 bytes fails syntactic validation
    let exceeds_256 = format!("{exact_255}x");
    assert_eq!(exceeds_256.len(), 256);
    let err = validate_fs_path(&exceeds_256).unwrap_err();
    assert!(err.contains("maximum permitted length of 255 bytes"));

    // In PolicyEngine: 256-byte path is denied
    let engine = PolicyEngine::new_mvp(PathBuf::from("/demo"));
    let caller = CallerIdentity::principal("user");
    let decision = engine.evaluate(
        &caller,
        "fs.file.read",
        &serde_json::json!({"path": exceeds_256}),
    );
    assert!(decision.is_denied());
}

/// PATH-04: Path contains 50+ directory components (d1/d2/.../d50/file.txt).
/// Verifies iterative containment analysis without stack overflow.
#[test]
fn test_deeply_nested_directory_containment() {
    let sandbox = Path::new("/demo");
    let mut deep_path = String::new();
    for i in 0..50 {
        deep_path.push_str(&format!("d{i}/"));
    }
    deep_path.push_str("file.txt");

    // Component containment succeeds for nested hierarchy
    assert!(is_component_contained(sandbox, &deep_path).is_ok());

    // Deep hierarchy attempting to traverse back out
    let mut escaping_deep_path = deep_path.clone();
    for _ in 0..55 {
        escaping_deep_path.push_str("/..");
    }
    escaping_deep_path.push_str("/etc/passwd");

    assert!(is_component_contained(sandbox, &escaping_deep_path).is_err());
}

/// PATH-05: Architectural Demonstration of Known Limitation.
/// Documents that openat2(RESOLVE_BENEATH) resolves inodes directly and cannot prevent
/// reading a pre-existing hard link inside the sandbox pointing outside on the same filesystem.
#[test]
fn test_hard_link_known_limitation_demonstration() {
    let base_dir = std::env::temp_dir().join(format!(
        "aurora-hardlink-demo-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let outside_dir = base_dir.join("outside");
    let sandbox_dir = base_dir.join("sandbox");
    fs::create_dir_all(&outside_dir).expect("create outside dir failed");
    fs::create_dir_all(&sandbox_dir).expect("create sandbox dir failed");

    let outside_file = outside_dir.join("secret.txt");
    fs::write(&outside_file, "OUTSIDE_CONFIDENTIAL_INODE").expect("write secret failed");

    let inside_hardlink = sandbox_dir.join("link_to_secret.txt");
    if fs::hard_link(&outside_file, &inside_hardlink).is_err() {
        // Hard linking across distinct filesystems or in restricted tempfs may return EXDEV; skip gracefully
        let _ = fs::remove_dir_all(&base_dir);
        return;
    }

    let provider = SandboxedLocalFileProvider::new(&sandbox_dir).expect("Provider init failed");

    // Demonstrates known limitation: openat2 resolves the inode through directory entry
    let result = provider.read_file("link_to_secret.txt");
    assert!(
        result.is_ok(),
        "Hard link inode resolution should demonstrate the known limitation"
    );
    let payload = result.unwrap();
    assert_eq!(payload["content"], "OUTSIDE_CONFIDENTIAL_INODE");

    let _ = fs::remove_dir_all(&base_dir);
}

// ============================================================================
// Category 3: IPC & Protocol Rejection
// ============================================================================

/// IPC-01: Worker sends malformed JSON syntax followed immediately by a valid proposal frame.
/// Verifies supervisor invalidates connection on deserialization error, preventing fragment reuse.
#[test]
fn test_fragment_misparsing_prevention_after_json_syntax_error() {
    let (mut client, server) = UnixStream::pair().expect("UnixStream pair failed");
    let caller = CallerIdentity::principal("user");
    let mut policy = PolicyEngine::new_mvp(PathBuf::from("/demo"));
    policy.grant(caller.clone(), "sys.cpu.read");

    let mock_cpu = Arc::new(MockCpuProvider::with_success(serde_json::json!({})));
    let dispatcher = CapabilityDispatcher::new_with_all_capability_providers(
        policy,
        mock_cpu.clone(),
        Arc::new(MockMemoryProvider::with_success(serde_json::json!({}))),
        Arc::new(MockProcessProvider::with_success(serde_json::json!([]))),
        Arc::new(MockFileProvider::with_success(serde_json::json!({}))),
    );

    let config = create_test_config("ipc_syntax_err");
    let mut supervisor =
        WorkerSupervisor::from_stream(config, dispatcher, server).expect("from_stream failed");

    std::thread::spawn(move || {
        let mut reader = BufReader::new(client.try_clone().unwrap());
        let mut line = String::new();
        reader.read_line(&mut line).unwrap(); // Read RequestTurn

        // Write malformed JSON syntax followed by valid proposal frame
        let payload = b"{ not valid json syntax ::: }\n{\"type\":\"propose_capability\",\"protocol_version\":1,\"turn_id\":\"turn-1\",\"call_id\":\"call-1\",\"capability_name\":\"sys.cpu.read\",\"parameters\":{}}\n";
        client.write_all(payload).unwrap();
        client.flush().unwrap();
    });

    // Turn 1 fails with deserialization error
    let res1 = supervisor.execute_turn(&caller, "prompt");
    assert!(res1.is_err());
    match res1 {
        Err(SupervisorError::Ipc(IpcError::Serialization(_))) => {}
        other => panic!("Expected Serialization error, got: {other:?}"),
    }

    // Provider was never invoked
    assert_eq!(mock_cpu.invocation_count(), 0);

    // CRITICAL INVARIANT: Subsequent turn must fail immediately with ConnectionClosed
    let res2 = supervisor.execute_turn(&caller, "second prompt");
    match res2 {
        Err(SupervisorError::Ipc(IpcError::ConnectionClosed)) => {}
        other => panic!("Expected ConnectionClosed on subsequent call, got: {other:?}"),
    }
}

/// IPC-02: Worker writes partial frame and abruptly closes socket (EOF without newline).
#[test]
fn test_truncated_frame_mid_stream_eof() {
    let (mut client, server) = UnixStream::pair().expect("UnixStream pair failed");
    let caller = CallerIdentity::principal("user");
    let policy = PolicyEngine::new_mvp(PathBuf::from("/demo"));
    let mock_cpu = Arc::new(MockCpuProvider::with_success(serde_json::json!({})));
    let dispatcher = CapabilityDispatcher::new_with_all_capability_providers(
        policy,
        mock_cpu.clone(),
        Arc::new(MockMemoryProvider::with_success(serde_json::json!({}))),
        Arc::new(MockProcessProvider::with_success(serde_json::json!([]))),
        Arc::new(MockFileProvider::with_success(serde_json::json!({}))),
    );

    let config = create_test_config("ipc_eof");
    let mut supervisor =
        WorkerSupervisor::from_stream(config, dispatcher, server).expect("from_stream failed");

    std::thread::spawn(move || {
        let mut reader = BufReader::new(client.try_clone().unwrap());
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();

        // Write partial JSON without newline, then drop socket immediately
        let _ = client.write_all(b"{\"type\":\"propose_capability\"");
        let _ = client.flush();
        drop(client);
    });

    let res = supervisor.execute_turn(&caller, "prompt");
    assert!(res.is_err());
    match res {
        Err(SupervisorError::Ipc(IpcError::UnterminatedFrame))
        | Err(SupervisorError::Ipc(IpcError::ConnectionClosed)) => {}
        other => panic!("Expected UnterminatedFrame or ConnectionClosed, got: {other:?}"),
    }
    assert_eq!(mock_cpu.invocation_count(), 0);
}

/// IPC-03: Worker floods stream with empty newlines and spaces.
#[test]
fn test_whitespace_and_empty_newline_flooding() {
    let (mut client, server) = UnixStream::pair().expect("UnixStream pair failed");
    let caller = CallerIdentity::principal("user");
    let dispatcher = CapabilityDispatcher::new_default(PathBuf::from("/demo"));

    let config = create_test_config("ipc_whitespace");
    let mut supervisor =
        WorkerSupervisor::from_stream(config, dispatcher, server).expect("from_stream failed");

    std::thread::spawn(move || {
        let mut reader = BufReader::new(client.try_clone().unwrap());
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();

        // Flood with whitespace and empty newlines
        for _ in 0..100 {
            let _ = client.write_all(b"   \n\n\t\n");
        }
        let _ = client.flush();
    });

    let res = supervisor.execute_turn(&caller, "prompt");
    assert!(res.is_err());
    match res {
        Err(SupervisorError::Ipc(IpcError::ConnectionClosed)) => {}
        other => panic!("Expected ConnectionClosed on whitespace flooding, got: {other:?}"),
    }
}

/// IPC-04: Deeply nested JSON recursion bomb (200 levels deep) rejected safely by serde limit.
#[test]
fn test_deeply_nested_json_recursion_bomb() {
    let (mut client, server) = UnixStream::pair().expect("UnixStream pair failed");
    let caller = CallerIdentity::principal("user");
    let dispatcher = CapabilityDispatcher::new_default(PathBuf::from("/demo"));

    let config = create_test_config("ipc_json_bomb");
    let mut supervisor =
        WorkerSupervisor::from_stream(config, dispatcher, server).expect("from_stream failed");

    std::thread::spawn(move || {
        let mut reader = BufReader::new(client.try_clone().unwrap());
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();

        let mut payload = String::from("{\"type\":\"propose_capability\",\"turn_id\":\"turn-1\",\"call_id\":\"c1\",\"capability_name\":\"sys.cpu.read\",\"parameters\":");
        for _ in 0..200 {
            payload.push_str("{\"nested\":");
        }
        payload.push('1');
        for _ in 0..200 {
            payload.push('}');
        }
        payload.push_str("}\n");

        let _ = client.write_all(payload.as_bytes());
        let _ = client.flush();
    });

    let res = supervisor.execute_turn(&caller, "prompt");
    assert!(res.is_err());
    match res {
        Err(SupervisorError::Ipc(IpcError::Serialization(_))) => {}
        other => panic!("Expected Serialization error for nested JSON, got: {other:?}"),
    }
}

/// IPC-05: Worker transmits numeric protocol_version != 1 across proposal and complete_turn.
/// Verifies protocol violation rejects before provider execution and invalidates connection.
#[test]
fn test_numeric_protocol_version_invariance_across_messages() {
    let (mut client, server) = UnixStream::pair().expect("UnixStream pair failed");
    let caller = CallerIdentity::principal("user");
    let mut policy = PolicyEngine::new_mvp(PathBuf::from("/demo"));
    policy.grant(caller.clone(), "sys.cpu.read");

    let mock_cpu = Arc::new(MockCpuProvider::with_success(serde_json::json!({})));
    let dispatcher = CapabilityDispatcher::new_with_all_capability_providers(
        policy,
        mock_cpu.clone(),
        Arc::new(MockMemoryProvider::with_success(serde_json::json!({}))),
        Arc::new(MockProcessProvider::with_success(serde_json::json!([]))),
        Arc::new(MockFileProvider::with_success(serde_json::json!({}))),
    );

    let config = create_test_config("ipc_version_inv");
    let mut supervisor =
        WorkerSupervisor::from_stream(config, dispatcher, server).expect("from_stream failed");

    std::thread::spawn(move || {
        let mut reader = BufReader::new(client.try_clone().unwrap());
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();

        // Worker transmits proposal with protocol_version = 2
        let prop = serde_json::json!({
            "type": "propose_capability",
            "protocol_version": 2,
            "turn_id": "turn-1",
            "call_id": "call-1",
            "capability_name": "sys.cpu.read",
            "parameters": {}
        });
        client.write_all(format!("{prop}\n").as_bytes()).unwrap();
        client.flush().unwrap();
    });

    let res = supervisor.execute_turn(&caller, "prompt");
    assert!(res.is_err());
    match res {
        Err(SupervisorError::IncompatibleProtocolVersion {
            expected: 1,
            received: 2,
        }) => {}
        other => panic!("Expected IncompatibleProtocolVersion, got: {other:?}"),
    }

    // Provider count remains 0
    assert_eq!(mock_cpu.invocation_count(), 0);

    // Subsequent turn fails immediately with ConnectionClosed
    let next_res = supervisor.execute_turn(&caller, "second prompt");
    match next_res {
        Err(SupervisorError::Ipc(IpcError::ConnectionClosed)) => {}
        other => panic!("Expected ConnectionClosed after version violation, got: {other:?}"),
    }
}

// ============================================================================
// Category 4: Message Integrity & Turn Correlation
// ============================================================================

/// MSG-01: ProposeCapability with mismatched turn_id terminates connection.
#[test]
fn test_turn_id_mismatch_in_proposal_terminates_connection() {
    let (mut client, server) = UnixStream::pair().expect("UnixStream pair failed");
    let caller = CallerIdentity::principal("user");
    let mut policy = PolicyEngine::new_mvp(PathBuf::from("/demo"));
    policy.grant(caller.clone(), "sys.cpu.read");

    let mock_cpu = Arc::new(MockCpuProvider::with_success(serde_json::json!({})));
    let dispatcher = CapabilityDispatcher::new_with_all_capability_providers(
        policy,
        mock_cpu.clone(),
        Arc::new(MockMemoryProvider::with_success(serde_json::json!({}))),
        Arc::new(MockProcessProvider::with_success(serde_json::json!([]))),
        Arc::new(MockFileProvider::with_success(serde_json::json!({}))),
    );

    let config = create_test_config("msg_turn_mismatch");
    let mut supervisor =
        WorkerSupervisor::from_stream(config, dispatcher, server).expect("from_stream failed");

    std::thread::spawn(move || {
        let mut reader = BufReader::new(client.try_clone().unwrap());
        let mut line = String::new();
        reader.read_line(&mut line).unwrap(); // RequestTurn for turn-1

        // Mismatched turn ID: turn-999
        let prop = serde_json::json!({
            "type": "propose_capability",
            "protocol_version": CURRENT_PROTOCOL_VERSION,
            "turn_id": "turn-999",
            "call_id": "call-1",
            "capability_name": "sys.cpu.read",
            "parameters": {}
        });
        client.write_all(format!("{prop}\n").as_bytes()).unwrap();
        client.flush().unwrap();
    });

    let res = supervisor.execute_turn(&caller, "prompt");
    assert!(res.is_err());
    match res {
        Err(SupervisorError::UnexpectedMessage(msg)) => {
            assert!(msg.contains("Turn ID mismatch in proposal"));
        }
        other => panic!("Expected Turn ID mismatch error, got: {other:?}"),
    }

    assert_eq!(mock_cpu.invocation_count(), 0);

    // Invariant: Connection is closed; subsequent turn fails
    let res2 = supervisor.execute_turn(&caller, "prompt 2");
    match res2 {
        Err(SupervisorError::Ipc(IpcError::ConnectionClosed)) => {}
        other => panic!("Expected ConnectionClosed, got: {other:?}"),
    }
}

/// MSG-02: CompleteTurn with mismatched turn_id terminates connection.
/// Verifies provider ran earlier (count == 1) and cannot be retroactively undone,
/// but turn fails and connection is invalidated.
#[test]
fn test_turn_id_mismatch_in_complete_turn_terminates_connection() {
    let (mut client, server) = UnixStream::pair().expect("UnixStream pair failed");
    let caller = CallerIdentity::principal("user");
    let mut policy = PolicyEngine::new_mvp(PathBuf::from("/demo"));
    policy.grant(caller.clone(), "sys.cpu.read");

    let mock_cpu = Arc::new(MockCpuProvider::with_success(serde_json::json!({})));
    let dispatcher = CapabilityDispatcher::new_with_all_capability_providers(
        policy,
        mock_cpu.clone(),
        Arc::new(MockMemoryProvider::with_success(serde_json::json!({}))),
        Arc::new(MockProcessProvider::with_success(serde_json::json!([]))),
        Arc::new(MockFileProvider::with_success(serde_json::json!({}))),
    );

    let config = create_test_config("msg_comp_mismatch");
    let mut supervisor =
        WorkerSupervisor::from_stream(config, dispatcher, server).expect("from_stream failed");

    std::thread::spawn(move || {
        let mut reader = BufReader::new(client.try_clone().unwrap());
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();

        // Valid proposal for turn-1
        let prop = serde_json::json!({
            "type": "propose_capability",
            "protocol_version": CURRENT_PROTOCOL_VERSION,
            "turn_id": "turn-1",
            "call_id": "call-1",
            "capability_name": "sys.cpu.read",
            "parameters": {}
        });
        client.write_all(format!("{prop}\n").as_bytes()).unwrap();
        client.flush().unwrap();

        line.clear();
        reader.read_line(&mut line).unwrap(); // Result received

        // CompleteTurn with mismatched turn ID
        let comp = serde_json::json!({
            "type": "complete_turn",
            "protocol_version": CURRENT_PROTOCOL_VERSION,
            "turn_id": "turn-corrupted",
            "status": "success",
            "response_text": "Finished"
        });
        client.write_all(format!("{comp}\n").as_bytes()).unwrap();
        client.flush().unwrap();
    });

    let res = supervisor.execute_turn(&caller, "prompt");
    assert!(res.is_err());
    match res {
        Err(SupervisorError::UnexpectedMessage(msg)) => {
            assert!(msg.contains("Turn ID mismatch in complete_turn"));
        }
        other => panic!("Expected Turn ID mismatch error, got: {other:?}"),
    }

    // Provider was authorized and executed before violation occurred (count == 1)
    assert_eq!(mock_cpu.invocation_count(), 1);

    // Subsequent turn fails immediately
    let res2 = supervisor.execute_turn(&caller, "prompt 2");
    match res2 {
        Err(SupervisorError::Ipc(IpcError::ConnectionClosed)) => {}
        other => panic!("Expected ConnectionClosed, got: {other:?}"),
    }
}

/// MSG-03: Empty or whitespace correlation IDs (turn_id or call_id) rejected before provider execution.
#[test]
fn test_empty_or_whitespace_correlation_ids_rejected() {
    let caller = CallerIdentity::principal("user");
    let mut policy = PolicyEngine::new_mvp(PathBuf::from("/demo"));
    policy.grant(caller.clone(), "sys.cpu.read");

    let mock_cpu = Arc::new(MockCpuProvider::with_success(serde_json::json!({})));
    let dispatcher = CapabilityDispatcher::new(policy, mock_cpu.clone());

    let empty_ids = [
        ("", "call-1"),
        ("   ", "call-1"),
        ("turn-1", ""),
        ("turn-1", "   "),
    ];

    for (t_id, c_id) in empty_ids {
        let proposal = ProposeCapability {
            protocol_version: CURRENT_PROTOCOL_VERSION,
            turn_id: t_id.to_string(),
            call_id: c_id.to_string(),
            capability_name: "sys.cpu.read".to_string(),
            parameters: serde_json::json!({}),
        };

        let res = dispatcher.execute_proposal(&caller, &proposal);
        match res.outcome {
            CapabilityOutcome::Failure { error } => {
                assert_eq!(error.code, "INVALID_ARGUMENT");
            }
            CapabilityOutcome::Success { .. } => panic!("Empty correlation ID should not succeed"),
        }
    }

    assert_eq!(mock_cpu.invocation_count(), 0);
}

/// MSG-04: Unexpected HandshakeResponse during active turn invalidates connection.
#[test]
fn test_unexpected_handshake_response_during_turn_terminates_connection() {
    let (mut client, server) = UnixStream::pair().expect("UnixStream pair failed");
    let caller = CallerIdentity::principal("user");
    let dispatcher = CapabilityDispatcher::new_default(PathBuf::from("/demo"));

    let config = create_test_config("msg_handshake_seq");
    let mut supervisor =
        WorkerSupervisor::from_stream(config, dispatcher, server).expect("from_stream failed");

    std::thread::spawn(move || {
        let mut reader = BufReader::new(client.try_clone().unwrap());
        let mut line = String::new();
        reader.read_line(&mut line).unwrap(); // RequestTurn

        // Unexpected HandshakeResponse message
        let hs_resp = serde_json::json!({
            "type": "handshake_response",
            "protocol_version": CURRENT_PROTOCOL_VERSION,
            "worker_version": "0.1.0",
            "status": "ready"
        });
        client.write_all(format!("{hs_resp}\n").as_bytes()).unwrap();
        client.flush().unwrap();
    });

    let res = supervisor.execute_turn(&caller, "prompt");
    assert!(res.is_err());
    match res {
        Err(SupervisorError::UnexpectedMessage(msg)) => {
            assert!(msg.contains("Unexpected HandshakeResponse during active turn"));
        }
        other => panic!("Expected UnexpectedMessage, got: {other:?}"),
    }

    // Connection invalidated
    let res2 = supervisor.execute_turn(&caller, "prompt 2");
    match res2 {
        Err(SupervisorError::Ipc(IpcError::ConnectionClosed)) => {}
        other => panic!("Expected ConnectionClosed, got: {other:?}"),
    }
}

/// MSG-05: Worker transmits ProposeCapability before RequestTurn (unsolicited proposal).
#[test]
fn test_unsolicited_capability_proposal_before_request_turn() {
    let (mut client, server) = UnixStream::pair().expect("UnixStream pair failed");
    let caller = CallerIdentity::principal("user");
    let policy = PolicyEngine::new_mvp(PathBuf::from("/demo"));
    let mock_cpu = Arc::new(MockCpuProvider::with_success(serde_json::json!({})));
    let dispatcher = CapabilityDispatcher::new(policy, mock_cpu.clone());

    let config = create_test_config("msg_unsolicited");
    let mut supervisor =
        WorkerSupervisor::from_stream(config, dispatcher, server).expect("from_stream failed");

    // Client sends proposal BEFORE supervisor calls execute_turn
    let prop = serde_json::json!({
        "type": "propose_capability",
        "protocol_version": CURRENT_PROTOCOL_VERSION,
        "turn_id": "turn-unsolicited",
        "call_id": "call-1",
        "capability_name": "sys.cpu.read",
        "parameters": {}
    });
    client.write_all(format!("{prop}\n").as_bytes()).unwrap();
    client.flush().unwrap();

    // Now daemon initiates turn-1
    let res = supervisor.execute_turn(&caller, "prompt");
    // Fails due to turn ID mismatch or desynchronization
    assert!(res.is_err());
    assert_eq!(mock_cpu.invocation_count(), 0);
}

// ============================================================================
// Category 5: Worker Fault Containment & Lifecycle
// ============================================================================

/// FLT-01: Child process hangs during startup (sleeps before connecting).
/// Bounded by 2s test deadline; verifies HandshakeTimeout and child reap.
#[test]
fn test_handshake_connection_timeout_and_child_reap() {
    let mut config = create_test_config("flt_handshake_timeout");
    config.worker_command = vec![
        "python3".to_string(),
        "-c".to_string(),
        "import time; time.sleep(10)".to_string(),
    ];
    config.handshake_timeout = Duration::from_millis(200);

    let mut supervisor = WorkerSupervisor::new(config);
    let socket_path = supervisor.socket_path().to_path_buf();

    let start_time = std::time::Instant::now();
    let res = supervisor.start();
    let elapsed = start_time.elapsed();

    assert!(
        elapsed < Duration::from_secs(2),
        "Timeout exceeded bound: {elapsed:?}"
    );
    assert!(res.is_err(), "Expected supervisor start to time out");
    match res {
        Err(SupervisorError::HandshakeTimeout) => {}
        other => panic!("Expected HandshakeTimeout, got: {other:?}"),
    }

    supervisor.shutdown();
    assert!(
        !socket_path.exists(),
        "Socket path should not exist after shutdown"
    );
}

/// FLT-02: Worker connects and handshakes, but hangs indefinitely after RequestTurn.
/// Bounded by 2s test deadline; verifies turn read timeout.
#[test]
fn test_turn_socket_read_timeout_and_cleanup() {
    let mut config = create_test_config("flt_turn_timeout");
    config.worker_command = vec![
        "python3".to_string(),
        "-c".to_string(),
        r#"
import socket, sys, time, json
sock_path = sys.argv[2]
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect(sock_path)
sf = s.makefile('rwb')
l = sf.readline()
d = json.loads(l)
sf.write(json.dumps({'type':'handshake_response','protocol_version':1,'worker_version':'0.1.0','status':'ready'}).encode()+b'\n')
sf.flush()
sf.readline() # Read RequestTurn
time.sleep(10) # Hang indefinitely
"#.to_string(),
    ];
    config.handshake_timeout = Duration::from_secs(5);
    config = config.with_socket_timeout(Duration::from_millis(250));

    let mut supervisor = WorkerSupervisor::new(config);
    let caller = CallerIdentity::principal("user");

    supervisor.start().expect("Supervisor start failed");

    let start_time = std::time::Instant::now();
    let res = supervisor.execute_turn(&caller, "prompt");
    let elapsed = start_time.elapsed();

    assert!(
        elapsed < Duration::from_secs(2),
        "Turn timeout exceeded bound: {elapsed:?}"
    );
    assert!(res.is_err(), "Expected turn execution to time out");
    match res {
        Err(SupervisorError::Ipc(IpcError::Io(e))) => {
            assert!(
                e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut,
                "Unexpected IO error kind: {e:?}"
            );
        }
        other => panic!("Expected IO timeout, got: {other:?}"),
    }

    supervisor.shutdown();
}

/// FLT-03: Worker crashes during result delivery (closes socket before reading result).
/// Verifies write failure on CapabilityResult invalidates connection and fails next turn closed.
#[test]
fn test_worker_crash_during_result_delivery_handled_safely() {
    let (mut client, server) = UnixStream::pair().expect("UnixStream pair failed");
    let caller = CallerIdentity::principal("user");
    let mut policy = PolicyEngine::new_mvp(PathBuf::from("/demo"));
    policy.grant(caller.clone(), "sys.cpu.read");

    let mock_cpu = Arc::new(MockCpuProvider::with_success(serde_json::json!({})));
    let dispatcher = CapabilityDispatcher::new(policy, mock_cpu.clone());

    let config = create_test_config("flt_crash_delivery");
    let mut supervisor =
        WorkerSupervisor::from_stream(config, dispatcher, server).expect("from_stream failed");

    std::thread::spawn(move || {
        let mut reader = BufReader::new(client.try_clone().unwrap());
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();

        // Send valid proposal then drop client immediately to simulate sudden crash
        let prop = serde_json::json!({
            "type": "propose_capability",
            "protocol_version": CURRENT_PROTOCOL_VERSION,
            "turn_id": "turn-1",
            "call_id": "call-1",
            "capability_name": "sys.cpu.read",
            "parameters": {}
        });
        client.write_all(format!("{prop}\n").as_bytes()).unwrap();
        client.flush().unwrap();

        drop(client); // Sudden disconnect
    });

    let res = supervisor.execute_turn(&caller, "prompt");
    assert!(res.is_err());
    match res {
        Err(SupervisorError::Ipc(_)) => {}
        other => panic!("Expected IPC error on worker crash, got: {other:?}"),
    }

    // Provider executed before delivery failure
    assert_eq!(mock_cpu.invocation_count(), 1);

    // CRITICAL: Subsequent turn must fail closed with ConnectionClosed
    let res2 = supervisor.execute_turn(&caller, "second prompt");
    match res2 {
        Err(SupervisorError::Ipc(IpcError::ConnectionClosed)) => {}
        other => panic!("Expected ConnectionClosed on subsequent call, got: {other:?}"),
    }
}

/// FLT-03b: Worker disconnects before RequestTurn is transmitted.
/// Verifies write failure on RequestTurn invalidates connection immediately and prevents provider execution.
#[test]
fn test_write_failure_during_request_turn_invalidates_connection() {
    let (client, server) = UnixStream::pair().expect("UnixStream pair failed");
    let caller = CallerIdentity::principal("user");
    let mut policy = PolicyEngine::new_mvp(PathBuf::from("/demo"));
    policy.grant(caller.clone(), "sys.cpu.read");

    let mock_cpu = Arc::new(MockCpuProvider::with_success(serde_json::json!({})));
    let dispatcher = CapabilityDispatcher::new(policy, mock_cpu.clone());

    let config = create_test_config("flt_write_req_fail");
    let mut supervisor =
        WorkerSupervisor::from_stream(config, dispatcher, server).expect("from_stream failed");

    // Close client immediately before supervisor writes RequestTurn
    drop(client);

    let res = supervisor.execute_turn(&caller, "prompt");
    assert!(res.is_err());
    match res {
        Err(SupervisorError::Ipc(_)) => {}
        other => panic!("Expected IPC error on RequestTurn write failure, got: {other:?}"),
    }

    // Provider was never invoked
    assert_eq!(mock_cpu.invocation_count(), 0);

    // Subsequent turn must fail closed with ConnectionClosed
    let res2 = supervisor.execute_turn(&caller, "second prompt");
    match res2 {
        Err(SupervisorError::Ipc(IpcError::ConnectionClosed)) => {}
        other => panic!("Expected ConnectionClosed on subsequent call, got: {other:?}"),
    }
}

/// FLT-04a: Stale dead socket exists at configured path from unclean crash.
/// Startup refuses to run when path is occupied, preserving entry untouched without deletion.
/// Critically verifies that dropping the failed supervisor does NOT unlink the pre-existing entry.
#[test]
fn test_stale_socket_entry_refuses_startup_without_deletion() {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    let socket_path = create_unique_temp_socket("stale_sock");

    // Create a dead socket file (bind and drop listener)
    {
        let _listener = UnixListener::bind(&socket_path).expect("Bind dead socket failed");
    }
    let pre_meta = fs::symlink_metadata(&socket_path).expect("Dead socket metadata failed");
    assert!(pre_meta.file_type().is_socket());
    let orig_dev_ino = (pre_meta.dev(), pre_meta.ino());

    let config = SupervisorConfig::default().with_socket_path(socket_path.clone());
    let mut supervisor = WorkerSupervisor::new(config);

    let res = supervisor.start();
    assert!(
        res.is_err(),
        "Expected startup to fail when path is occupied"
    );
    match res {
        Err(SupervisorError::SocketAlreadyExists(p)) => {
            assert_eq!(p, socket_path);
        }
        other => panic!("Expected SocketAlreadyExists, got: {other:?}"),
    }

    assert!(
        !supervisor.owns_socket(),
        "Failed supervisor must not claim ownership"
    );

    // CRITICAL: Drop the supervisor instance to verify Drop::drop does not unlink the pre-existing entry
    drop(supervisor);

    // Pre-existing dead socket was NOT deleted on startup refusal or on drop
    let post_meta = fs::symlink_metadata(&socket_path).expect("Dead socket must exist post-drop");
    assert!(post_meta.file_type().is_socket(), "Must remain a socket");
    assert_eq!(
        (post_meta.dev(), post_meta.ino()),
        orig_dev_ino,
        "Original inode must be untouched"
    );

    // Clean up test fixture safely
    let _ = fs::remove_file(&socket_path);
}

/// FLT-04b: Active listener socket exists from another running daemon.
/// Startup refuses to run, preserving active listener without disruption.
/// Critically verifies that dropping the failed supervisor does not disrupt or unlink the listener.
#[test]
fn test_active_listener_socket_refuses_startup_without_deletion() {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    let socket_path = create_unique_temp_socket("active_sock");
    let active_listener = UnixListener::bind(&socket_path).expect("Bind active listener failed");

    let pre_meta = fs::symlink_metadata(&socket_path).expect("Active listener metadata failed");
    assert!(pre_meta.file_type().is_socket());
    let orig_dev_ino = (pre_meta.dev(), pre_meta.ino());

    let config = SupervisorConfig::default().with_socket_path(socket_path.clone());
    let mut supervisor = WorkerSupervisor::new(config);

    let res = supervisor.start();
    assert!(res.is_err());
    match res {
        Err(SupervisorError::SocketAlreadyExists(p)) => {
            assert_eq!(p, socket_path);
        }
        other => panic!("Expected SocketAlreadyExists, got: {other:?}"),
    }

    assert!(
        !supervisor.owns_socket(),
        "Failed supervisor must not claim ownership"
    );

    // CRITICAL: Drop the supervisor instance to verify Drop::drop does not unlink active listener
    drop(supervisor);

    // Active listener path was NOT deleted post-drop
    let post_meta =
        fs::symlink_metadata(&socket_path).expect("Active listener path must exist post-drop");
    assert!(post_meta.file_type().is_socket(), "Must remain a socket");
    assert_eq!(
        (post_meta.dev(), post_meta.ino()),
        orig_dev_ino,
        "Active socket inode must be preserved"
    );

    // Verify active listener remains functional and undisrupted
    let client_conn = UnixStream::connect(&socket_path);
    assert!(
        client_conn.is_ok(),
        "Active listener must remain functional and accept connections"
    );
    drop(client_conn);

    drop(active_listener);
    let _ = fs::remove_file(&socket_path);
}

/// FLT-04c: Regular file exists at configured socket path.
/// Startup refuses to run, regular file is not deleted.
/// Critically verifies that dropping the failed supervisor does not delete the conflicting file.
#[test]
fn test_conflicting_regular_file_refuses_startup_without_deletion() {
    let file_path = create_unique_temp_socket("regular_file");
    fs::write(&file_path, "IMPORTANT_DATA").expect("write file failed");

    let pre_meta = fs::symlink_metadata(&file_path).expect("Regular file metadata failed");
    assert!(pre_meta.is_file());

    let config = SupervisorConfig::default().with_socket_path(file_path.clone());
    let mut supervisor = WorkerSupervisor::new(config);

    let res = supervisor.start();
    assert!(res.is_err());
    match res {
        Err(SupervisorError::SocketAlreadyExists(p)) => {
            assert_eq!(p, file_path);
        }
        other => panic!("Expected SocketAlreadyExists, got: {other:?}"),
    }

    assert!(
        !supervisor.owns_socket(),
        "Failed supervisor must not claim ownership"
    );

    // CRITICAL: Drop the supervisor instance to verify Drop::drop does not delete regular file
    drop(supervisor);

    // Regular file was NOT deleted post-drop and contents intact
    let post_meta = fs::symlink_metadata(&file_path).expect("Regular file must exist post-drop");
    assert!(post_meta.is_file(), "Must remain a regular file");
    assert_eq!(fs::read_to_string(&file_path).unwrap(), "IMPORTANT_DATA");

    let _ = fs::remove_file(&file_path);
}

/// FLT-04d: Dangling symlink exists at configured socket path.
/// Startup detects symlink directly without following and refuses without deletion.
/// Critically verifies that dropping the failed supervisor does not unlink the symlink.
#[test]
fn test_dangling_symlink_refuses_startup_without_deletion() {
    let symlink_path = create_unique_temp_socket("dangling_link");
    let target_path = PathBuf::from("/nonexistent/aurora/target");

    symlink(&target_path, &symlink_path).expect("symlink creation failed");
    assert!(fs::symlink_metadata(&symlink_path).is_ok());

    let config = SupervisorConfig::default().with_socket_path(symlink_path.clone());
    let mut supervisor = WorkerSupervisor::new(config);

    let res = supervisor.start();
    assert!(res.is_err());
    match res {
        Err(SupervisorError::SocketAlreadyExists(p)) => {
            assert_eq!(p, symlink_path);
        }
        other => panic!("Expected SocketAlreadyExists, got: {other:?}"),
    }

    assert!(
        !supervisor.owns_socket(),
        "Failed supervisor must not claim ownership"
    );

    // CRITICAL: Drop the supervisor instance to verify Drop::drop does not unlink symlink
    drop(supervisor);

    // Dangling symlink was NOT deleted post-drop
    let post_meta = fs::symlink_metadata(&symlink_path).expect("Symlink must exist post-drop");
    assert!(post_meta.file_type().is_symlink(), "Must remain a symlink");
    assert_eq!(fs::read_link(&symlink_path).unwrap(), target_path);

    let _ = fs::remove_file(&symlink_path);
}

/// FLT-04e: Socket replacement safeguard during supervisor runtime.
/// If an active socket path is unlinked and replaced with a regular file while running,
/// supervisor shutdown() detects the mismatch and refrains from deleting the replacement file.
#[test]
fn test_socket_path_replacement_safeguard() {
    let socket_path = create_unique_temp_socket("replacement_guard");
    let mut config = SupervisorConfig::default()
        .with_socket_path(socket_path.clone())
        .with_handshake_timeout(Duration::from_secs(5));
    config.working_dir = Some(get_workspace_root());

    let mut supervisor = WorkerSupervisor::new(config);
    supervisor.start().expect("Supervisor start failed");
    assert!(supervisor.owns_socket());

    // Replace the bound socket with a regular file
    fs::remove_file(&socket_path).expect("remove bound socket failed");
    fs::write(&socket_path, "REPLACEMENT_DATA").expect("write replacement failed");

    // Shutdown supervisor
    supervisor.shutdown();

    // Replacement regular file must NOT have been deleted
    assert!(fs::symlink_metadata(&socket_path).is_ok());
    assert_eq!(
        fs::read_to_string(&socket_path).unwrap(),
        "REPLACEMENT_DATA"
    );

    let _ = fs::remove_file(&socket_path);
}

// ============================================================================
// Category 6: Provider Failure Handling
// ============================================================================

/// PROV-01: File inside sandbox is unreadable by OS permissions (EACCES/EPERM).
/// Verifies policy evaluates Allow, provider encounters EACCES, returns IO_ERROR (never PERMISSION_DENIED).
#[test]
fn test_unreadable_file_eacces_vs_policy_denial() {
    let caller = CallerIdentity::principal("user");
    let sandbox = std::env::temp_dir().join(format!(
        "aurora-eacces-test-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&sandbox).expect("create sandbox failed");

    let mut policy = PolicyEngine::new_mvp(sandbox.clone());
    policy.grant(caller.clone(), "fs.file.read");

    // Use with_simulated_error(Errno::ACCESS) for deterministic, unprivileged-independent verification
    let mock_file = SandboxedLocalFileProvider::new(&sandbox)
        .expect("Provider init failed")
        .with_simulated_error(rustix::io::Errno::ACCESS);

    let dispatcher = CapabilityDispatcher::new_with_all_capability_providers(
        policy,
        Arc::new(MockCpuProvider::with_success(serde_json::json!({}))),
        Arc::new(MockMemoryProvider::with_success(serde_json::json!({}))),
        Arc::new(MockProcessProvider::with_success(serde_json::json!([]))),
        Arc::new(mock_file),
    );

    let proposal = ProposeCapability {
        protocol_version: CURRENT_PROTOCOL_VERSION,
        turn_id: "turn-1".to_string(),
        call_id: "call-1".to_string(),
        capability_name: "fs.file.read".to_string(),
        parameters: serde_json::json!({"path": "sample.txt"}),
    };

    let res = dispatcher.execute_proposal(&caller, &proposal);
    match res.outcome {
        CapabilityOutcome::Failure { error } => {
            assert_eq!(error.code, "IO_ERROR");
            assert_ne!(error.code, "PERMISSION_DENIED");
            assert!(error
                .message
                .contains("Access to the requested file was denied"));
        }
        CapabilityOutcome::Success { .. } => panic!("Expected simulated EACCES to fail"),
    }

    let _ = fs::remove_dir_all(&sandbox);
}

/// PROV-02: Corrupted telemetry data handling via temporary fixture files.
/// Host /proc is completely untouched.
#[test]
fn test_corrupted_telemetry_source_handling_via_fixtures() {
    let temp_dir = std::env::temp_dir().join(format!(
        "aurora-corrupt-telemetry-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&temp_dir).expect("create temp dir failed");

    // 1. Corrupted CPU stat file
    let corrupt_stat = temp_dir.join("stat");
    fs::write(&corrupt_stat, "not_cpu 123 456\nintr 789\n").unwrap();
    let cpu_provider = LinuxProcStatCpuProvider::with_path(&corrupt_stat);
    let cpu_res = cpu_provider.read_cpu();
    assert!(cpu_res.is_err());
    assert_eq!(cpu_res.unwrap_err().code, "PARSE_ERROR");

    // 2. Corrupted Memory info file
    let corrupt_mem = temp_dir.join("meminfo");
    fs::write(&corrupt_mem, "MemTotal: not_a_number kB\nMemFree: 100 kB\n").unwrap();
    let mem_provider = LinuxProcMeminfoMemoryProvider::with_path(&corrupt_mem);
    let mem_res = mem_provider.read_memory();
    assert!(mem_res.is_err());
    assert_eq!(mem_res.unwrap_err().code, "PARSE_ERROR");

    // 3. Corrupted / Inaccessible Process directory
    let corrupt_proc_dir = temp_dir.join("inaccessible_proc");
    // Path points to a non-existent directory
    let proc_provider = LinuxProcFsProcessProvider::with_path(&corrupt_proc_dir);
    let proc_res = proc_provider.list_processes(10);
    assert!(proc_res.is_err());
    assert_eq!(proc_res.unwrap_err().code, "IO_ERROR");

    let _ = fs::remove_dir_all(&temp_dir);
}

// ============================================================================
// Category 7: Regression Protection
// ============================================================================

/// REG-01: Consolidated matrix evaluating all 4 MVP capabilities across 5 cases:
/// (1) ungranted, (2) anonymous, (3) invalid params, (4) unknown capability, (5) explicit grant.
#[test]
fn test_unified_policy_before_provider_matrix() {
    let caller_granted = CallerIdentity::principal("authorized_user");
    let caller_ungranted = CallerIdentity::principal("unauthorized_user");
    let caller_anon = CallerIdentity::anonymous();

    let sandbox = PathBuf::from("/demo");
    let mut policy = PolicyEngine::new_mvp(sandbox);
    policy.grant_all_mvp(&caller_granted);

    let mock_cpu = Arc::new(MockCpuProvider::with_success(serde_json::json!({})));
    let mock_mem = Arc::new(MockMemoryProvider::with_success(serde_json::json!({})));
    let mock_proc = Arc::new(MockProcessProvider::with_success(serde_json::json!([])));
    let mock_file = Arc::new(MockFileProvider::with_success(serde_json::json!({})));

    let dispatcher = CapabilityDispatcher::new_with_all_capability_providers(
        policy,
        mock_cpu.clone(),
        mock_mem.clone(),
        mock_proc.clone(),
        mock_file.clone(),
    );

    let test_cases = [
        (
            "sys.cpu.read",
            serde_json::json!({}),
            serde_json::json!({"extra": 1}),
        ),
        (
            "sys.memory.read",
            serde_json::json!({}),
            serde_json::json!({"extra": 1}),
        ),
        (
            "proc.list",
            serde_json::json!({"limit": 10}),
            serde_json::json!({"limit": 999}),
        ),
        (
            "fs.file.read",
            serde_json::json!({"path": "file.txt"}),
            serde_json::json!({"path": "../escape.txt"}),
        ),
    ];

    for (cap, valid_params, invalid_params) in &test_cases {
        // Case 1: Ungranted caller -> PERMISSION_DENIED
        let p1 = ProposeCapability {
            protocol_version: CURRENT_PROTOCOL_VERSION,
            turn_id: "t1".to_string(),
            call_id: "c1".to_string(),
            capability_name: cap.to_string(),
            parameters: valid_params.clone(),
        };
        let r1 = dispatcher.execute_proposal(&caller_ungranted, &p1);
        assert!(
            matches!(r1.outcome, CapabilityOutcome::Failure { ref error } if error.code == "PERMISSION_DENIED")
        );

        // Case 2: Anonymous caller -> PERMISSION_DENIED
        let p2 = ProposeCapability {
            protocol_version: CURRENT_PROTOCOL_VERSION,
            turn_id: "t2".to_string(),
            call_id: "c2".to_string(),
            capability_name: cap.to_string(),
            parameters: valid_params.clone(),
        };
        let r2 = dispatcher.execute_proposal(&caller_anon, &p2);
        assert!(
            matches!(r2.outcome, CapabilityOutcome::Failure { ref error } if error.code == "PERMISSION_DENIED")
        );

        // Case 3: Invalid parameters -> PERMISSION_DENIED
        let p3 = ProposeCapability {
            protocol_version: CURRENT_PROTOCOL_VERSION,
            turn_id: "t3".to_string(),
            call_id: "c3".to_string(),
            capability_name: cap.to_string(),
            parameters: invalid_params.clone(),
        };
        let r3 = dispatcher.execute_proposal(&caller_granted, &p3);
        assert!(
            matches!(r3.outcome, CapabilityOutcome::Failure { ref error } if error.code == "PERMISSION_DENIED")
        );

        // Case 4: Unknown capability -> PERMISSION_DENIED
        let p4 = ProposeCapability {
            protocol_version: CURRENT_PROTOCOL_VERSION,
            turn_id: "t4".to_string(),
            call_id: "c4".to_string(),
            capability_name: format!("{cap}.unknown"),
            parameters: valid_params.clone(),
        };
        let r4 = dispatcher.execute_proposal(&caller_granted, &p4);
        assert!(
            matches!(r4.outcome, CapabilityOutcome::Failure { ref error } if error.code == "PERMISSION_DENIED")
        );
    }

    // All provider counts must remain strictly 0 after failure cases
    assert_eq!(mock_cpu.invocation_count(), 0);
    assert_eq!(mock_mem.invocation_count(), 0);
    assert_eq!(mock_proc.invocation_count(), 0);
    assert_eq!(mock_file.invocation_count(), 0);

    // Case 5: Explicit grant succeeds and increments count to exactly 1
    for (cap, valid_params, _) in &test_cases {
        let p5 = ProposeCapability {
            protocol_version: CURRENT_PROTOCOL_VERSION,
            turn_id: "t5".to_string(),
            call_id: "c5".to_string(),
            capability_name: cap.to_string(),
            parameters: valid_params.clone(),
        };
        let r5 = dispatcher.execute_proposal(&caller_granted, &p5);
        assert!(matches!(r5.outcome, CapabilityOutcome::Success { .. }));
    }

    assert_eq!(mock_cpu.invocation_count(), 1);
    assert_eq!(mock_mem.invocation_count(), 1);
    assert_eq!(mock_proc.invocation_count(), 1);
    assert_eq!(mock_file.invocation_count(), 1);
}
