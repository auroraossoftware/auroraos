//! Milestone 6c Integration Tests: fs.file.read Capability Execution Boundary
//!
//! Pursuant to ADR-001, ADR-002, and Vertical Slice Prototype Design:
//! - `aurora-ai` daemon is the sole policy enforcement point for file reads.
//! - The Python worker is untrusted and can only propose actions over private IPC.
//! - Authorization and strict syntactic validation MUST strictly occur BEFORE capability provider execution.
//! - Denied, anonymous, invalid, or escaping requests must NEVER invoke the provider (proven via mock counter).
//! - Paths are strictly relative; '..', '.', empty segments, null bytes, control chars, and length > 255 are rejected.
//! - Kernel-enforced path containment via `openat2` with `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV`.
//! - File size limit: max 64 KiB (65,536 bytes). Files exceeding this are rejected (`RESOURCE_EXHAUSTED`).
//! - Strictly regular files: directories, FIFOs, devices, sockets are rejected without blocking.
//! - Strict UTF-8 validation: binary files fail cleanly without partial content (`INVALID_DATA`).
//! - Provider failures (e.g. `NOT_FOUND`, `RESOURCE_EXHAUSTED`, `IO_ERROR`) are cleanly distinguished from `PERMISSION_DENIED`.
//! - Fail-closed on syscall failures (`EAGAIN`, `ENOSYS`) without userspace canonicalization fallback.
//! - Race resistance: TOCTOU path swap races cannot leak external files.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use aurora_ai::{
    CallerIdentity, CapabilityDispatcher, CapabilityExecutionError, FileProvider, MockCpuProvider,
    MockFileProvider, MockMemoryProvider, MockProcessProvider, PolicyEngine,
    SandboxedLocalFileProvider, SupervisorConfig, WorkerSupervisor, MAX_FILE_SIZE_BYTES,
};
use aurora_protocol::{CapabilityOutcome, ProposeCapability, TurnStatus, CURRENT_PROTOCOL_VERSION};

fn get_workspace_root() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .map(|p| p.to_path_buf())
        .unwrap_or(manifest_dir)
}

fn create_test_config(test_name: &str, sandbox_path: &Path) -> SupervisorConfig {
    let temp_socket = std::env::temp_dir().join(format!(
        "aurora-m6c-{test_name}-{}.sock",
        std::process::id()
    ));
    let mut config = SupervisorConfig::default()
        .with_socket_path(temp_socket)
        .with_handshake_timeout(Duration::from_secs(5))
        .with_demo_sandbox_path(sandbox_path);
    config.working_dir = Some(get_workspace_root());
    config
}

fn make_file_proposal(params: serde_json::Value) -> ProposeCapability {
    ProposeCapability {
        protocol_version: CURRENT_PROTOCOL_VERSION,
        turn_id: "turn-m6c-001".to_string(),
        call_id: "call-file-001".to_string(),
        capability_name: "fs.file.read".to_string(),
        parameters: params,
    }
}

fn mock_success_file() -> Arc<MockFileProvider> {
    Arc::new(MockFileProvider::with_success(serde_json::json!({
        "content": "sample content",
        "byte_length": 14
    })))
}

// ============================================================================
// Group 1: Policy Non-Invocation Invariants (mock provider counter == 0)
// ============================================================================

#[test]
fn test_unauthorized_caller_denied_provider_count_zero() {
    let caller = CallerIdentity::principal("unauthorized-agent");
    let sandbox = PathBuf::from("/tmp/test_sandbox_m6c");
    let policy = PolicyEngine::new_mvp(sandbox); // No grants

    let mock_file = mock_success_file();
    let dispatcher = CapabilityDispatcher::new_with_all_capability_providers(
        policy,
        Arc::new(MockCpuProvider::with_success(serde_json::json!({}))),
        Arc::new(MockMemoryProvider::with_success(serde_json::json!({}))),
        Arc::new(MockProcessProvider::with_success(serde_json::json!([]))),
        mock_file.clone(),
    );

    let proposal = make_file_proposal(serde_json::json!({"path": "file.txt"}));
    let result = dispatcher.execute_proposal(&caller, &proposal);

    // CRITICAL SECURITY INVARIANT: Provider must NEVER be invoked
    assert_eq!(mock_file.invocation_count(), 0);

    match result.outcome {
        CapabilityOutcome::Failure { error } => {
            assert_eq!(error.code, "PERMISSION_DENIED");
            assert!(error.message.contains("not permitted"));
        }
        CapabilityOutcome::Success { .. } => panic!("Unauthorized request unexpectedly succeeded"),
    }
}

#[test]
fn test_anonymous_caller_denied_provider_count_zero() {
    let anon = CallerIdentity::anonymous();
    let sandbox = PathBuf::from("/tmp/test_sandbox_m6c");
    let mut policy = PolicyEngine::new_mvp(sandbox);
    policy.grant(anon.clone(), "fs.file.read"); // Granting anonymous is ignored by policy engine

    let mock_file = mock_success_file();
    let dispatcher = CapabilityDispatcher::new_with_all_capability_providers(
        policy,
        Arc::new(MockCpuProvider::with_success(serde_json::json!({}))),
        Arc::new(MockMemoryProvider::with_success(serde_json::json!({}))),
        Arc::new(MockProcessProvider::with_success(serde_json::json!([]))),
        mock_file.clone(),
    );

    let proposal = make_file_proposal(serde_json::json!({"path": "file.txt"}));
    let result = dispatcher.execute_proposal(&anon, &proposal);

    assert_eq!(mock_file.invocation_count(), 0);

    match result.outcome {
        CapabilityOutcome::Failure { error } => {
            assert_eq!(error.code, "PERMISSION_DENIED");
        }
        CapabilityOutcome::Success { .. } => panic!("Anonymous request unexpectedly succeeded"),
    }
}

#[test]
fn test_missing_path_parameter_denied_provider_count_zero() {
    let caller = CallerIdentity::principal("user");
    let sandbox = PathBuf::from("/tmp/test_sandbox_m6c");
    let mut policy = PolicyEngine::new_mvp(sandbox);
    policy.grant(caller.clone(), "fs.file.read");

    let mock_file = mock_success_file();
    let dispatcher = CapabilityDispatcher::new_with_all_capability_providers(
        policy,
        Arc::new(MockCpuProvider::with_success(serde_json::json!({}))),
        Arc::new(MockMemoryProvider::with_success(serde_json::json!({}))),
        Arc::new(MockProcessProvider::with_success(serde_json::json!([]))),
        mock_file.clone(),
    );

    let proposal = make_file_proposal(serde_json::json!({}));
    let result = dispatcher.execute_proposal(&caller, &proposal);

    assert_eq!(mock_file.invocation_count(), 0);
    match result.outcome {
        CapabilityOutcome::Failure { error } => {
            assert_eq!(error.code, "PERMISSION_DENIED");
            assert!(error.message.contains("Missing required parameter 'path'"));
        }
        _ => panic!("Expected failure"),
    }
}

#[test]
fn test_non_string_path_parameter_denied_provider_count_zero() {
    let caller = CallerIdentity::principal("user");
    let sandbox = PathBuf::from("/tmp/test_sandbox_m6c");
    let mut policy = PolicyEngine::new_mvp(sandbox);
    policy.grant(caller.clone(), "fs.file.read");

    let mock_file = mock_success_file();
    let dispatcher = CapabilityDispatcher::new_with_all_capability_providers(
        policy,
        Arc::new(MockCpuProvider::with_success(serde_json::json!({}))),
        Arc::new(MockMemoryProvider::with_success(serde_json::json!({}))),
        Arc::new(MockProcessProvider::with_success(serde_json::json!([]))),
        mock_file.clone(),
    );

    for bad_path in [
        serde_json::json!(12345),
        serde_json::json!(true),
        serde_json::json!(["file.txt"]),
        serde_json::json!({"name": "file.txt"}),
    ] {
        let proposal = make_file_proposal(serde_json::json!({"path": bad_path}));
        let result = dispatcher.execute_proposal(&caller, &proposal);

        assert_eq!(mock_file.invocation_count(), 0);
        match result.outcome {
            CapabilityOutcome::Failure { error } => {
                assert_eq!(error.code, "PERMISSION_DENIED");
            }
            _ => panic!("Expected failure for {:?}", bad_path),
        }
    }
}

#[test]
fn test_unexpected_fields_denied_provider_count_zero() {
    let caller = CallerIdentity::principal("user");
    let sandbox = PathBuf::from("/tmp/test_sandbox_m6c");
    let mut policy = PolicyEngine::new_mvp(sandbox);
    policy.grant(caller.clone(), "fs.file.read");

    let mock_file = mock_success_file();
    let dispatcher = CapabilityDispatcher::new_with_all_capability_providers(
        policy,
        Arc::new(MockCpuProvider::with_success(serde_json::json!({}))),
        Arc::new(MockMemoryProvider::with_success(serde_json::json!({}))),
        Arc::new(MockProcessProvider::with_success(serde_json::json!([]))),
        mock_file.clone(),
    );

    let proposal = make_file_proposal(serde_json::json!({
        "path": "file.txt",
        "extra_field": "unauthorized"
    }));
    let result = dispatcher.execute_proposal(&caller, &proposal);

    assert_eq!(mock_file.invocation_count(), 0);
    match result.outcome {
        CapabilityOutcome::Failure { error } => {
            assert_eq!(error.code, "PERMISSION_DENIED");
            assert!(error
                .message
                .contains("Unexpected parameter for fs.file.read: 'extra_field'"));
        }
        _ => panic!("Expected failure for unexpected fields"),
    }
}

#[test]
fn test_control_characters_denied_provider_count_zero() {
    let caller = CallerIdentity::principal("user");
    let sandbox = PathBuf::from("/tmp/test_sandbox_m6c");
    let mut policy = PolicyEngine::new_mvp(sandbox);
    policy.grant(caller.clone(), "fs.file.read");

    let mock_file = mock_success_file();
    let dispatcher = CapabilityDispatcher::new_with_all_capability_providers(
        policy,
        Arc::new(MockCpuProvider::with_success(serde_json::json!({}))),
        Arc::new(MockMemoryProvider::with_success(serde_json::json!({}))),
        Arc::new(MockProcessProvider::with_success(serde_json::json!([]))),
        mock_file.clone(),
    );

    for bad_path in [
        "file\nname.txt",
        "file\rname.txt",
        "file\x1b[0m.txt",
        "file\t.txt",
    ] {
        let proposal = make_file_proposal(serde_json::json!({"path": bad_path}));
        let result = dispatcher.execute_proposal(&caller, &proposal);

        assert_eq!(mock_file.invocation_count(), 0);
        match result.outcome {
            CapabilityOutcome::Failure { error } => {
                assert_eq!(error.code, "PERMISSION_DENIED");
                assert!(error.message.contains("control characters"));
            }
            _ => panic!("Expected failure for control char in path: {:?}", bad_path),
        }
    }
}

#[test]
fn test_empty_and_whitespace_path_denied_provider_count_zero() {
    let caller = CallerIdentity::principal("user");
    let sandbox = PathBuf::from("/tmp/test_sandbox_m6c");
    let mut policy = PolicyEngine::new_mvp(sandbox);
    policy.grant(caller.clone(), "fs.file.read");

    let mock_file = mock_success_file();
    let dispatcher = CapabilityDispatcher::new_with_all_capability_providers(
        policy,
        Arc::new(MockCpuProvider::with_success(serde_json::json!({}))),
        Arc::new(MockMemoryProvider::with_success(serde_json::json!({}))),
        Arc::new(MockProcessProvider::with_success(serde_json::json!([]))),
        mock_file.clone(),
    );

    for empty_path in ["", "   ", "\t  \n"] {
        let proposal = make_file_proposal(serde_json::json!({"path": empty_path}));
        let result = dispatcher.execute_proposal(&caller, &proposal);

        assert_eq!(mock_file.invocation_count(), 0);
        match result.outcome {
            CapabilityOutcome::Failure { error } => {
                assert_eq!(error.code, "PERMISSION_DENIED");
            }
            _ => panic!("Expected failure for empty path"),
        }
    }
}

#[test]
fn test_null_byte_path_denied_provider_count_zero() {
    let caller = CallerIdentity::principal("user");
    let sandbox = PathBuf::from("/tmp/test_sandbox_m6c");
    let mut policy = PolicyEngine::new_mvp(sandbox);
    policy.grant(caller.clone(), "fs.file.read");

    let mock_file = mock_success_file();
    let dispatcher = CapabilityDispatcher::new_with_all_capability_providers(
        policy,
        Arc::new(MockCpuProvider::with_success(serde_json::json!({}))),
        Arc::new(MockMemoryProvider::with_success(serde_json::json!({}))),
        Arc::new(MockProcessProvider::with_success(serde_json::json!([]))),
        mock_file.clone(),
    );

    let proposal = make_file_proposal(serde_json::json!({"path": "secret.txt\0.safe"}));
    let result = dispatcher.execute_proposal(&caller, &proposal);

    assert_eq!(mock_file.invocation_count(), 0);
    match result.outcome {
        CapabilityOutcome::Failure { error } => {
            assert_eq!(error.code, "PERMISSION_DENIED");
            assert!(error.message.contains("null byte"));
        }
        _ => panic!("Expected failure for null byte in path"),
    }
}

#[test]
fn test_path_length_exceeded_denied_provider_count_zero() {
    let caller = CallerIdentity::principal("user");
    let sandbox = PathBuf::from("/tmp/test_sandbox_m6c");
    let mut policy = PolicyEngine::new_mvp(sandbox);
    policy.grant(caller.clone(), "fs.file.read");

    let mock_file = mock_success_file();
    let dispatcher = CapabilityDispatcher::new_with_all_capability_providers(
        policy,
        Arc::new(MockCpuProvider::with_success(serde_json::json!({}))),
        Arc::new(MockMemoryProvider::with_success(serde_json::json!({}))),
        Arc::new(MockProcessProvider::with_success(serde_json::json!([]))),
        mock_file.clone(),
    );

    let long_path = "a".repeat(256);
    let proposal = make_file_proposal(serde_json::json!({"path": long_path}));
    let result = dispatcher.execute_proposal(&caller, &proposal);

    assert_eq!(mock_file.invocation_count(), 0);
    match result.outcome {
        CapabilityOutcome::Failure { error } => {
            assert_eq!(error.code, "PERMISSION_DENIED");
            assert!(error
                .message
                .contains("maximum permitted length of 255 bytes"));
        }
        _ => panic!("Expected failure for length > 255"),
    }
}

#[test]
fn test_explicit_dot_component_denied_provider_count_zero() {
    let caller = CallerIdentity::principal("user");
    let sandbox = PathBuf::from("/tmp/test_sandbox_m6c");
    let mut policy = PolicyEngine::new_mvp(sandbox);
    policy.grant(caller.clone(), "fs.file.read");

    let mock_file = mock_success_file();
    let dispatcher = CapabilityDispatcher::new_with_all_capability_providers(
        policy,
        Arc::new(MockCpuProvider::with_success(serde_json::json!({}))),
        Arc::new(MockMemoryProvider::with_success(serde_json::json!({}))),
        Arc::new(MockProcessProvider::with_success(serde_json::json!([]))),
        mock_file.clone(),
    );

    for dot_path in ["dir/./file.txt", "./file.txt", ".", "dir/."] {
        let proposal = make_file_proposal(serde_json::json!({"path": dot_path}));
        let result = dispatcher.execute_proposal(&caller, &proposal);

        assert_eq!(
            mock_file.invocation_count(),
            0,
            "Provider was invoked for dot path: {dot_path}"
        );
        match result.outcome {
            CapabilityOutcome::Failure { error } => {
                assert_eq!(error.code, "PERMISSION_DENIED");
                assert!(
                    error.message.contains("'.'"),
                    "Expected '.' denial message for {dot_path}: {}",
                    error.message
                );
            }
            _ => panic!("Expected failure for dot path: {dot_path}"),
        }
    }
}

#[test]
fn test_path_traversal_dot_dot_denied_provider_count_zero() {
    let caller = CallerIdentity::principal("user");
    let sandbox = PathBuf::from("/tmp/test_sandbox_m6c");
    let mut policy = PolicyEngine::new_mvp(sandbox);
    policy.grant(caller.clone(), "fs.file.read");

    let mock_file = mock_success_file();
    let dispatcher = CapabilityDispatcher::new_with_all_capability_providers(
        policy,
        Arc::new(MockCpuProvider::with_success(serde_json::json!({}))),
        Arc::new(MockMemoryProvider::with_success(serde_json::json!({}))),
        Arc::new(MockProcessProvider::with_success(serde_json::json!([]))),
        mock_file.clone(),
    );

    for dot_dot_path in [
        "../secret.txt",
        "sub/../../etc/passwd",
        "sub/../file.txt",
        "..",
    ] {
        let proposal = make_file_proposal(serde_json::json!({"path": dot_dot_path}));
        let result = dispatcher.execute_proposal(&caller, &proposal);

        assert_eq!(
            mock_file.invocation_count(),
            0,
            "Provider was invoked for traversal path: {dot_dot_path}"
        );
        match result.outcome {
            CapabilityOutcome::Failure { error } => {
                assert_eq!(error.code, "PERMISSION_DENIED");
                assert!(
                    error.message.contains("..") || error.message.contains("traversal"),
                    "Expected traversal denial for {dot_dot_path}: {}",
                    error.message
                );
            }
            _ => panic!("Expected failure for traversal path: {dot_dot_path}"),
        }
    }
}

#[test]
fn test_absolute_path_denied_provider_count_zero() {
    let caller = CallerIdentity::principal("user");
    let sandbox = PathBuf::from("/tmp/test_sandbox_m6c");
    let mut policy = PolicyEngine::new_mvp(sandbox);
    policy.grant(caller.clone(), "fs.file.read");

    let mock_file = mock_success_file();
    let dispatcher = CapabilityDispatcher::new_with_all_capability_providers(
        policy,
        Arc::new(MockCpuProvider::with_success(serde_json::json!({}))),
        Arc::new(MockMemoryProvider::with_success(serde_json::json!({}))),
        Arc::new(MockProcessProvider::with_success(serde_json::json!([]))),
        mock_file.clone(),
    );

    for abs_path in [
        "/etc/passwd",
        "/tmp/test_sandbox_m6c/file.txt",
        "~/secret.txt",
    ] {
        let proposal = make_file_proposal(serde_json::json!({"path": abs_path}));
        let result = dispatcher.execute_proposal(&caller, &proposal);

        assert_eq!(
            mock_file.invocation_count(),
            0,
            "Provider was invoked for absolute path: {abs_path}"
        );
        match result.outcome {
            CapabilityOutcome::Failure { error } => {
                assert_eq!(error.code, "PERMISSION_DENIED");
                assert!(
                    error.message.contains("relative") || error.message.contains("escapes"),
                    "Expected relative path requirement for {abs_path}: {}",
                    error.message
                );
            }
            _ => panic!("Expected failure for absolute path: {abs_path}"),
        }
    }
}

// ============================================================================
// Group 2: Provider-Level Containment & Invariants (SandboxedLocalFileProvider)
// ============================================================================

#[test]
fn test_direct_provider_sibling_directory_rejection() {
    let base = std::env::temp_dir().join(format!("aurora-sibling-test-{}", std::process::id()));
    let sandbox = base.join("sandbox");
    let sibling = base.join("sandbox_sibling");
    fs::create_dir_all(&sandbox).unwrap();
    fs::create_dir_all(&sibling).unwrap();

    fs::write(sibling.join("secret.txt"), "TOP_SECRET").unwrap();

    let provider = SandboxedLocalFileProvider::new(&sandbox).unwrap();

    // Trying to reach sibling via relative path fails containment
    let err = provider
        .read_file("../sandbox_sibling/secret.txt")
        .unwrap_err();
    assert!(
        err.code == "PERMISSION_DENIED" || err.code == "INVALID_ARGUMENT",
        "Expected containment denial, got {:?}",
        err
    );

    let _ = fs::remove_dir_all(&base);
}

#[test]
fn test_authorized_nominal_file_read() {
    let sandbox = std::env::temp_dir().join(format!("aurora-nominal-file-{}", std::process::id()));
    fs::create_dir_all(&sandbox).unwrap();
    let file_path = sandbox.join("hello.txt");
    fs::write(&file_path, "Hello, Aurora OS!").unwrap();

    let caller = CallerIdentity::principal("user");
    let mut policy = PolicyEngine::new_mvp(sandbox.clone());
    policy.grant(caller.clone(), "fs.file.read");

    let real_provider = Arc::new(SandboxedLocalFileProvider::new(&sandbox).unwrap());
    let dispatcher = CapabilityDispatcher::new_with_all_capability_providers(
        policy,
        Arc::new(MockCpuProvider::with_success(serde_json::json!({}))),
        Arc::new(MockMemoryProvider::with_success(serde_json::json!({}))),
        Arc::new(MockProcessProvider::with_success(serde_json::json!([]))),
        real_provider,
    );

    let proposal = make_file_proposal(serde_json::json!({"path": "hello.txt"}));
    let result = dispatcher.execute_proposal(&caller, &proposal);

    match result.outcome {
        CapabilityOutcome::Success { data } => {
            assert_eq!(data["content"], "Hello, Aurora OS!");
            assert_eq!(data["size_bytes"], 17);
        }
        CapabilityOutcome::Failure { error } => panic!("Read failed: {:?}", error),
    }

    let _ = fs::remove_dir_all(&sandbox);
}

#[test]
fn test_nested_subpath_file_read() {
    let sandbox = std::env::temp_dir().join(format!("aurora-nested-file-{}", std::process::id()));
    let sub = sandbox.join("docs").join("architecture");
    fs::create_dir_all(&sub).unwrap();
    fs::write(sub.join("adr001.md"), "# ADR-001 Architecture").unwrap();

    let provider = SandboxedLocalFileProvider::new(&sandbox).unwrap();
    let res = provider.read_file("docs/architecture/adr001.md").unwrap();

    assert_eq!(res["content"], "# ADR-001 Architecture");
    assert_eq!(res["size_bytes"], 22);

    let _ = fs::remove_dir_all(&sandbox);
}

#[test]
fn test_leaf_symlink_rejected_no_outside_content() {
    let base = std::env::temp_dir().join(format!("aurora-symlink-leaf-{}", std::process::id()));
    let sandbox = base.join("sandbox");
    let outside = base.join("outside");
    fs::create_dir_all(&sandbox).unwrap();
    fs::create_dir_all(&outside).unwrap();

    let secret_file = outside.join("secret.key");
    fs::write(&secret_file, "SUPER_SECRET_KEY").unwrap();

    // Create leaf symlink inside sandbox pointing to outside file
    #[cfg(unix)]
    std::os::unix::fs::symlink(&secret_file, sandbox.join("link_to_secret.key")).unwrap();

    let provider = SandboxedLocalFileProvider::new(&sandbox).unwrap();
    let err = provider.read_file("link_to_secret.key").unwrap_err();

    // Must fail without leaking secret
    assert_eq!(err.code, "SYMLINK_REJECTED");
    assert!(!err.message.contains("SUPER_SECRET_KEY"));

    let _ = fs::remove_dir_all(&base);
}

#[test]
fn test_intermediate_directory_symlink_rejected_no_outside_content() {
    let base = std::env::temp_dir().join(format!("aurora-symlink-dir-{}", std::process::id()));
    let sandbox = base.join("sandbox");
    let outside = base.join("outside");
    fs::create_dir_all(&sandbox).unwrap();
    fs::create_dir_all(&outside).unwrap();

    let secret_file = outside.join("secret.conf");
    fs::write(&secret_file, "CONFIDENTIAL").unwrap();

    // Create intermediate symlink inside sandbox pointing to outside directory
    #[cfg(unix)]
    std::os::unix::fs::symlink(&outside, sandbox.join("ext_dir")).unwrap();

    let provider = SandboxedLocalFileProvider::new(&sandbox).unwrap();
    let err = provider.read_file("ext_dir/secret.conf").unwrap_err();

    assert_eq!(err.code, "SYMLINK_REJECTED");
    assert!(!err.message.contains("CONFIDENTIAL"));

    let _ = fs::remove_dir_all(&base);
}

#[test]
fn test_fifo_rejected_without_blocking() {
    let sandbox = std::env::temp_dir().join(format!("aurora-fifo-test-{}", std::process::id()));
    fs::create_dir_all(&sandbox).unwrap();
    let fifo_path = sandbox.join("pipe.fifo");

    let status = std::process::Command::new("mkfifo")
        .arg(&fifo_path)
        .status()
        .expect("Failed to execute mkfifo");
    assert!(status.success(), "mkfifo command failed");

    let provider = SandboxedLocalFileProvider::new(&sandbox).unwrap();

    // Reading a FIFO must fail immediately without blocking indefinitely
    let err = provider.read_file("pipe.fifo").unwrap_err();
    assert_eq!(err.code, "NOT_REGULAR_FILE");
    assert!(err.message.contains("regular file"));

    let _ = fs::remove_dir_all(&sandbox);
}

#[test]
fn test_directory_path_rejected() {
    let sandbox = std::env::temp_dir().join(format!("aurora-dir-test-{}", std::process::id()));
    let sub = sandbox.join("subfolder");
    fs::create_dir_all(&sub).unwrap();

    let provider = SandboxedLocalFileProvider::new(&sandbox).unwrap();
    let err = provider.read_file("subfolder").unwrap_err();

    assert_eq!(err.code, "IS_A_DIRECTORY");
    assert!(err.message.contains("directory"));

    let _ = fs::remove_dir_all(&sandbox);
}

#[test]
fn test_file_size_exactly_64k_succeeds() {
    let sandbox = std::env::temp_dir().join(format!("aurora-64k-exact-{}", std::process::id()));
    fs::create_dir_all(&sandbox).unwrap();

    let exact_64k = "A".repeat(MAX_FILE_SIZE_BYTES as usize);
    fs::write(sandbox.join("exact.txt"), &exact_64k).unwrap();

    let provider = SandboxedLocalFileProvider::new(&sandbox).unwrap();
    let res = provider.read_file("exact.txt").unwrap();

    assert_eq!(res["size_bytes"], MAX_FILE_SIZE_BYTES);
    assert_eq!(res["content"], exact_64k);

    let _ = fs::remove_dir_all(&sandbox);
}

#[test]
fn test_file_size_64k_plus_one_byte_fails() {
    let sandbox = std::env::temp_dir().join(format!("aurora-64k-plus-one-{}", std::process::id()));
    fs::create_dir_all(&sandbox).unwrap();

    let oversized = "A".repeat((MAX_FILE_SIZE_BYTES + 1) as usize);
    fs::write(sandbox.join("oversized.txt"), &oversized).unwrap();

    let provider = SandboxedLocalFileProvider::new(&sandbox).unwrap();
    let err = provider.read_file("oversized.txt").unwrap_err();

    assert_eq!(err.code, "FILE_TOO_LARGE");
    assert!(err.message.contains("exceeds maximum"));

    let _ = fs::remove_dir_all(&sandbox);
}

#[test]
fn test_non_utf8_binary_fails_without_partial_content() {
    let sandbox = std::env::temp_dir().join(format!("aurora-binary-utf8-{}", std::process::id()));
    fs::create_dir_all(&sandbox).unwrap();

    // Invalid UTF-8 sequence
    let binary_data: Vec<u8> = vec![0x80, 0x81, 0xFF, 0xFE, 0xFD, 0x00];
    fs::write(sandbox.join("binary.bin"), &binary_data).unwrap();

    let provider = SandboxedLocalFileProvider::new(&sandbox).unwrap();
    let err = provider.read_file("binary.bin").unwrap_err();

    assert_eq!(err.code, "INVALID_ENCODING");
    assert!(err.message.contains("valid UTF-8"));

    let _ = fs::remove_dir_all(&sandbox);
}

#[test]
fn test_missing_file_returns_not_found() {
    let sandbox = std::env::temp_dir().join(format!("aurora-missing-file-{}", std::process::id()));
    fs::create_dir_all(&sandbox).unwrap();

    let provider = SandboxedLocalFileProvider::new(&sandbox).unwrap();
    let err = provider.read_file("does_not_exist.txt").unwrap_err();

    assert_eq!(err.code, "NOT_FOUND");
    assert!(err.message.contains("File not found"));

    let _ = fs::remove_dir_all(&sandbox);
}

#[test]
fn test_simulated_eagain_from_openat2_fails_safely() {
    let caller = CallerIdentity::principal("user");
    let sandbox = PathBuf::from("/tmp/test_sandbox_m6c");
    let mut policy = PolicyEngine::new_mvp(sandbox);
    policy.grant(caller.clone(), "fs.file.read");

    let mock_file = Arc::new(MockFileProvider::with_error(CapabilityExecutionError::new(
        "TEMPORARILY_UNAVAILABLE",
        "Resource temporarily unavailable (EAGAIN)",
    )));

    let dispatcher = CapabilityDispatcher::new_with_all_capability_providers(
        policy,
        Arc::new(MockCpuProvider::with_success(serde_json::json!({}))),
        Arc::new(MockMemoryProvider::with_success(serde_json::json!({}))),
        Arc::new(MockProcessProvider::with_success(serde_json::json!([]))),
        mock_file.clone(),
    );

    let proposal = make_file_proposal(serde_json::json!({"path": "resource.txt"}));
    let result = dispatcher.execute_proposal(&caller, &proposal);

    assert_eq!(mock_file.invocation_count(), 1);
    match result.outcome {
        CapabilityOutcome::Failure { error } => {
            assert_eq!(error.code, "TEMPORARILY_UNAVAILABLE");
            assert!(error.message.contains("EAGAIN"));
        }
        _ => panic!("Expected failure on simulated EAGAIN"),
    }
}

#[test]
fn test_unsupported_openat2_enosys_fails_closed() {
    let caller = CallerIdentity::principal("user");
    let sandbox = PathBuf::from("/tmp/test_sandbox_m6c");
    let mut policy = PolicyEngine::new_mvp(sandbox);
    policy.grant(caller.clone(), "fs.file.read");

    let mock_file = Arc::new(MockFileProvider::with_error(CapabilityExecutionError::new(
        "UNSUPPORTED_PLATFORM",
        "Kernel openat2 unsupported (ENOSYS)",
    )));

    let dispatcher = CapabilityDispatcher::new_with_all_capability_providers(
        policy,
        Arc::new(MockCpuProvider::with_success(serde_json::json!({}))),
        Arc::new(MockMemoryProvider::with_success(serde_json::json!({}))),
        Arc::new(MockProcessProvider::with_success(serde_json::json!([]))),
        mock_file.clone(),
    );

    let proposal = make_file_proposal(serde_json::json!({"path": "file.txt"}));
    let result = dispatcher.execute_proposal(&caller, &proposal);

    assert_eq!(mock_file.invocation_count(), 1);
    match result.outcome {
        CapabilityOutcome::Failure { error } => {
            assert_eq!(error.code, "UNSUPPORTED_PLATFORM");
            assert!(error.message.contains("ENOSYS"));
        }
        _ => panic!("Expected failure on simulated ENOSYS"),
    }
}

#[test]
fn test_concurrent_path_replacement_race_stress() {
    let base = std::env::temp_dir().join(format!("aurora-race-test-{}", std::process::id()));
    let sandbox = base.join("sandbox");
    let outside = base.join("outside");
    fs::create_dir_all(&sandbox).unwrap();
    fs::create_dir_all(&outside).unwrap();

    let outside_secret = outside.join("secret.txt");
    fs::write(&outside_secret, "LEAKED_OUTSIDE_SECRET_DATA").unwrap();

    let target_file = sandbox.join("target.txt");
    fs::write(&target_file, "SAFE_SANDBOX_DATA").unwrap();

    let provider = Arc::new(SandboxedLocalFileProvider::new(&sandbox).unwrap());
    let stop_flag = Arc::new(AtomicBool::new(false));

    // Background thread continuously alternates target.txt between normal file and symlink
    let target_clone = target_file.clone();
    let outside_clone = outside_secret.clone();
    let stop_clone = stop_flag.clone();

    let swapper = thread::spawn(move || {
        let temp_link = target_clone.with_extension("tmp_link");
        let temp_file = target_clone.with_extension("tmp_file");
        let _ = fs::write(&temp_file, "SAFE_SANDBOX_DATA");

        while !stop_clone.load(Ordering::Relaxed) {
            // Swap to symlink
            let _ = fs::remove_file(&temp_link);
            #[cfg(unix)]
            let _ = std::os::unix::fs::symlink(&outside_clone, &temp_link);
            let _ = fs::rename(&temp_link, &target_clone);

            // Swap back to normal file
            let _ = fs::write(&temp_file, "SAFE_SANDBOX_DATA");
            let _ = fs::rename(&temp_file, &target_clone);
        }
        let _ = fs::remove_file(&temp_link);
        let _ = fs::remove_file(&temp_file);
    });

    // Reader thread reads 100 times concurrently
    for _ in 0..100 {
        match provider.read_file("target.txt") {
            Ok(val) => {
                let content = val["content"].as_str().unwrap();
                // INVARIANT: Outside secret must NEVER be read
                assert_eq!(
                    content, "SAFE_SANDBOX_DATA",
                    "Security breach: TOCTOU race leaked outside secret data!"
                );
            }
            Err(err) => {
                // Denials, symlink rejections, or temporary IO errors during rename are expected and safe
                assert!(
                    err.code == "SYMLINK_REJECTED"
                        || err.code == "PERMISSION_DENIED"
                        || err.code == "IO_ERROR"
                        || err.code == "NOT_FOUND",
                    "Unexpected error during race: {:?}",
                    err
                );
                assert!(!err.message.contains("LEAKED_OUTSIDE_SECRET_DATA"));
            }
        }
    }

    stop_flag.store(true, Ordering::Relaxed);
    let _ = swapper.join();
    let _ = fs::remove_dir_all(&base);
}

// ============================================================================
// Group 3: Live End-to-End Worker Request Turn Flows
// ============================================================================

#[test]
fn test_authorized_end_to_end_file_read_turn() {
    let sandbox = std::env::temp_dir().join(format!("aurora-e2e-read-{}", std::process::id()));
    fs::create_dir_all(&sandbox).unwrap();
    fs::write(sandbox.join("sample.txt"), "Live E2E file read payload").unwrap();

    let config = create_test_config("auth_read_e2e", &sandbox);
    let caller = CallerIdentity::principal("desktop-user");

    let mut supervisor = WorkerSupervisor::new(config);
    supervisor
        .policy_engine_mut()
        .grant(caller.clone(), "fs.file.read");

    supervisor.start().expect("Supervisor failed to start");

    let turn = supervisor
        .execute_turn(&caller, "read sample.txt")
        .expect("Turn execution failed");

    assert_eq!(turn.status, TurnStatus::Success);
    assert!(
        turn.response_text.contains("Live E2E file read payload"),
        "Response should contain file payload: {}",
        turn.response_text
    );
    assert!(turn.response_text.contains("File content (26 bytes):"));

    supervisor.shutdown();
    let _ = fs::remove_dir_all(&sandbox);
}

#[test]
fn test_unauthorized_end_to_end_file_read_turn_denied() {
    let sandbox = std::env::temp_dir().join(format!("aurora-e2e-unauth-{}", std::process::id()));
    fs::create_dir_all(&sandbox).unwrap();
    fs::write(sandbox.join("secret.txt"), "Hidden confidential text").unwrap();

    let config = create_test_config("unauth_read_e2e", &sandbox);
    let caller = CallerIdentity::principal("unauthorized-user");

    // No grant configured
    let mut supervisor = WorkerSupervisor::new(config);

    supervisor.start().expect("Supervisor failed to start");

    let turn = supervisor
        .execute_turn(&caller, "read secret.txt")
        .expect("Turn should complete gracefully with error status");

    assert_eq!(turn.status, TurnStatus::Error);
    assert!(turn.response_text.contains("PERMISSION_DENIED"));
    assert!(!turn.response_text.contains("Hidden confidential text"));

    supervisor.shutdown();
    let _ = fs::remove_dir_all(&sandbox);
}

#[test]
fn test_escape_end_to_end_file_read_turn_denied() {
    let base = std::env::temp_dir().join(format!("aurora-e2e-escape-{}", std::process::id()));
    let sandbox = base.join("sandbox");
    let outside = base.join("outside");
    fs::create_dir_all(&sandbox).unwrap();
    fs::create_dir_all(&outside).unwrap();
    fs::write(outside.join("secret.txt"), "Outside root secret").unwrap();

    let config = create_test_config("escape_e2e", &sandbox);
    let caller = CallerIdentity::principal("desktop-user");

    let mut supervisor = WorkerSupervisor::new(config);
    supervisor
        .policy_engine_mut()
        .grant(caller.clone(), "fs.file.read");

    supervisor.start().expect("Supervisor failed to start");

    // The Python worker sends "escape" as {"path": "../secret.txt"}
    let turn = supervisor
        .execute_turn(&caller, "escape")
        .expect("Turn should complete gracefully with error status");

    assert_eq!(turn.status, TurnStatus::Error);
    assert!(turn.response_text.contains("PERMISSION_DENIED"));
    assert!(!turn.response_text.contains("Outside root secret"));

    supervisor.shutdown();
    let _ = fs::remove_dir_all(&base);
}
