use aurora_ai::{SupervisorConfig, SupervisorError, WorkerStatus, WorkerSupervisor};
use std::path::PathBuf;
use std::time::Duration;

fn get_workspace_root() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    // CARGO_MANIFEST_DIR is crates/aurora-ai, so parent of parent is workspace root
    manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .map(|p| p.to_path_buf())
        .unwrap_or(manifest_dir)
}

fn create_test_config(test_name: &str) -> SupervisorConfig {
    let temp_socket = std::env::temp_dir().join(format!("aurora-test-{test_name}-{}.sock", std::process::id()));
    SupervisorConfig::default()
        .with_socket_path(temp_socket)
        .with_handshake_timeout(Duration::from_secs(5))
}

#[test]
fn test_daemon_starts_and_initializes_state() {
    let config = create_test_config("init");
    let supervisor = WorkerSupervisor::new(config);
    assert!(supervisor.socket_path().to_str().unwrap().contains("aurora-test-init"));
    assert_eq!(supervisor.worker_version(), None);
}

#[test]
fn test_worker_spawn_connection_and_handshake_success() {
    let workspace = get_workspace_root();
    let mut config = create_test_config("handshake_success");
    config.working_dir = Some(workspace);

    let mut supervisor = WorkerSupervisor::new(config);
    let socket_path = supervisor.socket_path().to_path_buf();

    // 1. Daemon starts, worker starts, connection established, handshake succeeds
    let start_result = supervisor.start();
    assert!(start_result.is_ok(), "Supervisor failed to start: {:?}", start_result.err());

    // 2. Protocol version compatibility confirmed
    assert_eq!(supervisor.worker_version(), Some("0.1.0"));

    // 3. Worker process is running
    let status = supervisor.poll_status().expect("poll_status failed");
    assert_eq!(status, WorkerStatus::Running);

    // 4. Socket file exists while running
    assert!(socket_path.exists(), "Socket file should exist while supervisor is running");

    // 5. Clean shutdown cleans up IPC resources
    supervisor.shutdown();
    assert!(!socket_path.exists(), "Socket file must be removed after clean shutdown");
}

#[test]
fn test_reject_incompatible_protocol_version() {
    let workspace = get_workspace_root();
    let mut config = create_test_config("incompatible_version");
    config.working_dir = Some(workspace);
    config.worker_command = vec![
        "python3".to_string(),
        "-m".to_string(),
        "worker.main".to_string(),
        "--simulate-incompatible-version".to_string(),
    ];

    let mut supervisor = WorkerSupervisor::new(config);
    let socket_path = supervisor.socket_path().to_path_buf();

    // Supervisor should fail handshake due to version mismatch
    let result = supervisor.start();
    assert!(result.is_err(), "Expected start to fail due to incompatible version");

    match result {
        Err(SupervisorError::HandshakeRejected(reason)) => {
            assert!(reason.contains("IncompatibleVersion"));
        }
        Err(other) => panic!("Expected HandshakeRejected, got: {other:?}"),
        Ok(_) => panic!("Expected failure"),
    }

    // Ensure daemon does not crash and socket is cleaned up
    supervisor.shutdown();
    assert!(!socket_path.exists(), "Socket file must be removed after failed start");
}

#[test]
fn test_worker_termination_detected_without_crash() {
    let workspace = get_workspace_root();
    let mut config = create_test_config("worker_crash");
    config.working_dir = Some(workspace);

    let mut supervisor = WorkerSupervisor::new(config);
    let socket_path = supervisor.socket_path().to_path_buf();

    supervisor.start().expect("Supervisor start failed");
    assert_eq!(supervisor.poll_status().unwrap(), WorkerStatus::Running);

    // Terminate the worker abruptly using shutdown() simulation
    supervisor.shutdown();

    // Verify polling terminated worker does not panic or crash daemon
    let status = supervisor.poll_status().expect("poll_status should not error on terminated worker");
    assert_eq!(status, WorkerStatus::Terminated(None));
    assert!(!socket_path.exists(), "Socket must be removed after shutdown");
}

#[test]
fn test_clean_shutdown_removes_socket_and_reaps_worker() {
    let workspace = get_workspace_root();
    let mut config = create_test_config("clean_shutdown");
    config.working_dir = Some(workspace);

    let mut supervisor = WorkerSupervisor::new(config);
    let socket_path = supervisor.socket_path().to_path_buf();

    supervisor.start().expect("Supervisor start failed");
    assert!(socket_path.exists());

    // Normal shutdown
    supervisor.shutdown();

    // Socket unlinked
    assert!(!socket_path.exists(), "Socket path should not exist after shutdown");

    // Re-calling shutdown is idempotent
    supervisor.shutdown();
    assert!(!socket_path.exists());
}
