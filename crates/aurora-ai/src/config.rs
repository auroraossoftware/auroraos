//! Configuration for aurora-ai daemon runtime and worker supervisor.

use std::path::PathBuf;
use std::time::Duration;

/// Configuration options for the worker supervisor.
#[derive(Debug, Clone)]
pub struct SupervisorConfig {
    /// Filesystem path to the private Unix domain socket.
    pub socket_path: PathBuf,
    /// Command and arguments used to spawn the worker process.
    pub worker_command: Vec<String>,
    /// Working directory for worker spawn (defaults to current dir).
    pub working_dir: Option<PathBuf>,
    /// Sandbox directory used for demo filesystem capability scope checks.
    pub demo_sandbox_path: PathBuf,
    /// Maximum duration to wait for worker to connect and complete handshake.
    pub handshake_timeout: Duration,
    /// Read/write timeout on the established IPC socket.
    pub socket_timeout: Duration,
}

impl Default for SupervisorConfig {
    fn default() -> Self {
        let unique_id = std::process::id();
        let socket_path = std::env::temp_dir().join(format!("aurora-ai-{unique_id}.sock"));
        let demo_sandbox_path = std::env::temp_dir().join("aurora-demo");
        Self {
            socket_path,
            worker_command: vec![
                "python3".to_string(),
                "-m".to_string(),
                "worker.main".to_string(),
            ],
            working_dir: None,
            demo_sandbox_path,
            handshake_timeout: Duration::from_secs(5),
            socket_timeout: Duration::from_secs(5),
        }
    }
}

impl SupervisorConfig {
    /// Creates a configuration with a custom socket path.
    pub fn with_socket_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.socket_path = path.into();
        self
    }

    /// Sets custom worker command.
    pub fn with_worker_command(mut self, cmd: Vec<String>) -> Self {
        self.worker_command = cmd;
        self
    }

    /// Sets custom sandbox directory path.
    pub fn with_demo_sandbox_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.demo_sandbox_path = path.into();
        self
    }

    /// Sets custom handshake timeout.
    pub fn with_handshake_timeout(mut self, timeout: Duration) -> Self {
        self.handshake_timeout = timeout;
        self
    }
}
