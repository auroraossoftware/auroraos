//! Configuration for aurora-ai daemon runtime and worker supervisor.

use std::path::PathBuf;
use std::time::Duration;

/// Configuration options for the worker supervisor.
#[derive(Debug, Clone)]
pub struct SupervisorConfig {
    /// Filesystem path to the private Unix domain socket (retained for backward compatibility).
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
    /// Maximum number of capability proposals permitted in a single turn (defaults to 20).
    pub max_proposals_per_turn: usize,
    /// Maximum number of consecutive failed replacement attempts before transitioning to Degraded (defaults to 3).
    pub max_consecutive_restarts: usize,
    /// Base duration for exponential backoff between replacement restart attempts (defaults to 50ms).
    pub restart_backoff_base: Duration,
    /// Minimum continuous healthy duration (in Ready or Busy) required to reset the restart counter (defaults to 10s).
    pub healthy_reset_window: Duration,
    /// Whether to enable Linux signalfd-based signal handling for SIGINT and SIGTERM (defaults to true).
    pub enable_signal_handling: bool,
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
            max_proposals_per_turn: 20,
            max_consecutive_restarts: 3,
            restart_backoff_base: Duration::from_millis(50),
            healthy_reset_window: Duration::from_secs(10),
            enable_signal_handling: true,
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

    /// Sets custom working directory for worker spawn.
    pub fn with_working_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.working_dir = Some(dir.into());
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

    /// Sets read/write timeout on the established IPC socket (testability convenience).
    pub fn with_socket_timeout(mut self, timeout: Duration) -> Self {
        self.socket_timeout = timeout;
        self
    }

    /// Sets maximum number of capability proposals permitted in a single turn.
    pub fn with_max_proposals_per_turn(mut self, max: usize) -> Self {
        self.max_proposals_per_turn = max;
        self
    }

    /// Sets maximum number of consecutive replacement restart attempts.
    pub fn with_max_consecutive_restarts(mut self, max: usize) -> Self {
        self.max_consecutive_restarts = max;
        self
    }

    /// Sets base backoff duration between restart attempts.
    pub fn with_restart_backoff_base(mut self, duration: Duration) -> Self {
        self.restart_backoff_base = duration;
        self
    }

    /// Sets continuous healthy duration required to reset the restart counter.
    pub fn with_healthy_reset_window(mut self, duration: Duration) -> Self {
        self.healthy_reset_window = duration;
        self
    }

    /// Sets whether signalfd-based signal handling is enabled.
    pub fn with_signal_handling(mut self, enabled: bool) -> Self {
        self.enable_signal_handling = enabled;
        self
    }
}
