//! Worker process lifecycle supervisor and private IPC connection manager.
//!
//! Pursuant to ADR-001 and ADR-002, the supervisor is responsible for:
//! 1. Managing the lifecycle of the isolated AI worker process as a non-embedded child.
//! 2. Establishing and supervising the private Unix domain socket channel.
//! 3. Executing the startup handshake and verifying protocol version compatibility.
//! 4. Monitoring worker health and detecting unexpected termination without crashing the daemon.
//! 5. Guaranteeing clean shutdown and IPC resource cleanup.

use crate::config::SupervisorConfig;
use crate::dispatcher::CapabilityDispatcher;
use crate::identity::CallerIdentity;
use crate::ipc::{read_worker_message, send_daemon_message, IpcError};
use crate::policy::{PolicyDecision, PolicyEngine};
use aurora_protocol::{
    CURRENT_PROTOCOL_VERSION, CapabilityResult, DaemonToWorkerMessage, Handshake,
    HandshakeResponse, HandshakeStatus, ProposeCapability, WorkerToDaemonMessage,
};
use std::io::BufReader;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// Status of the supervised worker process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkerStatus {
    /// Worker process is running and IPC connection is healthy.
    Running,
    /// Worker process has exited with the given exit code.
    Terminated(Option<i32>),
    /// Worker is alive as a process but the IPC channel disconnected (EOF).
    Disconnected,
}

/// Errors occurring during supervisor lifecycle operations.
#[derive(Debug)]
pub enum SupervisorError {
    Io(std::io::Error),
    Ipc(IpcError),
    WorkerSpawnFailed(String),
    HandshakeTimeout,
    WorkerPrematureExit(Option<i32>),
    IncompatibleProtocolVersion { expected: u32, received: u32 },
    HandshakeRejected(String),
    UnexpectedMessage(String),
    SocketAlreadyExists(PathBuf),
}

impl std::fmt::Display for SupervisorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O error: {e}"),
            Self::Ipc(e) => write!(f, "IPC error: {e}"),
            Self::WorkerSpawnFailed(msg) => write!(f, "failed to spawn worker process: {msg}"),
            Self::HandshakeTimeout => write!(f, "timed out waiting for worker handshake"),
            Self::WorkerPrematureExit(code) => {
                write!(f, "worker exited prematurely with code: {code:?}")
            }
            Self::IncompatibleProtocolVersion { expected, received } => {
                write!(
                    f,
                    "incompatible protocol version: expected {expected}, received {received}"
                )
            }
            Self::HandshakeRejected(reason) => write!(f, "handshake rejected by worker: {reason}"),
            Self::UnexpectedMessage(msg) => write!(f, "unexpected message received: {msg}"),
            Self::SocketAlreadyExists(p) => write!(f, "socket path already exists: {}", p.display()),
        }
    }
}

impl std::error::Error for SupervisorError {}

impl From<std::io::Error> for SupervisorError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<IpcError> for SupervisorError {
    fn from(e: IpcError) -> Self {
        Self::Ipc(e)
    }
}

/// Manages the lifecycle of an AI worker child process and its private IPC channel.
pub struct WorkerSupervisor {
    config: SupervisorConfig,
    socket_path: PathBuf,
    child: Option<Child>,
    stream: Option<UnixStream>,
    worker_version: Option<String>,
    dispatcher: CapabilityDispatcher,
}

impl WorkerSupervisor {
    /// Creates a new supervisor instance with the specified configuration.
    pub fn new(config: SupervisorConfig) -> Self {
        let socket_path = config.socket_path.clone();
        let dispatcher = CapabilityDispatcher::new_default(config.demo_sandbox_path.clone());
        Self {
            config,
            socket_path,
            child: None,
            stream: None,
            worker_version: None,
            dispatcher,
        }
    }

    /// Creates a supervisor with a custom capability dispatcher (useful for testing with mock providers).
    pub fn with_dispatcher(config: SupervisorConfig, dispatcher: CapabilityDispatcher) -> Self {
        let socket_path = config.socket_path.clone();
        Self {
            config,
            socket_path,
            child: None,
            stream: None,
            worker_version: None,
            dispatcher,
        }
    }

    /// Returns a reference to the supervisor's policy engine.
    pub fn policy_engine(&self) -> &PolicyEngine {
        self.dispatcher.policy_engine()
    }

    /// Returns a mutable reference to the supervisor's policy engine.
    pub fn policy_engine_mut(&mut self) -> &mut PolicyEngine {
        self.dispatcher.policy_engine_mut()
    }

    /// Returns a reference to the capability dispatcher.
    pub fn dispatcher(&self) -> &CapabilityDispatcher {
        &self.dispatcher
    }

    /// Returns a mutable reference to the capability dispatcher.
    pub fn dispatcher_mut(&mut self) -> &mut CapabilityDispatcher {
        &mut self.dispatcher
    }

    /// Evaluates whether an untrusted capability proposal emitted by the worker is authorized for the caller.
    pub fn evaluate_proposal(
        &self,
        caller: &CallerIdentity,
        proposal: &ProposeCapability,
    ) -> PolicyDecision {
        self.dispatcher.evaluate(caller, proposal)
    }

    /// Executes an untrusted capability proposal through the deterministic policy boundary.
    ///
    /// Evaluates policy first and strictly executes the capability provider only upon `Allow`.
    pub fn execute_proposal(
        &self,
        caller: &CallerIdentity,
        proposal: &ProposeCapability,
    ) -> CapabilityResult {
        self.dispatcher.execute_proposal(caller, proposal)
    }

    /// Returns the socket path used by the supervisor.
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    /// Returns the worker version reported during handshake, if established.
    pub fn worker_version(&self) -> Option<&str> {
        self.worker_version.as_deref()
    }

    /// Starts the supervisor: binds listener, spawns worker child, and performs handshake.
    pub fn start(&mut self) -> Result<(), SupervisorError> {
        // Step 1: Ensure socket file does not already exist
        if self.socket_path.exists() {
            let _ = std::fs::remove_file(&self.socket_path);
        }

        // Step 2: Bind Unix listener on private socket path
        let listener = UnixListener::bind(&self.socket_path).map_err(SupervisorError::Io)?;
        listener.set_nonblocking(true).map_err(SupervisorError::Io)?;

        // Step 3: Spawn the worker process as an isolated child process
        if self.config.worker_command.is_empty() {
            return Err(SupervisorError::WorkerSpawnFailed(
                "worker_command is empty".to_string(),
            ));
        }

        let prog = &self.config.worker_command[0];
        let mut cmd = Command::new(prog);
        if self.config.worker_command.len() > 1 {
            cmd.args(&self.config.worker_command[1..]);
        }
        cmd.arg("--socket-path");
        cmd.arg(&self.socket_path);

        if let Some(ref cwd) = self.config.working_dir {
            cmd.current_dir(cwd);
        }

        // Avoid leaking stdout/stderr by redirecting to null or inheriting
        cmd.stdin(Stdio::null());

        let child = cmd
            .spawn()
            .map_err(|e| SupervisorError::WorkerSpawnFailed(e.to_string()))?;
        self.child = Some(child);

        // Step 4: Accept worker connection with timeout and premature exit detection
        let stream = self.accept_worker_connection(&listener)?;
        stream.set_nonblocking(false).map_err(SupervisorError::Io)?;
        stream
            .set_read_timeout(Some(self.config.socket_timeout))
            .map_err(SupervisorError::Io)?;
        stream
            .set_write_timeout(Some(self.config.socket_timeout))
            .map_err(SupervisorError::Io)?;

        // Step 5: Execute protocol handshake
        let worker_version = self.execute_handshake(&stream)?;
        self.worker_version = Some(worker_version);
        self.stream = Some(stream);

        Ok(())
    }

    /// Accepts the connection from the spawned child process within configured timeout.
    fn accept_worker_connection(&mut self, listener: &UnixListener) -> Result<UnixStream, SupervisorError> {
        let start = Instant::now();
        let timeout = self.config.handshake_timeout;

        loop {
            match listener.accept() {
                Ok((stream, _addr)) => return Ok(stream),
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    // Check if child exited prematurely
                    if let Some(ref mut child) = self.child {
                        if let Ok(Some(status)) = child.try_wait() {
                            return Err(SupervisorError::WorkerPrematureExit(status.code()));
                        }
                    }

                    if start.elapsed() > timeout {
                        return Err(SupervisorError::HandshakeTimeout);
                    }
                    std::thread::sleep(Duration::from_millis(25));
                }
                Err(e) => return Err(SupervisorError::Io(e)),
            }
        }
    }

    /// Executes the initial handshake exchange over the connected stream.
    fn execute_handshake(&self, stream: &UnixStream) -> Result<String, SupervisorError> {
        let mut writer = stream.try_clone().map_err(SupervisorError::Io)?;
        let mut reader = BufReader::new(stream.try_clone().map_err(SupervisorError::Io)?);

        // Send Handshake
        let handshake_msg = DaemonToWorkerMessage::Handshake(Handshake::new("0.1.0"));
        send_daemon_message(&mut writer, &handshake_msg)?;

        // Read HandshakeResponse
        let response = read_worker_message(&mut reader)?
            .ok_or(SupervisorError::HandshakeRejected("EOF before handshake response".to_string()))?;

        match response {
            WorkerToDaemonMessage::HandshakeResponse(HandshakeResponse {
                protocol_version,
                worker_version,
                status,
            }) => {
                if protocol_version != CURRENT_PROTOCOL_VERSION {
                    return Err(SupervisorError::IncompatibleProtocolVersion {
                        expected: CURRENT_PROTOCOL_VERSION,
                        received: protocol_version,
                    });
                }
                if status != HandshakeStatus::Ready {
                    return Err(SupervisorError::HandshakeRejected(format!("{status:?}")));
                }
                Ok(worker_version)
            }
            other => Err(SupervisorError::UnexpectedMessage(format!("{other:?}"))),
        }
    }

    /// Polls the health of the worker child process.
    pub fn poll_status(&mut self) -> Result<WorkerStatus, SupervisorError> {
        if let Some(ref mut child) = self.child {
            if let Some(status) = child.try_wait().map_err(SupervisorError::Io)? {
                return Ok(WorkerStatus::Terminated(status.code()));
            }
            Ok(WorkerStatus::Running)
        } else {
            Ok(WorkerStatus::Terminated(None))
        }
    }

    /// Cleanly terminates the worker process and unlinks the Unix socket file.
    pub fn shutdown(&mut self) {
        // Drop stream to signal EOF to child
        self.stream = None;

        // Terminate child process if still running
        if let Some(mut child) = self.child.take() {
            if child.try_wait().ok().flatten().is_none() {
                let _ = child.kill();
                let _ = child.wait();
            }
        }

        // Clean up socket file from filesystem
        if self.socket_path.exists() {
            let _ = std::fs::remove_file(&self.socket_path);
        }
    }
}

impl Drop for WorkerSupervisor {
    fn drop(&mut self) {
        self.shutdown();
    }
}
