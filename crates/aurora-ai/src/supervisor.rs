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
    CapabilityResult, DaemonToWorkerMessage, Handshake, HandshakeResponse, HandshakeStatus,
    ProposeCapability, WorkerToDaemonMessage, CURRENT_PROTOCOL_VERSION,
};
use std::io::BufReader;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
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
            Self::SocketAlreadyExists(p) => {
                write!(f, "socket path already exists: {}", p.display())
            }
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
    reader: Option<BufReader<UnixStream>>,
    writer: Option<UnixStream>,
    worker_version: Option<String>,
    dispatcher: CapabilityDispatcher,
    turn_counter: u64,
    owns_socket: bool,
    bound_socket_dev_ino: Option<(u64, u64)>,
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
            reader: None,
            writer: None,
            worker_version: None,
            dispatcher,
            turn_counter: 0,
            owns_socket: false,
            bound_socket_dev_ino: None,
        }
    }

    /// Creates a supervisor with a custom capability dispatcher (useful for testing with mock providers).
    pub fn with_dispatcher(config: SupervisorConfig, dispatcher: CapabilityDispatcher) -> Self {
        let socket_path = config.socket_path.clone();
        Self {
            config,
            socket_path,
            child: None,
            reader: None,
            writer: None,
            worker_version: None,
            dispatcher,
            turn_counter: 0,
            owns_socket: false,
            bound_socket_dev_ino: None,
        }
    }

    /// Creates a supervisor attached to an already-connected UnixStream (useful for synthetic/mock testing).
    pub fn from_stream(
        config: SupervisorConfig,
        dispatcher: CapabilityDispatcher,
        stream: UnixStream,
    ) -> Result<Self, SupervisorError> {
        let writer = stream.try_clone().map_err(SupervisorError::Io)?;
        let reader = BufReader::new(stream);
        Ok(Self {
            socket_path: config.socket_path.clone(),
            config,
            child: None,
            reader: Some(reader),
            writer: Some(writer),
            worker_version: Some("0.1.0".to_string()),
            dispatcher,
            turn_counter: 0,
            owns_socket: false,
            bound_socket_dev_ino: None,
        })
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

    /// Returns whether this supervisor instance owns the socket at `socket_path`.
    pub fn owns_socket(&self) -> bool {
        self.owns_socket
    }

    /// Starts the supervisor: binds listener, spawns worker child, and performs handshake.
    pub fn start(&mut self) -> Result<(), SupervisorError> {
        // Step 1: Ensure socket path does not already contain any filesystem entry.
        // Pre-checks without following symlinks (detects dead sockets, active listeners, files, or dangling symlinks).
        // Refuses startup if any entry exists, preserving the pre-existing entry untouched without deletion.
        match std::fs::symlink_metadata(&self.socket_path) {
            Ok(_) => {
                return Err(SupervisorError::SocketAlreadyExists(
                    self.socket_path.clone(),
                ));
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::NotFound => {
                // Path is clear; proceed to bind
            }
            Err(e) => {
                return Err(SupervisorError::Io(e));
            }
        }

        // Step 2: Bind Unix listener on private socket path
        let listener = UnixListener::bind(&self.socket_path).map_err(SupervisorError::Io)?;
        self.owns_socket = true;
        self.bound_socket_dev_ino = std::fs::symlink_metadata(&self.socket_path)
            .ok()
            .map(|m| (m.dev(), m.ino()));

        if let Err(e) = listener.set_nonblocking(true) {
            self.shutdown();
            return Err(SupervisorError::Io(e));
        }

        // Step 3: Spawn the worker process as an isolated child process
        if self.config.worker_command.is_empty() {
            self.shutdown();
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

        let child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                self.shutdown();
                return Err(SupervisorError::WorkerSpawnFailed(e.to_string()));
            }
        };
        self.child = Some(child);

        // Step 4: Accept worker connection with timeout and premature exit detection
        let stream = match self.accept_worker_connection(&listener) {
            Ok(s) => s,
            Err(e) => {
                self.shutdown();
                return Err(e);
            }
        };

        if let Err(e) = stream.set_nonblocking(false) {
            self.shutdown();
            return Err(SupervisorError::Io(e));
        }
        if let Err(e) = stream.set_read_timeout(Some(self.config.socket_timeout)) {
            self.shutdown();
            return Err(SupervisorError::Io(e));
        }
        if let Err(e) = stream.set_write_timeout(Some(self.config.socket_timeout)) {
            self.shutdown();
            return Err(SupervisorError::Io(e));
        }

        // Step 5: Execute protocol handshake
        let mut writer = match stream.try_clone() {
            Ok(w) => w,
            Err(e) => {
                self.shutdown();
                return Err(SupervisorError::Io(e));
            }
        };
        let mut reader = BufReader::new(stream);
        let worker_version = match Self::execute_handshake_on_channels(&mut writer, &mut reader) {
            Ok(v) => v,
            Err(e) => {
                self.shutdown();
                return Err(e);
            }
        };
        self.worker_version = Some(worker_version);
        self.writer = Some(writer);
        self.reader = Some(reader);

        Ok(())
    }

    /// Accepts the connection from the spawned child process within configured timeout.
    fn accept_worker_connection(
        &mut self,
        listener: &UnixListener,
    ) -> Result<UnixStream, SupervisorError> {
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

    /// Executes the initial handshake exchange over the connected channels.
    fn execute_handshake_on_channels(
        writer: &mut UnixStream,
        reader: &mut BufReader<UnixStream>,
    ) -> Result<String, SupervisorError> {
        // Send Handshake
        let handshake_msg = DaemonToWorkerMessage::Handshake(Handshake::new("0.1.0"));
        send_daemon_message(writer, &handshake_msg)?;

        // Read HandshakeResponse
        let response = read_worker_message(reader)?.ok_or(SupervisorError::HandshakeRejected(
            "EOF before handshake response".to_string(),
        ))?;

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

    /// Executes a complete reasoning turn end-to-end with the supervised worker.
    ///
    /// Request flow:
    /// 1. Establishes a unique turn_id and transmits `RequestTurn` to worker.
    /// 2. Reads untrusted worker messages across private IPC.
    /// 3. Validates capability proposal (`ProposeCapability`) and enforces deterministic policy.
    /// 4. If allowed, invokes `CapabilityDispatcher` to execute capability provider.
    /// 5. Delivers structured `CapabilityResult` back to worker.
    /// 6. Reads final `CompleteTurn` from worker and returns it to caller.
    pub fn execute_turn(
        &mut self,
        caller: &CallerIdentity,
        prompt: &str,
    ) -> Result<aurora_protocol::CompleteTurn, SupervisorError> {
        self.turn_counter += 1;
        let turn_id = format!("turn-{}", self.turn_counter);
        self.execute_turn_with_id(caller, &turn_id, prompt)
    }

    /// Executes a reasoning turn with an explicit turn ID.
    pub fn execute_turn_with_id(
        &mut self,
        caller: &CallerIdentity,
        turn_id: &str,
        prompt: &str,
    ) -> Result<aurora_protocol::CompleteTurn, SupervisorError> {
        let writer = self
            .writer
            .as_mut()
            .ok_or(SupervisorError::Ipc(IpcError::ConnectionClosed))?;

        // Construct RequestTurn message with registered available capabilities
        let available_capabilities = vec![
            aurora_protocol::CapabilitySchema {
                name: "sys.cpu.read".to_string(),
                description: "Reads host CPU telemetry metrics".to_string(),
                parameters_schema: serde_json::json!({}),
            },
            aurora_protocol::CapabilitySchema {
                name: "sys.memory.read".to_string(),
                description: "Reads host memory telemetry metrics".to_string(),
                parameters_schema: serde_json::json!({}),
            },
            aurora_protocol::CapabilitySchema {
                name: "proc.list".to_string(),
                description: "Lists active processes with resource usage metrics".to_string(),
                parameters_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "limit": {
                            "type": "integer",
                            "minimum": 1,
                            "maximum": 50
                        }
                    }
                }),
            },
            aurora_protocol::CapabilitySchema {
                name: "fs.file.read".to_string(),
                description: "Reads file contents strictly within the demonstration sandbox"
                    .to_string(),
                parameters_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string"
                        }
                    },
                    "required": ["path"]
                }),
            },
        ];

        let request = aurora_protocol::RequestTurn {
            protocol_version: CURRENT_PROTOCOL_VERSION,
            turn_id: turn_id.to_string(),
            prompt: prompt.to_string(),
            available_capabilities,
        };

        if let Err(e) = send_daemon_message(writer, &DaemonToWorkerMessage::RequestTurn(request)) {
            self.reader = None;
            self.writer = None;
            return Err(SupervisorError::Ipc(e));
        }

        loop {
            let res = {
                let reader = self
                    .reader
                    .as_mut()
                    .ok_or(SupervisorError::Ipc(IpcError::ConnectionClosed))?;
                read_worker_message(reader)
            };

            let msg = match res {
                Ok(Some(msg)) => msg,
                Ok(None) => {
                    self.reader = None;
                    self.writer = None;
                    return Err(SupervisorError::Ipc(IpcError::ConnectionClosed));
                }
                Err(e) => {
                    self.reader = None;
                    self.writer = None;
                    return Err(SupervisorError::Ipc(e));
                }
            };

            match msg {
                WorkerToDaemonMessage::ProposeCapability(proposal) => {
                    if proposal.turn_id != turn_id {
                        self.reader = None;
                        self.writer = None;
                        return Err(SupervisorError::UnexpectedMessage(format!(
                            "Turn ID mismatch in proposal: expected '{turn_id}', got '{}'",
                            proposal.turn_id
                        )));
                    }

                    if proposal.protocol_version != CURRENT_PROTOCOL_VERSION {
                        self.reader = None;
                        self.writer = None;
                        return Err(SupervisorError::IncompatibleProtocolVersion {
                            expected: CURRENT_PROTOCOL_VERSION,
                            received: proposal.protocol_version,
                        });
                    }

                    // Enforce deterministic policy and execute capability provider strictly if authorized
                    let outcome = self.dispatcher.execute_proposal(caller, &proposal);

                    // Deliver CapabilityResult back to worker
                    let writer = match self.writer.as_mut() {
                        Some(w) => w,
                        None => {
                            self.reader = None;
                            return Err(SupervisorError::Ipc(IpcError::ConnectionClosed));
                        }
                    };
                    if let Err(e) = send_daemon_message(
                        writer,
                        &DaemonToWorkerMessage::CapabilityResult(outcome),
                    ) {
                        self.reader = None;
                        self.writer = None;
                        return Err(SupervisorError::Ipc(e));
                    }
                }
                WorkerToDaemonMessage::CompleteTurn(complete_turn) => {
                    if complete_turn.turn_id != turn_id {
                        self.reader = None;
                        self.writer = None;
                        return Err(SupervisorError::UnexpectedMessage(format!(
                            "Turn ID mismatch in complete_turn: expected '{turn_id}', got '{}'",
                            complete_turn.turn_id
                        )));
                    }
                    if let Err(e) = complete_turn.validate() {
                        self.reader = None;
                        self.writer = None;
                        return Err(SupervisorError::UnexpectedMessage(e.to_string()));
                    }
                    return Ok(complete_turn);
                }
                WorkerToDaemonMessage::HandshakeResponse(_) => {
                    self.reader = None;
                    self.writer = None;
                    return Err(SupervisorError::UnexpectedMessage(
                        "Unexpected HandshakeResponse during active turn".to_string(),
                    ));
                }
            }
        }
    }

    /// Polls the health of the worker child process.
    pub fn poll_status(&mut self) -> Result<WorkerStatus, SupervisorError> {
        if let Some(ref mut child) = self.child {
            if let Some(status) = child.try_wait().map_err(SupervisorError::Io)? {
                return Ok(WorkerStatus::Terminated(status.code()));
            }
            if self.writer.is_none() || self.reader.is_none() {
                return Ok(WorkerStatus::Disconnected);
            }
            Ok(WorkerStatus::Running)
        } else {
            Ok(WorkerStatus::Terminated(None))
        }
    }

    /// Cleanly terminates the worker process and unlinks the Unix socket file if owned.
    pub fn shutdown(&mut self) {
        // Drop stream channels to signal EOF to child
        self.reader = None;
        self.writer = None;

        // Terminate child process if still running
        if let Some(mut child) = self.child.take() {
            if child.try_wait().ok().flatten().is_none() {
                let _ = child.kill();
                let _ = child.wait();
            }
        }

        // Clean up socket file from filesystem strictly if this supervisor created/owns it.
        // Safeguards:
        // 1. If start() was refused due to an existing entry (or from_stream was used),
        //    owns_socket is false and the pre-existing entry is never unlinked.
        // 2. Socket-path replacement: verifies the entry is still a socket matching the bound inode.
        // Residual limitation: A check-then-unlink sequence retains a microscopic TOCTOU window
        // if an attacker with write access to the directory swaps the entry between check and unlink.
        if self.owns_socket {
            self.owns_socket = false;
            if let Ok(meta) = std::fs::symlink_metadata(&self.socket_path) {
                let is_socket = meta.file_type().is_socket();
                let matches_bound_inode = self
                    .bound_socket_dev_ino
                    .map(|(dev, ino)| meta.dev() == dev && meta.ino() == ino)
                    .unwrap_or(true);

                if is_socket && matches_bound_inode {
                    let _ = std::fs::remove_file(&self.socket_path);
                }
            }
            self.bound_socket_dev_ino = None;
        }
    }
}

impl Drop for WorkerSupervisor {
    fn drop(&mut self) {
        self.shutdown();
    }
}
