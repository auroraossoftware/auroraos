//! Worker process lifecycle supervisor and private IPC connection manager.
//!
//! Pursuant to ADR-001, ADR-002, and Accepted ADR-003, the supervisor is responsible for:
//! 1. Managing the lifecycle of the isolated AI worker process as a non-embedded child.
//! 2. Establishing and supervising the private anonymous Unix stream socket pair (`socketpair`).
//! 3. Passing the worker endpoint via standard input (`Stdio::from(OwnedFd)`) with low-descriptor safety.
//! 4. Executing the startup handshake and verifying protocol version compatibility.
//! 5. Monitoring worker health with explicit error propagation and zero zombie leaks.
//! 6. Implementing lazy replacement recovery bounded by a three-failed-replacement limit.
//! 7. Enforcing the invariant that interrupted turns and capability proposals are never replayed.
//! 8. Guaranteeing orderly shutdown escalation and emergency parent-death containment.

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
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// Lifecycle state of the worker supervisor state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerState {
    /// Supervisor is configured, but no worker process is running.
    Uninitialized,
    /// Worker child process is spawned and waiting for handshake completion.
    Starting,
    /// Worker completed handshake, verified protocol version, and is ready for turns.
    Ready,
    /// An active reasoning turn is executing.
    Busy,
    /// Worker crashed or disconnected; supervisor is waiting to attempt lazy recovery.
    Recovering,
    /// Replacement restart budget exhausted (3 consecutive failures) or incompatible version.
    Degraded,
    /// Supervisor has been explicitly shut down.
    Terminated,
}

/// Status of the supervised worker process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkerStatus {
    /// Worker process is running and IPC connection is healthy.
    Running,
    /// Worker process has exited with the given exit code.
    Terminated(Option<i32>),
    /// Worker is alive as a process but the IPC channel disconnected (EOF).
    Disconnected,
    /// Worker supervisor is in Degraded state due to repeated restart failures.
    Degraded,
}

/// Errors occurring during supervisor lifecycle operations.
#[derive(Debug)]
pub enum SupervisorError {
    Io(std::io::Error),
    Ipc(IpcError),
    WorkerSpawnFailed(String),
    HandshakeTimeout,
    WorkerPrematureExit(Option<i32>),
    IncompatibleProtocolVersion {
        expected: u32,
        received: u32,
    },
    HandshakeRejected(String),
    UnexpectedMessage(String),
    SocketAlreadyExists(PathBuf),
    TurnProposalLimitExceeded {
        count: usize,
        limit: usize,
    },
    WorkerTerminatedDuringTurn {
        turn_id: String,
        completed_proposals: Vec<String>,
        exit_code: Option<i32>,
    },
    WorkerRestartLimitExceeded,
    DaemonShuttingDown,
    Interrupted,
    ThreadAffinityViolation,
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
            Self::TurnProposalLimitExceeded { count, limit } => {
                write!(
                    f,
                    "turn capability proposal limit exceeded: received {count} proposals, maximum allowed is {limit}"
                )
            }
            Self::WorkerTerminatedDuringTurn {
                turn_id,
                completed_proposals,
                exit_code,
            } => {
                write!(
                    f,
                    "worker terminated during turn '{turn_id}' (exit code: {exit_code:?}, completed proposals: {completed_proposals:?})"
                )
            }
            Self::WorkerRestartLimitExceeded => {
                write!(
                    f,
                    "worker replacement restart limit exceeded (supervisor degraded)"
                )
            }
            Self::DaemonShuttingDown => write!(f, "daemon is shutting down"),
            Self::Interrupted => write!(f, "operation interrupted by signal"),
            Self::ThreadAffinityViolation => {
                write!(f, "supervisor invoked from non-owner thread")
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

/// Ensures a UnixStream descriptor is allocated at FD >= 3 to prevent collisions with stdio handles.
pub fn ensure_fd_above_stdio(stream: UnixStream) -> Result<UnixStream, SupervisorError> {
    let raw = stream.as_raw_fd();
    if raw < 3 {
        let new_raw = unsafe { libc::fcntl(raw, libc::F_DUPFD_CLOEXEC, 3) };
        if new_raw < 0 {
            return Err(SupervisorError::Io(std::io::Error::last_os_error()));
        }
        drop(stream);
        let new_stream = unsafe { UnixStream::from_raw_fd(new_raw) };
        Ok(new_stream)
    } else {
        Ok(stream)
    }
}

/// Helper to configure a Linux signalfd on the designated owner thread for SIGINT and SIGTERM.
fn create_signalfd_for_owner_thread() -> Option<libc::c_int> {
    unsafe {
        let mut mask: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut mask);
        libc::sigaddset(&mut mask, libc::SIGINT);
        libc::sigaddset(&mut mask, libc::SIGTERM);
        if libc::pthread_sigmask(libc::SIG_BLOCK, &mask, std::ptr::null_mut()) == 0 {
            let fd = libc::signalfd(-1, &mask, libc::SFD_NONBLOCK | libc::SFD_CLOEXEC);
            if fd >= 0 {
                Some(fd)
            } else {
                None
            }
        } else {
            None
        }
    }
}

/// Manages the lifecycle of an AI worker child process and its private IPC channel.
///
/// Pinned to a single designated thread to guarantee correct Linux `PR_SET_PDEATHSIG` semantics.
pub struct WorkerSupervisor {
    config: SupervisorConfig,
    state: WorkerState,
    child: Option<Child>,
    reader: Option<BufReader<UnixStream>>,
    writer: Option<UnixStream>,
    worker_version: Option<String>,
    dispatcher: CapabilityDispatcher,
    turn_counter: u64,
    consecutive_restarts: usize,
    worker_spawn_instant: Option<Instant>,
    owner_thread_id: std::thread::ThreadId,
    is_synthetic_stream: bool,
    signalfd: Option<libc::c_int>,
    _not_send_sync: std::marker::PhantomData<*const ()>,
}

impl WorkerSupervisor {
    /// Creates a new supervisor instance with the specified configuration.
    pub fn new(config: SupervisorConfig) -> Self {
        let dispatcher = CapabilityDispatcher::new_default(config.demo_sandbox_path.clone());
        let signalfd = if config.enable_signal_handling {
            create_signalfd_for_owner_thread()
        } else {
            None
        };
        Self {
            config,
            state: WorkerState::Uninitialized,
            child: None,
            reader: None,
            writer: None,
            worker_version: None,
            dispatcher,
            turn_counter: 0,
            consecutive_restarts: 0,
            worker_spawn_instant: None,
            owner_thread_id: std::thread::current().id(),
            is_synthetic_stream: false,
            signalfd,
            _not_send_sync: std::marker::PhantomData,
        }
    }

    /// Creates a supervisor with a custom capability dispatcher (useful for testing with mock providers).
    pub fn with_dispatcher(config: SupervisorConfig, dispatcher: CapabilityDispatcher) -> Self {
        let signalfd = if config.enable_signal_handling {
            create_signalfd_for_owner_thread()
        } else {
            None
        };
        Self {
            config,
            state: WorkerState::Uninitialized,
            child: None,
            reader: None,
            writer: None,
            worker_version: None,
            dispatcher,
            turn_counter: 0,
            consecutive_restarts: 0,
            worker_spawn_instant: None,
            owner_thread_id: std::thread::current().id(),
            is_synthetic_stream: false,
            signalfd,
            _not_send_sync: std::marker::PhantomData,
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
            config,
            state: WorkerState::Ready,
            child: None,
            reader: Some(reader),
            writer: Some(writer),
            worker_version: Some("0.1.0".to_string()),
            dispatcher,
            turn_counter: 0,
            consecutive_restarts: 0,
            worker_spawn_instant: Some(Instant::now()),
            owner_thread_id: std::thread::current().id(),
            is_synthetic_stream: true,
            signalfd: None,
            _not_send_sync: std::marker::PhantomData,
        })
    }

    /// Asserts that operations are called from the designated owner thread.
    fn assert_owner_thread(&self) {
        assert_eq!(
            std::thread::current().id(),
            self.owner_thread_id,
            "WorkerSupervisor operations must be invoked from the designated owner thread"
        );
    }

    /// Returns the current lifecycle state of the supervisor.
    pub fn state(&self) -> WorkerState {
        self.state
    }

    /// Returns the current consecutive failed replacement count.
    pub fn consecutive_restarts(&self) -> usize {
        self.consecutive_restarts
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
    pub fn execute_proposal(
        &self,
        caller: &CallerIdentity,
        proposal: &ProposeCapability,
    ) -> CapabilityResult {
        self.dispatcher.execute_proposal(caller, proposal)
    }

    /// Returns a reference to the supervisor configuration.
    pub fn config(&self) -> &SupervisorConfig {
        &self.config
    }

    /// Returns a mutable reference to the supervisor configuration.
    pub fn config_mut(&mut self) -> &mut SupervisorConfig {
        &mut self.config
    }

    /// Returns the configured socket path (retained for backward compatibility).
    pub fn socket_path(&self) -> &Path {
        &self.config.socket_path
    }

    /// Returns whether this supervisor owns a filesystem socket path (false under socketpair).
    pub fn owns_socket(&self) -> bool {
        false
    }

    /// Returns the worker version reported during handshake, if established.
    pub fn worker_version(&self) -> Option<&str> {
        self.worker_version.as_deref()
    }

    /// Returns the process ID of the supervised worker child process, if running.
    pub fn worker_pid(&self) -> Option<u32> {
        self.child.as_ref().map(|c| c.id())
    }

    /// Resets a healthy window: if the worker has remained healthy for >= healthy_reset_window, reset counter.
    fn check_and_reset_healthy_window(&mut self) {
        if let Some(instant) = self.worker_spawn_instant {
            if instant.elapsed() >= self.config.healthy_reset_window {
                self.consecutive_restarts = 0;
            }
        }
    }

    /// Checks if the worker socket stream has closed non-blockingly.
    fn is_socket_closed(&self) -> bool {
        if let Some(ref writer) = self.writer {
            let fd = writer.as_raw_fd();
            let mut pfd = libc::pollfd {
                fd,
                events: libc::POLLIN | libc::POLLHUP | libc::POLLERR,
                revents: 0,
            };
            let ret = unsafe { libc::poll(&mut pfd, 1, 0) };
            if ret > 0 {
                if (pfd.revents & (libc::POLLHUP | libc::POLLERR)) != 0 {
                    return true;
                }
                if (pfd.revents & libc::POLLIN) != 0 {
                    let mut buf = [0u8; 1];
                    let peek_ret = unsafe {
                        libc::recv(
                            fd,
                            buf.as_mut_ptr() as *mut libc::c_void,
                            1,
                            libc::MSG_PEEK | libc::MSG_DONTWAIT,
                        )
                    };
                    if peek_ret == 0 {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// Internal routine: spawns worker child with socketpair and executes handshake.
    fn spawn_and_handshake(&mut self) -> Result<String, SupervisorError> {
        if self.config.worker_command.is_empty() {
            return Err(SupervisorError::WorkerSpawnFailed(
                "worker_command is empty".to_string(),
            ));
        }

        // 1. Create anonymous connected Unix stream socket pair
        let (daemon_stream, worker_stream) = UnixStream::pair().map_err(SupervisorError::Io)?;
        let daemon_stream = ensure_fd_above_stdio(daemon_stream)?;
        let worker_stream = ensure_fd_above_stdio(worker_stream)?;

        let daemon_fd = daemon_stream.as_raw_fd();
        let parent_pid = std::process::id() as libc::pid_t;

        let prog = &self.config.worker_command[0];
        let mut cmd = Command::new(prog);
        if self.config.worker_command.len() > 1 {
            cmd.args(&self.config.worker_command[1..]);
        }
        cmd.arg("--stdio-ipc");

        if let Some(ref cwd) = self.config.working_dir {
            cmd.current_dir(cwd);
        }

        // Handoff worker socket endpoint safely on standard input (FD 0)
        let worker_fd: OwnedFd = worker_stream.into();
        cmd.stdin(Stdio::from(worker_fd));
        cmd.stdout(Stdio::null());
        cmd.stderr(Stdio::inherit());

        // Assign child to its own process group to isolate terminal Ctrl+C
        cmd.process_group(0);

        // Pre-exec hook: async-signal-safe, non-allocating configuration
        unsafe {
            cmd.pre_exec(move || {
                // Close daemon supervisor endpoint in child
                if libc::close(daemon_fd) != 0 {
                    return Err(std::io::Error::last_os_error());
                }

                // Reset signal mask so child does not inherit daemon's blocked signals
                let mut empty_set: libc::sigset_t = std::mem::zeroed();
                libc::sigemptyset(&mut empty_set);
                if libc::sigprocmask(libc::SIG_SETMASK, &empty_set, std::ptr::null_mut()) != 0 {
                    return Err(std::io::Error::last_os_error());
                }

                // Register emergency parent-death signal (SIGKILL)
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
                    return Err(std::io::Error::last_os_error());
                }

                // Parent death check: if parent exited before prctl, abort spawn
                if libc::getppid() != parent_pid {
                    return Err(std::io::Error::from_raw_os_error(libc::EPIPE));
                }

                Ok(())
            });
        }

        let mut child = cmd
            .spawn()
            .map_err(|e| SupervisorError::WorkerSpawnFailed(e.to_string()))?;

        // Configure socket timeouts: during handshake, use handshake_timeout
        daemon_stream
            .set_read_timeout(Some(self.config.handshake_timeout))
            .map_err(SupervisorError::Io)?;
        daemon_stream
            .set_write_timeout(Some(self.config.handshake_timeout))
            .map_err(SupervisorError::Io)?;

        let mut writer = daemon_stream.try_clone().map_err(SupervisorError::Io)?;
        let mut reader = BufReader::new(daemon_stream);

        // Execute protocol handshake
        let start = Instant::now();
        let timeout = self.config.handshake_timeout;

        let handshake_msg = DaemonToWorkerMessage::Handshake(Handshake::new("0.1.0"));
        if let Err(e) = send_daemon_message(&mut writer, &handshake_msg) {
            let _ = child.kill();
            let _ = child.wait();
            return Err(SupervisorError::Ipc(e));
        }

        let version = loop {
            // Check if child exited prematurely
            match child.try_wait() {
                Ok(Some(status)) => {
                    return Err(SupervisorError::WorkerPrematureExit(status.code()));
                }
                Ok(None) => {}
                Err(e) => return Err(SupervisorError::Io(e)),
            }

            match read_worker_message(&mut reader) {
                Ok(Some(WorkerToDaemonMessage::HandshakeResponse(HandshakeResponse {
                    protocol_version,
                    worker_version,
                    status,
                }))) => {
                    if protocol_version != CURRENT_PROTOCOL_VERSION {
                        let _ = child.kill();
                        let _ = child.wait();
                        return Err(SupervisorError::IncompatibleProtocolVersion {
                            expected: CURRENT_PROTOCOL_VERSION,
                            received: protocol_version,
                        });
                    }
                    if status != HandshakeStatus::Ready {
                        let _ = child.kill();
                        let _ = child.wait();
                        return Err(SupervisorError::HandshakeRejected(format!("{status:?}")));
                    }
                    break worker_version;
                }
                Ok(Some(other)) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(SupervisorError::UnexpectedMessage(format!("{other:?}")));
                }
                Ok(None) => {
                    let status = child.try_wait().ok().flatten().and_then(|s| s.code());
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(SupervisorError::WorkerPrematureExit(status));
                }
                Err(IpcError::Io(ref e))
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut =>
                {
                    if start.elapsed() > timeout {
                        let _ = child.kill();
                        let _ = child.wait();
                        return Err(SupervisorError::HandshakeTimeout);
                    }
                    std::thread::sleep(Duration::from_millis(25));
                }
                Err(e) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(SupervisorError::Ipc(e));
                }
            }
        };

        // Handshake verified: switch socket read/write timeouts to operational socket_timeout
        let _ = writer.set_read_timeout(Some(self.config.socket_timeout));
        let _ = writer.set_write_timeout(Some(self.config.socket_timeout));

        self.child = Some(child);
        self.reader = Some(reader);
        self.writer = Some(writer);
        Ok(version)
    }

    /// Starts the supervisor: initial worker launch (Attempt 1/1).
    pub fn start(&mut self) -> Result<(), SupervisorError> {
        self.assert_owner_thread();
        if self.state != WorkerState::Uninitialized && self.state != WorkerState::Terminated {
            return Ok(());
        }

        // Backward compatibility: refuse startup if socket_path already exists on the filesystem
        if std::fs::symlink_metadata(&self.config.socket_path).is_ok() {
            return Err(SupervisorError::SocketAlreadyExists(
                self.config.socket_path.clone(),
            ));
        }

        self.state = WorkerState::Starting;
        match self.spawn_and_handshake() {
            Ok(version) => {
                self.worker_version = Some(version);
                self.state = WorkerState::Ready;
                self.consecutive_restarts = 0;
                self.worker_spawn_instant = Some(Instant::now());
                Ok(())
            }
            Err(e) => {
                self.shutdown();
                self.state = WorkerState::Terminated;
                Err(e)
            }
        }
    }

    /// Internal routine: reaps dead child and transitions state to Recovering.
    fn handle_worker_death(&mut self, _exit_code: Option<i32>) {
        if let Some(mut child) = self.child.take() {
            let _ = child.wait();
        }
        self.reader = None;
        self.writer = None;

        // Check if the worker was healthy for >= healthy_reset_window
        if let Some(spawn_instant) = self.worker_spawn_instant {
            if spawn_instant.elapsed() < self.config.healthy_reset_window {
                // Short-lived replacement worker crash consumes an attempt
                self.consecutive_restarts += 1;
                if self.consecutive_restarts >= self.config.max_consecutive_restarts {
                    self.state = WorkerState::Degraded;
                    return;
                }
            } else {
                // Was healthy, original failure triggers recovery without penalty
                self.consecutive_restarts = 0;
            }
        }

        self.state = WorkerState::Recovering;
    }

    /// Performs lazy replacement worker restart bounded by the replacement limit.
    fn perform_lazy_restart(&mut self) -> Result<(), SupervisorError> {
        self.assert_owner_thread();
        if self.is_synthetic_stream {
            return Err(SupervisorError::Ipc(IpcError::ConnectionClosed));
        }
        if self.consecutive_restarts >= self.config.max_consecutive_restarts {
            self.state = WorkerState::Degraded;
            return Err(SupervisorError::WorkerRestartLimitExceeded);
        }

        // Apply backoff delay
        let backoff = self.config.restart_backoff_base * (1 << self.consecutive_restarts.min(6));
        std::thread::sleep(backoff);

        self.state = WorkerState::Starting;
        match self.spawn_and_handshake() {
            Ok(version) => {
                self.worker_version = Some(version);
                self.state = WorkerState::Ready;
                self.worker_spawn_instant = Some(Instant::now());
                Ok(())
            }
            Err(SupervisorError::IncompatibleProtocolVersion { expected, received }) => {
                self.consecutive_restarts = self.config.max_consecutive_restarts;
                self.state = WorkerState::Degraded;
                self.shutdown();
                Err(SupervisorError::IncompatibleProtocolVersion { expected, received })
            }
            Err(SupervisorError::HandshakeRejected(reason)) => {
                self.consecutive_restarts = self.config.max_consecutive_restarts;
                self.state = WorkerState::Degraded;
                self.shutdown();
                Err(SupervisorError::HandshakeRejected(reason))
            }
            Err(other) => {
                self.consecutive_restarts += 1;
                self.shutdown();
                if self.consecutive_restarts >= self.config.max_consecutive_restarts {
                    self.state = WorkerState::Degraded;
                } else {
                    self.state = WorkerState::Recovering;
                }
                Err(other)
            }
        }
    }

    /// Executes a reasoning turn with automatic turn-id allocation.
    pub fn execute_turn(
        &mut self,
        caller: &CallerIdentity,
        prompt: &str,
    ) -> Result<aurora_protocol::CompleteTurn, SupervisorError> {
        self.turn_counter += 1;
        let turn_id = format!("turn-{}", self.turn_counter);
        self.execute_turn_with_id(caller, &turn_id, prompt)
    }

    /// Executes a reasoning turn end-to-end with deterministic mediation and no-replay semantics.
    pub fn execute_turn_with_id(
        &mut self,
        caller: &CallerIdentity,
        turn_id: &str,
        prompt: &str,
    ) -> Result<aurora_protocol::CompleteTurn, SupervisorError> {
        self.assert_owner_thread();

        // 1. Guard against degraded or terminated states
        if self.is_synthetic_stream
            && (self.state == WorkerState::Terminated || self.writer.is_none())
        {
            return Err(SupervisorError::Ipc(IpcError::ConnectionClosed));
        }
        if self.state == WorkerState::Degraded {
            return Err(SupervisorError::WorkerRestartLimitExceeded);
        }
        if self.state == WorkerState::Terminated {
            return Err(SupervisorError::DaemonShuttingDown);
        }

        // 2. Health check if currently marked Ready
        if self.state == WorkerState::Ready {
            self.check_and_reset_healthy_window();
            if let Some(ref mut child) = self.child {
                match child.try_wait() {
                    Ok(Some(status)) => {
                        self.handle_worker_death(status.code());
                    }
                    Ok(None) => {
                        if self.is_socket_closed() {
                            self.handle_worker_death(None);
                        }
                    }
                    Err(e) => {
                        return Err(SupervisorError::Io(e));
                    }
                }
            }
        }

        // 3. Lazy recovery if in Recovering state
        if self.state == WorkerState::Recovering {
            self.perform_lazy_restart()?;
        }

        if self.state != WorkerState::Ready {
            return Err(SupervisorError::WorkerRestartLimitExceeded);
        }

        self.state = WorkerState::Busy;
        let turn_result = self.run_turn_flow(caller, turn_id, prompt);

        match turn_result {
            Ok(complete_turn) => {
                self.state = WorkerState::Ready;
                self.check_and_reset_healthy_window();
                Ok(complete_turn)
            }
            Err((err, completed_proposals)) => {
                self.handle_active_turn_failure(turn_id, err, completed_proposals)
            }
        }
    }

    /// Internal execution loop for an active turn.
    fn run_turn_flow(
        &mut self,
        caller: &CallerIdentity,
        turn_id: &str,
        prompt: &str,
    ) -> Result<aurora_protocol::CompleteTurn, (SupervisorError, Vec<String>)> {
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

        let mut completed_proposals: Vec<String> = Vec::new();

        let writer = match self.writer.as_mut() {
            Some(w) => w,
            None => {
                return Err((
                    SupervisorError::Ipc(IpcError::ConnectionClosed),
                    completed_proposals,
                ))
            }
        };

        if let Err(e) = send_daemon_message(writer, &DaemonToWorkerMessage::RequestTurn(request)) {
            return Err((SupervisorError::Ipc(e), completed_proposals));
        }

        let mut turn_proposals_count: usize = 0;

        loop {
            // Signal-integrated IPC waiting via poll()
            if let Some(ref writer) = self.writer {
                let mut pfds = [
                    libc::pollfd {
                        fd: writer.as_raw_fd(),
                        events: libc::POLLIN | libc::POLLHUP | libc::POLLERR,
                        revents: 0,
                    },
                    libc::pollfd {
                        fd: self.signalfd.unwrap_or(-1),
                        events: if self.signalfd.is_some() {
                            libc::POLLIN
                        } else {
                            0
                        },
                        revents: 0,
                    },
                ];
                let nfds = if self.signalfd.is_some() { 2 } else { 1 };
                let timeout_ms =
                    self.config.socket_timeout.as_millis().min(i32::MAX as u128) as libc::c_int;

                let ret = unsafe { libc::poll(pfds.as_mut_ptr(), nfds, timeout_ms) };
                if ret < 0 {
                    let err = std::io::Error::last_os_error();
                    if err.raw_os_error() == Some(libc::EINTR) {
                        return Err((SupervisorError::Interrupted, completed_proposals));
                    }
                } else if ret == 0 {
                    return Err((
                        SupervisorError::Ipc(IpcError::Io(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "IPC turn wait timed out",
                        ))),
                        completed_proposals,
                    ));
                } else if self.signalfd.is_some() && (pfds[1].revents & libc::POLLIN) != 0 {
                    let sfd = pfds[1].fd;
                    let mut siginfo: libc::signalfd_siginfo = unsafe { std::mem::zeroed() };
                    let _ = unsafe {
                        libc::read(
                            sfd,
                            &mut siginfo as *mut _ as *mut libc::c_void,
                            std::mem::size_of::<libc::signalfd_siginfo>(),
                        )
                    };
                    return Err((SupervisorError::Interrupted, completed_proposals));
                }
            }

            let res = {
                let reader = match self.reader.as_mut() {
                    Some(r) => r,
                    None => {
                        return Err((
                            SupervisorError::Ipc(IpcError::ConnectionClosed),
                            completed_proposals,
                        ))
                    }
                };
                read_worker_message(reader)
            };

            let msg = match res {
                Ok(Some(msg)) => msg,
                Ok(None) => {
                    return Err((
                        SupervisorError::Ipc(IpcError::ConnectionClosed),
                        completed_proposals,
                    ));
                }
                Err(e) => {
                    return Err((SupervisorError::Ipc(e), completed_proposals));
                }
            };

            match msg {
                WorkerToDaemonMessage::ProposeCapability(proposal) => {
                    turn_proposals_count += 1;
                    if turn_proposals_count > self.config.max_proposals_per_turn {
                        return Err((
                            SupervisorError::TurnProposalLimitExceeded {
                                count: turn_proposals_count,
                                limit: self.config.max_proposals_per_turn,
                            },
                            completed_proposals,
                        ));
                    }

                    if proposal.turn_id != turn_id {
                        return Err((
                            SupervisorError::UnexpectedMessage(format!(
                                "Turn ID mismatch in proposal: expected '{turn_id}', got '{}'",
                                proposal.turn_id
                            )),
                            completed_proposals,
                        ));
                    }

                    if proposal.protocol_version != CURRENT_PROTOCOL_VERSION {
                        return Err((
                            SupervisorError::IncompatibleProtocolVersion {
                                expected: CURRENT_PROTOCOL_VERSION,
                                received: proposal.protocol_version,
                            },
                            completed_proposals,
                        ));
                    }

                    let cap_name = proposal.capability_name.clone();
                    let outcome = self.dispatcher.execute_proposal(caller, &proposal);
                    completed_proposals.push(cap_name);

                    let writer = match self.writer.as_mut() {
                        Some(w) => w,
                        None => {
                            return Err((
                                SupervisorError::Ipc(IpcError::ConnectionClosed),
                                completed_proposals,
                            ))
                        }
                    };
                    if let Err(e) = send_daemon_message(
                        writer,
                        &DaemonToWorkerMessage::CapabilityResult(outcome),
                    ) {
                        return Err((SupervisorError::Ipc(e), completed_proposals));
                    }
                }
                WorkerToDaemonMessage::CompleteTurn(complete_turn) => {
                    if complete_turn.turn_id != turn_id {
                        return Err((
                            SupervisorError::UnexpectedMessage(format!(
                                "Turn ID mismatch in complete_turn: expected '{turn_id}', got '{}'",
                                complete_turn.turn_id
                            )),
                            completed_proposals,
                        ));
                    }
                    if let Err(e) = complete_turn.validate() {
                        return Err((
                            SupervisorError::UnexpectedMessage(e.to_string()),
                            completed_proposals,
                        ));
                    }
                    return Ok(complete_turn);
                }
                WorkerToDaemonMessage::HandshakeResponse(_) => {
                    return Err((
                        SupervisorError::UnexpectedMessage(
                            "Unexpected HandshakeResponse during active turn".to_string(),
                        ),
                        completed_proposals,
                    ));
                }
            }
        }
    }

    /// Handles failure during an active turn: tears down worker, records proposals, and fails closed without replay.
    fn handle_active_turn_failure(
        &mut self,
        turn_id: &str,
        err: SupervisorError,
        completed_proposals: Vec<String>,
    ) -> Result<aurora_protocol::CompleteTurn, SupervisorError> {
        if self.is_synthetic_stream {
            self.shutdown();
            self.state = WorkerState::Terminated;
            return Err(err);
        }

        let exit_code = if let Some(ref mut child) = self.child {
            match child.try_wait() {
                Ok(Some(s)) => s.code(),
                Ok(None) => {
                    // Give exiting child a brief moment to update exit status before reaping
                    std::thread::sleep(Duration::from_millis(20));
                    child.try_wait().ok().flatten().and_then(|s| s.code())
                }
                Err(_) => None,
            }
        } else {
            None
        };

        self.shutdown();
        self.state = WorkerState::Recovering;

        if let Some(spawn_instant) = self.worker_spawn_instant {
            if spawn_instant.elapsed() < self.config.healthy_reset_window {
                self.consecutive_restarts += 1;
                if self.consecutive_restarts >= self.config.max_consecutive_restarts {
                    self.state = WorkerState::Degraded;
                }
            } else {
                self.consecutive_restarts = 0;
            }
        }

        match err {
            SupervisorError::TurnProposalLimitExceeded { .. } => Err(err),
            SupervisorError::Interrupted => Err(err),
            SupervisorError::Ipc(IpcError::Serialization(_)) => Err(err),
            SupervisorError::Ipc(IpcError::FrameTooLarge) => Err(err),
            SupervisorError::Ipc(IpcError::UnterminatedFrame) => Err(err),
            SupervisorError::Ipc(IpcError::Io(ref e))
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                Err(err)
            }
            SupervisorError::UnexpectedMessage(_) => Err(err),
            SupervisorError::IncompatibleProtocolVersion { .. } => Err(err),
            _ => Err(SupervisorError::WorkerTerminatedDuringTurn {
                turn_id: turn_id.to_string(),
                completed_proposals,
                exit_code,
            }),
        }
    }

    /// Polls the health of the worker child process with explicit error propagation.
    pub fn poll_status(&mut self) -> Result<WorkerStatus, SupervisorError> {
        self.assert_owner_thread();
        if self.state == WorkerState::Degraded {
            return Ok(WorkerStatus::Degraded);
        }

        // Check if signalfd received SIGINT or SIGTERM
        if let Some(sfd) = self.signalfd {
            let mut pfd = libc::pollfd {
                fd: sfd,
                events: libc::POLLIN,
                revents: 0,
            };
            let ret = unsafe { libc::poll(&mut pfd, 1, 0) };
            if ret > 0 && (pfd.revents & libc::POLLIN) != 0 {
                let mut siginfo: libc::signalfd_siginfo = unsafe { std::mem::zeroed() };
                let _ = unsafe {
                    libc::read(
                        sfd,
                        &mut siginfo as *mut _ as *mut libc::c_void,
                        std::mem::size_of::<libc::signalfd_siginfo>(),
                    )
                };
                self.shutdown();
                return Err(SupervisorError::Interrupted);
            }
        }

        if let Some(ref mut child) = self.child {
            match child.try_wait() {
                Ok(Some(status)) => {
                    self.handle_worker_death(status.code());
                    Ok(WorkerStatus::Terminated(status.code()))
                }
                Ok(None) => {
                    if self.is_socket_closed() {
                        self.handle_worker_death(None);
                        Ok(WorkerStatus::Disconnected)
                    } else {
                        self.check_and_reset_healthy_window();
                        Ok(WorkerStatus::Running)
                    }
                }
                Err(e) => {
                    // Propagate error explicitly; never assume worker is healthy on waitpid failure
                    Err(SupervisorError::Io(e))
                }
            }
        } else if self.state == WorkerState::Degraded {
            Ok(WorkerStatus::Degraded)
        } else {
            Ok(WorkerStatus::Terminated(None))
        }
    }

    /// Programmatic operator reset API to recover a degraded supervisor.
    pub fn reset(&mut self) -> Result<(), SupervisorError> {
        self.assert_owner_thread();
        self.shutdown();
        self.consecutive_restarts = 0;
        self.state = WorkerState::Uninitialized;
        if self.config.enable_signal_handling {
            self.signalfd = create_signalfd_for_owner_thread();
        }
        self.start()
    }

    /// Cleanly terminates the worker process with orderly signal escalation and mandatory child reaping.
    pub fn shutdown(&mut self) {
        self.assert_owner_thread();
        self.state = WorkerState::Terminated;
        self.reader = None;
        self.writer = None;
        if let Some(sfd) = self.signalfd.take() {
            unsafe {
                libc::close(sfd);
            }
        }

        if let Some(mut child) = self.child.take() {
            let child_pid = child.id() as libc::pid_t;

            // Stage 1: Graceful wait for up to 200ms
            let start = Instant::now();
            let mut exited = false;
            while start.elapsed() < Duration::from_millis(200) {
                if let Ok(Some(_)) = child.try_wait() {
                    exited = true;
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }

            // Stage 2: SIGTERM escalation
            if !exited {
                unsafe {
                    libc::kill(child_pid, libc::SIGTERM);
                }
                let term_start = Instant::now();
                while term_start.elapsed() < Duration::from_millis(300) {
                    if let Ok(Some(_)) = child.try_wait() {
                        exited = true;
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
            }

            // Stage 3: SIGKILL escalation
            if !exited {
                unsafe {
                    libc::kill(child_pid, libc::SIGKILL);
                }
            }

            // Stage 4: Mandatory wait/reap
            let _ = child.wait();
        }
    }
}

impl Drop for WorkerSupervisor {
    fn drop(&mut self) {
        self.shutdown();
    }
}
