//! Core library for the Aurora OS AI daemon (`aurora-ai`).
//!
//! Exposes runtime configuration, private IPC transport framing, worker
//! process lifecycle supervision, capability definitions, and the deterministic policy engine.

pub mod capability;
pub mod config;
pub mod dispatcher;
pub mod identity;
pub mod ipc;
pub mod policy;
pub mod provider;
pub mod supervisor;

pub use capability::{
    is_component_contained, normalize_path, validate_fs_path, CapabilityDefinition,
    CapabilityNature, CapabilityRegistry,
};
pub use config::SupervisorConfig;
pub use dispatcher::CapabilityDispatcher;
pub use identity::CallerIdentity;
pub use ipc::{
    read_daemon_message, read_worker_message, send_daemon_message, send_worker_message, IpcError,
    MAX_IPC_FRAME_SIZE,
};
pub use policy::{PolicyDecision, PolicyEngine};
pub use provider::{
    parse_proc_meminfo, parse_proc_stat, CapabilityExecutionError, CpuProvider, FileProvider,
    LinuxProcFsProcessProvider, LinuxProcMeminfoMemoryProvider, LinuxProcStatCpuProvider,
    MemoryProvider, MockCpuProvider, MockFileProvider, MockMemoryProvider, MockProcessProvider,
    ProcessProvider, SandboxedLocalFileProvider, MAX_FILE_SIZE_BYTES,
};
pub use supervisor::{SupervisorError, WorkerStatus, WorkerSupervisor};
