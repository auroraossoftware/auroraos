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
    is_component_contained, normalize_path, CapabilityDefinition, CapabilityNature,
    CapabilityRegistry,
};
pub use config::SupervisorConfig;
pub use dispatcher::CapabilityDispatcher;
pub use identity::CallerIdentity;
pub use policy::{PolicyDecision, PolicyEngine};
pub use provider::{
    parse_proc_stat, CapabilityExecutionError, CpuProvider, LinuxProcStatCpuProvider,
    MockCpuProvider,
};
pub use supervisor::{SupervisorError, WorkerStatus, WorkerSupervisor};

