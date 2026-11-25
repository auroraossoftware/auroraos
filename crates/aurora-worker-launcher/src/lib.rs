//! Standalone native trusted launcher library for Aurora OS AI worker.
//!
//! Provides rootless Linux namespaces, UID/GID mapping, rootfs assembly,
//! capability stripping, signalfd-based reaper proxy, and parent-death synchronization.

pub mod caps;
pub mod idmap;
pub mod ns;
pub mod pdeath;
pub mod reaper;
pub mod rootfs;

use std::fmt;

pub const TOKEN_ARMED: u8 = 0x01;
pub const TOKEN_CONTINUE: u8 = 0x02;
pub const TOKEN_EARLY_ARMED: u8 = 0x03;
pub const TOKEN_EARLY_CONTINUE: u8 = 0x04;
pub const GATE_READY: u8 = 0x01;
pub const GATE_CONTINUE: u8 = 0x01;

pub const CONTAINER_UID: libc::uid_t = 1000;
pub const CONTAINER_GID: libc::gid_t = 1000;

pub const ERR_USERNS_UNSUPPORTED: i32 = 70;
pub const ERR_PROCFS_SUBSET_PID_UNSUPPORTED: i32 = 71;
pub const ERR_CGROUP_GATE_MISSING: i32 = 72;
pub const ERR_SETUP_CAPS_MISSING: i32 = 73;
pub const ERR_ROOTFS_FAILED: i32 = 74;
pub const ERR_CAPS_PURGE_FAILED: i32 = 75;
pub const ERR_SECURITY_LOCK_FAILED: i32 = 76;
pub const ERR_PDEATH_FAILED: i32 = 77;
pub const ERR_EXEC_FAILED: i32 = 78;

#[derive(Debug)]
pub enum LauncherError {
    Io(std::io::Error),
    Os(&'static str, i32),
    InvalidArgs(String),
    UserNsUnsupported,
    ProcfsSubsetPidUnsupported,
    CgroupGateMissing(String),
    SetupCapsMissing(String),
    RootfsAssembly(String),
    CapsPurge(String),
    SecurityLock(String),
    PdeathSync(String),
    SignalTerminated(i32),
    ExecFailed(String),
}

impl fmt::Display for LauncherError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O error: {e}"),
            Self::Os(op, code) => write!(f, "OS error during {op}: errno {code}"),
            Self::InvalidArgs(msg) => write!(f, "Invalid launcher arguments: {msg}"),
            Self::UserNsUnsupported => {
                write!(f, "Unprivileged user namespaces unsupported by kernel")
            }
            Self::ProcfsSubsetPidUnsupported => {
                write!(f, "Procfs subset=pid unsupported by kernel")
            }
            Self::CgroupGateMissing(msg) => write!(f, "Cgroup startup gate error: {msg}"),
            Self::SetupCapsMissing(msg) => write!(f, "Setup capabilities missing: {msg}"),
            Self::RootfsAssembly(msg) => write!(f, "Root filesystem assembly error: {msg}"),
            Self::CapsPurge(msg) => write!(f, "Capability purge error: {msg}"),
            Self::SecurityLock(msg) => write!(f, "Security lock error: {msg}"),
            Self::PdeathSync(msg) => write!(f, "Parent-death handshake error: {msg}"),
            Self::SignalTerminated(sig) => {
                write!(
                    f,
                    "Terminated by signal {sig} while waiting at startup gate"
                )
            }
            Self::ExecFailed(msg) => write!(f, "Worker execve failed: {msg}"),
        }
    }
}

impl std::error::Error for LauncherError {}

impl From<std::io::Error> for LauncherError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl LauncherError {
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::InvalidArgs(_) => 2,
            Self::UserNsUnsupported => ERR_USERNS_UNSUPPORTED,
            Self::ProcfsSubsetPidUnsupported => ERR_PROCFS_SUBSET_PID_UNSUPPORTED,
            Self::CgroupGateMissing(_) => ERR_CGROUP_GATE_MISSING,
            Self::SetupCapsMissing(_) => ERR_SETUP_CAPS_MISSING,
            Self::RootfsAssembly(_) => ERR_ROOTFS_FAILED,
            Self::CapsPurge(_) => ERR_CAPS_PURGE_FAILED,
            Self::SecurityLock(_) => ERR_SECURITY_LOCK_FAILED,
            Self::PdeathSync(_) => ERR_PDEATH_FAILED,
            Self::SignalTerminated(sig) => 128 + sig,
            Self::ExecFailed(_) => ERR_EXEC_FAILED,
            _ => 1,
        }
    }
}
