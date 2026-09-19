//! Private IPC protocol framing and transport utilities.

use aurora_protocol::{DaemonToWorkerMessage, WorkerToDaemonMessage};
use std::io::{BufRead, Write};

/// Error types occurring during IPC transmission and framing.
#[derive(Debug)]
pub enum IpcError {
    Io(std::io::Error),
    Serialization(serde_json::Error),
    ConnectionClosed,
}

impl std::fmt::Display for IpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O error: {e}"),
            Self::Serialization(e) => write!(f, "serialization error: {e}"),
            Self::ConnectionClosed => write!(f, "connection closed by remote peer"),
        }
    }
}

impl std::error::Error for IpcError {}

impl From<std::io::Error> for IpcError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<serde_json::Error> for IpcError {
    fn from(e: serde_json::Error) -> Self {
        Self::Serialization(e)
    }
}

/// Transmits a typed daemon message across the stream followed by a newline delimiter.
pub fn send_daemon_message<W: Write>(
    writer: &mut W,
    message: &DaemonToWorkerMessage,
) -> Result<(), IpcError> {
    let json_bytes = serde_json::to_vec(message)?;
    writer.write_all(&json_bytes)?;
    writer.write_all(b"\n")?;
    writer.flush()?;
    Ok(())
}

/// Reads a single newline-delimited message from the stream and deserializes it into a worker message.
pub fn read_worker_message<R: BufRead>(
    reader: &mut R,
) -> Result<Option<WorkerToDaemonMessage>, IpcError> {
    let mut line = String::new();
    let bytes_read = reader.read_line(&mut line)?;
    if bytes_read == 0 {
        return Ok(None);
    }
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    let message: WorkerToDaemonMessage = serde_json::from_str(trimmed)?;
    Ok(Some(message))
}
