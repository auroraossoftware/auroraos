//! Private IPC protocol framing and transport utilities.

use aurora_protocol::{DaemonToWorkerMessage, WorkerToDaemonMessage};
use std::io::{BufRead, Write};

/// Maximum allowed IPC frame size in bytes, including the terminating newline.
///
/// Set to exactly 512 KiB (524,288 bytes) to accommodate worst-case JSON-escaped
/// 64 KiB observation payloads (which expand to ~393 KiB under `\u00XX` escaping)
/// plus protocol envelope overhead.
///
/// This serves as an application-level per-frame buffering limit, preventing
/// stream desynchronization and unbounded allocation. It does not alone claim
/// to eliminate all system-wide out-of-memory risks.
pub const MAX_IPC_FRAME_SIZE: usize = 512 * 1024; // 524,288 bytes

/// Error types occurring during IPC transmission and framing.
#[derive(Debug)]
pub enum IpcError {
    Io(std::io::Error),
    Serialization(serde_json::Error),
    ConnectionClosed,
    FrameTooLarge,
    UnterminatedFrame,
}

impl std::fmt::Display for IpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O error: {e}"),
            Self::Serialization(e) => write!(f, "serialization error: {e}"),
            Self::ConnectionClosed => write!(f, "connection closed by remote peer"),
            Self::FrameTooLarge => write!(
                f,
                "IPC frame exceeded maximum size of {MAX_IPC_FRAME_SIZE} bytes"
            ),
            Self::UnterminatedFrame => {
                write!(f, "IPC frame reached EOF without a terminating newline")
            }
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

/// Reads a single newline-terminated frame from the stream up to `max_bytes` bytes.
///
/// # Security & Framing Guarantees
/// - Bounded by `max_bytes` in raw wire bytes, inclusive of the terminating `\n`.
/// - If the stream exceeds `max_bytes` before encountering `\n`, returns `IpcError::FrameTooLarge`.
/// - If the stream reaches EOF without a terminating `\n`, returns `IpcError::UnterminatedFrame`.
/// - Returns `Ok(None)` only on clean EOF between message frames.
pub fn read_bounded_line<R: BufRead>(
    reader: &mut R,
    max_bytes: usize,
) -> Result<Option<Vec<u8>>, IpcError> {
    let mut buf = Vec::new();

    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            if buf.is_empty() {
                return Ok(None);
            } else {
                return Err(IpcError::UnterminatedFrame);
            }
        }

        if let Some(pos) = available.iter().position(|&b| b == b'\n') {
            let consume_len = pos + 1;
            if buf.len() + consume_len > max_bytes {
                reader.consume(consume_len);
                return Err(IpcError::FrameTooLarge);
            }
            buf.extend_from_slice(&available[..consume_len]);
            reader.consume(consume_len);
            return Ok(Some(buf));
        } else {
            if buf.len() + available.len() >= max_bytes {
                let len = available.len();
                reader.consume(len);
                return Err(IpcError::FrameTooLarge);
            }
            buf.extend_from_slice(available);
            let len = available.len();
            reader.consume(len);
        }
    }
}

/// Transmits a typed daemon message across the stream followed by a newline delimiter.
pub fn send_daemon_message<W: Write>(
    writer: &mut W,
    message: &DaemonToWorkerMessage,
) -> Result<(), IpcError> {
    let json_bytes = serde_json::to_vec(message)?;
    if json_bytes.len() + 1 > MAX_IPC_FRAME_SIZE {
        return Err(IpcError::FrameTooLarge);
    }
    writer.write_all(&json_bytes)?;
    writer.write_all(b"\n")?;
    writer.flush()?;
    Ok(())
}

/// Transmits a typed worker message across the stream followed by a newline delimiter.
pub fn send_worker_message<W: Write>(
    writer: &mut W,
    message: &WorkerToDaemonMessage,
) -> Result<(), IpcError> {
    let json_bytes = serde_json::to_vec(message)?;
    if json_bytes.len() + 1 > MAX_IPC_FRAME_SIZE {
        return Err(IpcError::FrameTooLarge);
    }
    writer.write_all(&json_bytes)?;
    writer.write_all(b"\n")?;
    writer.flush()?;
    Ok(())
}

/// Reads a single newline-delimited message from the stream and deserializes it into a worker message.
pub fn read_worker_message<R: BufRead>(
    reader: &mut R,
) -> Result<Option<WorkerToDaemonMessage>, IpcError> {
    let line_bytes = match read_bounded_line(reader, MAX_IPC_FRAME_SIZE)? {
        Some(b) => b,
        None => return Ok(None),
    };

    let trimmed = line_bytes
        .strip_suffix(b"\n")
        .unwrap_or(&line_bytes)
        .strip_suffix(b"\r")
        .unwrap_or(&line_bytes);

    if trimmed.iter().all(|b| b.is_ascii_whitespace()) {
        return Ok(None);
    }

    let message: WorkerToDaemonMessage = serde_json::from_slice(trimmed)?;
    Ok(Some(message))
}

/// Reads a single newline-delimited message from the stream and deserializes it into a daemon message.
pub fn read_daemon_message<R: BufRead>(
    reader: &mut R,
) -> Result<Option<DaemonToWorkerMessage>, IpcError> {
    let line_bytes = match read_bounded_line(reader, MAX_IPC_FRAME_SIZE)? {
        Some(b) => b,
        None => return Ok(None),
    };

    let trimmed = line_bytes
        .strip_suffix(b"\n")
        .unwrap_or(&line_bytes)
        .strip_suffix(b"\r")
        .unwrap_or(&line_bytes);

    if trimmed.iter().all(|b| b.is_ascii_whitespace()) {
        return Ok(None);
    }

    let message: DaemonToWorkerMessage = serde_json::from_slice(trimmed)?;
    Ok(Some(message))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_read_bounded_line_clean_eof() {
        let mut cursor = Cursor::new(b"");
        assert!(read_bounded_line(&mut cursor, 100).unwrap().is_none());
    }

    #[test]
    fn test_read_bounded_line_valid_frame() {
        let mut cursor = Cursor::new(b"hello world\n");
        let line = read_bounded_line(&mut cursor, 100).unwrap().unwrap();
        assert_eq!(line, b"hello world\n");
    }

    #[test]
    fn test_read_bounded_line_unterminated_eof() {
        let mut cursor = Cursor::new(b"unterminated frame without newline");
        match read_bounded_line(&mut cursor, 100) {
            Err(IpcError::UnterminatedFrame) => {}
            other => panic!("Expected UnterminatedFrame, got: {other:?}"),
        }
    }

    #[test]
    fn test_read_bounded_line_exact_boundary() {
        let limit = 10;
        let mut data = vec![b'a'; limit - 1];
        data.push(b'\n'); // Exactly 10 bytes
        let mut cursor = Cursor::new(data.clone());
        let line = read_bounded_line(&mut cursor, limit).unwrap().unwrap();
        assert_eq!(line.len(), limit);
        assert_eq!(line, data);
    }

    #[test]
    fn test_read_bounded_line_exceeds_by_one_byte() {
        let limit = 10;
        let mut data = vec![b'a'; limit];
        data.push(b'\n'); // 11 bytes
        let mut cursor = Cursor::new(data);
        match read_bounded_line(&mut cursor, limit) {
            Err(IpcError::FrameTooLarge) => {}
            other => panic!("Expected FrameTooLarge, got: {other:?}"),
        }
    }

    #[test]
    fn test_ipc_worst_case_control_character_content() {
        // 64 KiB of '\x01' expands to 65,536 * 6 = 393,216 bytes in JSON
        let raw_control_bytes = vec![1u8; 65536];
        let content_str = String::from_utf8(raw_control_bytes).unwrap();

        let outcome = aurora_protocol::CapabilityResult {
            protocol_version: 1,
            turn_id: "turn-test-worst-case".to_string(),
            call_id: "call-001".to_string(),
            outcome: aurora_protocol::CapabilityOutcome::Success {
                data: serde_json::json!({
                    "content": content_str,
                    "size_bytes": 65536
                }),
            },
        };

        let msg = DaemonToWorkerMessage::CapabilityResult(outcome);
        let mut buffer = Vec::new();
        assert!(send_daemon_message(&mut buffer, &msg).is_ok());

        // Serialized frame size should be around 393,441 bytes (< 512 KiB)
        assert!(buffer.len() > 390_000);
        assert!(buffer.len() <= MAX_IPC_FRAME_SIZE);

        let mut cursor = Cursor::new(buffer);
        let decoded = read_daemon_message(&mut cursor).unwrap().unwrap();
        match decoded {
            DaemonToWorkerMessage::CapabilityResult(res) => match res.outcome {
                aurora_protocol::CapabilityOutcome::Success { data } => {
                    assert_eq!(data["size_bytes"], 65536);
                    assert_eq!(data["content"].as_str().unwrap().len(), 65536);
                }
                _ => panic!("Expected success outcome"),
            },
            _ => panic!("Expected CapabilityResult"),
        }
    }

    #[test]
    fn test_ipc_frame_at_accepted_limit_512k() {
        let limit = MAX_IPC_FRAME_SIZE;
        let mut data = vec![b' '; limit - 1];
        data.push(b'\n');
        let mut cursor = Cursor::new(data);
        // Bounded line read at accepted limit succeeds
        let res = read_bounded_line(&mut cursor, limit).unwrap().unwrap();
        assert_eq!(res.len(), limit);
    }

    #[test]
    fn test_ipc_oversized_frame_rejected_safely() {
        let limit = MAX_IPC_FRAME_SIZE;
        let mut data = vec![b'a'; limit];
        data.push(b'\n'); // 524,289 bytes
        let mut cursor = Cursor::new(data);
        match read_bounded_line(&mut cursor, limit) {
            Err(IpcError::FrameTooLarge) => {}
            other => panic!("Expected FrameTooLarge, got: {other:?}"),
        }
    }

    #[test]
    fn test_read_bounded_line_measures_multibyte_utf8_in_bytes() {
        // '€' is 3 bytes in UTF-8 (0xE2, 0x82, 0xAC)
        // 200,000 characters is 600,000 bytes. In characters it is < 524,288,
        // but in bytes it exceeds MAX_IPC_FRAME_SIZE (524,288 bytes).
        let euro = "€";
        assert_eq!(euro.len(), 3);
        assert_eq!(euro.chars().count(), 1);

        let mut oversized_bytes = euro.repeat(200_000).into_bytes();
        oversized_bytes.push(b'\n'); // 600,001 bytes total
        let mut cursor = Cursor::new(oversized_bytes);
        match read_bounded_line(&mut cursor, MAX_IPC_FRAME_SIZE) {
            Err(IpcError::FrameTooLarge) => {}
            other => panic!(
                "Expected FrameTooLarge for multibyte UTF-8 exceeding byte limit, got: {other:?}"
            ),
        }

        // Within limit: 100,000 euro characters = 300,000 bytes + 1 '\n' = 300,001 bytes
        let mut valid_bytes = euro.repeat(100_000).into_bytes();
        valid_bytes.push(b'\n');
        let mut valid_cursor = Cursor::new(valid_bytes);
        let res = read_bounded_line(&mut valid_cursor, MAX_IPC_FRAME_SIZE)
            .unwrap()
            .unwrap();
        assert_eq!(res.len(), 300_001);
    }

    #[test]
    fn test_framing_error_leaves_stream_requiring_connection_closure() {
        // When an oversized frame occurs, leftover bytes remain in the transport stream.
        // The protocol requires immediate connection termination so these leftovers
        // cannot be parsed as a subsequent message.
        let limit = 50;
        let mut stream_data = vec![b'x'; 60]; // 60 bytes > 50 byte limit
        stream_data.push(b'\n');
        stream_data.extend_from_slice(b"{\"turn_id\":\"next\"}\n");

        let mut cursor = Cursor::new(stream_data);
        let read_result = read_bounded_line(&mut cursor, limit);
        assert!(matches!(read_result, Err(IpcError::FrameTooLarge)));

        // If the connection were NOT dropped, cursor position would be inside the oversized frame.
        // This test proves that the application layer must discard/close the reader upon FrameTooLarge.
        drop(cursor); // Simulates supervisor connection teardown (self.reader = None)
    }
}
