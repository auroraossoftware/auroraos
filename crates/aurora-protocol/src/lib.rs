//! Aurora OS Internal Daemon ↔ Worker Protocol (v1)
//!
//! This module defines the typed contract governing communication between the
//! `aurora-ai` core daemon and the isolated AI worker process over a private
//! IPC channel (pursuant to ADR-001 and ADR-002).
//!
//! # Security Principles
//! - **Untrusted Input:** All messages received from the worker are treated as untrusted input.
//! - **No Self-Authorization:** The worker cannot grant capabilities or alter policy.
//! - **Strict Framing:** Messages must conform to explicit types; unknown or malformed messages are rejected.
//! - **Provisional Serialization:** JSON serialization is used provisionally for M1/M2 to establish
//!   the structure and allow validation tests without premature lock-in to an encoding format.

use serde::{Deserialize, Serialize};

/// Current supported protocol version.
pub const CURRENT_PROTOCOL_VERSION: u32 = 1;

/// Message sent from the Daemon to the Worker across the private IPC socket.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DaemonToWorkerMessage {
    /// Initial handshake sent upon private IPC connection establishment.
    Handshake(Handshake),
    /// Request the worker to initiate an intent reasoning turn.
    RequestTurn(RequestTurn),
    /// Return the deterministic outcome of a previously proposed capability.
    CapabilityResult(CapabilityResult),
}

/// Message sent from the Worker to the Daemon across the private IPC socket.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WorkerToDaemonMessage {
    /// Handshake response confirming worker readiness and protocol compatibility.
    HandshakeResponse(HandshakeResponse),
    /// Worker proposes a capability execution.
    ProposeCapability(ProposeCapability),
    /// Worker signals turn completion with final synthesized response.
    CompleteTurn(CompleteTurn),
}

/// Handshake initiated by daemon upon establishing private IPC connection.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Handshake {
    /// Protocol version offered by daemon.
    pub protocol_version: u32,
    /// Daemon service version string.
    pub daemon_version: String,
}

/// Status of handshake response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HandshakeStatus {
    /// Worker is ready and compatible with protocol version.
    Ready,
    /// Worker rejected the handshake due to version incompatibility.
    IncompatibleVersion,
}

/// Handshake response returned by worker.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HandshakeResponse {
    /// Protocol version acknowledged by worker.
    pub protocol_version: u32,
    /// Worker version string.
    pub worker_version: String,
    /// Handshake outcome.
    pub status: HandshakeStatus,
}

/// Declarative schema of an available capability exposed to the worker for planning.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CapabilitySchema {
    /// Canonical capability identifier (e.g. `sys.cpu.read`).
    pub name: String,
    /// Human-readable explanation of capability purpose.
    pub description: String,
    /// Schema of accepted parameters (provisional JSON schema structure).
    pub parameters_schema: serde_json::Value,
}

/// Daemon asks the worker to reason about a client request.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RequestTurn {
    /// Protocol version.
    pub protocol_version: u32,
    /// Unique identifier for this turn.
    pub turn_id: String,
    /// The user or calling application prompt.
    pub prompt: String,
    /// Capabilities available for the worker to propose during this turn.
    pub available_capabilities: Vec<CapabilitySchema>,
}

/// Worker proposes invoking a capability.
///
/// Note: This is an intent proposal only. The daemon deterministic policy engine
/// validates, authorizes, and executes the capability.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProposeCapability {
    /// Protocol version.
    pub protocol_version: u32,
    /// Associated turn identifier.
    pub turn_id: String,
    /// Unique correlation ID for this specific capability proposal.
    pub call_id: String,
    /// Canonical capability identifier (e.g. `sys.cpu.read`, `fs.file.read`).
    pub capability_name: String,
    /// Structured parameters for the capability.
    pub parameters: serde_json::Value,
}

/// Error returned when a capability fails execution or policy authorization.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CapabilityError {
    /// Machine-readable error code (e.g., `PERMISSION_DENIED`, `NOT_FOUND`, `INVALID_ARGUMENT`).
    pub code: String,
    /// Human-readable diagnostic description.
    pub message: String,
}

/// Execution outcome of a requested capability.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum CapabilityOutcome {
    /// The capability was authorized and executed successfully.
    Success {
        /// Observation telemetry or data payload.
        data: serde_json::Value,
    },
    /// The capability was denied by policy or failed during execution.
    Failure {
        /// Error details.
        error: CapabilityError,
    },
}

/// Daemon delivers the execution result or policy denial of a capability back to the worker.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CapabilityResult {
    /// Protocol version.
    pub protocol_version: u32,
    /// Associated turn identifier.
    pub turn_id: String,
    /// Correlated call identifier matching the `ProposeCapability` proposal.
    pub call_id: String,
    /// Deterministic execution outcome.
    pub outcome: CapabilityOutcome,
}

/// Status of turn completion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TurnStatus {
    /// The turn was synthesized successfully.
    Success,
    /// The turn completed with an error.
    Error,
}

/// Worker signals the turn is complete and provides final synthesized response.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CompleteTurn {
    /// Protocol version.
    pub protocol_version: u32,
    /// Associated turn identifier.
    pub turn_id: String,
    /// Turn status.
    pub status: TurnStatus,
    /// Final text response intended for the caller.
    pub response_text: String,
}

/// Errors detected during protocol message validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolValidationError {
    /// Protocol version mismatch.
    UnsupportedVersion(u32),
    /// Handshake rejected or reported incompatible version.
    HandshakeFailed(HandshakeStatus),
    /// Turn ID is missing or empty.
    EmptyTurnId,
    /// Call ID is missing or empty.
    EmptyCallId,
    /// Capability name is missing, empty, or contains invalid characters.
    InvalidCapabilityName(String),
}

impl std::fmt::Display for ProtocolValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedVersion(v) => write!(f, "unsupported protocol version: {v}"),
            Self::HandshakeFailed(s) => write!(f, "handshake failed with status: {s:?}"),
            Self::EmptyTurnId => write!(f, "turn_id cannot be empty"),
            Self::EmptyCallId => write!(f, "call_id cannot be empty"),
            Self::InvalidCapabilityName(name) => write!(f, "invalid capability name: '{name}'"),
        }
    }
}

impl std::error::Error for ProtocolValidationError {}

/// Checks if a capability name conforms to canonical naming conventions.
pub fn is_valid_capability_name(name: &str) -> bool {
    if name.is_empty() || name.len() > 128 {
        return false;
    }
    let segments: Vec<&str> = name.split('.').collect();
    if segments.len() < 2 {
        return false;
    }
    for seg in segments {
        if seg.is_empty() {
            return false;
        }
        if !seg.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_') {
            return false;
        }
    }
    true
}

impl Handshake {
    pub fn new(daemon_version: impl Into<String>) -> Self {
        Self {
            protocol_version: CURRENT_PROTOCOL_VERSION,
            daemon_version: daemon_version.into(),
        }
    }

    pub fn validate(&self) -> Result<(), ProtocolValidationError> {
        if self.protocol_version != CURRENT_PROTOCOL_VERSION {
            return Err(ProtocolValidationError::UnsupportedVersion(self.protocol_version));
        }
        Ok(())
    }
}

impl HandshakeResponse {
    pub fn new_ready(worker_version: impl Into<String>) -> Self {
        Self {
            protocol_version: CURRENT_PROTOCOL_VERSION,
            worker_version: worker_version.into(),
            status: HandshakeStatus::Ready,
        }
    }

    pub fn new_incompatible(worker_version: impl Into<String>) -> Self {
        Self {
            protocol_version: CURRENT_PROTOCOL_VERSION,
            worker_version: worker_version.into(),
            status: HandshakeStatus::IncompatibleVersion,
        }
    }

    pub fn validate(&self) -> Result<(), ProtocolValidationError> {
        if self.protocol_version != CURRENT_PROTOCOL_VERSION {
            return Err(ProtocolValidationError::UnsupportedVersion(self.protocol_version));
        }
        if self.status != HandshakeStatus::Ready {
            return Err(ProtocolValidationError::HandshakeFailed(self.status));
        }
        Ok(())
    }
}

impl ProposeCapability {
    /// Validates basic structural correctness of a capability proposal.
    pub fn validate(&self) -> Result<(), ProtocolValidationError> {
        if self.protocol_version != CURRENT_PROTOCOL_VERSION {
            return Err(ProtocolValidationError::UnsupportedVersion(self.protocol_version));
        }
        if self.turn_id.trim().is_empty() {
            return Err(ProtocolValidationError::EmptyTurnId);
        }
        if self.call_id.trim().is_empty() {
            return Err(ProtocolValidationError::EmptyCallId);
        }
        if !is_valid_capability_name(&self.capability_name) {
            return Err(ProtocolValidationError::InvalidCapabilityName(self.capability_name.clone()));
        }
        Ok(())
    }
}

impl CompleteTurn {
    /// Validates basic structural correctness of turn completion.
    pub fn validate(&self) -> Result<(), ProtocolValidationError> {
        if self.protocol_version != CURRENT_PROTOCOL_VERSION {
            return Err(ProtocolValidationError::UnsupportedVersion(self.protocol_version));
        }
        if self.turn_id.trim().is_empty() {
            return Err(ProtocolValidationError::EmptyTurnId);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_construct_and_validate_handshake() {
        let hs = Handshake::new("0.1.0");
        assert_eq!(hs.protocol_version, CURRENT_PROTOCOL_VERSION);
        assert!(hs.validate().is_ok());

        let bad_hs = Handshake {
            protocol_version: 99,
            daemon_version: "0.1.0".to_string(),
        };
        assert!(bad_hs.validate().is_err());
    }

    #[test]
    fn test_construct_and_validate_handshake_response() {
        let resp = HandshakeResponse::new_ready("0.1.0");
        assert_eq!(resp.protocol_version, CURRENT_PROTOCOL_VERSION);
        assert_eq!(resp.status, HandshakeStatus::Ready);
        assert!(resp.validate().is_ok());

        let incomp = HandshakeResponse::new_incompatible("0.1.0");
        match incomp.validate() {
            Err(ProtocolValidationError::HandshakeFailed(HandshakeStatus::IncompatibleVersion)) => (),
            other => panic!("Expected HandshakeFailed, got {other:?}"),
        }

        let bad_version = HandshakeResponse {
            protocol_version: 42,
            worker_version: "0.1.0".to_string(),
            status: HandshakeStatus::Ready,
        };
        assert!(bad_version.validate().is_err());
    }

    #[test]
    fn test_handshake_serialization_roundtrip() {
        let daemon_msg = DaemonToWorkerMessage::Handshake(Handshake::new("0.1.0"));
        let json = serde_json::to_string(&daemon_msg).expect("serialization failed");
        let decoded: DaemonToWorkerMessage = serde_json::from_str(&json).expect("deserialization failed");
        assert_eq!(daemon_msg, decoded);

        let worker_msg = WorkerToDaemonMessage::HandshakeResponse(HandshakeResponse::new_ready("0.1.0"));
        let worker_json = serde_json::to_string(&worker_msg).expect("serialization failed");
        let worker_decoded: WorkerToDaemonMessage = serde_json::from_str(&worker_json).expect("deserialization failed");
        assert_eq!(worker_msg, worker_decoded);
    }

    #[test]
    fn test_construct_request_turn() {
        let req = RequestTurn {
            protocol_version: CURRENT_PROTOCOL_VERSION,
            turn_id: "turn-1001".to_string(),
            prompt: "What is current CPU usage?".to_string(),
            available_capabilities: vec![CapabilitySchema {
                name: "sys.cpu.read".to_string(),
                description: "Reads host CPU telemetry".to_string(),
                parameters_schema: serde_json::json!({}),
            }],
        };
        assert_eq!(req.turn_id, "turn-1001");
        assert_eq!(req.available_capabilities.len(), 1);
    }

    #[test]
    fn test_construct_and_validate_propose_capability() {
        let prop = ProposeCapability {
            protocol_version: CURRENT_PROTOCOL_VERSION,
            turn_id: "turn-1001".to_string(),
            call_id: "call-001".to_string(),
            capability_name: "sys.cpu.read".to_string(),
            parameters: serde_json::json!({}),
        };
        assert!(prop.validate().is_ok());
    }

    #[test]
    fn test_reject_invalid_capability_names() {
        let invalid_names = vec![
            "",
            "cpu",                    // missing namespace
            "sys..cpu.read",          // empty segment
            "sys.CPU.read",           // uppercase
            "sys.cpu.read;rm -rf /",  // injection chars
            "sys/cpu/read",           // slash
            "sys cpu read",           // space
        ];

        for name in invalid_names {
            let prop = ProposeCapability {
                protocol_version: CURRENT_PROTOCOL_VERSION,
                turn_id: "turn-1".to_string(),
                call_id: "call-1".to_string(),
                capability_name: name.to_string(),
                parameters: serde_json::json!({}),
            };
            assert!(
                prop.validate().is_err(),
                "Expected capability name '{name}' to be rejected"
            );
        }
    }

    #[test]
    fn test_reject_unsupported_protocol_version() {
        let prop = ProposeCapability {
            protocol_version: 999,
            turn_id: "turn-1".to_string(),
            call_id: "call-1".to_string(),
            capability_name: "sys.cpu.read".to_string(),
            parameters: serde_json::json!({}),
        };
        match prop.validate() {
            Err(ProtocolValidationError::UnsupportedVersion(999)) => (),
            other => panic!("Expected UnsupportedVersion(999), got {other:?}"),
        }
    }

    #[test]
    fn test_construct_capability_outcome_success_and_failure() {
        let success = CapabilityResult {
            protocol_version: CURRENT_PROTOCOL_VERSION,
            turn_id: "turn-1".to_string(),
            call_id: "call-1".to_string(),
            outcome: CapabilityOutcome::Success {
                data: serde_json::json!({"user_percent": 12.5}),
            },
        };
        assert_eq!(success.call_id, "call-1");

        let failure = CapabilityResult {
            protocol_version: CURRENT_PROTOCOL_VERSION,
            turn_id: "turn-1".to_string(),
            call_id: "call-1".to_string(),
            outcome: CapabilityOutcome::Failure {
                error: CapabilityError {
                    code: "PERMISSION_DENIED".to_string(),
                    message: "Path escapes demo sandbox".to_string(),
                },
            },
        };
        if let CapabilityOutcome::Failure { error } = &failure.outcome {
            assert_eq!(error.code, "PERMISSION_DENIED");
        } else {
            panic!("Expected Failure outcome");
        }
    }

    #[test]
    fn test_serialization_roundtrip_provisional_json() {
        let worker_msg = WorkerToDaemonMessage::ProposeCapability(ProposeCapability {
            protocol_version: CURRENT_PROTOCOL_VERSION,
            turn_id: "turn-1".to_string(),
            call_id: "call-1".to_string(),
            capability_name: "fs.file.read".to_string(),
            parameters: serde_json::json!({"path": "sample.txt"}),
        });

        let json_str = serde_json::to_string(&worker_msg).expect("serialization failed");
        let deserialized: WorkerToDaemonMessage =
            serde_json::from_str(&json_str).expect("deserialization failed");
        assert_eq!(worker_msg, deserialized);
    }

    #[test]
    fn test_reject_unknown_message_types() {
        let invalid_json = r#"{"type": "arbitrary_grant", "role": "root"}"#;
        let result: Result<WorkerToDaemonMessage, _> = serde_json::from_str(invalid_json);
        assert!(result.is_err(), "Worker should not accept unknown message types");
    }

    #[test]
    fn test_worker_cannot_forge_daemon_messages() {
        let daemon_json = r#"{
            "type": "request_turn",
            "protocol_version": 1,
            "turn_id": "turn-1",
            "prompt": "test",
            "available_capabilities": []
        }"#;
        let result: Result<WorkerToDaemonMessage, _> = serde_json::from_str(daemon_json);
        assert!(
            result.is_err(),
            "DaemonToWorker message must not be accepted as WorkerToDaemon message"
        );
    }
}
