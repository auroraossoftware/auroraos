"""Aurora OS Internal Daemon <-> Worker Protocol (Python v1).

This module defines Python structures and serialization contracts matching
crates/aurora-protocol for the isolated AI worker process.

Security Invariant:
All messages are typed and validated. The worker cannot authorize itself,
modify policy, or execute capabilities directly.
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

CURRENT_PROTOCOL_VERSION = 1

CAPABILITY_NAME_PATTERN = re.compile(r"^[a-z0-9_]+(\.[a-z0-9_]+)+$")


class ProtocolValidationError(Exception):
    """Raised when a protocol message fails structural validation."""
    pass


@dataclass
class Handshake:
    protocol_version: int
    daemon_version: str

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Handshake:
        return cls(
            protocol_version=data.get("protocol_version", 0),
            daemon_version=data.get("daemon_version", ""),
        )

    def validate(self) -> None:
        if self.protocol_version != CURRENT_PROTOCOL_VERSION:
            raise ProtocolValidationError(f"Unsupported protocol version: {self.protocol_version}")


@dataclass
class HandshakeResponse:
    protocol_version: int
    worker_version: str
    status: str  # "ready" or "incompatible_version"

    def validate(self) -> None:
        if self.protocol_version != CURRENT_PROTOCOL_VERSION:
            raise ProtocolValidationError(f"Unsupported protocol version: {self.protocol_version}")
        if self.status not in ("ready", "incompatible_version"):
            raise ProtocolValidationError(f"Invalid handshake status: {self.status}")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": "handshake_response",
            "protocol_version": self.protocol_version,
            "worker_version": self.worker_version,
            "status": self.status,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> HandshakeResponse:
        return cls(
            protocol_version=data.get("protocol_version", 0),
            worker_version=data.get("worker_version", ""),
            status=data.get("status", "unknown"),
        )


@dataclass
class CapabilitySchema:
    name: str
    description: str
    parameters_schema: Dict[str, Any] = field(default_factory=dict)


@dataclass
class RequestTurn:
    protocol_version: int
    turn_id: str
    prompt: str
    available_capabilities: List[CapabilitySchema] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> RequestTurn:
        version = data.get("protocol_version", CURRENT_PROTOCOL_VERSION)
        caps = [
            CapabilitySchema(
                name=c["name"],
                description=c["description"],
                parameters_schema=c.get("parameters_schema", {}),
            )
            for c in data.get("available_capabilities", [])
        ]
        return cls(
            protocol_version=version,
            turn_id=data["turn_id"],
            prompt=data["prompt"],
            available_capabilities=caps,
        )


@dataclass
class ProposeCapability:
    protocol_version: int
    turn_id: str
    call_id: str
    capability_name: str
    parameters: Dict[str, Any] = field(default_factory=dict)

    def validate(self) -> None:
        if self.protocol_version != CURRENT_PROTOCOL_VERSION:
            raise ProtocolValidationError(f"Unsupported protocol version: {self.protocol_version}")
        if not self.turn_id or not self.turn_id.strip():
            raise ProtocolValidationError("turn_id cannot be empty")
        if not self.call_id or not self.call_id.strip():
            raise ProtocolValidationError("call_id cannot be empty")
        if not self.capability_name or not CAPABILITY_NAME_PATTERN.match(self.capability_name):
            raise ProtocolValidationError(f"Invalid capability name: '{self.capability_name}'")

    def to_dict(self) -> Dict[str, Any]:
        self.validate()
        return {
            "type": "propose_capability",
            "protocol_version": self.protocol_version,
            "turn_id": self.turn_id,
            "call_id": self.call_id,
            "capability_name": self.capability_name,
            "parameters": self.parameters,
        }


@dataclass
class CapabilityError:
    code: str
    message: str


@dataclass
class CapabilityResult:
    protocol_version: int
    turn_id: str
    call_id: str
    status: str  # "success" or "failure"
    data: Optional[Dict[str, Any]] = None
    error: Optional[CapabilityError] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> CapabilityResult:
        outcome = data.get("outcome", {})
        status = outcome.get("status", "unknown")
        err = None
        result_data = None
        if status == "success":
            result_data = outcome.get("data")
        elif status == "failure":
            err_data = outcome.get("error", {})
            err = CapabilityError(code=err_data.get("code", "UNKNOWN"), message=err_data.get("message", ""))

        return cls(
            protocol_version=data.get("protocol_version", CURRENT_PROTOCOL_VERSION),
            turn_id=data["turn_id"],
            call_id=data["call_id"],
            status=status,
            data=result_data,
            error=err,
        )


@dataclass
class CompleteTurn:
    protocol_version: int
    turn_id: str
    status: str  # "success" or "error"
    response_text: str

    def validate(self) -> None:
        if self.protocol_version != CURRENT_PROTOCOL_VERSION:
            raise ProtocolValidationError(f"Unsupported protocol version: {self.protocol_version}")
        if not self.turn_id or not self.turn_id.strip():
            raise ProtocolValidationError("turn_id cannot be empty")
        if self.status not in ("success", "error"):
            raise ProtocolValidationError(f"Invalid turn status: {self.status}")

    def to_dict(self) -> Dict[str, Any]:
        self.validate()
        return {
            "type": "complete_turn",
            "protocol_version": self.protocol_version,
            "turn_id": self.turn_id,
            "status": self.status,
            "response_text": self.response_text,
        }
