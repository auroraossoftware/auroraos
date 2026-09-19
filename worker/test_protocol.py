"""Unit tests for Aurora OS Worker protocol structures (M1 & M2)."""

import unittest
from worker.protocol import (
    CURRENT_PROTOCOL_VERSION,
    CapabilityResult,
    CompleteTurn,
    Handshake,
    HandshakeResponse,
    ProposeCapability,
    ProtocolValidationError,
    RequestTurn,
)


class TestWorkerProtocol(unittest.TestCase):
    def test_construct_and_validate_handshake(self):
        hs = Handshake(protocol_version=CURRENT_PROTOCOL_VERSION, daemon_version="0.1.0")
        hs.validate()

        bad_hs = Handshake(protocol_version=99, daemon_version="0.1.0")
        with self.assertRaises(ProtocolValidationError):
            bad_hs.validate()

    def test_construct_and_validate_handshake_response(self):
        resp = HandshakeResponse(
            protocol_version=CURRENT_PROTOCOL_VERSION,
            worker_version="0.1.0",
            status="ready",
        )
        resp.validate()
        d = resp.to_dict()
        self.assertEqual(d["type"], "handshake_response")
        self.assertEqual(d["status"], "ready")

        bad_status = HandshakeResponse(
            protocol_version=CURRENT_PROTOCOL_VERSION,
            worker_version="0.1.0",
            status="invalid_status",
        )
        with self.assertRaises(ProtocolValidationError):
            bad_status.validate()

    def test_construct_and_validate_propose_capability(self):
        prop = ProposeCapability(
            protocol_version=CURRENT_PROTOCOL_VERSION,
            turn_id="turn-101",
            call_id="call-001",
            capability_name="sys.cpu.read",
            parameters={},
        )
        prop.validate()
        payload = prop.to_dict()
        self.assertEqual(payload["type"], "propose_capability")
        self.assertEqual(payload["capability_name"], "sys.cpu.read")

    def test_reject_invalid_capability_names(self):
        invalid_names = [
            "",
            "cpu",
            "sys..cpu.read",
            "sys.CPU.read",
            "sys.cpu.read;rm -rf /",
            "sys/cpu/read",
            "sys cpu read",
        ]
        for name in invalid_names:
            prop = ProposeCapability(
                protocol_version=CURRENT_PROTOCOL_VERSION,
                turn_id="turn-1",
                call_id="call-1",
                capability_name=name,
            )
            with self.assertRaises(ProtocolValidationError, msg=f"Should reject: {name}"):
                prop.validate()

    def test_reject_unsupported_version(self):
        prop = ProposeCapability(
            protocol_version=999,
            turn_id="turn-1",
            call_id="call-1",
            capability_name="sys.cpu.read",
        )
        with self.assertRaises(ProtocolValidationError):
            prop.validate()

    def test_construct_complete_turn(self):
        comp = CompleteTurn(
            protocol_version=CURRENT_PROTOCOL_VERSION,
            turn_id="turn-1",
            status="success",
            response_text="Observation complete.",
        )
        comp.validate()
        d = comp.to_dict()
        self.assertEqual(d["type"], "complete_turn")
        self.assertEqual(d["status"], "success")

    def test_parse_request_turn(self):
        data = {
            "type": "request_turn",
            "protocol_version": 1,
            "turn_id": "turn-42",
            "prompt": "inspect system",
            "available_capabilities": [
                {"name": "sys.cpu.read", "description": "CPU telemetry", "parameters_schema": {}}
            ],
        }
        req = RequestTurn.from_dict(data)
        self.assertEqual(req.turn_id, "turn-42")
        self.assertEqual(len(req.available_capabilities), 1)
        self.assertEqual(req.available_capabilities[0].name, "sys.cpu.read")


if __name__ == "__main__":
    unittest.main()
