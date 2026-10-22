"""Integration tests for worker socket connection and handshake lifecycle."""

import json
import os
import socket
import tempfile
import threading
import time
import unittest

from worker.main import run_worker
from worker.protocol import CURRENT_PROTOCOL_VERSION


class TestWorkerLifecycle(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.socket_path = os.path.join(self.tmp_dir.name, "test_worker.sock")

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_worker_handshake_success(self):
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(self.socket_path)
        server.listen(1)

        def mock_daemon():
            conn, _ = server.accept()
            conn_file = conn.makefile("rw", buffering=1, encoding="utf-8")
            # Send handshake
            conn_file.write(
                json.dumps({
                    "type": "handshake",
                    "protocol_version": CURRENT_PROTOCOL_VERSION,
                    "daemon_version": "0.1.0",
                })
                + "\n"
            )
            conn_file.flush()

            # Read response
            resp_line = conn_file.readline()
            resp = json.loads(resp_line.strip())
            self.assertEqual(resp.get("type"), "handshake_response")
            self.assertEqual(resp.get("status"), "ready")
            self.assertEqual(resp.get("protocol_version"), CURRENT_PROTOCOL_VERSION)

            # Close connection to trigger clean worker exit
            conn_file.close()
            conn.close()

        daemon_thread = threading.Thread(target=mock_daemon)
        daemon_thread.start()

        # Run worker
        exit_code = run_worker(self.socket_path)
        self.assertEqual(exit_code, 0)
        daemon_thread.join()
        server.close()

    def test_worker_handshake_incompatible_version(self):
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(self.socket_path)
        server.listen(1)

        def mock_daemon():
            conn, _ = server.accept()
            conn_file = conn.makefile("rw", buffering=1, encoding="utf-8")
            # Send handshake with incompatible version 999
            conn_file.write(
                json.dumps({
                    "type": "handshake",
                    "protocol_version": 999,
                    "daemon_version": "0.1.0",
                })
                + "\n"
            )
            conn_file.flush()

            # Read response
            resp_line = conn_file.readline()
            resp = json.loads(resp_line.strip())
            self.assertEqual(resp.get("type"), "handshake_response")
            self.assertEqual(resp.get("status"), "incompatible_version")

            conn_file.close()
            conn.close()

        daemon_thread = threading.Thread(target=mock_daemon)
        daemon_thread.start()

        # Run worker; should exit with code 2 for version mismatch
        exit_code = run_worker(self.socket_path)
        self.assertEqual(exit_code, 2)
        daemon_thread.join()
        server.close()

    def test_worker_execute_authorized_turn_flow(self):
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(self.socket_path)
        server.listen(1)

        def mock_daemon():
            conn, _ = server.accept()
            conn_file = conn.makefile("rw", buffering=1, encoding="utf-8")

            # 1. Handshake
            conn_file.write(
                json.dumps({
                    "type": "handshake",
                    "protocol_version": CURRENT_PROTOCOL_VERSION,
                    "daemon_version": "0.1.0",
                })
                + "\n"
            )
            conn_file.flush()
            hs_resp = json.loads(conn_file.readline().strip())
            self.assertEqual(hs_resp["status"], "ready")

            # 2. RequestTurn
            conn_file.write(
                json.dumps({
                    "type": "request_turn",
                    "protocol_version": CURRENT_PROTOCOL_VERSION,
                    "turn_id": "turn-test-01",
                    "prompt": "check cpu usage",
                    "available_capabilities": [
                        {
                            "name": "sys.cpu.read",
                            "description": "Reads CPU telemetry",
                            "parameters_schema": {},
                        }
                    ],
                })
                + "\n"
            )
            conn_file.flush()

            # 3. Read ProposeCapability
            prop = json.loads(conn_file.readline().strip())
            self.assertEqual(prop.get("type"), "propose_capability")
            self.assertEqual(prop.get("turn_id"), "turn-test-01")
            self.assertEqual(prop.get("capability_name"), "sys.cpu.read")

            # 4. Return CapabilityResult (Success)
            conn_file.write(
                json.dumps({
                    "type": "capability_result",
                    "protocol_version": CURRENT_PROTOCOL_VERSION,
                    "turn_id": "turn-test-01",
                    "call_id": prop.get("call_id"),
                    "outcome": {
                        "status": "success",
                        "data": {
                            "user_percent": 14.2,
                            "system_percent": 5.1,
                            "idle_percent": 80.7,
                        },
                    },
                })
                + "\n"
            )
            conn_file.flush()

            # 5. Read CompleteTurn
            comp = json.loads(conn_file.readline().strip())
            self.assertEqual(comp.get("type"), "complete_turn")
            self.assertEqual(comp.get("turn_id"), "turn-test-01")
            self.assertEqual(comp.get("status"), "success")
            self.assertIn("14.2%", comp.get("response_text", ""))

            # Clean shutdown
            conn_file.close()
            conn.close()

        daemon_thread = threading.Thread(target=mock_daemon)
        daemon_thread.start()

        exit_code = run_worker(self.socket_path)
        self.assertEqual(exit_code, 0)
        daemon_thread.join()
        server.close()

    def test_worker_execute_denied_turn_flow(self):
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(self.socket_path)
        server.listen(1)

        def mock_daemon():
            conn, _ = server.accept()
            conn_file = conn.makefile("rw", buffering=1, encoding="utf-8")

            # Handshake
            conn_file.write(
                json.dumps({
                    "type": "handshake",
                    "protocol_version": CURRENT_PROTOCOL_VERSION,
                    "daemon_version": "0.1.0",
                })
                + "\n"
            )
            conn_file.flush()
            conn_file.readline()

            # RequestTurn
            conn_file.write(
                json.dumps({
                    "type": "request_turn",
                    "protocol_version": CURRENT_PROTOCOL_VERSION,
                    "turn_id": "turn-denied-01",
                    "prompt": "check cpu",
                    "available_capabilities": [],
                })
                + "\n"
            )
            conn_file.flush()

            # Read proposal
            prop = json.loads(conn_file.readline().strip())
            self.assertEqual(prop.get("capability_name"), "sys.cpu.read")

            # Send Failure CapabilityResult
            conn_file.write(
                json.dumps({
                    "type": "capability_result",
                    "protocol_version": CURRENT_PROTOCOL_VERSION,
                    "turn_id": "turn-denied-01",
                    "call_id": prop.get("call_id"),
                    "outcome": {
                        "status": "failure",
                        "error": {
                            "code": "PERMISSION_DENIED",
                            "message": "Caller unauthorized",
                        },
                    },
                })
                + "\n"
            )
            conn_file.flush()

            # Read CompleteTurn (status error)
            comp = json.loads(conn_file.readline().strip())
            self.assertEqual(comp.get("type"), "complete_turn")
            self.assertEqual(comp.get("status"), "error")
            self.assertIn("PERMISSION_DENIED", comp.get("response_text", ""))

            conn_file.close()
            conn.close()

        daemon_thread = threading.Thread(target=mock_daemon)
        daemon_thread.start()

        exit_code = run_worker(self.socket_path)
        self.assertEqual(exit_code, 0)
        daemon_thread.join()
        server.close()

    def test_worker_multi_turn_flow(self):
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(self.socket_path)
        server.listen(1)

        def mock_daemon():
            conn, _ = server.accept()
            conn_file = conn.makefile("rw", buffering=1, encoding="utf-8")

            # Handshake
            conn_file.write(
                json.dumps({
                    "type": "handshake",
                    "protocol_version": CURRENT_PROTOCOL_VERSION,
                    "daemon_version": "0.1.0",
                })
                + "\n"
            )
            conn_file.flush()
            conn_file.readline()

            # Turn 1
            conn_file.write(
                json.dumps({
                    "type": "request_turn",
                    "protocol_version": CURRENT_PROTOCOL_VERSION,
                    "turn_id": "turn-1",
                    "prompt": "cpu",
                    "available_capabilities": [],
                })
                + "\n"
            )
            conn_file.flush()
            prop1 = json.loads(conn_file.readline().strip())
            conn_file.write(
                json.dumps({
                    "type": "capability_result",
                    "protocol_version": CURRENT_PROTOCOL_VERSION,
                    "turn_id": "turn-1",
                    "call_id": prop1.get("call_id"),
                    "outcome": {
                        "status": "success",
                        "data": {"user_percent": 10.0, "system_percent": 5.0, "idle_percent": 85.0},
                    },
                })
                + "\n"
            )
            conn_file.flush()
            comp1 = json.loads(conn_file.readline().strip())
            self.assertEqual(comp1["status"], "success")

            # Turn 2: Direct noop
            conn_file.write(
                json.dumps({
                    "type": "request_turn",
                    "protocol_version": CURRENT_PROTOCOL_VERSION,
                    "turn_id": "turn-2",
                    "prompt": "noop direct test",
                    "available_capabilities": [],
                })
                + "\n"
            )
            conn_file.flush()
            comp2 = json.loads(conn_file.readline().strip())
            self.assertEqual(comp2["status"], "success")
            self.assertIn("Direct worker response", comp2["response_text"])

            conn_file.close()
            conn.close()

        daemon_thread = threading.Thread(target=mock_daemon)
        daemon_thread.start()

        exit_code = run_worker(self.socket_path)
        self.assertEqual(exit_code, 0)
        daemon_thread.join()
        server.close()

    def test_worker_handles_memory_request_turn(self):
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(self.socket_path)
        server.listen(1)

        def mock_daemon():
            conn, _ = server.accept()
            conn_file = conn.makefile("rw", buffering=1, encoding="utf-8")

            # 1. Handshake
            conn_file.write(
                json.dumps({
                    "type": "handshake",
                    "protocol_version": CURRENT_PROTOCOL_VERSION,
                    "daemon_version": "0.1.0",
                })
                + "\n"
            )
            conn_file.flush()
            conn_file.readline()

            # 2. RequestTurn with "check memory"
            conn_file.write(
                json.dumps({
                    "type": "request_turn",
                    "protocol_version": CURRENT_PROTOCOL_VERSION,
                    "turn_id": "turn-mem-01",
                    "prompt": "check memory",
                    "available_capabilities": [
                        {
                            "name": "sys.memory.read",
                            "description": "Reads host memory telemetry metrics",
                            "parameters_schema": {},
                        }
                    ],
                })
                + "\n"
            )
            conn_file.flush()

            # 3. Read ProposeCapability
            prop = json.loads(conn_file.readline().strip())
            self.assertEqual(prop.get("type"), "propose_capability")
            self.assertEqual(prop.get("capability_name"), "sys.memory.read")

            # 4. Return CapabilityResult
            conn_file.write(
                json.dumps({
                    "type": "capability_result",
                    "protocol_version": CURRENT_PROTOCOL_VERSION,
                    "turn_id": "turn-mem-01",
                    "call_id": prop.get("call_id"),
                    "outcome": {
                        "status": "success",
                        "data": {
                            "total_mb": 16000,
                            "used_mb": 4000,
                            "free_mb": 2000,
                            "available_mb": 12000,
                        },
                    },
                })
                + "\n"
            )
            conn_file.flush()

            # 5. Read CompleteTurn
            comp = json.loads(conn_file.readline().strip())
            self.assertEqual(comp.get("type"), "complete_turn")
            self.assertEqual(comp.get("status"), "success")
            self.assertIn("16000MB", comp.get("response_text", ""))
            self.assertIn("12000MB", comp.get("response_text", ""))

            conn_file.close()
            conn.close()

        daemon_thread = threading.Thread(target=mock_daemon)
        daemon_thread.start()

        exit_code = run_worker(self.socket_path)
        self.assertEqual(exit_code, 0)
        daemon_thread.join()
        server.close()


if __name__ == "__main__":
    unittest.main()

