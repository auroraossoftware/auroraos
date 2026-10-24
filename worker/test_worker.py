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

    def test_worker_handles_process_request_turn(self):
        """Worker should propose proc.list when prompted for processes and format the result."""
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(self.socket_path)
        server.listen(1)

        def mock_daemon():
            conn, _ = server.accept()
            conn_file = conn.makefile("rw", buffering=1)

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

            # 2. Read HandshakeResponse
            resp = json.loads(conn_file.readline().strip())
            self.assertEqual(resp.get("type"), "handshake_response")

            # 3. Send RequestTurn for processes
            conn_file.write(
                json.dumps({
                    "type": "request_turn",
                    "protocol_version": CURRENT_PROTOCOL_VERSION,
                    "turn_id": "turn-proc-01",
                    "prompt": "list processes with limit 5",
                    "available_capabilities": [],
                })
                + "\n"
            )
            conn_file.flush()

            # 4. Read ProposeCapability
            prop = json.loads(conn_file.readline().strip())
            self.assertEqual(prop.get("type"), "propose_capability")
            self.assertEqual(prop.get("capability_name"), "proc.list")
            self.assertEqual(prop.get("parameters", {}).get("limit"), 5)

            # 5. Return CapabilityResult with process array
            conn_file.write(
                json.dumps({
                    "type": "capability_result",
                    "protocol_version": CURRENT_PROTOCOL_VERSION,
                    "turn_id": "turn-proc-01",
                    "call_id": prop.get("call_id"),
                    "outcome": {
                        "status": "success",
                        "data": [
                            {"pid": 1, "name": "systemd", "memory_mb": 15},
                            {"pid": 2, "name": "kthreadd", "memory_mb": 0},
                        ],
                    },
                })
                + "\n"
            )
            conn_file.flush()

            # 6. Read CompleteTurn
            comp = json.loads(conn_file.readline().strip())
            self.assertEqual(comp.get("type"), "complete_turn")
            self.assertEqual(comp.get("status"), "success")
            self.assertIn("systemd", comp.get("response_text", ""))
            self.assertIn("Running processes", comp.get("response_text", ""))

            conn_file.close()
            conn.close()

        daemon_thread = threading.Thread(target=mock_daemon)
        daemon_thread.start()

        exit_code = run_worker(self.socket_path)
        self.assertEqual(exit_code, 0)
        daemon_thread.join()
        server.close()

    def test_process_query_matching_intent_boundaries(self):
        """Verifies process query matching distinguishes genuine queries from substrings/unrelated tasks."""
        from worker.main import is_process_query

        # 1. Genuine process-list queries
        self.assertTrue(is_process_query("list processes"))
        self.assertTrue(is_process_query("show processes"))
        self.assertTrue(is_process_query("show running tasks"))
        self.assertTrue(is_process_query("running processes"))
        self.assertTrue(is_process_query("ps"))
        self.assertTrue(is_process_query("top processes"))

        # 2. Prompts containing 'ps' as part of an unrelated word (must NOT trigger proc.list)
        self.assertFalse(is_process_query("what steps should we take?"))
        self.assertFalse(is_process_query("check the maps"))
        self.assertFalse(is_process_query("eclipse is running"))
        self.assertFalse(is_process_query("https://example.com"))
        self.assertFalse(is_process_query("oops something happened"))
        self.assertFalse(is_process_query("stops here"))

        # 3. Prompts mentioning 'tasks' in an unrelated context (must NOT trigger proc.list)
        self.assertFalse(is_process_query("complete this task tomorrow"))
        self.assertFalse(is_process_query("task list for sprint"))
        self.assertFalse(is_process_query("what tasks are on my calendar?"))
        self.assertFalse(is_process_query("multitasking is hard"))
        self.assertFalse(is_process_query("schedule a daily task"))

    def test_worker_does_not_propose_proc_list_for_unrelated_ps_or_task_words(self):
        """Verifies worker does not propose proc.list when 'ps' or 'task' appears in unrelated context."""
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(self.socket_path)
        server.listen(1)

        def mock_daemon():
            conn, _ = server.accept()
            conn_file = conn.makefile("rw", buffering=1)

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

            # 2. Read HandshakeResponse
            resp = json.loads(conn_file.readline().strip())
            self.assertEqual(resp.get("type"), "handshake_response")

            # 3. Send RequestTurn with 'steps' (contains 'ps') and 'task' in unrelated context
            conn_file.write(
                json.dumps({
                    "type": "request_turn",
                    "protocol_version": CURRENT_PROTOCOL_VERSION,
                    "turn_id": "turn-unrelated-01",
                    "prompt": "what steps are required for this task?",
                    "available_capabilities": [],
                })
                + "\n"
            )
            conn_file.flush()

            # 4. Read ProposeCapability: MUST NOT be proc.list (defaults to sys.cpu.read)
            prop = json.loads(conn_file.readline().strip())
            self.assertEqual(prop.get("type"), "propose_capability")
            self.assertNotEqual(
                prop.get("capability_name"),
                "proc.list",
                "Unrelated prompt containing 'steps' or 'task' incorrectly triggered proc.list!"
            )
            self.assertEqual(prop.get("capability_name"), "sys.cpu.read")

            # 5. Return CapabilityResult
            conn_file.write(
                json.dumps({
                    "type": "capability_result",
                    "protocol_version": CURRENT_PROTOCOL_VERSION,
                    "turn_id": "turn-unrelated-01",
                    "call_id": prop.get("call_id"),
                    "outcome": {
                        "status": "success",
                        "data": {"user_percent": 10.0, "system_percent": 5.0, "idle_percent": 85.0},
                    },
                })
                + "\n"
            )
            conn_file.flush()

            # 6. Read CompleteTurn
            comp = json.loads(conn_file.readline().strip())
            self.assertEqual(comp.get("type"), "complete_turn")
            self.assertEqual(comp.get("status"), "success")

            conn_file.close()
            conn.close()

        daemon_thread = threading.Thread(target=mock_daemon)
        daemon_thread.start()

        exit_code = run_worker(self.socket_path)
        self.assertEqual(exit_code, 0)
        daemon_thread.join()
        server.close()

    def test_bounded_socket_file_framing_limits(self):
        """Verifies Python BoundedSocketFile enforces 512 KiB byte limit and handles edge cases."""
        from worker.main import BoundedSocketFile, IpcFramingError, MAX_IPC_FRAME_SIZE
        import io

        # 1. Exact boundary: 524,288 bytes ending with \n
        payload = b"x" * (MAX_IPC_FRAME_SIZE - 1) + b"\n"
        s1, s2 = socket.socketpair()
        # Use underlying makefile directly or mock
        bf = BoundedSocketFile(s1)
        # Mock _r with BytesIO to avoid socket buffer deadlock
        bf._r = io.BytesIO(payload)
        line = bf.readline()
        self.assertEqual(len(line.encode("utf-8")), MAX_IPC_FRAME_SIZE)
        bf.close()
        s2.close()

        # 2. Oversized: 524,289 bytes
        oversized = b"x" * MAX_IPC_FRAME_SIZE + b"\n"
        s1, s2 = socket.socketpair()
        bf = BoundedSocketFile(s1)
        bf._r = io.BytesIO(oversized)
        with self.assertRaises(IpcFramingError):
            bf.readline()
        bf.close()
        s2.close()

        # 3. Unterminated reaching EOF without \n
        unterminated = b"unterminated frame without newline"
        s1, s2 = socket.socketpair()
        bf = BoundedSocketFile(s1)
        bf._r = io.BytesIO(unterminated)
        with self.assertRaises(IpcFramingError):
            bf.readline()
        bf.close()
        s2.close()

    def test_bounded_socket_file_measures_multibyte_utf8_in_bytes(self):
        """Verifies that BoundedSocketFile enforces limits in bytes, not Unicode characters."""
        from worker.main import BoundedSocketFile, IpcFramingError, MAX_IPC_FRAME_SIZE
        import io

        # '€' is 3 bytes in UTF-8. 200,000 characters is 600,000 bytes.
        # Character count (200,000) < 524,288, but byte count (600,001 with \n) > 524,288.
        euro_char = "€"
        self.assertEqual(len(euro_char.encode("utf-8")), 3)

        oversized_text = (euro_char * 200_000) + "\n"
        oversized_bytes = oversized_text.encode("utf-8")
        self.assertEqual(len(oversized_bytes), 600_001)

        s1, s2 = socket.socketpair()
        bf = BoundedSocketFile(s1)
        bf._r = io.BytesIO(oversized_bytes)
        with self.assertRaises(IpcFramingError):
            bf.readline()
        bf.close()
        s2.close()

        # Within limit: 100,000 euro characters = 300,000 bytes + 1 '\n' = 300,001 bytes <= 524,288
        valid_text = (euro_char * 100_000) + "\n"
        valid_bytes = valid_text.encode("utf-8")
        s1, s2 = socket.socketpair()
        bf = BoundedSocketFile(s1)
        bf._r = io.BytesIO(valid_bytes)
        line = bf.readline()
        self.assertEqual(len(line.encode("utf-8")), 300_001)
        bf.close()
        s2.close()

    def test_bounded_socket_file_worst_case_control_characters_roundtrip(self):
        """Verifies that a 64 KiB file of control characters expanding to ~393 KiB in JSON fits in 512 KiB."""
        from worker.main import BoundedSocketFile, MAX_IPC_FRAME_SIZE
        import io

        # 64 KiB of '\x01' expands to 65,536 * 6 = 393,216 bytes in JSON
        raw_control = "\x01" * 65536
        daemon_msg = {
            "type": "capability_result",
            "protocol_version": 1,
            "turn_id": "turn-worst-case-test",
            "call_id": "call-fs-01",
            "status": "success",
            "data": {
                "content": raw_control,
                "size_bytes": 65536,
            },
        }
        serialized = (json.dumps(daemon_msg) + "\n").encode("utf-8")

        # Confirm serialized JSON size is ~393 KiB and strictly within 512 KiB limit
        self.assertGreater(len(serialized), 390_000)
        self.assertLessEqual(len(serialized), MAX_IPC_FRAME_SIZE)

        s1, s2 = socket.socketpair()
        bf = BoundedSocketFile(s1)
        bf._r = io.BytesIO(serialized)
        line = bf.readline()
        parsed = json.loads(line.strip())
        self.assertEqual(parsed.get("type"), "capability_result")
        self.assertEqual(len(parsed["data"]["content"]), 65536)
        bf.close()
        s2.close()

    def test_worker_terminates_and_closes_socket_on_framing_error(self):
        """Verifies that run_worker exits with code 1 and closes the socket when daemon sends oversized frame."""
        from worker.main import run_worker, MAX_IPC_FRAME_SIZE

        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(self.socket_path)
        server.listen(1)

    def test_worker_terminates_and_closes_socket_on_framing_error(self):
        """Verifies that run_worker exits with code 1 and closes the socket on framing error."""
        from worker.main import run_worker, CURRENT_PROTOCOL_VERSION

        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(self.socket_path)
        server.listen(1)

        def mock_daemon():
            conn, _ = server.accept()
            conn_file = conn.makefile("rw", buffering=1, encoding="utf-8")

            # 1. Send Handshake
            conn_file.write(
                json.dumps({
                    "type": "handshake",
                    "protocol_version": CURRENT_PROTOCOL_VERSION,
                    "supported_capabilities": [],
                })
                + "\n"
            )
            conn_file.flush()

            # 2. Read HandshakeResponse
            line = conn_file.readline()
            hs = json.loads(line.strip())
            self.assertEqual(hs.get("type"), "handshake_response")

            # 3. Send unterminated frame reaching EOF without newline
            conn_file.write("unterminated_frame_at_eof")
            conn_file.flush()
            conn_file.close()
            conn.close()

        daemon_thread = threading.Thread(target=mock_daemon)
        daemon_thread.start()

        exit_code = run_worker(self.socket_path)
        # Framing error must result in exit code 1
        self.assertEqual(exit_code, 1)

        daemon_thread.join()
        server.close()

    def test_worker_proposes_fs_file_read_and_synthesizes_content(self):
        """Verifies worker proposes fs.file.read for file queries and formats output."""
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(self.socket_path)
        server.listen(1)

        def mock_daemon():
            conn, _ = server.accept()
            conn_file = conn.makefile("rwb", buffering=0)

            # Handshake
            conn_file.write(
                json.dumps({
                    "type": "handshake",
                    "protocol_version": CURRENT_PROTOCOL_VERSION,
                    "daemon_version": "0.1.0",
                }).encode("utf-8") + b"\n"
            )

            # Read HandshakeResponse
            resp = json.loads(conn_file.readline().decode("utf-8").strip())
            self.assertEqual(resp.get("type"), "handshake_response")

            # Send RequestTurn: read notes.txt
            conn_file.write(
                json.dumps({
                    "type": "request_turn",
                    "protocol_version": CURRENT_PROTOCOL_VERSION,
                    "turn_id": "turn-fs-01",
                    "prompt": "read notes.txt",
                    "available_capabilities": [],
                }).encode("utf-8") + b"\n"
            )

            # Read ProposeCapability
            prop = json.loads(conn_file.readline().decode("utf-8").strip())
            self.assertEqual(prop.get("type"), "propose_capability")
            self.assertEqual(prop.get("capability_name"), "fs.file.read")
            self.assertEqual(prop.get("parameters"), {"path": "notes.txt"})

            # Send CapabilityResult
            conn_file.write(
                json.dumps({
                    "type": "capability_result",
                    "protocol_version": CURRENT_PROTOCOL_VERSION,
                    "turn_id": "turn-fs-01",
                    "call_id": prop.get("call_id"),
                    "outcome": {
                        "status": "success",
                        "data": {"content": "Hello Aurora OS sandboxed file", "size_bytes": 31},
                    },
                }).encode("utf-8") + b"\n"
            )

            # Read CompleteTurn
            comp = json.loads(conn_file.readline().decode("utf-8").strip())
            self.assertEqual(comp.get("type"), "complete_turn")
            self.assertEqual(comp.get("status"), "success")
            self.assertIn("File content (31 bytes): Hello Aurora OS", comp.get("response_text", ""))

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

