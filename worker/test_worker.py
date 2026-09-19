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


if __name__ == "__main__":
    unittest.main()
