"""Aurora OS Milestone 7 Python Worker Adversarial Tests.

Validates worker process behavior against framing errors, malformed incoming daemon messages,
and connection drops pursuant to ADR-001, ADR-002, and Internal Worker Protocol v1.
"""

import json
import socket
import threading
import time
import unittest

from worker.main import MAX_IPC_FRAME_SIZE, run_worker


class TestWorkerAdversarial(unittest.TestCase):
    """Adversarial test suite for the Python AI worker stub."""

    def test_worker_terminates_and_closes_socket_on_daemon_framing_error(self):
        """PY-01: Verifies that an incoming oversized daemon frame (> 512 KiB) causes the worker

        to raise IpcFramingError, close the socket, and terminate with exit code 1.
        """
        import os
        import tempfile

        temp_sock_path = os.path.join(
            tempfile.gettempdir(),
            f"aurora-py-adv-{os.getpid()}-{time.time_ns()}.sock",
        )
        server_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server_sock.bind(temp_sock_path)
        server_sock.listen(1)

        def daemon_driver():
            conn, _ = server_sock.accept()
            f = conn.makefile("rwb")
            try:
                # 1. Send Handshake
                hs = {"type": "handshake", "protocol_version": 1, "daemon_version": "0.1.0"}
                f.write(json.dumps(hs).encode("utf-8") + b"\n")
                f.flush()

                # 2. Read HandshakeResponse
                resp_line = f.readline()
                resp = json.loads(resp_line.decode("utf-8").strip())
                assert resp["status"] == "ready"

                # 3. Transmit oversized frame exceeding 512 KiB
                f.write(b"a" * (MAX_IPC_FRAME_SIZE + 1) + b"\n")
                f.flush()
            except (BrokenPipeError, ConnectionResetError):
                pass
            finally:
                f.close()
                conn.close()
                server_sock.close()

        t = threading.Thread(target=daemon_driver)
        t.start()

        ret = run_worker(temp_sock_path)
        t.join()

        if os.path.exists(temp_sock_path):
            os.remove(temp_sock_path)

        # Worker must return 1 on fatal IPC framing error
        self.assertEqual(ret, 1)

    def test_worker_rejects_malformed_daemon_json_during_turn(self):
        """PY-02: Verifies that malformed JSON received from daemon is rejected safely

        without crashing the worker, and subsequent EOF cleanly terminates the loop.
        """
        import os
        import tempfile

        temp_sock_path = os.path.join(
            tempfile.gettempdir(),
            f"aurora-py-malformed-{os.getpid()}-{time.time_ns()}.sock",
        )
        server_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server_sock.bind(temp_sock_path)
        server_sock.listen(1)

        def daemon_driver():
            conn, _ = server_sock.accept()
            f = conn.makefile("rwb")
            hs = {"type": "handshake", "protocol_version": 1, "daemon_version": "0.1.0"}
            f.write(json.dumps(hs).encode("utf-8") + b"\n")
            f.flush()
            _ = f.readline() # handshake response

            # Send malformed JSON syntax
            f.write(b"{ malformed not json syntax ::: }\n")
            f.flush()

            # Close connection (simulating clean daemon teardown after error)
            time.sleep(0.05)
            f.close()
            conn.close()
            server_sock.close()

        t = threading.Thread(target=daemon_driver)
        t.start()

        ret = run_worker(temp_sock_path)
        t.join()

        if os.path.exists(temp_sock_path):
            os.remove(temp_sock_path)

        # Worker cleanly exits event loop upon connection close (return 0)
        self.assertEqual(ret, 0)


if __name__ == "__main__":
    unittest.main()
