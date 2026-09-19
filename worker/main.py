"""Aurora OS AI Worker Stub - Milestone 2 Lifecycle & IPC.

Pursuant to ADR-001 and ADR-002, the AI worker process is an isolated, unprivileged
runtime dedicated to model reasoning and intent proposal generation.

Milestone 2 establishes:
1. Connecting to the private Unix domain socket provided by the daemon.
2. Performing the initial protocol handshake.
3. Remaining in a ready loop until daemon termination or socket closure.
"""

import argparse
import json
import os
import signal
import socket
import sys
from typing import Optional

from worker.protocol import (
    CURRENT_PROTOCOL_VERSION,
    Handshake,
    HandshakeResponse,
)

WORKER_VERSION = "0.1.0"


def run_worker(
    socket_path: str,
    simulate_incompatible_version: bool = False,
) -> int:
    """Connect to the daemon's private Unix domain socket and run the worker event loop."""
    if not os.path.exists(socket_path):
        print(f"[worker] Error: socket path does not exist: {socket_path}", file=sys.stderr)
        return 1

    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock.connect(socket_path)
    except Exception as e:
        print(f"[worker] Failed to connect to socket {socket_path}: {e}", file=sys.stderr)
        return 1

    sock_file = sock.makefile("rw", buffering=1, encoding="utf-8")

    try:
        # Step 1: Await Handshake from daemon
        raw_line = sock_file.readline()
        if not raw_line:
            print("[worker] Daemon closed connection before handshake", file=sys.stderr)
            return 1

        try:
            msg_data = json.loads(raw_line.strip())
        except json.JSONDecodeError as e:
            print(f"[worker] Malformed JSON received from daemon: {e}", file=sys.stderr)
            return 1

        if msg_data.get("type") != "handshake":
            print(f"[worker] Unexpected initial message: {msg_data.get('type')}", file=sys.stderr)
            return 1

        daemon_version = msg_data.get("protocol_version", 0)

        # Step 2: Validate protocol version
        if simulate_incompatible_version or daemon_version != CURRENT_PROTOCOL_VERSION:
            print(
                f"[worker] Incompatible protocol version: expected {CURRENT_PROTOCOL_VERSION}, got {daemon_version}",
                file=sys.stderr,
            )
            resp = HandshakeResponse(
                protocol_version=CURRENT_PROTOCOL_VERSION,
                worker_version=WORKER_VERSION,
                status="incompatible_version",
            )
            sock_file.write(json.dumps(resp.to_dict()) + "\n")
            sock_file.flush()
            return 2

        # Step 3: Respond Ready
        resp = HandshakeResponse(
            protocol_version=CURRENT_PROTOCOL_VERSION,
            worker_version=WORKER_VERSION,
            status="ready",
        )
        sock_file.write(json.dumps(resp.to_dict()) + "\n")
        sock_file.flush()

        # Step 4: Event loop - wait for daemon instructions or EOF
        # In M2, no capabilities or turns are executed yet; we simply remain alive
        # until the socket is closed or the process receives a termination signal.
        while True:
            line = sock_file.readline()
            if not line:
                # Daemon closed socket (normal shutdown)
                break

        return 0

    except (BrokenPipeError, ConnectionResetError):
        # Daemon disconnected
        return 0
    finally:
        try:
            sock_file.close()
            sock.close()
        except Exception:
            pass


def main(args: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="aurora-worker",
        description="Aurora OS AI Worker Stub (M2 Lifecycle)",
    )
    parser.add_argument(
        "--socket-path",
        "-s",
        type=str,
        required=False,
        help="Path to the private Unix domain socket hosted by aurora-ai daemon",
    )
    parser.add_argument(
        "--simulate-incompatible-version",
        action="store_true",
        help="Simulate protocol version incompatibility for testing",
    )

    parsed = parser.parse_args(args if args is not None else sys.argv[1:])

    if not parsed.socket_path:
        print(f"aurora-ai worker stub skeleton (M2)")
        print(f"Protocol version: {CURRENT_PROTOCOL_VERSION}")
        return 0

    return run_worker(
        parsed.socket_path,
        simulate_incompatible_version=parsed.simulate_incompatible_version,
    )


if __name__ == "__main__":
    sys.exit(main())
