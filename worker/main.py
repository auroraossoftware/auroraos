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
import re
import signal
import socket
import sys
from typing import Optional

from worker.protocol import (
    CURRENT_PROTOCOL_VERSION,
    CapabilityResult,
    CompleteTurn,
    Handshake,
    HandshakeResponse,
    ProposeCapability,
    RequestTurn,
)

WORKER_VERSION = "0.1.0"

PROCESS_QUERY_PATTERNS = [
    re.compile(r"\b(?:list|show|get|display|inspect)\s+(?:running\s+)?processes\b", re.IGNORECASE),
    re.compile(r"\b(?:list|show|get|display)\s+running\s+tasks\b", re.IGNORECASE),
    re.compile(r"\brunning\s+processes\b", re.IGNORECASE),
    re.compile(r"\brunning\s+tasks\b", re.IGNORECASE),
    re.compile(r"\b(?:show\s+)?procs\b", re.IGNORECASE),
    re.compile(r"\bps\b", re.IGNORECASE),
    re.compile(r"\btop\s+processes\b", re.IGNORECASE),
]


def is_process_query(prompt: str) -> bool:
    """Returns True only if prompt is an intended process listing request.

    Uses strict regex word-boundary and phrase patterns to avoid false matches
    on unrelated words containing 'ps' (e.g. 'steps', 'maps') or mentions of 'tasks'
    in unrelated contexts (e.g. 'complete this task', 'task list for tomorrow').
    """
    return any(pat.search(prompt) for pat in PROCESS_QUERY_PATTERNS)


def handle_request_turn(sock_file, req_data: dict) -> None:
    """Handles an incoming RequestTurn message deterministically for M5."""
    turn_id = req_data.get("turn_id", "")
    prompt = req_data.get("prompt", "")

    # Test seams for negative testing
    if "simulate_crash" in prompt:
        # Simulate worker crash / abnormal exit
        sys.exit(137)

    if "invalid_proposal_name" in prompt:
        # Propose capability with invalid name syntax
        prop_payload = {
            "type": "propose_capability",
            "protocol_version": CURRENT_PROTOCOL_VERSION,
            "turn_id": turn_id,
            "call_id": "call-err-01",
            "capability_name": "sys..cpu.read",
            "parameters": {},
        }
        sock_file.write(json.dumps(prop_payload) + "\n")
        sock_file.flush()
    elif "invalid_params" in prompt:
        cap_name = "sys.memory.read" if "memory" in prompt else "sys.cpu.read"
        prop = ProposeCapability(
            protocol_version=CURRENT_PROTOCOL_VERSION,
            turn_id=turn_id,
            call_id="call-err-02",
            capability_name=cap_name,
            parameters={"unexpected_extra": 123},
        )
        sock_file.write(json.dumps(prop.to_dict()) + "\n")
        sock_file.flush()
    elif "unknown_capability" in prompt:
        # Propose an unknown capability
        prop = ProposeCapability(
            protocol_version=CURRENT_PROTOCOL_VERSION,
            turn_id=turn_id,
            call_id="call-err-03",
            capability_name="sys.quantum_core.read",
            parameters={},
        )
        sock_file.write(json.dumps(prop.to_dict()) + "\n")
        sock_file.flush()
    elif "noop" in prompt or "direct_reply" in prompt:
        # Direct reply without capability proposal
        complete = CompleteTurn(
            protocol_version=CURRENT_PROTOCOL_VERSION,
            turn_id=turn_id,
            status="success",
            response_text="Direct worker response without capability invocation.",
        )
        sock_file.write(json.dumps(complete.to_dict()) + "\n")
        sock_file.flush()
        return
    elif "memory" in prompt:
        # Deterministic M6a behavior: propose sys.memory.read
        prop = ProposeCapability(
            protocol_version=CURRENT_PROTOCOL_VERSION,
            turn_id=turn_id,
            call_id="call-mem-01",
            capability_name="sys.memory.read",
            parameters={},
        )
        sock_file.write(json.dumps(prop.to_dict()) + "\n")
        sock_file.flush()
    elif is_process_query(prompt):
        # Deterministic M6b behavior: propose proc.list
        limit = 10
        match = re.search(r"limit\s+(\d+)", prompt, re.IGNORECASE)
        if match:
            limit = int(match.group(1))
        prop = ProposeCapability(
            protocol_version=CURRENT_PROTOCOL_VERSION,
            turn_id=turn_id,
            call_id="call-proc-01",
            capability_name="proc.list",
            parameters={"limit": limit},
        )
        sock_file.write(json.dumps(prop.to_dict()) + "\n")
        sock_file.flush()
    else:
        # Default behavior: propose sys.cpu.read
        prop = ProposeCapability(
            protocol_version=CURRENT_PROTOCOL_VERSION,
            turn_id=turn_id,
            call_id="call-cpu-01",
            capability_name="sys.cpu.read",
            parameters={},
        )
        sock_file.write(json.dumps(prop.to_dict()) + "\n")
        sock_file.flush()

    # Await CapabilityResult from daemon
    res_line = sock_file.readline()
    if not res_line:
        print("[worker] Daemon closed connection before capability result", file=sys.stderr)
        return

    try:
        res_data = json.loads(res_line.strip())
    except json.JSONDecodeError as e:
        print(f"[worker] Malformed capability result JSON: {e}", file=sys.stderr)
        return

    if res_data.get("type") != "capability_result":
        print(f"[worker] Expected capability_result, got: {res_data.get('type')}", file=sys.stderr)
        return

    result = CapabilityResult.from_dict(res_data)
    if result.status == "success":
        data = result.data
        if isinstance(data, list):
            proc_summaries = [f"[{p.get('pid')}] {p.get('name')} ({p.get('memory_mb', 0)}MB)" for p in data]
            summary_str = ", ".join(proc_summaries[:5])
            if len(proc_summaries) > 5:
                summary_str += f", ... (+{len(proc_summaries) - 5} more)"
            response_text = f"Running processes ({len(data)} returned): {summary_str}"
        elif isinstance(data, dict):
            total_mb = data.get("total_mb")
            used_mb = data.get("used_mb")
            free_mb = data.get("free_mb")
            available_mb = data.get("available_mb")

            user = data.get("user_percent")
            system = data.get("system_percent")
            idle = data.get("idle_percent")

            if total_mb is not None and available_mb is not None:
                response_text = f"Host memory metrics: total={total_mb}MB, used={used_mb}MB, free={free_mb}MB, available={available_mb}MB"
            elif user is not None and idle is not None:
                response_text = f"Host CPU metrics: user={user}%, system={system}%, idle={idle}%"
            else:
                response_text = f"Capability executed successfully: {json.dumps(data)}"
        else:
            response_text = f"Capability executed successfully: {json.dumps(data)}"
        turn_status = "success"
    else:
        err = result.error
        code = err.code if err else "UNKNOWN"
        msg = err.message if err else "Unknown capability error"
        response_text = f"Capability execution failed: [{code}] {msg}"
        turn_status = "error"

    complete = CompleteTurn(
        protocol_version=CURRENT_PROTOCOL_VERSION,
        turn_id=turn_id,
        status=turn_status,
        response_text=response_text,
    )
    sock_file.write(json.dumps(complete.to_dict()) + "\n")
    sock_file.flush()


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
        while True:
            line = sock_file.readline()
            if not line:
                # Daemon closed socket (normal shutdown)
                break

            line_str = line.strip()
            if not line_str:
                continue

            try:
                msg_data = json.loads(line_str)
            except json.JSONDecodeError as e:
                print(f"[worker] Malformed JSON received from daemon: {e}", file=sys.stderr)
                continue

            msg_type = msg_data.get("type")
            if msg_type == "request_turn":
                handle_request_turn(sock_file, msg_data)
            else:
                print(f"[worker] Unexpected message type: {msg_type}", file=sys.stderr)

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
        description="Aurora OS AI Worker Stub (M5 Vertical Slice)",
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
