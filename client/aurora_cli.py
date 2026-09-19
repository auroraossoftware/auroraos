"""Aurora OS CLI Test Client - Milestone 1 Skeleton.

Pursuant to ADR-001 and ADR-002, desktop applications and CLI tools communicate
with the central aurora-ai service over public D-Bus IPC.

Milestone 1 establishes the client directory and execution boundary.
D-Bus communication and interactive request issuing are deferred to subsequent milestones.
"""

import argparse
import sys


def parse_args(args: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="aurora-cli",
        description="Aurora OS AI Test Client (M1 Skeleton)",
    )
    parser.add_argument(
        "--prompt",
        "-p",
        type=str,
        help="Simulated user prompt or query (deferred to M4+)",
    )
    return parser.parse_args(args)


def main(args: list[str] | None = None) -> int:
    parsed = parse_args(args if args is not None else sys.argv[1:])
    print("aurora-cli test client skeleton (M1)")
    if parsed.prompt:
        print(f"Captured prompt: {parsed.prompt}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
