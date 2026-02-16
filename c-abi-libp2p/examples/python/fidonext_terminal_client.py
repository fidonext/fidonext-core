#!/usr/bin/env python3
"""
Friendly terminal client wrapper for ping_standalone_nodes.py.

This wrapper keeps runtime logic in ping_standalone_nodes.py and exposes
simple subcommands:
  - relay
  - leaf
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from ping_standalone_nodes import main as standalone_main  # noqa: E402


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="FidoNext terminal client (relay/leaf wrapper)."
    )
    sub = parser.add_subparsers(dest="command", required=True)

    relay = sub.add_parser("relay", help="Run this node as relay.")
    relay.add_argument(
        "--force-hop",
        action="store_true",
        help="Enable relay hop immediately (skip AutoNAT waiting).",
    )
    relay.add_argument(
        "passthrough",
        nargs=argparse.REMAINDER,
        help="Extra args passed to ping_standalone_nodes.py",
    )

    leaf = sub.add_parser("leaf", help="Run this node as leaf.")
    leaf.add_argument(
        "passthrough",
        nargs=argparse.REMAINDER,
        help="Extra args passed to ping_standalone_nodes.py",
    )

    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.command == "relay":
        forwarded = ["--role", "relay"]
        if args.force_hop:
            forwarded.append("--force-hop")
        forwarded.extend(args.passthrough)
    else:
        forwarded = ["--role", "leaf", *args.passthrough]

    sys.argv = ["ping_standalone_nodes.py", *forwarded]
    standalone_main()


if __name__ == "__main__":
    main()

