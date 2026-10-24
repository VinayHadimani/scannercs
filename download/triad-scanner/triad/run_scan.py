#!/usr/bin/env python3
"""CLI JSON runner for TRIAD_Scanner (used by the web console, also handy
for scripting: one process, one JSON document on stdout).

Usage:
    python3 run_scan.py --target <url> [--live | --demo] [--timeout S]
    python3 run_scan.py --health

Exit code 0 on a completed scan (including "unreachable"/"invalid" info
reports); 2 on usage errors; 3 on engine crash (message on stderr).
"""
from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from triad_scanner import TRIAD_Scanner  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(prog="run_scan")
    ap.add_argument("--target", help="github repo / website url / local dir")
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--live", action="store_true", help="real network scan")
    mode.add_argument("--demo", action="store_true", help="bundled fixtures")
    ap.add_argument("--timeout", type=float, default=6.0,
                    help="per-request timeout for live mode (default 6s)")
    ap.add_argument("--health", action="store_true", help="print health json")
    args = ap.parse_args()

    if args.health:
        scanner = TRIAD_Scanner()
        print(json.dumps({
            "status": "ok",
            "engine": "triad_scanner.py",
            "templates": len(scanner.templates),
            "timeout": scanner.timeout,
        }))
        return 0

    if not args.target:
        print("run_scan: --target is required (or --health)", file=sys.stderr)
        return 2

    demo: bool | None
    if args.live:
        demo = False
    elif args.demo:
        demo = True
    else:
        demo = None          # engine default: TRIAD_DEMO_MODE env, else off

    try:
        scanner = TRIAD_Scanner(timeout=args.timeout)
        print(json.dumps(scanner.scan(args.target, demo=demo)))
        return 0
    except Exception as exc:                       # engine crash -> 504 path
        print(f"run_scan: engine error: {type(exc).__name__}: {exc}",
              file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
