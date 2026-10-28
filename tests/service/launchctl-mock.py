#!/usr/bin/env python3
"""Explicit fixture-only launchctl replacement used by service lifecycle tests."""

from __future__ import annotations

import json
import os
from pathlib import Path
import sys
import time

LABEL = "com.ios-unsandboxed.daemon"


def main() -> int:
    if len(sys.argv) < 2 or (sys.argv[1] != "list" and (len(sys.argv) != 3 or not (sys.argv[2] == LABEL or sys.argv[2].endswith("/com.ios-unsandboxed.daemon.plist")))):
        return 64
    verb = sys.argv[1]
    operand = sys.argv[2] if len(sys.argv) == 3 else ""
    mode = os.environ.get("IU_MOCK_LAUNCHD_MODE", "normal")
    delay = float(os.environ.get("IU_MOCK_LAUNCHD_DELAY", "0"))
    if delay > 0:
        time.sleep(min(delay, 2.0))
    if mode == "hang":
        time.sleep(10)
    fixture_root = Path(__file__).resolve().parents[3]
    state_path = Path(os.environ["IU_MOCK_LAUNCHD_STATE"]).resolve()
    try:
        state_path.relative_to(fixture_root)
    except ValueError:
        return 66
    log_path = state_path.with_suffix(".calls")
    try:
        state = json.loads(state_path.read_text())
    except FileNotFoundError:
        state = {"loaded": False, "running": False}
    except (json.JSONDecodeError, OSError):
        return 65
    with log_path.open("a", encoding="ascii") as log:
        log.write(f"{verb} {operand}\n")
    if mode == "unsupported" and verb in {"list", "load", "unload", "start", "stop"}:
        print("mock reports unsupported launchctl syntax", file=sys.stderr)
        return 64
    if verb == "list":
        print("PID Status Label")
        if state["loaded"]:
            print(f"{'123' if state['running'] else '-'} 0 {LABEL}")
        return 0
    if verb == "load":
        if mode == "registration-rejected" or state["loaded"]:
            print("mock rejected registration", file=sys.stderr)
            return 1
        state["loaded"] = True
        state["running"] = mode != "immediate-exit"
    elif verb == "start":
        if mode == "start-failure" or not state["loaded"]:
            print("mock start failed", file=sys.stderr)
            return 1
        state["running"] = mode != "immediate-exit"
    elif verb == "stop":
        if mode == "stop-timeout":
            print("mock stop timed out", file=sys.stderr)
            return 1
        state["running"] = False
    elif verb == "unload":
        if mode == "unregister-failure" or not state["loaded"]:
            print("mock unload failed", file=sys.stderr)
            return 1
        state["loaded"] = False
        state["running"] = False
    else:
        return 64
    state_path.write_text(json.dumps(state, sort_keys=True), encoding="ascii")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
