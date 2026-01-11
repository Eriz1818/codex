#!/usr/bin/env python3
"""
Example hook: show a Linux desktop notification for hook events (notify-send).
"""
import json
import shutil
import subprocess

import xcodex_hooks

def main() -> int:
    payload = xcodex_hooks.read_payload()

    notify_send = shutil.which("notify-send")
    if notify_send is None:
        return 0

    event_type = payload.get("type") or "unknown"
    kind = payload.get("kind")
    cwd = payload.get("cwd") or ""

    title = "xcodex hook"
    if event_type == "approval-requested":
        title = "xcodex approval requested"

    details = []
    details.append(f"type={event_type}")
    if kind:
        details.append(f"kind={kind}")
    if cwd:
        details.append(f"cwd={cwd}")
    message = " ".join(details)

    subprocess.run([notify_send, title, message], check=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
