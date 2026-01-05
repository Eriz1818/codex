#!/usr/bin/env python3
import json
import pathlib
import shutil
import subprocess
import sys


def read_payload() -> dict:
    raw = sys.stdin.read() or "{}"
    payload = json.loads(raw)
    payload_path = payload.get("payload-path")
    if payload_path:
        payload = json.loads(pathlib.Path(payload_path).read_text())
    return payload


def main() -> int:
    payload = read_payload()

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

