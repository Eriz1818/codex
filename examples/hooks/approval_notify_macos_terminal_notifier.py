#!/usr/bin/env python3
import json
import os
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
    if payload.get("type") != "approval-requested":
        return 0

    notifier = shutil.which("terminal-notifier")
    if notifier is None:
        return 0

    kind = payload.get("kind") or "unknown"
    cwd = payload.get("cwd") or ""
    title = "xcodex approval requested"
    message = f"kind={kind} cwd={cwd}".strip()

    subprocess.run([notifier, "-title", title, "-message", message], check=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

