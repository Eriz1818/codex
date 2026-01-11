#!/usr/bin/env python3
"""
Sample external hook: show a macOS notification on approval requests (if terminal-notifier is installed).
"""

import shutil
import subprocess

import xcodex_hooks


def main() -> int:
    payload = xcodex_hooks.read_payload()
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

