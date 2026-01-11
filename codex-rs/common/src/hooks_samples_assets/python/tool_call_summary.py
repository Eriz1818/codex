#!/usr/bin/env python3
"""
Sample external hook: log compact tool-call summaries to CODEX_HOME/hooks-tool-calls.log.

Customize by editing `main()` below.
"""

import os
import pathlib

import xcodex_hooks


def main() -> int:
    payload = xcodex_hooks.read_payload()
    if payload.get("type") != "tool-call-finished":
        return 0

    tool_name = payload.get("tool-name") or payload.get("tool_name") or "unknown"
    status = payload.get("status") or "unknown"
    duration_ms = payload.get("duration-ms") or payload.get("duration_ms") or 0
    success = payload.get("success")
    output_bytes = payload.get("output-bytes") or payload.get("output_bytes") or 0
    cwd = payload.get("cwd") or ""

    codex_home = pathlib.Path(
        os.environ.get("CODEX_HOME", str(pathlib.Path.home() / ".xcodex"))
    )
    out = codex_home / "hooks-tool-calls.log"
    out.parent.mkdir(parents=True, exist_ok=True)

    line = (
        f"type=tool-call-finished tool={tool_name} status={status} "
        f"success={success} duration_ms={duration_ms} output_bytes={output_bytes} cwd={cwd}\n"
    )
    with out.open("a", encoding="utf-8") as f:
        f.write(line)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

