#!/usr/bin/env python3
import json
import os
import pathlib
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
    codex_home = pathlib.Path(os.environ.get("CODEX_HOME", str(pathlib.Path.home() / ".xcodex")))
    out = codex_home / "hooks.jsonl"
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("a", encoding="utf-8") as f:
        f.write(json.dumps(payload) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

