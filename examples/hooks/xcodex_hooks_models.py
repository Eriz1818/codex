from __future__ import annotations

"""
xCodex hooks kit: Python runtime models for external hooks.

This file is generated from the Rust hook payload schema (source-of-truth).
It is installed into `$CODEX_HOME/hooks/` by:
  - `xcodex hooks install sdks python`

Re-generate from the repo:
  cd codex-rs
  cargo run -p codex-core --bin hooks_python_models --features hooks-schema --quiet \
    > common/src/hooks_sdk_assets/python/xcodex_hooks_models.py

This module is intentionally dependency-free (no pydantic). It aims to provide:
- ergonomic attribute access (dataclasses)
- forward compatibility (unknown fields are preserved in `.extras` / `.raw`)

Docs:
- Hooks overview: docs/xcodex/hooks.md
- Machine-readable schema: docs/xcodex/hooks.schema.json
"""

from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional


def _as_str(value: Any) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, str):
        return value
    try:
        return str(value)
    except Exception:
        return None


def _as_int(value: Any) -> Optional[int]:
    if value is None:
        return None
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        try:
            return int(value, 10)
        except Exception:
            return None
    return None


def _as_bool(value: Any) -> Optional[bool]:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value != 0
    if isinstance(value, str):
        v = value.strip().lower()
        if v in ("true", "1", "yes", "y", "on"):
            return True
        if v in ("false", "0", "no", "n", "off"):
            return False
    return None


def _as_str_list(value: Any) -> Optional[List[str]]:
    if value is None:
        return None
    if isinstance(value, list):
        out: List[str] = []
        for item in value:
            s = _as_str(item)
            if s is not None:
                out.append(s)
        return out
    return None


@dataclass
class HookPayload:
    cwd: str
    event_id: str
    hook_event_name: str
    permission_mode: str
    schema_version: int
    session_id: str
    timestamp: str
    transcript_path: str
    xcodex_event_type: str
    approval_policy: Optional[Any] = None
    attempt: Optional[Any] = None
    call_id: Optional[Any] = None
    command: Optional[Any] = None
    duration_ms: Optional[Any] = None
    grant_root: Optional[Any] = None
    has_output_schema: Optional[Any] = None
    input_item_count: Optional[Any] = None
    input_messages: Optional[Any] = None
    kind: Optional[Any] = None
    last_assistant_message: Optional[Any] = None
    message: Optional[Any] = None
    model: Optional[Any] = None
    model_request_id: Optional[Any] = None
    needs_follow_up: Optional[Any] = None
    notification_type: Optional[Any] = None
    output_bytes: Optional[Any] = None
    output_preview: Optional[Any] = None
    parallel_tool_calls: Optional[Any] = None
    paths: Optional[Any] = None
    prompt: Optional[Any] = None
    proposed_execpolicy_amendment: Optional[Any] = None
    provider: Optional[Any] = None
    reason: Optional[Any] = None
    request_id: Optional[Any] = None
    response_id: Optional[Any] = None
    sandbox_policy: Optional[Any] = None
    server_name: Optional[Any] = None
    session_source: Optional[Any] = None
    status: Optional[Any] = None
    subagent: Optional[Any] = None
    success: Optional[Any] = None
    title: Optional[Any] = None
    token_usage: Optional[Any] = None
    tool_count: Optional[Any] = None
    tool_input: Optional[Any] = None
    tool_name: Optional[Any] = None
    tool_response: Optional[Any] = None
    tool_use_id: Optional[Any] = None
    trigger: Optional[Any] = None
    turn_id: Optional[Any] = None


    raw: Dict[str, Any] = None  # type: ignore[assignment]
    extras: Dict[str, Any] = None  # type: ignore[assignment]


def parse_hook_payload(payload: Mapping[str, Any]) -> HookPayload:
    raw = dict(payload)
    known = {
        "approval_policy",
        "attempt",
        "call_id",
        "command",
        "cwd",
        "duration_ms",
        "event_id",
        "grant_root",
        "has_output_schema",
        "hook_event_name",
        "input_item_count",
        "input_messages",
        "kind",
        "last_assistant_message",
        "message",
        "model",
        "model_request_id",
        "needs_follow_up",
        "notification_type",
        "output_bytes",
        "output_preview",
        "parallel_tool_calls",
        "paths",
        "permission_mode",
        "prompt",
        "proposed_execpolicy_amendment",
        "provider",
        "reason",
        "request_id",
        "response_id",
        "sandbox_policy",
        "schema_version",
        "server_name",
        "session_id",
        "session_source",
        "status",
        "subagent",
        "success",
        "timestamp",
        "title",
        "token_usage",
        "tool_count",
        "tool_input",
        "tool_name",
        "tool_response",
        "tool_use_id",
        "transcript_path",
        "trigger",
        "turn_id",
        "xcodex_event_type",
    }
    extras = {k: v for (k, v) in raw.items() if k not in known}

    return HookPayload(
        approval_policy=lambda x: x(raw.get("approval_policy")),
        attempt=lambda x: x(raw.get("attempt")),
        call_id=lambda x: x(raw.get("call_id")),
        command=lambda x: x(raw.get("command")),
        cwd=_as_str(raw.get("cwd")),
        duration_ms=lambda x: x(raw.get("duration_ms")),
        event_id=_as_str(raw.get("event_id")),
        grant_root=lambda x: x(raw.get("grant_root")),
        has_output_schema=lambda x: x(raw.get("has_output_schema")),
        hook_event_name=_as_str(raw.get("hook_event_name")),
        input_item_count=lambda x: x(raw.get("input_item_count")),
        input_messages=lambda x: x(raw.get("input_messages")),
        kind=lambda x: x(raw.get("kind")),
        last_assistant_message=lambda x: x(raw.get("last_assistant_message")),
        message=lambda x: x(raw.get("message")),
        model=lambda x: x(raw.get("model")),
        model_request_id=lambda x: x(raw.get("model_request_id")),
        needs_follow_up=lambda x: x(raw.get("needs_follow_up")),
        notification_type=lambda x: x(raw.get("notification_type")),
        output_bytes=lambda x: x(raw.get("output_bytes")),
        output_preview=lambda x: x(raw.get("output_preview")),
        parallel_tool_calls=lambda x: x(raw.get("parallel_tool_calls")),
        paths=lambda x: x(raw.get("paths")),
        permission_mode=_as_str(raw.get("permission_mode")),
        prompt=lambda x: x(raw.get("prompt")),
        proposed_execpolicy_amendment=lambda x: x(raw.get("proposed_execpolicy_amendment")),
        provider=lambda x: x(raw.get("provider")),
        reason=lambda x: x(raw.get("reason")),
        request_id=lambda x: x(raw.get("request_id")),
        response_id=lambda x: x(raw.get("response_id")),
        sandbox_policy=lambda x: x(raw.get("sandbox_policy")),
        schema_version=_as_int(raw.get("schema_version")),
        server_name=lambda x: x(raw.get("server_name")),
        session_id=_as_str(raw.get("session_id")),
        session_source=lambda x: x(raw.get("session_source")),
        status=lambda x: x(raw.get("status")),
        subagent=lambda x: x(raw.get("subagent")),
        success=lambda x: x(raw.get("success")),
        timestamp=_as_str(raw.get("timestamp")),
        title=lambda x: x(raw.get("title")),
        token_usage=lambda x: x(raw.get("token_usage")),
        tool_count=lambda x: x(raw.get("tool_count")),
        tool_input=lambda x: x(raw.get("tool_input")),
        tool_name=lambda x: x(raw.get("tool_name")),
        tool_response=lambda x: x(raw.get("tool_response")),
        tool_use_id=lambda x: x(raw.get("tool_use_id")),
        transcript_path=_as_str(raw.get("transcript_path")),
        trigger=lambda x: x(raw.get("trigger")),
        turn_id=lambda x: x(raw.get("turn_id")),
        xcodex_event_type=_as_str(raw.get("xcodex_event_type")),
        raw=raw,
        extras=extras,
    )
