from __future__ import annotations

"""
xCodex hooks kit: Python typed helpers for external hooks.

This file is generated from the Rust hook payload schema (source-of-truth).
It is installed into `$CODEX_HOME/hooks/` by:
- `xcodex hooks install sdks python`

Re-generate from the repo:
cd codex-rs
cargo run -p codex-core --bin hooks_python_types --features hooks-schema --quiet \
> common/src/hooks_sdk_assets/python/xcodex_hooks_types.py

Docs:
- Hooks overview: docs/xcodex/hooks.md
- Machine-readable schema: docs/xcodex/hooks.schema.json
- Hook SDK installers: docs/xcodex/hooks-sdks.md
"""


from typing import Any, Dict, List, Literal, Optional, TypedDict, Union
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import NotRequired, Required
else:
    class _Req:
        def __class_getitem__(cls, item):  # noqa: D401
            return item

    Required = NotRequired = _Req  # type: ignore

HookPayload = TypedDict(
    "HookPayload",
    {
        "approval_policy": NotRequired[Union[None, Union[Literal["never"], Literal["on-failure"], Literal["on-request"], Literal["untrusted"]]]],
        "attempt": NotRequired[Union[None, int]],
        "call_id": NotRequired[Union[None, str]],
        "command": NotRequired[Union[List[str], None]],
        "cwd": Required[str],
        "duration_ms": NotRequired[Union[None, int]],
        "event_id": Required[str],
        "grant_root": NotRequired[Union[None, str]],
        "has_output_schema": NotRequired[Union[None, bool]],
        "hook_event_name": Required[str],
        "input_item_count": NotRequired[Union[None, int]],
        "input_messages": NotRequired[Union[List[str], None]],
        "kind": NotRequired[Union[None, str]],
        "last_assistant_message": NotRequired[Union[None, str]],
        "message": NotRequired[Union[None, str]],
        "model": NotRequired[Union[None, str]],
        "model_request_id": NotRequired[Union[None, str]],
        "needs_follow_up": NotRequired[Union[None, bool]],
        "notification_type": NotRequired[Union[None, str]],
        "output_bytes": NotRequired[Union[None, int]],
        "output_preview": NotRequired[Union[None, str]],
        "parallel_tool_calls": NotRequired[Union[None, bool]],
        "paths": NotRequired[Union[List[str], None]],
        "permission_mode": Required[str],
        "prompt": NotRequired[Union[None, str]],
        "proposed_execpolicy_amendment": NotRequired[Union[List[str], None]],
        "provider": NotRequired[Union[None, str]],
        "reason": NotRequired[Union[None, str]],
        "request_id": NotRequired[Union[None, str]],
        "response_id": NotRequired[Union[None, str]],
        "sandbox_policy": NotRequired[Union[Any, None]],
        "schema_version": Required[int],
        "server_name": NotRequired[Union[None, str]],
        "session_id": Required[str],
        "session_source": NotRequired[Union[None, str]],
        "status": NotRequired[Union[None, str]],
        "subagent": NotRequired[Union[None, str]],
        "success": NotRequired[Union[None, bool]],
        "timestamp": Required[str],
        "title": NotRequired[Union[None, str]],
        "token_usage": NotRequired[Union[Any, None]],
        "tool_count": NotRequired[Union[None, int]],
        "tool_input": NotRequired[Any],
        "tool_name": NotRequired[Union[None, str]],
        "tool_response": NotRequired[Any],
        "tool_use_id": NotRequired[Union[None, str]],
        "transcript_path": Required[str],
        "trigger": NotRequired[Union[None, str]],
        "turn_id": NotRequired[Union[None, str]],
        "xcodex_event_type": Required[str],
    },
    total=False,
)

