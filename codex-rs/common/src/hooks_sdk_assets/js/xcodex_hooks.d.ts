/**
 * xCodex hooks kit: TypeScript type definitions for external hooks.
 *
 * Installed into `$CODEX_HOME/hooks/` by:
 * - `xcodex hooks install sdks javascript`
 * - `xcodex hooks install sdks typescript`
 *
 * These types model the JSON payload shape emitted by Codex hooks.
 *
 * Docs:
 * - Hooks overview: docs/xcodex/hooks.md
 * - Hook SDK installers: docs/xcodex/hooks-sdks.md
 * - Machine-readable schema: docs/xcodex/hooks.schema.json
 * - Authoritative config reference: docs/config.md#hooks
 */

export type HookPayload = {
  approval_policy?: "untrusted" | "on-failure" | "on-request" | "never" | null;
  attempt?: null | number;
  call_id?: null | string;
  command?: null | string[];
  cwd: string;
  duration_ms?: null | number;
  event_id: string;
  grant_root?: null | string;
  has_output_schema?: boolean | null;
  hook_event_name: string;
  input_item_count?: null | number;
  input_messages?: null | string[];
  kind?: null | string;
  last_assistant_message?: null | string;
  message?: null | string;
  model?: null | string;
  model_request_id?: null | string;
  needs_follow_up?: boolean | null;
  notification_type?: null | string;
  output_bytes?: null | number;
  output_preview?: null | string;
  parallel_tool_calls?: boolean | null;
  paths?: null | string[];
  permission_mode: string;
  prompt?: null | string;
  proposed_execpolicy_amendment?: null | string[];
  provider?: null | string;
  reason?: null | string;
  request_id?: null | string;
  response_id?: null | string;
  sandbox_policy?: null | unknown;
  schema_version: number;
  server_name?: null | string;
  session_id: string;
  session_source?: null | string;
  status?: null | string;
  subagent?: null | string;
  success?: boolean | null;
  timestamp: string;
  title?: null | string;
  token_usage?: null | unknown;
  tool_count?: null | number;
  tool_input?: unknown;
  tool_name?: null | string;
  tool_response?: unknown;
  tool_use_id?: null | string;
  transcript_path: string;
  trigger?: null | string;
  turn_id?: null | string;
  xcodex_event_type: string;
};

/**
 * Read a hook payload (handles stdin vs payload_path envelopes).
 *
 * @param raw Optional stdin string; if omitted, reads from fd 0.
 */
export function readPayload(raw?: string): HookPayload;
