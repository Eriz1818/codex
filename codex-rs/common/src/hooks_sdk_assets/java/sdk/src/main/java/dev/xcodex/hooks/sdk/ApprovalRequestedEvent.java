package dev.xcodex.hooks.sdk;

import com.fasterxml.jackson.databind.JsonNode;
import java.util.List;
import java.util.Map;
import java.util.Set;

public record ApprovalRequestedEvent(
    String type,
    Integer schemaVersion,
    String eventId,
    String timestamp,
    JsonNode raw,
    Map<String, JsonNode> extra,
    String kind,
    String threadId,
    String turnId,
    String approvalPolicy,
    String callId,
    List<String> command,
    String cwd,
    String grantRoot,
    String message,
    List<String> paths,
    List<String> proposedExecpolicyAmendment,
    String reason,
    String requestId,
    JsonNode sandboxPolicy,
    String serverName)
    implements HookEvent {
  private static final Set<String> KNOWN_KEYS =
      Set.of(
          "schema-version",
          "event-id",
          "timestamp",
          "type",
          "kind",
          "thread-id",
          "turn-id",
          "approval-policy",
          "call-id",
          "command",
          "cwd",
          "grant-root",
          "message",
          "paths",
          "proposed-execpolicy-amendment",
          "reason",
          "request-id",
          "sandbox-policy",
          "server-name");

  static ApprovalRequestedEvent from(
      JsonNode payload, Integer schemaVersion, String eventId, String timestamp) {
    return new ApprovalRequestedEvent(
        "approval-requested",
        schemaVersion,
        eventId,
        timestamp,
        payload,
        HookParser.extras(payload, KNOWN_KEYS),
        HookParser.textOrNull(payload.get("kind")),
        HookParser.textOrNull(payload.get("thread-id")),
        HookParser.textOrNull(payload.get("turn-id")),
        HookParser.textOrNull(payload.get("approval-policy")),
        HookParser.textOrNull(payload.get("call-id")),
        HookParser.stringArrayOrNull(payload.get("command")),
        HookParser.textOrNull(payload.get("cwd")),
        HookParser.textOrNull(payload.get("grant-root")),
        HookParser.textOrNull(payload.get("message")),
        HookParser.stringArrayOrNull(payload.get("paths")),
        HookParser.stringArrayOrNull(payload.get("proposed-execpolicy-amendment")),
        HookParser.textOrNull(payload.get("reason")),
        HookParser.textOrNull(payload.get("request-id")),
        payload.get("sandbox-policy"),
        HookParser.textOrNull(payload.get("server-name")));
  }
}
