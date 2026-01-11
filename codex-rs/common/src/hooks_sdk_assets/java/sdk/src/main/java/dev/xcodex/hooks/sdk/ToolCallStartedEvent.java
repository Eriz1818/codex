package dev.xcodex.hooks.sdk;

import com.fasterxml.jackson.databind.JsonNode;
import java.util.Map;
import java.util.Set;

public record ToolCallStartedEvent(
    String type,
    Integer schemaVersion,
    String eventId,
    String timestamp,
    JsonNode raw,
    Map<String, JsonNode> extra,
    Integer attempt,
    String callId,
    String cwd,
    String modelRequestId,
    String threadId,
    String toolName,
    String turnId)
    implements HookEvent {
  private static final Set<String> KNOWN_KEYS =
      Set.of(
          "schema-version",
          "event-id",
          "timestamp",
          "type",
          "attempt",
          "call-id",
          "cwd",
          "model-request-id",
          "thread-id",
          "tool-name",
          "turn-id");

  static ToolCallStartedEvent from(
      JsonNode payload, Integer schemaVersion, String eventId, String timestamp) {
    return new ToolCallStartedEvent(
        "tool-call-started",
        schemaVersion,
        eventId,
        timestamp,
        payload,
        HookParser.extras(payload, KNOWN_KEYS),
        HookParser.intOrNull(payload.get("attempt")),
        HookParser.textOrNull(payload.get("call-id")),
        HookParser.textOrNull(payload.get("cwd")),
        HookParser.textOrNull(payload.get("model-request-id")),
        HookParser.textOrNull(payload.get("thread-id")),
        HookParser.textOrNull(payload.get("tool-name")),
        HookParser.textOrNull(payload.get("turn-id")));
  }
}
