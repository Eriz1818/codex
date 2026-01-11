package dev.xcodex.hooks.sdk;

import com.fasterxml.jackson.databind.JsonNode;
import java.util.Map;
import java.util.Set;

public record ToolCallFinishedEvent(
    String type,
    Integer schemaVersion,
    String eventId,
    String timestamp,
    JsonNode raw,
    Map<String, JsonNode> extra,
    Integer attempt,
    String callId,
    String cwd,
    Long durationMs,
    String modelRequestId,
    Long outputBytes,
    String outputPreview,
    String status,
    Boolean success,
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
          "duration-ms",
          "model-request-id",
          "output-bytes",
          "output-preview",
          "status",
          "success",
          "thread-id",
          "tool-name",
          "turn-id");

  static ToolCallFinishedEvent from(
      JsonNode payload, Integer schemaVersion, String eventId, String timestamp) {
    return new ToolCallFinishedEvent(
        "tool-call-finished",
        schemaVersion,
        eventId,
        timestamp,
        payload,
        HookParser.extras(payload, KNOWN_KEYS),
        HookParser.intOrNull(payload.get("attempt")),
        HookParser.textOrNull(payload.get("call-id")),
        HookParser.textOrNull(payload.get("cwd")),
        HookParser.longOrNull(payload.get("duration-ms")),
        HookParser.textOrNull(payload.get("model-request-id")),
        HookParser.longOrNull(payload.get("output-bytes")),
        HookParser.textOrNull(payload.get("output-preview")),
        HookParser.textOrNull(payload.get("status")),
        HookParser.boolOrNull(payload.get("success")),
        HookParser.textOrNull(payload.get("thread-id")),
        HookParser.textOrNull(payload.get("tool-name")),
        HookParser.textOrNull(payload.get("turn-id")));
  }
}
