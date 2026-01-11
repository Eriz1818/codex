package dev.xcodex.hooks.sdk;

import com.fasterxml.jackson.databind.JsonNode;
import java.util.Map;
import java.util.Set;

public record ModelResponseCompletedEvent(
    String type,
    Integer schemaVersion,
    String eventId,
    String timestamp,
    JsonNode raw,
    Map<String, JsonNode> extra,
    Integer attempt,
    String cwd,
    String modelRequestId,
    Boolean needsFollowUp,
    String responseId,
    String threadId,
    TokenUsage tokenUsage,
    String turnId)
    implements HookEvent {
  private static final Set<String> KNOWN_KEYS =
      Set.of(
          "schema-version",
          "event-id",
          "timestamp",
          "type",
          "attempt",
          "cwd",
          "model-request-id",
          "needs-follow-up",
          "response-id",
          "thread-id",
          "token-usage",
          "turn-id");

  static ModelResponseCompletedEvent from(
      JsonNode payload, Integer schemaVersion, String eventId, String timestamp) {
    return new ModelResponseCompletedEvent(
        "model-response-completed",
        schemaVersion,
        eventId,
        timestamp,
        payload,
        HookParser.extras(payload, KNOWN_KEYS),
        HookParser.intOrNull(payload.get("attempt")),
        HookParser.textOrNull(payload.get("cwd")),
        HookParser.textOrNull(payload.get("model-request-id")),
        HookParser.boolOrNull(payload.get("needs-follow-up")),
        HookParser.textOrNull(payload.get("response-id")),
        HookParser.textOrNull(payload.get("thread-id")),
        TokenUsage.fromJson(payload.get("token-usage")),
        HookParser.textOrNull(payload.get("turn-id")));
  }
}
