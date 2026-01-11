package dev.xcodex.hooks.sdk;

import com.fasterxml.jackson.databind.JsonNode;
import java.util.Map;
import java.util.Set;

public record ModelRequestStartedEvent(
    String type,
    Integer schemaVersion,
    String eventId,
    String timestamp,
    JsonNode raw,
    Map<String, JsonNode> extra,
    Integer attempt,
    String cwd,
    Boolean hasOutputSchema,
    String model,
    String modelRequestId,
    Boolean parallelToolCalls,
    Long promptInputItemCount,
    String provider,
    String threadId,
    Long toolCount,
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
          "has-output-schema",
          "model",
          "model-request-id",
          "parallel-tool-calls",
          "prompt-input-item-count",
          "provider",
          "thread-id",
          "tool-count",
          "turn-id");

  static ModelRequestStartedEvent from(
      JsonNode payload, Integer schemaVersion, String eventId, String timestamp) {
    return new ModelRequestStartedEvent(
        "model-request-started",
        schemaVersion,
        eventId,
        timestamp,
        payload,
        HookParser.extras(payload, KNOWN_KEYS),
        HookParser.intOrNull(payload.get("attempt")),
        HookParser.textOrNull(payload.get("cwd")),
        HookParser.boolOrNull(payload.get("has-output-schema")),
        HookParser.textOrNull(payload.get("model")),
        HookParser.textOrNull(payload.get("model-request-id")),
        HookParser.boolOrNull(payload.get("parallel-tool-calls")),
        HookParser.longOrNull(payload.get("prompt-input-item-count")),
        HookParser.textOrNull(payload.get("provider")),
        HookParser.textOrNull(payload.get("thread-id")),
        HookParser.longOrNull(payload.get("tool-count")),
        HookParser.textOrNull(payload.get("turn-id")));
  }
}
