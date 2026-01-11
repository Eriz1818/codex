package dev.xcodex.hooks.sdk;

import com.fasterxml.jackson.databind.JsonNode;
import java.util.Map;
import java.util.Set;

public record SessionStartEvent(
    String type,
    Integer schemaVersion,
    String eventId,
    String timestamp,
    JsonNode raw,
    Map<String, JsonNode> extra,
    String cwd,
    String sessionSource,
    String threadId)
    implements HookEvent {
  private static final Set<String> KNOWN_KEYS =
      Set.of(
          "schema-version",
          "event-id",
          "timestamp",
          "type",
          "cwd",
          "session-source",
          "thread-id");

  static SessionStartEvent from(
      JsonNode payload, Integer schemaVersion, String eventId, String timestamp) {
    return new SessionStartEvent(
        "session-start",
        schemaVersion,
        eventId,
        timestamp,
        payload,
        HookParser.extras(payload, KNOWN_KEYS),
        HookParser.textOrNull(payload.get("cwd")),
        HookParser.textOrNull(payload.get("session-source")),
        HookParser.textOrNull(payload.get("thread-id")));
  }
}
