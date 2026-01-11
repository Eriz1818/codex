package dev.xcodex.hooks.sdk;

import com.fasterxml.jackson.databind.JsonNode;
import java.util.List;
import java.util.Map;
import java.util.Set;

public record AgentTurnCompleteEvent(
    String type,
    Integer schemaVersion,
    String eventId,
    String timestamp,
    JsonNode raw,
    Map<String, JsonNode> extra,
    String cwd,
    List<String> inputMessages,
    String lastAssistantMessage,
    String threadId,
    String turnId)
    implements HookEvent {
  private static final Set<String> KNOWN_KEYS =
      Set.of(
          "schema-version",
          "event-id",
          "timestamp",
          "type",
          "cwd",
          "input-messages",
          "last-assistant-message",
          "thread-id",
          "turn-id");

  static AgentTurnCompleteEvent from(
      JsonNode payload, Integer schemaVersion, String eventId, String timestamp) {
    return new AgentTurnCompleteEvent(
        "agent-turn-complete",
        schemaVersion,
        eventId,
        timestamp,
        payload,
        HookParser.extras(payload, KNOWN_KEYS),
        HookParser.textOrNull(payload.get("cwd")),
        HookParser.stringArrayOrNull(payload.get("input-messages")),
        HookParser.textOrNull(payload.get("last-assistant-message")),
        HookParser.textOrNull(payload.get("thread-id")),
        HookParser.textOrNull(payload.get("turn-id")));
  }
}
