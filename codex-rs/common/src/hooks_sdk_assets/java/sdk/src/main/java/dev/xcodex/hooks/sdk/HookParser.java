package dev.xcodex.hooks.sdk;

import com.fasterxml.jackson.databind.JsonNode;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

final class HookParser {
  private static final Set<String> BASE_KEYS =
      Set.of("schema-version", "event-id", "timestamp", "type", "payload-path");

  private HookParser() {}

  static HookEvent parse(JsonNode payload) {
    if (payload == null) {
      return new UnknownHookEvent(null, null, null, null, null, Map.of());
    }

    if (!payload.isObject()) {
      return new UnknownHookEvent(
          textOrNull(payload.get("type")),
          intOrNull(payload.get("schema-version")),
          textOrNull(payload.get("event-id")),
          textOrNull(payload.get("timestamp")),
          payload,
          Map.of());
    }

    String type = textOrNull(payload.get("type"));
    Integer schemaVersion = intOrNull(payload.get("schema-version"));
    String eventId = textOrNull(payload.get("event-id"));
    String timestamp = textOrNull(payload.get("timestamp"));

    if (type == null) {
      return new UnknownHookEvent(null, schemaVersion, eventId, timestamp, payload, extras(payload, BASE_KEYS));
    }

    return switch (type) {
      case "agent-turn-complete" -> AgentTurnCompleteEvent.from(payload, schemaVersion, eventId, timestamp);
      case "approval-requested" -> ApprovalRequestedEvent.from(payload, schemaVersion, eventId, timestamp);
      case "session-start" -> SessionStartEvent.from(payload, schemaVersion, eventId, timestamp);
      case "session-end" -> SessionEndEvent.from(payload, schemaVersion, eventId, timestamp);
      case "model-request-started" -> ModelRequestStartedEvent.from(payload, schemaVersion, eventId, timestamp);
      case "model-response-completed" -> ModelResponseCompletedEvent.from(payload, schemaVersion, eventId, timestamp);
      case "tool-call-started" -> ToolCallStartedEvent.from(payload, schemaVersion, eventId, timestamp);
      case "tool-call-finished" -> ToolCallFinishedEvent.from(payload, schemaVersion, eventId, timestamp);
      default -> new UnknownHookEvent(type, schemaVersion, eventId, timestamp, payload, extras(payload, BASE_KEYS));
    };
  }

  static Map<String, JsonNode> extras(JsonNode payload, Set<String> knownKeys) {
    Map<String, JsonNode> out = new LinkedHashMap<>();
    payload.fields().forEachRemaining(entry -> {
      if (!knownKeys.contains(entry.getKey())) {
        out.put(entry.getKey(), entry.getValue());
      }
    });
    return Map.copyOf(out);
  }

  static String textOrNull(JsonNode node) {
    if (node == null || node.isNull()) {
      return null;
    }
    if (!node.isTextual()) {
      return node.asText();
    }
    return node.asText();
  }

  static Integer intOrNull(JsonNode node) {
    if (node == null || node.isNull()) {
      return null;
    }
    if (!node.isNumber()) {
      return null;
    }
    return node.asInt();
  }

  static Long longOrNull(JsonNode node) {
    if (node == null || node.isNull()) {
      return null;
    }
    if (!node.isNumber()) {
      return null;
    }
    return node.asLong();
  }

  static Boolean boolOrNull(JsonNode node) {
    if (node == null || node.isNull()) {
      return null;
    }
    if (!node.isBoolean()) {
      return null;
    }
    return node.asBoolean();
  }

  static List<String> stringArrayOrNull(JsonNode node) {
    if (node == null || node.isNull()) {
      return null;
    }
    if (!node.isArray()) {
      return null;
    }
    List<String> out = new ArrayList<>();
    for (JsonNode item : node) {
      if (item == null || item.isNull()) {
        continue;
      }
      out.add(item.asText());
    }
    return out;
  }
}
