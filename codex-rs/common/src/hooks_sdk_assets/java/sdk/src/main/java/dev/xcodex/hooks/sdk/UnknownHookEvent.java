package dev.xcodex.hooks.sdk;

import com.fasterxml.jackson.databind.JsonNode;
import java.util.Map;

public record UnknownHookEvent(
    String type,
    Integer schemaVersion,
    String eventId,
    String timestamp,
    JsonNode raw,
    Map<String, JsonNode> extra)
    implements HookEvent {}
