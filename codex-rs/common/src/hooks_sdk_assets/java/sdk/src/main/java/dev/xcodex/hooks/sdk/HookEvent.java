package dev.xcodex.hooks.sdk;

import com.fasterxml.jackson.databind.JsonNode;
import java.util.Map;

/** Base interface for all parsed external hook events. */
public sealed interface HookEvent
    permits AgentTurnCompleteEvent,
        ApprovalRequestedEvent,
        ModelRequestStartedEvent,
        ModelResponseCompletedEvent,
        SessionEndEvent,
        SessionStartEvent,
        ToolCallFinishedEvent,
        ToolCallStartedEvent,
        UnknownHookEvent {
  String type();

  Integer schemaVersion();

  String eventId();

  String timestamp();

  JsonNode raw();

  Map<String, JsonNode> extra();
}
