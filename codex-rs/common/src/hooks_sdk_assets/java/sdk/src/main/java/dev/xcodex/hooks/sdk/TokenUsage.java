package dev.xcodex.hooks.sdk;

import com.fasterxml.jackson.databind.JsonNode;

public record TokenUsage(
    Long cachedInputTokens,
    Long inputTokens,
    Long outputTokens,
    Long reasoningOutputTokens,
    Long totalTokens) {
  static TokenUsage fromJson(JsonNode node) {
    if (node == null || node.isNull()) {
      return null;
    }
    return new TokenUsage(
        HookParser.longOrNull(node.get("cached_input_tokens")),
        HookParser.longOrNull(node.get("input_tokens")),
        HookParser.longOrNull(node.get("output_tokens")),
        HookParser.longOrNull(node.get("reasoning_output_tokens")),
        HookParser.longOrNull(node.get("total_tokens")));
  }
}
