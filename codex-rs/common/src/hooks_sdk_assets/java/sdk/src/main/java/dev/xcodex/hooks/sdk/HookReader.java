package dev.xcodex.hooks.sdk;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * xCodex hooks kit: Java helper library for external hooks.
 *
 * <p>This module is vendored by {@code xcodex hooks install sdks java} into
 * {@code $CODEX_HOME/hooks/templates/java/}.
 *
 * <p>Most external hook programs receive JSON on stdin. For large payloads, stdin is a small JSON
 * envelope containing {@code payload_path}, which points to the full payload JSON file.
 */
public final class HookReader {
  private static final ObjectMapper MAPPER = new ObjectMapper();

  private HookReader() {}

  /**
   * Read a hook payload, handling stdin vs the {@code payload_path} envelope used for large
   * payloads.
   */
  public static JsonNode readPayload(byte[] stdinBytes) throws IOException {
    String raw = stdinBytes.length == 0 ? "{}" : new String(stdinBytes, StandardCharsets.UTF_8);
    JsonNode payload = MAPPER.readTree(raw);
    JsonNode payloadPathNode = payload.get("payload_path");
    if (payloadPathNode == null || !payloadPathNode.isTextual()) {
      payloadPathNode = payload.get("payload-path");
    }
    if (payloadPathNode != null && payloadPathNode.isTextual()) {
      Path payloadPath = Path.of(payloadPathNode.asText());
      String full = Files.readString(payloadPath);
      payload = MAPPER.readTree(full);
    }
    return payload;
  }

  /**
   * Read and parse a hook event from stdin bytes.
   *
   * <p>Unknown event types are returned as {@link UnknownHookEvent}.
   */
  public static HookEvent readEvent(byte[] stdinBytes) throws IOException {
    return HookParser.parse(readPayload(stdinBytes));
  }

  /** Read a hook event from an {@link InputStream}. */
  public static HookEvent readEvent(InputStream stdin) throws IOException {
    return readEvent(stdin.readAllBytes());
  }
}
