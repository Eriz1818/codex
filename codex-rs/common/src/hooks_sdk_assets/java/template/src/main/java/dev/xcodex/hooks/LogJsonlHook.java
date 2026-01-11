package dev.xcodex.hooks;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.xcodex.hooks.sdk.HookReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;

/**
 * xCodex hooks kit: Java template hook (logs payloads to hooks.jsonl).
 *
 * <p>This is a template you copy and edit. It shows how to:
 *
 * <ul>
 *   <li>Read the hook payload from stdin (including payload_path envelopes)</li>
 *   <li>Write a simple JSONL log under {@code $CODEX_HOME}</li>
 * </ul>
 */
public final class LogJsonlHook {
  private static final ObjectMapper MAPPER = new ObjectMapper();

  public static void main(String[] args) throws IOException {
    JsonNode payload = HookReader.readPayload(System.in.readAllBytes());

    String codexHome = System.getenv("CODEX_HOME");
    if (codexHome == null || codexHome.isEmpty()) {
      codexHome = Path.of(System.getProperty("user.home"), ".xcodex").toString();
    }

    Path outPath = Path.of(codexHome, "hooks.jsonl");
    Files.createDirectories(outPath.getParent());
    String line = MAPPER.writeValueAsString(payload) + "\n";
    Files.writeString(outPath, line, StandardOpenOption.CREATE, StandardOpenOption.APPEND);
  }
}
