/**
 * xCodex hooks kit: Node.js helper.
 *
 * Install into `$CODEX_HOME/hooks/` with:
 *
 *   xcodex hooks install sdks javascript
 *
 * This helper focuses on the most error-prone part of external hook authoring:
 * handling stdin vs the `payload_path` envelope used for large payloads.
 *
 * Docs:
 * - Hooks overview: docs/xcodex/hooks.md
 * - Hook SDK installers: docs/xcodex/hooks-sdks.md
 * - Authoritative config reference: docs/config.md#hooks
 */

import fs from "node:fs";

/**
 * Read a hook payload as a plain JS object.
 *
 * @param {string | undefined} raw - Optional raw stdin string; if omitted, reads from fd 0.
 * @returns {any} - The full payload object for the event.
 */
export function readPayload(raw) {
  const text = raw ?? fs.readFileSync(0, "utf8");
  const payload = JSON.parse(text || "{}");
  const payloadPath = payload["payload_path"] ?? payload["payload-path"];
  if (payloadPath) {
    return JSON.parse(fs.readFileSync(payloadPath, "utf8"));
  }
  return payload;
}
