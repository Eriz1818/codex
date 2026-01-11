#!/usr/bin/env node
/**
 * xCodex hooks kit: Node.js template hook (logs payloads to hooks.jsonl).
 *
 * This file is installed under `$CODEX_HOME/hooks/templates/js/` and is meant
 * as a starting point you copy and edit.
 *
 * It imports the shared helper from `$CODEX_HOME/hooks/xcodex_hooks.mjs`,
 * installed by:
 *
 *   xcodex hooks install sdks javascript
 */
import fs from "node:fs";
import path from "node:path";
import process from "node:process";

// Load the shared helper from `$CODEX_HOME/hooks/xcodex_hooks.mjs`.
import { readPayload } from "../../xcodex_hooks.mjs";

function main() {
  // Parse the event payload (handles stdin vs payload_path envelopes).
  const payload = readPayload();

  // Add your logic here. This template just logs the full payload.
  const codexHome = process.env.CODEX_HOME ?? path.join(process.env.HOME ?? "", ".xcodex");
  const outPath = path.join(codexHome, "hooks.jsonl");
  fs.mkdirSync(path.dirname(outPath), { recursive: true });
  fs.appendFileSync(outPath, JSON.stringify(payload) + "\n");
}

main();
