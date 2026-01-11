/**
 * xCodex hooks kit: TypeScript template hook (logs payloads to hooks.jsonl).
 *
 * This file is installed under `$CODEX_HOME/hooks/templates/ts/`. It imports
 * the Node helper from `$CODEX_HOME/hooks/xcodex_hooks.mjs`.
 *
 * Note: This is a template source file. You typically compile it to JS before
 * wiring it into `config.toml`, or run it with `ts-node`.
 */
import fs from "node:fs";
import path from "node:path";
import process from "node:process";

// Load the shared helper from `$CODEX_HOME/hooks/xcodex_hooks.mjs`.
import { readPayload } from "../../xcodex_hooks.mjs";

const payload = readPayload();
// Add your logic here. This template just logs the full payload.
const codexHome = process.env.CODEX_HOME ?? path.join(process.env.HOME ?? "", ".xcodex");
const outPath = path.join(codexHome, "hooks.jsonl");
fs.mkdirSync(path.dirname(outPath), { recursive: true });
fs.appendFileSync(outPath, JSON.stringify(payload) + "\n");
