# xcodex hooks (automation)

xcodex includes an “automation hooks” system: it can emit lifecycle events and either:

- spawn one-shot external commands (default),
- stream events to a long-lived host process (recommended for stateful Python), or
- run an experimental in-process PyO3 hook bridge (advanced; separate build).

Hooks are **observer-only** and **fire-and-forget**: failures are logged and do not block the run.

The authoritative configuration reference is `docs/config.md#hooks`.

## Hook modes (pick one)

| Mode | What it is | When to use | Docs |
|---|---|---|---|
| External hooks (spawn per event) | Spawn a command for each event; payload JSON on stdin (envelope for large payloads) | Safest/most portable; easiest to debug | `docs/xcodex/hooks-sdks.md` |
| Python Host hooks (long-lived) | One long-lived process receives hook events as JSONL | Stateful Python hooks without per-event spawn overhead | `docs/xcodex/hooks-python-host.md` |
| PyO3 hooks (in-proc) | Python runs inside xcodex via PyO3 | Advanced power users; trusted code only | `docs/xcodex/hooks-pyo3.md` |

## Performance

Measured via `hooks_perf` (release build, Python `3.11.14`, payload `373` bytes), repeated 3 times:

| Mode | Approx cost | Throughput |
|---|---:|---:|
| External hook (Python per-event spawn) | ~20.87–21.48 ms/event | ~47–48 ev/s |
| Python Host (persistent “py-box”) | ~1.88–1.90 µs/event | ~526k–532k ev/s |
| In-proc PyO3 | ~1.38–1.45 µs/event | ~690k–725k ev/s |

Larger payloads (dominant costs: JSON serialization + Python JSON parsing for Host; PyO3 avoids per-event `json.loads`):

| Payload size | External spawn | Python Host (“py-box”) | In-proc PyO3 |
|---:|---:|---:|---:|
| ~12 KB (`12040` bytes) | 20.98–22.07 ms/event | 11.71–12.85 µs/event | 2.09–2.48 µs/event |
| ~20 KB (`20040` bytes) | 21.80–22.37 ms/event | 17.41–19.55 µs/event | 2.35–2.84 µs/event |
| ~200 KB (`200040` bytes) | 24.03–24.51 ms/event | 162.56–170.48 µs/event | 12.19–13.49 µs/event |

To reproduce locally:

```sh
cd codex-rs
PY=$(command -v python3.11)
PYO3_PYTHON=$PY cargo run -p codex-core --bin hooks_perf --release --features pyo3-hooks -- --python "$PY" --iters 20000 --warmup 2000 --external-iters 200 --payload-bytes 373 --markdown
```

Use `--payload-bytes 12020`, `20020`, and `200020` to reproduce the larger-payload rows.

## Quickstart (guided)

The easiest way to start is the guided menu:

```sh
xcodex hooks init
```

Pass `--edit-config` to have `xcodex` update `CODEX_HOME/config.toml` directly (best-effort); otherwise it prints a snippet to paste.

Then:

```sh
xcodex hooks list
xcodex hooks paths
xcodex hooks install sdks list
xcodex hooks install samples list
xcodex hooks test external --configured-only
xcodex hooks test python-host --configured-only
xcodex hooks test pyo3 --configured-only
```

## Supported events

External hooks receive a single “payload object” per event (via stdin). The payload always includes:

- `schema_version`: currently `1`
- `event_id`: unique id for the event
- `timestamp`: RFC3339 timestamp
- `session_id`: session/thread id
- `cwd`: current working directory (best-effort)
- `hook_event_name`: the configured event name that triggered this hook (for `hooks.command`), or a default Claude-style name for other modes
- `xcodex_event_type`: canonical xcodex event type string (for example `tool-call-finished`)

Supported xcodex event types (via `xcodex_event_type`):

- `session-start`
- `session-end`
- `model-request-started`
- `model-response-completed`
- `tool-call-started`
- `tool-call-finished`
- `agent-turn-complete`
- `approval-requested`

Event parity: these same event types are emitted regardless of hook mode (external, Python Host, or PyO3). Python Host wraps the payload in a JSONL object with an `event` field; the `event` value is the same payload object external hooks receive.

## Configuration

See `docs/config.md#hooks` for the full config surface. High-level:

- External hooks: prefer `hooks.command` (matcher + per-hook options); legacy `[hooks]` argv arrays are still supported.
- Python Host hooks: configure `[hooks.host]` and a `command = [...]` argv to start the host process.
- PyO3 hooks: require `hooks.enable_unsafe_inproc = true`, `hooks.inproc = ["pyo3"]`, and a separately-built PyO3-enabled binary.
- Claude/OpenCode config compatibility: configure Claude-style events/matchers in `hooks.command`. See `docs/xcodex/hooks-claude-compat.md`.

## Where hook code lives

Hook code is **not required** to live in `CODEX_HOME`, but some modes have convenient defaults.

- External hooks (spawn per event):
  - Your hook is configured either in `hooks.command` (recommended) or legacy `[hooks]` argv arrays (for example `["python3", "/absolute/path/hook.py"]`).
  - The script/binary can live anywhere, but you should prefer **absolute paths** so it works no matter what directory you run `xcodex` from.
- Python Host (long-lived):
  - Your host is started via `hooks.host.command = [...]`.
  - The host process is spawned with `cwd=CODEX_HOME`, so **relative paths in the argv are resolved from `CODEX_HOME`**.
  - The host can load hook scripts from anywhere (absolute paths) or from within `CODEX_HOME` (relative paths).
- PyO3 (in-process):
  - Your Python hook is configured via `hooks.pyo3.script_path`.
  - If it’s relative, it’s resolved as `CODEX_HOME/<path>`. If it’s absolute, it can live anywhere.
  - Optional batching: if you set `hooks.pyo3.batch_size = N` (N>1) and your script defines `on_events(events: list[dict]) -> None`, xcodex will call `on_events` with batches (otherwise it falls back to `on_event(event: dict)`).

## Payload delivery (stdin + file fallback)

For small payloads, xcodex writes the full JSON payload to stdin.

For large payloads, xcodex writes the full payload JSON to a file under `CODEX_HOME` and writes a small JSON envelope to stdin containing `payload_path`. Hook scripts should handle both cases.

While the TUI is running, hook stdout/stderr are redirected to log files under `CODEX_HOME` so hooks do not corrupt the terminal UI.

## Testing hooks before running a session

You can exercise your configured hooks with synthetic events, without waiting for real session events:

- External hooks: `xcodex hooks test external` (spawns your configured `hooks.command` and legacy `[hooks]` commands).
- Python Host: `xcodex hooks test python-host` (spawns your configured `hooks.host.command`, sends one JSONL event, then expects a clean exit).
- PyO3: `xcodex hooks test pyo3` is a configuration/gating preflight; to actually execute the PyO3 hook, run the PyO3-enabled binary and trigger real events.

Logs and payload dumps are written under `CODEX_HOME/tmp/hooks/`. Run `xcodex hooks paths` to see the exact directories.

## Command reference

Run `xcodex hooks help` for the full, up-to-date list. Common commands:

- `xcodex hooks init [external|python-host|pyo3]`
- `xcodex hooks install sdks <sdk|all|list> [--dry-run] [--force] [--yes]`
- `xcodex hooks install samples <external|python-host|pyo3|all|list> [--dry-run] [--force] [--yes]`
- `xcodex hooks list`
- `xcodex hooks paths`
- `xcodex hooks doctor <external|python-host|pyo3>`
- `xcodex hooks test <external|python-host|pyo3|all> [--configured-only]`
- `xcodex hooks build pyo3`

## Compatibility policy (payload schema)

This policy applies to:

- hook authors (scripts you run via `[hooks]`)
- “typed hook SDKs” (helpers/templates/types that parse the hook JSON)

`schema_version` is currently `1`.

Payload shape changes are not backwards compatible by default. External hook consumers should parse defensively and treat unknown fields as ignorable.

External hook consumers should be forward compatible:

- treat unknown fields as ignorable
- prefer optional access patterns and safe defaults

## Machine-readable schema

xcodex checks in a generated JSON Schema bundle at:

- `docs/xcodex/hooks.schema.json`
