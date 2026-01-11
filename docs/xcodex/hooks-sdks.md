# Typed external hook SDKs

These SDKs are small, optional helpers/templates for writing **external hooks** in various languages.

They do **not** change how hooks run: external hooks are still executed as commands configured under `[hooks]` and receive event JSON on stdin (with `payload_path` envelopes for large payloads).

The installed files are intentionally “readable first”: you should be able to open them in `$CODEX_HOME/hooks/` and understand the hook flow just by reading the comments/docstrings.

## Packaging (optional)

You do **not** need any published packages (PyPI / npm / crates.io / Maven Central) to use these SDKs.

`xcodex hooks install sdks ...` vendors the helpers/templates directly into `$CODEX_HOME/hooks/`.

Notes:
- Script-based templates (Python/Node/Ruby) run as-is (you just need the language runtime installed).
- Compiled templates (Go/Rust/Java) are small project skeletons; you build them using your normal toolchain (Go / Cargo / Maven).

## Templates vs libraries

Some SDKs are just single-file helpers (meant to be copied), while others are reusable “real” libraries:

- Templates: example hooks under `$CODEX_HOME/hooks/templates/` that you copy and customize.
- Libraries: reusable code installed under `$CODEX_HOME/hooks/sdk/` that templates depend on, so parsing logic doesn’t drift across copies.

## Install

Install SDK helpers into your active `CODEX_HOME`:

```sh
xcodex hooks install sdks list
xcodex hooks install sdks python
xcodex hooks install sdks javascript
xcodex hooks install sdks typescript
xcodex hooks install sdks ruby
xcodex hooks install sdks go
xcodex hooks install sdks rust
xcodex hooks install sdks java
```

To install everything (or overwrite existing files), use:

```sh
xcodex hooks install sdks all
xcodex hooks install sdks all --force
```

In the TUI / TUI2 you can also run:

```text
/hooks install sdks list
/hooks install sdks python --yes
/hooks install sdks all --force --yes
```

Note: `xcodex hooks init external` scaffolds external-hook Python examples under `$CODEX_HOME/hooks/` and installs the Python helper (`xcodex_hooks.py`) so the examples work out of the box.

## Command summary

- `xcodex hooks init external`
- `xcodex hooks install sdks <sdk|all|list> [--dry-run] [--force] [--yes]`
- `xcodex hooks install samples external [--dry-run] [--force] [--yes]`
- `xcodex hooks doctor external`
- `xcodex hooks test external [--timeout-seconds N] [--configured-only] [--event ...]`
- `xcodex hooks paths`

## What gets installed

Files are written under:

- `$CODEX_HOME/hooks/` (shared helpers like `xcodex_hooks.py`, `xcodex_hooks.mjs`, `xcodex_hooks.rb`)
- `$CODEX_HOME/hooks/templates/` (ready-to-run templates, including Go/Rust/Java project skeletons)
- `$CODEX_HOME/hooks/sdk/` (installed libraries used by some templates)

## Where to keep your hook code

External hooks are just commands configured under `[hooks]`. Your hook scripts/binaries can live anywhere.

Recommendations:

- Prefer **absolute paths** in `config.toml` so hooks work regardless of where you run `xcodex` from.
- `$CODEX_HOME/hooks/` is a convenient place to keep personal hook scripts if you want everything self-contained (the SDK installer already puts templates/helpers there).

Python-specific notes:
- `xcodex_hooks.py` is the main helper (`read_payload()` and `read_payload_model()`).
- `xcodex_hooks_types.py` contains generated `TypedDict` event types.
- `xcodex_hooks_models.py` contains generated dataclass models + `parse_hook_event(...)` with light coercions.
- `xcodex_hooks_runtime.py` contains `TypeGuard` helpers like `is_tool_call_finished(...)`.

Rust-specific notes:
- `$CODEX_HOME/hooks/sdk/rust/` is an installed copy of the `codex-hooks-sdk` crate (tolerant stdin/envelope parsing + typed events).
- The Rust template under `$CODEX_HOME/hooks/templates/rust/` depends on that local crate (no copy-pasted parsing helpers).

Java-specific notes:
- `$CODEX_HOME/hooks/templates/java/` is a small Maven multi-module project:
  - `sdk/` contains the reusable library (`HookReader`, typed `HookEvent` models, unknown-field preservation via `extra()`).
  - `template/` contains a runnable example hook.

## Next steps

1) Pick a template from `$CODEX_HOME/hooks/templates/` and customize it.

2) Configure it in `config.toml`:

```toml
[hooks]
tool_call_finished = [["python3", "/absolute/path/to/your_hook.py"]]
```

For the full hooks contract (events + payloads), see `docs/xcodex/hooks.md` and `docs/config.md#hooks`.

## Testing before running a session

To exercise your configured external hook commands with synthetic events (without starting a real session), run:

```sh
xcodex hooks test external
```

## Toward “fully typed” SDKs

Today’s SDK installers focus on the most error-prone part of hook authoring: correctly handling stdin vs the `payload_path` envelope.

To make the SDKs *fully typed* across languages, we should:

1) Define a single “payload contract” document and compatibility policy (forward-compatible parsing, unknown fields, how `schema_version` evolves).
2) Generate a machine-readable schema from the Rust source-of-truth (`codex_core::hooks::{HookPayload, HookNotification, ...}`), e.g. JSON Schema.
3) Generate language-specific types (TS `.d.ts`, Python TypedDicts, Go structs, etc.) from that schema, and keep generation in CI.

The key is to keep the SDK parsers tolerant (unknown fields/types should not break hooks) while still providing strong typing for known events.

### Compatibility policy

The compatibility policy for external hook payloads is documented in:

- `docs/xcodex/hooks.md` (“Compatibility policy (payload schema)”)

If you’re writing hooks or SDKs, that section is the source of truth for:

- What `schema_version` means (and when it bumps)
- How unknown fields / unknown event types must be handled
- Why `payload_path` is treated as a transport envelope detail (SDK responsibility)

### Machine-readable schema

xcodex checks in a generated JSON Schema bundle at:

- `docs/xcodex/hooks.schema.json`

To regenerate it after hook payload changes:

```sh
cd codex-rs
cargo run -p codex-core --bin hooks_schema --features hooks-schema --quiet > ../docs/xcodex/hooks.schema.json
```

The TypeScript `.d.ts` installed by `xcodex hooks install sdks {javascript,typescript}` is also generated from the Rust source of truth:

```sh
cd codex-rs
cargo run -p codex-core --bin hooks_typescript --features hooks-schema --quiet > common/src/hooks_sdk_assets/js/xcodex_hooks.d.ts
```

Python types are generated too:

```sh
cd codex-rs
cargo run -p codex-core --bin hooks_python_types --features hooks-schema --quiet \
  > common/src/hooks_sdk_assets/python/xcodex_hooks_types.py
```

Python runtime models (dataclasses) are generated too:

```sh
cd codex-rs
cargo run -p codex-core --bin hooks_python_models --features hooks-schema --quiet \
  > common/src/hooks_sdk_assets/python/xcodex_hooks_models.py
```

Go types are generated too:

```sh
cd codex-rs
cargo run -p codex-core --bin hooks_go_types --features hooks-schema --quiet \
  > common/src/hooks_sdk_assets/go/hooksdk/types.go
```

## Contributor checks

```sh
cd codex-rs
cargo test -p codex-cli --test hooks
just hooks-codegen-check
```

Optional (requires Docker):

```sh
cd codex-rs
just hooks-templates-smoke
```
