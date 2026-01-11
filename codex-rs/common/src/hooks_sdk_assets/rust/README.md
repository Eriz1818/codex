# Rust hook template

This folder is part of the **xCodex hooks kit**.

`xcodex hooks install sdks rust` installs:

- `$CODEX_HOME/hooks/templates/rust/` (this template)
- `$CODEX_HOME/hooks/sdk/rust/` (the `codex-hooks-sdk` library crate)

Docs:
- Hooks overview: `docs/xcodex/hooks.md`
- Hook SDK installers: `docs/xcodex/hooks-sdks.md`
- Authoritative config reference: `docs/config.md#hooks`

This folder is a small Cargo project you can build into a hook binary.

## Build

```sh
cargo build --release
```

Binary output will be under `target/release/`.

## Configure

```toml
[hooks]
tool_call_finished = [["/absolute/path/to/target/release/xcodex-hooks-rust-template"]]
```
