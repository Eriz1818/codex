# PyO3 hooks (in-process; separately built)

PyO3 hooks run **in-process** inside xcodex (observer-only). They are advanced and higher-risk than external hooks.

Important:

- PyO3 support is not included in the default `xcodex` build.
- You must build/install a separate PyO3-enabled binary (this is effectively “build xcodex from source with PyO3 enabled”).
- PyO3 hooks are gated at runtime by `hooks.enable_unsafe_inproc = true`.

For most Python automation, prefer **Python Host hooks** (`docs/xcodex/hooks-python-host.md`): similar performance, but out-of-process.

Event parity: your PyO3 hook callable receives the same event payload object shape and event types as external hooks.

## Quickstart (guided)

1) Run the prerequisite checker:

```sh
xcodex hooks doctor pyo3
```

2) Build/install a PyO3-enabled binary (side-by-side):

```sh
xcodex hooks build pyo3
```

This flow clones the repo and compiles an `xcodex-pyo3` binary (it does not modify your existing `xcodex`).
By default, it checks out a pinned commit for reproducibility (override with `xcodex hooks build pyo3 --ref <commit|tag|branch>`).

3) Install a runnable sample hook script into your `CODEX_HOME`:

```sh
xcodex hooks install samples pyo3
```

This shows a plan and asks for confirmation before writing files (use `--yes` to skip the prompt).

4) Paste the printed snippet into `CODEX_HOME/config.toml`, then run your PyO3-enabled binary (default: `xcodex-pyo3`).

5) Smoke-test configuration:

```sh
xcodex hooks test pyo3 --configured-only
```

This is a configuration/gating preflight; it does not execute your Python hook callable. To exercise the hook logic, run your PyO3-enabled binary and trigger real events.

## Where to keep your PyO3 hook script

PyO3 hooks are configured via `hooks.pyo3.script_path` in `config.toml`.

- If `hooks.pyo3.script_path` is an **absolute path**, the file can live anywhere.
- If it’s a **relative path**, it’s resolved as `CODEX_HOME/<path>`.
- The sample installer writes `CODEX_HOME/hooks/pyo3_hook.py` and configures a relative `hooks.pyo3.script_path = "hooks/pyo3_hook.py"`.

## Command summary

- `xcodex hooks doctor pyo3`
- `xcodex hooks build pyo3`
- `xcodex hooks install samples pyo3 [--dry-run] [--force] [--yes]`
- `xcodex hooks test pyo3 [--configured-only]`
- `xcodex hooks paths`

## Contributor checks

```sh
cd codex-rs
cargo test -p codex-cli --test hooks
```

If you have a local PyO3 setup and want to run the feature-gated test:

```sh
cd codex-rs
cargo test -p codex-core --features pyo3-hooks hooks::tests::pyo3_inproc_hook_calls_python_on_event
```
