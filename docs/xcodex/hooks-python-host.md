# Python Host hooks (long-lived “python box”)

Python Host hooks are a **long-lived** hook process that receives hook events over stdin as JSONL.

This is the recommended way to write **stateful Python hooks** without paying per-event process spawn overhead, and without needing a separately built PyO3-enabled binary.

Event parity: the host receives the same event types as external hooks. Each JSONL line contains an `event` object that matches the external hook payload shape.

## Quickstart (no code required)

1) Install the runnable sample files into your active `CODEX_HOME`:

```sh
xcodex hooks install samples python-host
```

This shows a plan and asks for confirmation before writing files (use `--yes` to skip the prompt).

2) Paste the printed snippet into `CODEX_HOME/config.toml` (defaults to `~/.xcodex/config.toml`).

3) Test the configured host without running a full session:

```sh
xcodex hooks test python-host --configured-only
```

This spawns your configured `hooks.host.command`, writes a single JSONL hook event to stdin, then closes stdin; the host should exit cleanly on EOF.

4) Verify output:

- The reference example hook appends lines to `CODEX_HOME/hooks-host-tool-calls.log`.
- Host logs go under `CODEX_HOME/tmp/hooks/host/logs/`.

To see paths, run:

```sh
xcodex hooks paths
```

## Where to keep your host + hook scripts

- The sample installer writes files under `CODEX_HOME/hooks/` (for example `hooks/host/python/host.py` and `hooks/host/python/example_hook.py`).
- Your host script and hook scripts are **not required** to live in `CODEX_HOME`. Absolute paths work fine.
- The host process is spawned with `cwd=CODEX_HOME`, so relative paths in `hooks.host.command` are resolved from `CODEX_HOME`.

## Choosing your Python version

xcodex does not manage Python versions for the host. You choose the interpreter by setting the first argv entry in `hooks.host.command`, for example:

```toml
[hooks.host]
enabled = true
command = ["python3.12", "-u", "hooks/host/python/host.py", "hooks/host/python/example_hook.py"]
```

Notes:

- `hooks.host.command` is argv (no shell expansion).
- The host process is spawned with `cwd=CODEX_HOME`, so relative paths in the argv are resolved from `CODEX_HOME`.

## Command summary

- `xcodex hooks init python-host`
- `xcodex hooks install samples python-host [--dry-run] [--force] [--yes]`
- `xcodex hooks doctor python-host`
- `xcodex hooks test python-host [--timeout-seconds N] [--configured-only]`
- `xcodex hooks paths`

## TUI / TUI2

Inside the interactive TUI/TUI2 you can run:

```text
/hooks init
/hooks install samples python-host --yes
```

## Contributor checks

```sh
cd codex-rs
cargo test -p codex-cli --test hooks
cargo test -p codex-core hooks::tests::hook_host_receives_events
```

Optional (requires Docker for the template smoke test):

```sh
cd codex-rs
just hooks-codegen-check
just hooks-templates-smoke
```
