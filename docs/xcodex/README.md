# xcodex (xtreme-codex)

xcodex (xtreme-codex) is an effort to add features to upstream Codex CLI.

## Status

- Slash commands: `/compact`, `/autocompact`, and `/thoughts` are working.
- Background terminals: `/ps` lists running background terminals and hooks; `/ps-kill` can terminate background terminals.
- Hooks: basic automation hooks are in place.
- Other features are in progress; expect rough edges and some churn.

## What’s here

- Hooks: `docs/xcodex/hooks.md`
- Keeping context under control: `docs/xcodex/compact.md`
- Hiding thoughts: `docs/xcodex/thoughts.md`
- Background terminals: `docs/xcodex/background-terminals.md`

## Local install (as `xcodex`)

To build the current working tree and install it as `xcodex` locally:

```sh
just xcodex-install
```

This installs to `~/.local/bin/xcodex` by default.

## Coexisting with upstream `codex`

- Home directory: when invoked as `xcodex` and `CODEX_HOME` is unset, the default home is `~/.xcodex` (upstream `codex` remains `~/.codex`).
- MCP OAuth tokens: `xcodex` stores keyring-backed MCP OAuth tokens under a separate keyring service name from upstream `codex`, so refreshing/deleting tokens in `xcodex` won’t impact upstream `codex`.
- Hooks: hooks are configured under `$CODEX_HOME/config.toml`; with separate default homes, hooks you configure/run via `xcodex` won’t affect upstream `codex` unless you intentionally set `CODEX_HOME=~/.codex`.

## First run setup wizard

On first interactive run, `xcodex` may prompt to initialize its own home directory. You can:

- Start from scratch.
- Copy all from an existing codex home (includes sensitive data like `.credentials.json` and `history.jsonl`).
- Select what you copy from an existing codex home (scan-derived checklist with a “Select all” option).

`xcodex` does not overwrite existing destination files during the copy step.

Non-interactive `xcodex exec` requires first-run setup to be complete; if setup is missing, it fails fast and tells you to run `xcodex` once (or set `CODEX_HOME` to an initialized directory).

## Troubleshooting

### Re-run the setup wizard

The setup wizard runs when both of these are true:

- `$CODEX_HOME/config.toml` does not exist
- `$CODEX_HOME/.xcodex-first-run-wizard.complete` does not exist

To re-run the wizard without deleting anything, rename the directory (recommended), then start `xcodex` again:

```sh
mv "${CODEX_HOME:-$HOME/.xcodex}" "${CODEX_HOME:-$HOME/.xcodex}.bak"
xcodex
```

If you prefer a targeted reset, remove (or rename) both files in your xcodex home and rerun `xcodex`:

```sh
mv "${CODEX_HOME:-$HOME/.xcodex}/config.toml" "${CODEX_HOME:-$HOME/.xcodex}/config.toml.bak"
mv "${CODEX_HOME:-$HOME/.xcodex}/.xcodex-first-run-wizard.complete" "${CODEX_HOME:-$HOME/.xcodex}/.xcodex-first-run-wizard.complete.bak"
xcodex
```

### Use a fresh home directory

If you want to keep your current xcodex home intact, point `CODEX_HOME` at a new directory:

```sh
export CODEX_HOME="$HOME/.xcodex-new"
xcodex
```
