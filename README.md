# xCodex (xtreme-Codex)

`xCodex` (short for “xtreme-Codex”) is an independent fork of OpenAI’s Codex CLI.

- Repo: `xCodex`
- Binary: `xcodex`
- Upstream: https://github.com/openai/codex

`xCodex` is not affiliated with, endorsed by, or supported by OpenAI.

---

## Status / stability

This is a fast-moving fork. Some features are experimental, may be incomplete, and can be temporarily broken. Expect rough edges, churn, and occasional behavior changes.

When filing issues, include repro steps and attach the files printed by `/feedback`.

## Highlights

**New in xCodex**

- Keep context under control with `/compact` and `/autocompact` (see [`docs/xcodex/compact.md`](docs/xcodex/compact.md)).
- Hide/show agent thoughts in the TUI with `/thoughts` (see [`docs/xcodex/thoughts.md`](docs/xcodex/thoughts.md)).
- Track your worktrees and branches in the status bar with `/settings` (see [`docs/xcodex/settings.md`](docs/xcodex/settings.md)).
- Switch a session between git worktrees with `/worktree` (see [`docs/xcodex/worktrees.md`](docs/xcodex/worktrees.md)).
- Automate xcodex with hooks (see [`docs/xcodex/hooks.md`](docs/xcodex/hooks.md) and [`docs/xcodex/hooks-python-host.md`](docs/xcodex/hooks-python-host.md)).
- Manage background terminals with `/ps` (list) and `/ps-kill` (terminate) (see [`docs/xcodex/background-terminals.md`](docs/xcodex/background-terminals.md)).

**Fork-only docs**

Fork-specific docs live in `docs/xcodex/` (start at [`docs/xcodex/README.md`](docs/xcodex/README.md)).

## Quickstart

This fork ships an npm distribution (recommended) and also supports building from source.

### Install (npm)

```bash
npm i -g @eriz1818/xcodex
xcodex --version
xcodex
```

Prereleases are published under the `alpha` dist-tag:

```bash
npm i -g @eriz1818/xcodex@alpha
```

### Install (build from source)

See [`docs/install.md`](docs/install.md) for full requirements; the shortest path is:

```bash
# from repo root
cargo install just

# builds codex-rs and installs the CLI as `xcodex` (default: ~/.local/bin/xcodex)
cd codex-rs
just xcodex-install --release

# Default: local Bazel build (no BuildBuddy/remote cache).
# Opt into remote cache/BEP: just xcodex-install --release --remote
# Avoid all network fetches (requires deps already cached): just xcodex-install --release --offline

xcodex --version
xcodex
```

If you prefer not to use `just`, run:

```bash
scripts/install-xcodex.sh --release
```

## Usage

## Docs

Codex can access MCP servers. To configure them, refer to the [config docs](./docs/config.md#mcp_servers).

### Large prompts (stdin / file)

For large prompts, avoid putting the prompt on the command line. Read it from a file or stdin instead:

```bash
xcodex --file PROMPT.md
cat PROMPT.md | xcodex
```

### Hooks (automation)

Hooks can receive event payloads containing metadata like `cwd`, and may include truncated tool output previews. Treat hook payloads/logs as potentially sensitive.

**What xcodex supports**

- External hooks (default): spawn a command on lifecycle events; any language/runtime can be used.
- Python Host hooks (recommended for stateful Python): long-lived host process, JSONL over stdin.
- PyO3 hooks (advanced): in-process Python via a separately-built binary.
- Typed hook SDK installers: `xcodex hooks install sdks <sdk>` (Python/Rust/JavaScript/TypeScript/Go/Ruby/Java).

**Performance (rough numbers)**

Measured on macOS 26.2 (arm64), Python 3.11 (event: `tool-call-finished`, payload: 373 bytes):

```bash
cd codex-rs
PYO3_PYTHON=$(command -v python3.11) cargo run -p codex-core --bin hooks_perf --release --features pyo3-hooks -- --python $(command -v python3.11) --iters 20000 --warmup 2000 --external-iters 200 --markdown
```

- External hook (Python, per-event spawn): ~20.2ms/event (includes `serde_json::to_string` + `json.loads`)
- Out-of-proc host (Python, persistent): ~1.98µs/event (JSONL over stdin; includes `serde_json::to_string` + `json.loads`)
- In-proc baseline: ~0.33ns/iter (Rust loop only)
- In-proc PyO3: ~2.22µs/event (includes `serde_json::to_string` + `json.loads` + Python callable)

Start here:

- Hook configuration + supported events: `docs/xcodex/hooks.md`.
- Typed hook SDKs + installers (Python/Rust/JS/TS/Go/Ruby/Java): `docs/xcodex/hooks-sdks.md`.
- Python Host hooks (long-lived “python box”): `docs/xcodex/hooks-python-host.md`.
- PyO3 hooks (in-process; separately built): `docs/xcodex/hooks-pyo3.md`.
- Copy/paste scripts: `examples/hooks/` and `docs/xcodex/hooks-gallery.md`.
- CLI helpers: `xcodex hooks help`, `xcodex hooks init`, `xcodex hooks install sdks list`, `xcodex hooks install samples list`.

### Configuration

Codex CLI supports a rich set of configuration options, with preferences stored in `$CODEX_HOME/config.toml` (default: `~/.xcodex/config.toml` when invoked as `xcodex`). For full configuration options, see [Configuration](./docs/config.md).

### Execpolicy

See the [Execpolicy quickstart](./docs/execpolicy.md) to set up rules that govern what commands Codex can execute.

### Docs & FAQ

- [**Getting started**](./docs/getting-started.md)
  - [CLI usage](./docs/getting-started.md#cli-usage)
  - [Slash Commands](./docs/slash_commands.md)
  - [Running with a prompt as input](./docs/getting-started.md#running-with-a-prompt-as-input)
  - [Example prompts](./docs/getting-started.md#example-prompts)
  - [Custom prompts](./docs/prompts.md)
  - [Memory with AGENTS.md](./docs/getting-started.md#memory-with-agentsmd)
- [**Configuration**](./docs/config.md)
  - [Example config](./docs/example-config.md)
- [**Sandbox & approvals**](./docs/sandbox.md)
- [**Execpolicy quickstart**](./docs/execpolicy.md)
- [**Authentication**](./docs/authentication.md)
  - [Auth methods](./docs/authentication.md#forcing-a-specific-auth-method-advanced)
  - [Login on a "Headless" machine](./docs/authentication.md#connecting-on-a-headless-machine)
- **Automating Codex**
  - [GitHub Action](https://github.com/openai/codex-action)
  - [TypeScript SDK](./sdk/typescript/README.md)
  - [Non-interactive mode (`xcodex exec`)](./docs/exec.md)
- [**Advanced**](./docs/advanced.md)
  - [Tracing / verbose logging](./docs/advanced.md#tracing--verbose-logging)
  - [Model Context Protocol (MCP)](./docs/advanced.md#model-context-protocol-mcp)
- [**Zero data retention (ZDR)**](./docs/zdr.md)
- [**Contributing**](./docs/contributing.md)
- [**Installing & building**](./docs/install.md)
- [**Open source fund**](./docs/open-source-fund.md)

---

## Support

For `xCodex` issues/bugs/feature requests, please use this repository’s issue tracker (not upstream).

---

## License & attribution

This repository is licensed under the [Apache-2.0 License](LICENSE).

See [NOTICE](NOTICE) for upstream attribution and third-party notices. OpenAI and Codex are trademarks of their respective owners.
