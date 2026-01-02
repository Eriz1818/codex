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
- Automate xcodex with hooks (session/model/tool lifecycle events; see [`docs/xcodex/hooks.md`](docs/xcodex/hooks.md)).
- Manage background terminals with `/ps` (list) and `/ps-kill` (terminate) (see [`docs/xcodex/background-terminals.md`](docs/xcodex/background-terminals.md)).

**Fork-only docs**

Fork-specific docs live in `docs/xcodex/` (start at [`docs/xcodex/README.md`](docs/xcodex/README.md)).

## Quickstart

This fork does not use the upstream npm/Homebrew installation flow.

### Install (build from source)

See [`docs/install.md`](docs/install.md) for full requirements; the shortest path is:

```bash
# from repo root
cargo install just

# builds codex-rs and installs the CLI as `xcodex` (default: ~/.local/bin/xcodex)
cd codex-rs
just xcodex-install --release

xcodex --version
xcodex
```

If you prefer not to use `just`, run:

```bash
scripts/install-xcodex.sh --release
```

## Usage

### Model Context Protocol (MCP)

Codex can access MCP servers. To configure them, refer to the [config docs](./docs/config.md#mcp_servers).

### Large prompts (stdin / file)

For large prompts, avoid putting the prompt on the command line. Read it from a file or stdin instead:

```bash
xcodex --file PROMPT.md
cat PROMPT.md | xcodex
```

### Hooks (automation)

Hooks can receive event payloads containing metadata like `cwd`, and may include truncated tool output previews. Treat hook payloads/logs as potentially sensitive.

Start here:

- Hook configuration + supported events: `docs/xcodex/hooks.md`.
- Quick smoke test for your hook scripts: `xcodex hooks test --configured-only`.

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
- [**Install & build**](./docs/install.md)
  - [System Requirements](./docs/install.md#system-requirements)
  - [DotSlash](./docs/install.md#dotslash)
  - [Build from source](./docs/install.md#build-from-source)
- [**FAQ**](./docs/faq.md)
- [**Open source fund**](./docs/open-source-fund.md)

---

## Support

For `xCodex` issues/bugs/feature requests, please use this repository’s issue tracker (not upstream).

---

## License & attribution

This repository is licensed under the [Apache-2.0 License](LICENSE).

See [NOTICE](NOTICE) for upstream attribution and third-party notices. OpenAI and Codex are trademarks of their respective owners.
