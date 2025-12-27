<p align="center"><strong>xcodex (xtreme-codex)</strong> is an effort to add features to upstream Codex CLI.</p>

---

## Highlights

**New in this fork**

- Keep context under control with `/compact` and `/autocompact` (see [`docs/xcodex/compact.md`](docs/xcodex/compact.md)).
- Automate Codex with hooks (turn-complete + approval-requested; see [`docs/xcodex/hooks.md`](docs/xcodex/hooks.md)).
- Manage background terminals with `/ps` (list) and `/ps-kill` (terminate) (see [`docs/xcodex/background-terminals.md`](docs/xcodex/background-terminals.md)).
- More features are in progress; expect rough edges and some churn.

## Quickstart

This fork does not use the upstream npm/Homebrew installation flow. Build from source using the instructions in `docs/install.md`, then run the resulting `codex` binary.

### Model Context Protocol (MCP)

Codex can access MCP servers. To configure them, refer to the [config docs](./docs/config.md#mcp_servers).

### Configuration

Codex CLI supports a rich set of configuration options, with preferences stored in `~/.codex/config.toml`. For full configuration options, see [Configuration](./docs/config.md).

### Execpolicy

See the [Execpolicy quickstart](./docs/execpolicy.md) to set up rules that govern what commands Codex can execute.

### Keeping context under control (`/compact`, `/autocompact`)

- Use `/compact` to summarize the conversation and free up context.
- Use `/autocompact` to automatically compact when the conversation gets close to the model’s context limit (supports `on|off|toggle|status` and persists across sessions).

### Fork notes

- `/feedback` saves a local report for troubleshooting (no network upload); attach the files it prints when filing an issue in your fork.
- Fork-specific docs live in `docs/xcodex/`.

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
  - [Non-interactive mode (`codex exec`)](./docs/exec.md)
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

## License

This repository is licensed under the [Apache-2.0 License](LICENSE).
