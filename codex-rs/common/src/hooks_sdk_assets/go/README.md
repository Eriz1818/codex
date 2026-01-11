# Go hook template

This folder is part of the **xCodex hooks kit**. It is installed under
`$CODEX_HOME/hooks/templates/go/` by:

```sh
xcodex hooks install sdks go
```

Docs:
- Hooks overview: `docs/xcodex/hooks.md`
- Hook SDK installers: `docs/xcodex/hooks-sdks.md`
- Authoritative config reference: `docs/config.md#hooks`

This folder is a small Go module you can build into a hook binary.

## Build

```sh
go build -o hook-log-jsonl ./cmd/log_jsonl
```

## Configure

```toml
[hooks]
tool_call_finished = [["/absolute/path/to/hook-log-jsonl"]]
```
