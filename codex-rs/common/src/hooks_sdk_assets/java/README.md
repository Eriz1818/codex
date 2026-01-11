# Java hook template

This folder is part of the **xCodex hooks kit**. It is installed under
`$CODEX_HOME/hooks/templates/java/` by:

```sh
xcodex hooks install sdks java
```

Docs:
- Hooks overview: `docs/xcodex/hooks.md`
- Hook SDK installers: `docs/xcodex/hooks-sdks.md`
- Authoritative config reference: `docs/config.md#hooks`

This folder is a small Maven multi-module project:

- `sdk/`: reusable hook SDK library (`HookReader`, typed events)
- `template/`: a runnable example hook (logs payloads to `hooks.jsonl`)

## Build

```sh
mvn -q -DskipTests -pl template -am package dependency:copy-dependencies
```

Then run the hook with something like:

```sh
java -cp "template/target/classes:template/target/dependency/*" dev.xcodex.hooks.LogJsonlHook
```

## Configure

```toml
[hooks]
tool_call_finished = [["java", "-cp", "/absolute/path/to/...", "dev.xcodex.hooks.LogJsonlHook"]]
```
