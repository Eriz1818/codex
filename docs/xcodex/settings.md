# Settings (`/settings`)

`/settings` exposes a small set of runtime/persistent configuration toggles for `xcodex`.

Today, `xcodex` renders settings as an inline “card” in the transcript (not a full-screen menu).

## Status bar items

`xcodex` can optionally show additional items in the footer status bar, behind toggles.

The values shown are derived from the session’s working directory (the same directory shown in `/status`), so different sessions can show different branches/worktrees.

### Toggle via `/settings`

```text
/settings status-bar git-branch [on|off|toggle|status]
/settings status-bar worktree   [on|off|toggle|status]
```

- When the action is omitted, `toggle` is assumed.
- `status` prints the current values (no changes).
- Changes persist to your config.

### Configure via `config.toml`

These keys live under `[tui]`:

```toml
[tui]
status_bar_show_git_branch = false
status_bar_show_worktree = false
```

See:

- `docs/config.md` (`[tui]`)
- `docs/example-config.md`

## Related

- `docs/slash_commands.md`
- `docs/xcodex/README.md`
