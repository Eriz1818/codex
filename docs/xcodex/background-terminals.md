# Background terminals (`/ps`, `/ps-kill`)

This fork tracks long-running “background terminals” started via unified exec. These are separate from the main chat/task execution flow and can keep running until they exit, are pruned, or are terminated.

## `/ps` — list background activity

`/ps` prints two sections:

- **Background terminals (N)**: running unified-exec sessions.
  - Each entry includes a stable **session id** (the unified-exec `process_id`) and a truncated command snippet.
- **Hooks (N)**: running hook processes (if any).
  - Each entry includes the hook id and command snippet.

Notes:
- The `/ps` session id is a unified-exec session identifier (not necessarily an OS PID).
- Output is truncated to fit the terminal width.

## `/ps-kill` — terminate background terminals

`/ps-kill` opens an interactive picker:

- Select **Terminate all background terminals** to close every running background terminal session.
- Or select a specific session id to terminate just that session.

If no background terminals are running, `/ps-kill` prints an info message and does nothing.

## Automatic cleanup / monitoring

Codex keeps track of background terminals and performs a few cleanup actions automatically:

- **Exit detection**: background terminals are monitored so Codex can notice when they exit and update UI state.
- **Pruning under load**: if too many background terminal sessions are kept open, Codex may automatically prune older sessions.
- **Shutdown cleanup**: on Codex shutdown, all background terminal sessions are terminated.

## Feature summary

- `/ps` shows:
  - Background terminals (with stable ids + counts)
  - Hooks (with ids + counts)
- `/ps-kill` can:
  - Terminate one background terminal by session id
  - Terminate all background terminals
