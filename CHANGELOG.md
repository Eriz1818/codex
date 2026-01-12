# Changelog

Releases are published on GitHub: https://github.com/Eriz1818/xCodex/releases

This project follows SemVer (`xcodex-vX.Y.Z` / `xcodex-vX.Y.Z-alpha.N` tags) and publishes:

- `@eriz1818/xcodex` (CLI wrapper + native `xcodex` binaries + bundled `rg`)
- `@eriz1818/xcodex-responses-api-proxy` (native proxy binary)

## 0.2.0

Hooks and packaging improvements.

- Hooks system: external hooks, Python Host (“py-box”) hooks, and PyO3 hooks (separately built).
- Hooks tooling: guided setup (`xcodex hooks init`), SDK + sample installers, and `xcodex hooks test`.
- Worktrees: `/worktree` for switching between git worktrees (plus shared dirs).
- npm releases: publish `@eriz1818/xcodex` and `@eriz1818/xcodex-responses-api-proxy` via `xcodex-vX.Y.Z` tags.

## 0.1.0

Initial public release of the `xCodex` fork.

- Fork-only UX/features: `/compact`, `/autocompact`, `/thoughts`, `/ps` and `/ps-kill`, hooks automation, worktree/session helpers.
- First-run setup wizard for `xcodex` with fork-specific default home (`~/.xcodex`) and safer MCP token isolation from upstream.
- Npm packaging + release pipeline foundation: vendored native binaries per target, bundled `rg`, GitHub Actions tag-based releases (`xcodex-v*`) and OIDC publishing support.
