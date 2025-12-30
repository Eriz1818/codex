#!/bin/bash

set -euo pipefail

usage() {
    cat <<'EOF'
Install the current working tree's Codex CLI binary as `xcodex`.

Usage:
  scripts/install-xcodex.sh [--release] [--dest PATH]

Options:
  --release    Build `target/release/codex` instead of `target/debug/codex`.
  --debug      Build `target/debug/codex` (default).
  --dest PATH  Install path (default: ~/.local/bin/xcodex).
EOF
}

PROFILE="debug"
DEST="${XCODEX_DEST:-$HOME/.local/bin/xcodex}"

while [ $# -gt 0 ]; do
    case "$1" in
        --release)
            PROFILE="release"
            shift
            ;;
        --debug)
            PROFILE="debug"
            shift
            ;;
        --dest)
            DEST="${2:?missing value for --dest}"
            shift 2
            ;;
        -h | --help)
            usage
            exit 0
            ;;
        *)
            echo "unknown argument: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

ROOT_DIR="$(realpath "$(dirname "$0")/..")"
CODEX_RS_DIR="$ROOT_DIR/codex-rs"

(
    cd "$CODEX_RS_DIR"
    if [ "$PROFILE" = "release" ]; then
        cargo build -p codex-cli --bin codex --release
    else
        cargo build -p codex-cli --bin codex
    fi
)

BIN="$CODEX_RS_DIR/target/$PROFILE/codex"
if [ ! -f "$BIN" ]; then
    echo "expected built binary at $BIN" >&2
    exit 1
fi

mkdir -p "$(dirname "$DEST")"
install -m 755 "$BIN" "$DEST"

echo "Installed xcodex to: $DEST"
"$DEST" --version || true

if command -v codex >/dev/null 2>&1; then
    echo "codex: $(command -v codex)"
fi
if command -v xcodex >/dev/null 2>&1; then
    echo "xcodex: $(command -v xcodex)"
else
    echo "xcodex is not on PATH; add $(dirname "$DEST") to PATH."
fi
