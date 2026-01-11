#!/bin/bash

set -euo pipefail

usage() {
    cat <<'EOF'
Install the current working tree's Codex CLI binary as `xcodex-pyo3` (built with PyO3 enabled).

Usage:
  scripts/install-xcodex-pyo3.sh [--release] [--dest PATH] [--python PATH]

Options:
  --release       Build `target/release/codex` (default).
  --debug         Build `target/debug/codex`.
  --dest PATH     Install path (default: ~/.local/bin/xcodex-pyo3).
  --python PATH   Python executable to use for PyO3 (sets PYO3_PYTHON).
EOF
}

PROFILE="release"
DEST="${XCODEX_PYO3_DEST:-$HOME/.local/bin/xcodex-pyo3}"
PYTHON=""

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
        --python)
            PYTHON="${2:?missing value for --python}"
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

if [ -z "$PYTHON" ]; then
    if command -v python3.11 >/dev/null 2>&1; then
        PYTHON="$(command -v python3.11)"
    elif command -v python3 >/dev/null 2>&1; then
        PYTHON="$(command -v python3)"
    fi
fi

if [ -z "$PYTHON" ]; then
    echo "No python executable found; pass --python PATH" >&2
    exit 1
fi

(
    cd "$CODEX_RS_DIR"
    export PYO3_PYTHON="$PYTHON"
    if [ "$PROFILE" = "release" ]; then
        cargo build -p codex-cli --bin codex --release --features codex-core/pyo3-hooks
    else
        cargo build -p codex-cli --bin codex --features codex-core/pyo3-hooks
    fi
)

BIN="$CODEX_RS_DIR/target/$PROFILE/codex"
if [ ! -f "$BIN" ]; then
    echo "expected built binary at $BIN" >&2
    exit 1
fi

mkdir -p "$(dirname "$DEST")"
install -m 755 "$BIN" "$DEST"

echo "Installed xcodex-pyo3 to: $DEST"
"$DEST" --version || true

if command -v codex >/dev/null 2>&1; then
    echo "codex: $(command -v codex)"
fi
if command -v xcodex >/dev/null 2>&1; then
    echo "xcodex: $(command -v xcodex)"
fi
if command -v xcodex-pyo3 >/dev/null 2>&1; then
    echo "xcodex-pyo3: $(command -v xcodex-pyo3)"
else
    echo "xcodex-pyo3 is not on PATH; add $(dirname "$DEST") to PATH."
fi

