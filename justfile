set working-directory := "codex-rs"
set positional-arguments

# Display help
help:
    just -l

# `codex`
alias c := codex
codex *args:
    bazel run //codex-rs/cli:codex -- "$@"

# `codex exec`
exec *args:
    bazel run //codex-rs/cli:codex -- exec "$@"

# `codex tui`
tui *args:
    bazel run //codex-rs/cli:codex -- tui "$@"

# Build and install the CLI as `xcodex` (defaults to ~/.local/bin/xcodex).
xcodex-install *args:
    bash ../scripts/install-xcodex.sh "$@"

# Build and install a PyO3-enabled CLI as `xcodex-pyo3` (defaults to ~/.local/bin/xcodex-pyo3).
xcodex-pyo3-install *args:
    bash ../scripts/install-xcodex-pyo3.sh "$@"

# Run the CLI version of the file-search crate.
file-search *args:
    bazel run //codex-rs/file-search:codex-file-search -- "$@"

# Build the CLI and run the app-server test client
app-server-test-client *args:
    bazel build //codex-rs/cli:codex
    CODEX_BIN="$(bazel info bazel-bin)/codex-rs/cli/codex" bazel run //codex-rs/app-server-test-client:codex-app-server-test-client -- --codex-bin "$CODEX_BIN" "$@"

# Regenerate hooks schema + SDK assets (writes to working tree).
hooks-codegen:
    cargo run -p codex-core --bin hooks_schema --features hooks-schema --quiet > ../docs/xcodex/hooks.schema.json
    cargo run -p codex-core --bin hooks_typescript --features hooks-schema --quiet > common/src/hooks_sdk_assets/js/xcodex_hooks.d.ts
    cargo run -p codex-core --bin hooks_python_types --features hooks-schema --quiet > common/src/hooks_sdk_assets/python/xcodex_hooks_types.py
    cargo run -p codex-core --bin hooks_python_models --features hooks-schema --quiet > common/src/hooks_sdk_assets/python/xcodex_hooks_models.py
    cargo run -p codex-core --bin hooks_python_models --features hooks-schema --quiet > ../examples/hooks/xcodex_hooks_models.py
    cargo run -p codex-core --bin hooks_go_types --features hooks-schema --quiet > common/src/hooks_sdk_assets/go/hooksdk/types.go
    cargo run -p codex-core --bin hooks_rust_sdk --features hooks-schema --quiet > hooks-sdk/src/generated.rs

hooks-codegen-check:
    just hooks-codegen
    git diff --exit-code -- \
      ../docs/xcodex/hooks.schema.json \
      common/src/hooks_sdk_assets/js/xcodex_hooks.d.ts \
      common/src/hooks_sdk_assets/python/xcodex_hooks_types.py \
      common/src/hooks_sdk_assets/python/xcodex_hooks_models.py \
      ../examples/hooks/xcodex_hooks_models.py \
      hooks-sdk/src/generated.rs \
      common/src/hooks_sdk_assets/go/hooksdk/types.go

# Smoke test SDK templates via Docker (requires docker).
hooks-templates-smoke:
    bash -c 'set -euo pipefail; command -v docker >/dev/null || { echo "docker is required"; exit 1; }; \
      run_python() { docker run --rm -v "{{invocation_directory()}}:/ws" python:3.11-slim bash -lc '"'"'set -euo pipefail; CODEX_HOME="$(mktemp -d)"; export CODEX_HOME; \
        mkdir -p "$CODEX_HOME/hooks/templates/python"; \
        cp /ws/codex-rs/common/src/hooks_sdk_assets/python/xcodex_hooks.py "$CODEX_HOME/hooks/"; \
        cp /ws/codex-rs/common/src/hooks_sdk_assets/python/xcodex_hooks_models.py "$CODEX_HOME/hooks/"; \
        cp /ws/codex-rs/common/src/hooks_sdk_assets/python/xcodex_hooks_runtime.py "$CODEX_HOME/hooks/"; \
        cp /ws/codex-rs/common/src/hooks_sdk_assets/python/xcodex_hooks_types.py "$CODEX_HOME/hooks/"; \
        cp /ws/codex-rs/common/src/hooks_sdk_assets/python/template_hook.py "$CODEX_HOME/hooks/templates/python/log_jsonl.py"; \
        payload_path="$CODEX_HOME/payload.json"; \
        printf "%s" "{\"schema_version\":1,\"event_id\":\"e\",\"timestamp\":\"t\",\"session_id\":\"th\",\"transcript_path\":\"\",\"permission_mode\":\"default\",\"hook_event_name\":\"PostToolUse\",\"xcodex_event_type\":\"tool-call-finished\",\"turn_id\":\"tu\",\"cwd\":\"/tmp\",\"tool_name\":\"Bash\",\"tool_use_id\":\"c\",\"tool_response\":null,\"status\":\"completed\",\"duration_ms\":1,\"success\":true,\"output_bytes\":0,\"__marker__\":\"py\"}" > "$payload_path"; \
        printf "%s" "{\"payload_path\":\"$payload_path\"}" | python3 "$CODEX_HOME/hooks/templates/python/log_jsonl.py"; \
        grep -Eq "\"__marker__\"[[:space:]]*:[[:space:]]*\"py\"" "$CODEX_HOME/hooks.jsonl"; \
      '"'"'; }; \
      run_node() { docker run --rm -v "{{invocation_directory()}}:/ws" node:22 bash -lc '"'"'set -euo pipefail; CODEX_HOME="$(mktemp -d)"; export CODEX_HOME; \
        mkdir -p "$CODEX_HOME/hooks/templates/js"; \
        cp /ws/codex-rs/common/src/hooks_sdk_assets/js/xcodex_hooks.mjs "$CODEX_HOME/hooks/"; \
        cp /ws/codex-rs/common/src/hooks_sdk_assets/js/template_hook.mjs "$CODEX_HOME/hooks/templates/js/log_jsonl.mjs"; \
        payload_path="$CODEX_HOME/payload.json"; \
        printf "%s" "{\"schema_version\":1,\"event_id\":\"e\",\"timestamp\":\"t\",\"session_id\":\"th\",\"transcript_path\":\"\",\"permission_mode\":\"default\",\"hook_event_name\":\"PostToolUse\",\"xcodex_event_type\":\"tool-call-finished\",\"turn_id\":\"tu\",\"cwd\":\"/tmp\",\"tool_name\":\"Bash\",\"tool_use_id\":\"c\",\"tool_response\":null,\"status\":\"completed\",\"duration_ms\":1,\"success\":true,\"output_bytes\":0,\"__marker__\":\"node\"}" > "$payload_path"; \
        printf "%s" "{\"payload_path\":\"$payload_path\"}" | node "$CODEX_HOME/hooks/templates/js/log_jsonl.mjs"; \
        grep -Eq "\"__marker__\"[[:space:]]*:[[:space:]]*\"node\"" "$CODEX_HOME/hooks.jsonl"; \
      '"'"'; }; \
      run_ruby() { docker run --rm -v "{{invocation_directory()}}:/ws" ruby:3.3 bash -lc '"'"'set -euo pipefail; CODEX_HOME="$(mktemp -d)"; export CODEX_HOME; \
        mkdir -p "$CODEX_HOME/hooks/templates/ruby"; \
        cp /ws/codex-rs/common/src/hooks_sdk_assets/ruby/xcodex_hooks.rb "$CODEX_HOME/hooks/"; \
        cp /ws/codex-rs/common/src/hooks_sdk_assets/ruby/template_hook.rb "$CODEX_HOME/hooks/templates/ruby/log_jsonl.rb"; \
        payload_path="$CODEX_HOME/payload.json"; \
        printf "%s" "{\"schema_version\":1,\"event_id\":\"e\",\"timestamp\":\"t\",\"session_id\":\"th\",\"transcript_path\":\"\",\"permission_mode\":\"default\",\"hook_event_name\":\"PostToolUse\",\"xcodex_event_type\":\"tool-call-finished\",\"turn_id\":\"tu\",\"cwd\":\"/tmp\",\"tool_name\":\"Bash\",\"tool_use_id\":\"c\",\"tool_response\":null,\"status\":\"completed\",\"duration_ms\":1,\"success\":true,\"output_bytes\":0,\"__marker__\":\"rb\"}" > "$payload_path"; \
        printf "%s" "{\"payload_path\":\"$payload_path\"}" | ruby "$CODEX_HOME/hooks/templates/ruby/log_jsonl.rb"; \
        grep -Eq "\"__marker__\"[[:space:]]*:[[:space:]]*\"rb\"" "$CODEX_HOME/hooks.jsonl"; \
      '"'"'; }; \
      run_go() { docker run --rm -v "{{invocation_directory()}}:/ws" -w /ws/codex-rs/common/src/hooks_sdk_assets/go golang:1.22 bash -lc '"'"'set -euo pipefail; \
        /usr/local/go/bin/go build -o /tmp/hook ./cmd/log_jsonl; \
        CODEX_HOME="$(mktemp -d)"; export CODEX_HOME; \
        payload_path="$CODEX_HOME/payload.json"; \
        printf "%s" "{\"schema_version\":1,\"event_id\":\"e\",\"timestamp\":\"t\",\"session_id\":\"th\",\"transcript_path\":\"\",\"permission_mode\":\"default\",\"hook_event_name\":\"PostToolUse\",\"xcodex_event_type\":\"tool-call-finished\",\"turn_id\":\"tu\",\"cwd\":\"/tmp\",\"tool_name\":\"Bash\",\"tool_use_id\":\"c\",\"tool_response\":null,\"status\":\"completed\",\"duration_ms\":1,\"success\":true,\"output_bytes\":0,\"__marker__\":\"go\"}" > "$payload_path"; \
        printf "%s" "{\"payload_path\":\"$payload_path\"}" | /tmp/hook; \
        grep -Eq "\"__marker__\"[[:space:]]*:[[:space:]]*\"go\"" "$CODEX_HOME/hooks.jsonl"; \
      '"'"'; }; \
      run_java() { docker run --rm -v "{{invocation_directory()}}:/ws" -w /ws/codex-rs/common/src/hooks_sdk_assets/java maven:3.9-eclipse-temurin-17 bash -lc '"'"'set -euo pipefail; \
        mvn -q -DskipTests -pl template -am package dependency:copy-dependencies; \
        CODEX_HOME="$(mktemp -d)"; export CODEX_HOME; \
        payload_path="$CODEX_HOME/payload.json"; \
        printf "%s" "{\"schema_version\":1,\"event_id\":\"e\",\"timestamp\":\"t\",\"session_id\":\"th\",\"transcript_path\":\"\",\"permission_mode\":\"default\",\"hook_event_name\":\"PostToolUse\",\"xcodex_event_type\":\"tool-call-finished\",\"turn_id\":\"tu\",\"cwd\":\"/tmp\",\"tool_name\":\"Bash\",\"tool_use_id\":\"c\",\"tool_response\":null,\"status\":\"completed\",\"duration_ms\":1,\"success\":true,\"output_bytes\":0,\"__marker__\":\"java\"}" > "$payload_path"; \
        printf "%s" "{\"payload_path\":\"$payload_path\"}" | java -cp "template/target/classes:template/target/dependency/*" dev.xcodex.hooks.LogJsonlHook; \
        grep -Eq "\"__marker__\"[[:space:]]*:[[:space:]]*\"java\"" "$CODEX_HOME/hooks.jsonl"; \
      '"'"'; }; \
      run_rust() { docker run --rm -v "{{invocation_directory()}}:/ws" -w /ws/codex-rs/common/src/hooks_sdk_assets/rust rust:1.90 bash -lc '"'"'set -euo pipefail; \
        /usr/local/cargo/bin/cargo build --release; \
        CODEX_HOME="$(mktemp -d)"; export CODEX_HOME; \
        payload_path="$CODEX_HOME/payload.json"; \
        printf "%s" "{\"schema_version\":1,\"event_id\":\"e\",\"timestamp\":\"t\",\"session_id\":\"th\",\"transcript_path\":\"\",\"permission_mode\":\"default\",\"hook_event_name\":\"PostToolUse\",\"xcodex_event_type\":\"tool-call-finished\",\"turn_id\":\"tu\",\"cwd\":\"/tmp\",\"tool_name\":\"Bash\",\"tool_use_id\":\"c\",\"tool_response\":null,\"status\":\"completed\",\"duration_ms\":1,\"success\":true,\"output_bytes\":0,\"__marker__\":\"rust\"}" > "$payload_path"; \
        printf "%s" "{\"payload_path\":\"$payload_path\"}" | ./target/release/xcodex-hooks-rust-template; \
        grep -Eq "\"__marker__\"[[:space:]]*:[[:space:]]*\"rust\"" "$CODEX_HOME/hooks.jsonl"; \
      '"'"'; }; \
      run_python; run_node; run_ruby; run_go; run_java; run_rust; echo "ok";'

# Fetch deps needed for Bazel builds
install:
    bazel fetch //...

# Format the Rust workspace (defaults to `codex-rs/` via `working-directory`).
fmt:
    cargo fmt

# Run clippy with fixes applied. Prefer scoping: `just fix -p codex-tui`.
fix *args:
    bash -lc 'set -euo pipefail; \
      if [[ -z "${PYO3_PYTHON:-}" ]] && command -v python3.11 >/dev/null; then export PYO3_PYTHON="$(command -v python3.11)"; fi; \
      cargo clippy --fix --allow-dirty --allow-staged "$@"'

clippy *args:
    bash -lc 'set -euo pipefail; \
      if [[ -z "${PYO3_PYTHON:-}" ]] && command -v python3.11 >/dev/null; then export PYO3_PYTHON="$(command -v python3.11)"; fi; \
      cargo clippy "$@"'

# Default test runner
test:
    bazel test //... --keep_going

# Run the MCP server
mcp-server-run *args:
    bazel run //codex-rs/mcp-server:codex-mcp-server -- "$@"
bazel-test:
    bazel test //... --keep_going

bazel-remote-test:
    bazel test //... --config=remote --platforms=//:rbe --keep_going

build-for-release:
    bazel build //codex-rs/cli:release_binaries --config=remote

# Run the MCP server via Cargo (useful when Bazel isn't available/configured)
mcp-server-run-cargo *args:
    cargo run -p codex-mcp-server -- "$@"
