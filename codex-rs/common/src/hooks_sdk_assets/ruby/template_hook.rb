#!/usr/bin/env ruby
#
# xCodex hooks kit: Ruby template hook (logs payloads to hooks.jsonl).
#
# This file is installed under `$CODEX_HOME/hooks/templates/ruby/` and is meant
# as a starting point you copy and edit.
#
require "json"
require "fileutils"

# Load the shared helper from `$CODEX_HOME/hooks/xcodex_hooks.rb`.
require_relative "../../xcodex_hooks"

payload = XCodexHooks.read_payload
# Add your logic here. This template just logs the full payload.

codex_home = ENV.fetch("CODEX_HOME", File.join(Dir.home, ".xcodex"))
out_path = File.join(codex_home, "hooks.jsonl")
FileUtils.mkdir_p(File.dirname(out_path))
File.open(out_path, "a") do |f|
  f.write(JSON.dump(payload))
  f.write("\n")
end
