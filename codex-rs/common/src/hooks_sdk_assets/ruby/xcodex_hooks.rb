require "json"
require "pathname"

#
# xCodex hooks kit: Ruby helper.
#
# Install into `$CODEX_HOME/hooks/` with:
#
#   xcodex hooks install sdks ruby
#
# Provides `XCodexHooks.read_payload`, which handles stdin vs the `payload_path`
# envelope used for large payloads.
#
module XCodexHooks
  # Read a hook payload as a Ruby Hash.
  #
  # Input:
  # - raw: optional stdin string; when nil, reads STDIN.
  #
  # Output:
  # - Hash for the full event payload.
  def self.read_payload(raw = nil)
    raw = raw.nil? ? STDIN.read : raw
    raw = "{}" if raw.nil? || raw.empty?

    payload = JSON.parse(raw)
    payload_path = payload["payload_path"] || payload["payload-path"]
    if payload_path && !payload_path.empty?
      payload = JSON.parse(Pathname.new(payload_path).read)
    end
    payload
  end
end
