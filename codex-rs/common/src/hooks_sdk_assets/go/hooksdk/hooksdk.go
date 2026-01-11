// Package hooksdk is part of the xCodex hooks kit.
//
// This Go code is installed under `$CODEX_HOME/hooks/templates/go/` by:
//
//   xcodex hooks install sdks go
//
// It demonstrates how to correctly handle stdin vs the `payload_path` envelope
// used for large payloads.
package hooksdk

import (
	"encoding/json"
	"errors"
	"os"
)

type HookPayloadJSON map[string]any

// ReadPayload reads the hook payload for an external hook invocation and parses it into a typed
// payload struct.
//
// Input: reads stdin. For large payloads, stdin is a small JSON envelope that
// contains `payload_path`, which points to the full JSON payload file.
//
// Output: returns the typed payload (and preserves the raw JSON object for forward compatibility).
func ReadPayload() (*HookPayload, error) {
	full, err := readFullPayloadBytes()
	if err != nil {
		return nil, err
	}

	return ParseHookPayload(full)
}

// ReadPayloadJSON reads the hook payload for an external hook invocation and returns it as an
// untyped map.
func ReadPayloadJSON() (HookPayloadJSON, error) {
	full, err := readFullPayloadBytes()
	if err != nil {
		return nil, err
	}

	var payload HookPayloadJSON
	if err := json.Unmarshal(full, &payload); err != nil {
		return nil, err
	}
	return payload, nil
}

func readFullPayloadBytes() ([]byte, error) {
	stdinBytes, err := os.ReadFile("/dev/stdin")
	if err != nil {
		return nil, err
	}
	if len(stdinBytes) == 0 {
		stdinBytes = []byte("{}")
	}

	var envelope map[string]any
	if err := json.Unmarshal(stdinBytes, &envelope); err != nil {
		// If stdin isn't JSON, treat it as the full payload.
		return stdinBytes, nil
	}

	payloadPathAny, ok := envelope["payload_path"]
	if !ok || payloadPathAny == nil {
		payloadPathAny, ok = envelope["payload-path"]
	}
	if !ok || payloadPathAny == nil {
		return stdinBytes, nil
	}

	payloadPath, ok := payloadPathAny.(string)
	if !ok || payloadPath == "" {
		return nil, errors.New("invalid payload_path")
	}
	return os.ReadFile(payloadPath)
}
