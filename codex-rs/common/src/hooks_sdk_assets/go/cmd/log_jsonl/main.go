package main

import (
	"encoding/json"
	"os"
	"path/filepath"

	"example.com/xcodex/hooks-sdk/hooksdk"
)

func main() {
	// Parse the event payload (handles stdin vs payload_path envelopes).
	payload, err := hooksdk.ReadPayload()
	if err != nil {
		panic(err)
	}

	// Add your logic here. This template just logs the full payload.
	codexHome := os.Getenv("CODEX_HOME")
	if codexHome == "" {
		home, _ := os.UserHomeDir()
		codexHome = filepath.Join(home, ".xcodex")
	}
	outPath := filepath.Join(codexHome, "hooks.jsonl")
	_ = os.MkdirAll(filepath.Dir(outPath), 0o755)

	f, err := os.OpenFile(outPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	if err := enc.Encode(payload.RawPayload); err != nil {
		panic(err)
	}
}
