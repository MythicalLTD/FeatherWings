package parser

import (
	"encoding/json"
	"testing"
)

func replacement(t *testing.T, raw string) ConfigurationFileReplacement {
	t.Helper()

	var cfr ConfigurationFileReplacement
	if err := json.Unmarshal([]byte(raw), &cfr); err != nil {
		t.Fatalf("unmarshal %s: %v", raw, err)
	}

	return cfr
}
