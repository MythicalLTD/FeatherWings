package parser

import (
	"testing"

	"github.com/goccy/go-json"
)

func TestConfigurationFileSkipsOnlyBadReplacements(t *testing.T) {
	data := []byte(`{
		"file": "server.properties",
		"parser": "properties",
		"replace": [
			{"match": "server-port", "replace_with": "25565"},
			{"match": {"bad": true}, "replace_with": "x"},
			null,
			"not an object",
			{"match": "motd", "replace_with": "hello"}
		]
	}`)

	var f ConfigurationFile
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if len(f.Replace) != 2 {
		t.Fatalf("expected 2 replacements, got %d: %+v", len(f.Replace), f.Replace)
	}
	if f.Replace[0].Match != "server-port" || f.Replace[1].Match != "motd" {
		t.Fatalf("unexpected replacements or order: %+v", f.Replace)
	}
	for _, r := range f.Replace {
		if r.Match == "" {
			t.Fatalf("a replacement with an empty match was kept: %+v", f.Replace)
		}
	}
}

func TestConfigurationFileReplaceNotAnArray(t *testing.T) {
	data := []byte(`{"file": "a.yml", "parser": "yaml", "replace": {"match": "a", "replace_with": "b"}}`)
	var f ConfigurationFile
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if f.Replace == nil || len(f.Replace) != 0 {
		t.Fatalf("expected an empty replacement list, got %+v", f.Replace)
	}
}
