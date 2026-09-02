package cmd

import (
	"encoding/base64"
	"testing"

	"github.com/mythicalltd/featherwings/config"
)

func TestDecodeJoinData(t *testing.T) {
	yaml := "uuid: test\nremote: https://panel.example.com\n"
	encoded := base64.StdEncoding.EncodeToString([]byte(yaml))

	raw, err := decodeJoinData(encoded)
	if err != nil {
		t.Fatalf("decodeJoinData() error = %v", err)
	}
	if string(raw) != yaml {
		t.Fatalf("decodeJoinData() = %q, want %q", string(raw), yaml)
	}

	if _, err := decodeJoinData("not-base64!!!"); err == nil {
		t.Fatal("expected error for invalid base64")
	}
}

func TestIsFullWingsConfig(t *testing.T) {
	minimal := []byte("uuid: x\ntoken_id: a\ntoken: b\nremote: https://panel.example.com\n")
	if config.IsFullWingsConfig(minimal) {
		t.Fatal("minimal bootstrap should not be treated as full config")
	}

	full := []byte("uuid: x\ntoken_id: a\ntoken: b\nremote: https://panel.example.com\nsystem:\n  data: /var/lib/featherpanel/volumes\n")
	if !config.IsFullWingsConfig(full) {
		t.Fatal("expected full config detection")
	}
}

func TestJoinBootstrapValidateJoin(t *testing.T) {
	bootstrap := &config.JoinBootstrap{
		UUID:    "node-uuid",
		TokenID: "token-id",
		Token:   "secret",
		Remote:  "https://panel.example.com",
	}
	if err := bootstrap.ValidateJoin(); err != nil {
		t.Fatalf("ValidateJoin() error = %v", err)
	}

	bootstrap.Token = ""
	if err := bootstrap.ValidateJoin(); err == nil {
		t.Fatal("expected validation error for missing token")
	}
}
