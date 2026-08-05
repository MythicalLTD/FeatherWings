package fastdl

import (
	"testing"

	"github.com/mythicalltd/featherwings/config"
)

func TestResolveNginxServerName_UsesPublicHostname(t *testing.T) {
	cfg := &config.Configuration{}
	cfg.System.FastDL.PublicHostname = "nbg1.gamesphere.rs"
	cfg.PanelLocation = "https://panel.gamesphere.rs"
	cfg.Api.Ssl.CertificateFile = "/etc/letsencrypt/live/something.else/fullchain.pem"

	got := resolveNginxServerName(cfg)
	if got != "nbg1.gamesphere.rs" {
		t.Fatalf("expected node public_hostname, got %q", got)
	}
}

func TestResolveNginxServerName_StripsQuotes(t *testing.T) {
	cfg := &config.Configuration{}
	cfg.System.FastDL.PublicHostname = `"nbg1.gamesphere.rs"`
	cfg.PanelLocation = "https://panel.gamesphere.rs"

	got := resolveNginxServerName(cfg)
	if got != "nbg1.gamesphere.rs" {
		t.Fatalf("expected stripped hostname, got %q", got)
	}
}

func TestResolveNginxServerName_NeverUsesPanelURL(t *testing.T) {
	cfg := &config.Configuration{}
	cfg.PanelLocation = "https://panel.gamesphere.rs"
	cfg.Api.Ssl.CertificateFile = "/etc/letsencrypt/live/nbg1.gamesphere.rs/fullchain.pem"

	got := resolveNginxServerName(cfg)
	if got == "panel.gamesphere.rs" {
		t.Fatalf("must not use panel URL as server_name, got %q", got)
	}
	if got != "nbg1.gamesphere.rs" {
		t.Fatalf("expected SSL cert FQDN fallback, got %q", got)
	}
}

func TestResolveNginxServerName_CatchAllWhenEmpty(t *testing.T) {
	cfg := &config.Configuration{}
	cfg.PanelLocation = "https://panel.gamesphere.rs"

	got := resolveNginxServerName(cfg)
	if got != "_" {
		t.Fatalf("expected catch-all _, got %q", got)
	}
}
