package fastdl

import (
	"strings"
	"testing"

	"github.com/mythicalltd/featherwings/config"
)

func TestBuildNginxConfigOnlyExposesEnabledServers(t *testing.T) {
	cfg := &config.Configuration{}
	cfg.System.Data = "/var/lib/featherpanel/volumes"
	cfg.System.FastDL.Port = 8080
	cfg.System.FastDL.PublicHostname = "fastdl.example.com"

	servers := []serverConfig{
		{UUID: "0f6c1a54-1111-2222-3333-444455556666", Directory: "public"},
		{UUID: "../evil", Directory: "public"},
	}
	out := buildNginxConfig(cfg, servers)

	if strings.Contains(out, "root /var/lib/featherpanel/volumes;") {
		t.Fatalf("Konfiguration liefert weiterhin das gesamte Datenverzeichnis aus:\n%s", out)
	}
	if !strings.Contains(out, "alias /var/lib/featherpanel/volumes/0f6c1a54-1111-2222-3333-444455556666/;") {
		t.Fatalf("FastDL-Verzeichnis des aktiven Servers fehlt:\n%s", out)
	}
	if strings.Contains(out, "location /../evil/") {
		t.Fatalf("ungueltige UUID wurde nicht bereinigt:\n%s", out)
	}
	if !strings.Contains(out, "location / {\n\t\treturn 404;") {
		t.Fatalf("Catch-all auf 404 fehlt:\n%s", out)
	}
}
