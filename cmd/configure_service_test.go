package cmd

import (
	"strings"
	"testing"

	"github.com/mythicalltd/featherwings/config"
)

func TestBuildFeatherwingsUnit(t *testing.T) {
	unit := buildFeatherwingsUnit("/usr/local/bin/featherwings", config.DefaultLocation)

	for _, want := range []string{
		"Description=FeatherWings Daemon",
		"After=docker.service",
		"Requires=docker.service",
		"PartOf=docker.service",
		"User=root",
		"WorkingDirectory=/etc/featherpanel",
		"ExecStart=/usr/local/bin/featherwings",
		"Restart=always",
		"RestartSec=5",
		"StartLimitInterval=180",
		"StartLimitBurst=30",
		"StandardOutput=journal",
		"StandardError=journal",
		"WantedBy=multi-user.target",
	} {
		if !strings.Contains(unit, want) {
			t.Fatalf("unit missing %q:\n%s", want, unit)
		}
	}
}

func TestBuildFeatherwingsUnitCustomConfig(t *testing.T) {
	unit := buildFeatherwingsUnit("/usr/local/bin/featherwings", "/opt/wings/config.yml")
	if !strings.Contains(unit, "ExecStart=/usr/local/bin/featherwings --config /opt/wings/config.yml") {
		t.Fatalf("expected custom config in ExecStart, got:\n%s", unit)
	}
	if !strings.Contains(unit, "WorkingDirectory=/opt/wings") {
		t.Fatalf("expected custom working directory, got:\n%s", unit)
	}
}
