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

func TestPromptConfigureServiceInstallSkipsPackageManaged(t *testing.T) {
	prevFlags := configureFlags
	prevManaged := packageManagedFeatherwings
	t.Cleanup(func() {
		configureFlags = prevFlags
		packageManagedFeatherwings = prevManaged
	})

	configureFlags.InstallService = true
	configureFlags.NoService = false
	configureFlags.Quiet = true
	packageManagedFeatherwings = func() bool { return true }

	got, err := promptConfigureServiceInstall()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got {
		t.Fatal("expected apt-managed install to skip service prompt/install")
	}
}

func TestInstallFeatherwingsServiceSkipsPackageManaged(t *testing.T) {
	prevFlags := configureFlags
	prevManaged := packageManagedFeatherwings
	t.Cleanup(func() {
		configureFlags = prevFlags
		packageManagedFeatherwings = prevManaged
	})

	configureFlags.NoService = false
	packageManagedFeatherwings = func() bool { return true }

	result, err := installFeatherwingsService(config.DefaultLocation, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Skipped {
		t.Fatal("expected package-managed service install to be skipped")
	}
	if result.Installed || result.Enabled || result.Started {
		t.Fatalf("expected no service mutation, got %+v", result)
	}
	if !strings.Contains(result.Message, "apt package") {
		t.Fatalf("expected apt skip message, got %q", result.Message)
	}
}

func TestFeatherwingsServiceSkipResult(t *testing.T) {
	prevFlags := configureFlags
	prevManaged := packageManagedFeatherwings
	t.Cleanup(func() {
		configureFlags = prevFlags
		packageManagedFeatherwings = prevManaged
	})

	configureFlags.NoService = true
	packageManagedFeatherwings = func() bool { return false }
	result := featherwingsServiceSkipResult()
	if !result.Skipped || result.Message != "skipped by --no-service" {
		t.Fatalf("unexpected --no-service skip: %+v", result)
	}

	configureFlags.NoService = false
	packageManagedFeatherwings = func() bool { return true }
	result = featherwingsServiceSkipResult()
	if !result.Skipped || !strings.Contains(result.Message, "apt package") {
		t.Fatalf("unexpected apt skip: %+v", result)
	}
}
