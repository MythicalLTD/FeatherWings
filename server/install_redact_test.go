package server

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/docker/docker/client"

	"github.com/mythicalltd/featherwings/config"
	"github.com/mythicalltd/featherwings/environment"
	"github.com/mythicalltd/featherwings/remote"
)

func TestIsSensitiveVariable(t *testing.T) {
	sensitive := []string{"RCON_PASSWORD", "SERVER_PASSWORD", "STEAM_PASS", "STEAM_AUTH", "SRCDS_TOKEN", "API_KEY", "FIVEM_LICENSE", "DB_PWD", "client_secret", "SERVERPASSWORD", "STEAM_WEBAPIKEY", "STEAM_ACC", "GSLT", "RCONPASS", "DISCORD_WEBHOOK", "ADMIN_PW"}
	for _, name := range sensitive {
		if !isSensitiveVariable(name) {
			t.Errorf("isSensitiveVariable(%q) = false, expected true", name)
		}
	}

	kept := []string{"SERVER_MEMORY", "SERVER_PORT", "STARTUP", "BYPASS_CHECK", "MONKEY_MODE", "MAX_PLAYERS", "PASSIVE_MODE", "ACCESS_MODE", "TZ", "POWER_MODE"}
	for _, name := range kept {
		if isSensitiveVariable(name) {
			t.Errorf("isSensitiveVariable(%q) = true, expected false", name)
		}
	}
}

func TestRedactEnvironment(t *testing.T) {
	env := []string{
		"TZ=UTC",
		"STARTUP=./srcds_run +rcon_password hunter22 +sv_setsteamaccount ABCD1234TOKEN -port 27015",
		"SERVER_MEMORY=1024",
		"RCON_PASSWORD=hunter22",
		"STEAM_ACC=ABCD1234TOKEN",
		"SRCDS_TOKEN=ABCD1234TOKEN",
		"SERVER_PASSWORD=",
		"MAX_PLAYERS=16",
		"DISCORD_WEBHOOK=https://discord.com/api/webhooks/1/abc",
	}

	got := redactEnvironment(env)
	want := []string{
		"TZ=UTC",
		"STARTUP=./srcds_run +rcon_password ******** +sv_setsteamaccount ******** -port 27015",
		"SERVER_MEMORY=1024",
		"RCON_PASSWORD=********",
		"STEAM_ACC=********",
		"SRCDS_TOKEN=********",
		"SERVER_PASSWORD=",
		"MAX_PLAYERS=16",
		"DISCORD_WEBHOOK=********",
	}

	if len(got) != len(want) {
		t.Fatalf("redactEnvironment() returned %d variables, expected %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("redactEnvironment()[%d] = %q, expected %q", i, got[i], want[i])
		}
	}
	if env[3] != "RCON_PASSWORD=hunter22" {
		t.Errorf("redactEnvironment() changed its input: %q", env[3])
	}
}

func TestRedactEnvironmentLongestSecretFirst(t *testing.T) {
	got := redactEnvironment([]string{
		"STARTUP=run --key abcdef --password abcdefgh",
		"API_KEY=abcdef",
		"ADMIN_PASSWORD=abcdefgh",
	})
	if got[0] != "STARTUP=run --key ******** --password ********" {
		t.Errorf("redactEnvironment()[0] = %q", got[0])
	}
}

func TestRedactEnvironmentShortValues(t *testing.T) {
	got := redactEnvironment([]string{
		"STARTUP=./start --memory 1024 --auth true",
		"SERVER_MEMORY=1024",
		"AUTH_REQUIRED=true",
		"SERVER_PASSWORD=1",
	})
	want := []string{
		"STARTUP=./start --memory 1024 --auth true",
		"SERVER_MEMORY=1024",
		"AUTH_REQUIRED=********",
		"SERVER_PASSWORD=********",
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("redactEnvironment()[%d] = %q, expected %q", i, got[i], want[i])
		}
	}
}

// The installation log written after an install does not contain the values of
// sensitive variables, neither on their own line nor inside STARTUP.
func TestInstallLogDoesNotContainSecrets(t *testing.T) {
	logDir := t.TempDir()
	cfg, err := config.NewAtPath(filepath.Join(t.TempDir(), "config.yml"))
	if err != nil {
		t.Fatal(err)
	}
	cfg.AuthenticationToken = "test-token"
	cfg.System.LogDirectory = logDir
	config.Set(cfg)
	if err := os.MkdirAll(filepath.Join(logDir, "install"), 0o700); err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/logs") {
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = w.Write([]byte("installer output\n"))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"message":"not found"}`))
	}))
	defer srv.Close()
	cli, err := client.NewClientWithOpts(
		client.WithHost("tcp://"+strings.TrimPrefix(srv.URL, "http://")),
		client.WithHTTPClient(srv.Client()),
		client.WithVersion("1.44"),
	)
	if err != nil {
		t.Fatal(err)
	}

	s, err := New(nil)
	if err != nil {
		t.Fatal(err)
	}
	s.cfg.Invocation = "./start --license {{LICENSE_KEY}}"
	s.cfg.EnvVars = environment.Variables{"LICENSE_KEY": "s3cr3t-license", "MAX_PLAYERS": "16"}
	ip := &InstallationProcess{Server: s, client: cli, Script: &remote.InstallationScript{}}
	if err := ip.AfterExecute("test"); err != nil {
		t.Fatalf("AfterExecute() error = %v", err)
	}

	b, err := os.ReadFile(ip.GetLogPath())
	if err != nil {
		t.Fatal(err)
	}
	log := string(b)
	if strings.Contains(log, "s3cr3t-license") {
		t.Fatalf("installation log contains a secret:\n%s", log)
	}
	for _, want := range []string{"LICENSE_KEY=********", "STARTUP=./start --license ********", "MAX_PLAYERS=16", "installer output"} {
		if !strings.Contains(log, want) {
			t.Errorf("installation log does not contain %q:\n%s", want, log)
		}
	}
}
