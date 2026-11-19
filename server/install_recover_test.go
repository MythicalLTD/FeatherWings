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
)

// A panic during the installation is returned as an error instead of crashing
// the Wings process. A server without a Panel client panics as soon as the
// installation script is requested.
func TestInternalInstallRecoversFromPanic(t *testing.T) {
	cfg, err := config.NewAtPath(filepath.Join(t.TempDir(), "config.yml"))
	if err != nil {
		t.Fatal(err)
	}
	cfg.AuthenticationToken = "test-token"
	config.Set(cfg)

	s, err := New(nil)
	if err != nil {
		t.Fatal(err)
	}

	var installErr error
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("internalInstall() panicked: %v", r)
			}
		}()
		installErr = s.internalInstall()
	}()
	if installErr == nil || !strings.Contains(installErr.Error(), "panicked") {
		t.Fatalf("internalInstall() error = %v, expected a recovered panic", installErr)
	}
}

// When the installer container is gone before its logs are read, the
// installation log is skipped instead of copying from a nil reader.
func TestAfterExecuteSkipsLogWhenContainerIsGone(t *testing.T) {
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
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"message":"No such container: test_installer"}`))
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
	ip := &InstallationProcess{Server: s, client: cli}

	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("AfterExecute() panicked: %v", r)
			}
		}()
		if err := ip.AfterExecute("missing"); err != nil {
			t.Fatalf("AfterExecute() error = %v, expected nil", err)
		}
	}()

	if _, err := os.Stat(ip.GetLogPath()); !os.IsNotExist(err) {
		t.Fatalf("expected no installation log to be written, stat error = %v", err)
	}
}
