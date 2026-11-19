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
	"github.com/mythicalltd/featherwings/remote"
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

// fakeDocker answers image pulls with a stream that fails part way, and image
// inspects with 200 when the image exists locally or 404 when it does not.
func fakeDocker(t *testing.T, localImage bool) *client.Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/images/create"):
			_, _ = w.Write([]byte(`{"status":"Pulling from library/alpine","id":"latest"}` + "\n" + `{"errorDetail":{"message":"manifest unknown"},"error":"manifest unknown"}` + "\n"))
		case strings.Contains(r.URL.Path, "/images/") && strings.HasSuffix(r.URL.Path, "/json"):
			if !localImage {
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`{"message":"No such image"}`))
				return
			}
			_, _ = w.Write([]byte(`{"Id":"sha256:abc","RepoTags":["alpine:latest"]}`))
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"message":"not found"}`))
		}
	}))
	t.Cleanup(srv.Close)

	cli, err := client.NewClientWithOpts(
		client.WithHost("tcp://"+strings.TrimPrefix(srv.URL, "http://")),
		client.WithHTTPClient(srv.Client()),
		client.WithVersion("1.44"),
	)
	if err != nil {
		t.Fatal(err)
	}
	return cli
}

func TestPullInstallationImageStreamError(t *testing.T) {
	cfg, err := config.NewAtPath(filepath.Join(t.TempDir(), "config.yml"))
	if err != nil {
		t.Fatal(err)
	}
	cfg.AuthenticationToken = "test-token"
	config.Set(cfg)

	for _, local := range []bool{true, false} {
		s, err := New(nil)
		if err != nil {
			t.Fatal(err)
		}
		ip := &InstallationProcess{
			Server: s,
			Script: &remote.InstallationScript{ContainerImage: "docker.io/library/alpine:latest"},
			client: fakeDocker(t, local),
		}
		err = ip.pullInstallationImage()
		if local && err != nil {
			t.Fatalf("expected the local image to be used, got %v", err)
		}
		if !local && (err == nil || !strings.Contains(err.Error(), "manifest unknown")) {
			t.Fatalf("expected the stream error without a local image, got %v", err)
		}
	}
}
