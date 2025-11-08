package router

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/apex/log"
	"github.com/apex/log/handlers/discard"
	"github.com/gin-gonic/gin"

	"github.com/mythicalltd/featherwings/config"
)

func newTestLogger() *log.Entry {
	return log.NewEntry(&log.Logger{
		Handler: discard.New(),
		Level:   log.DebugLevel,
	})
}

func TestResolveShellExecutable_Default(t *testing.T) {
	args, err := resolveShellExecutable(config.HostTerminalConfiguration{}, "")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(args) == 0 {
		t.Fatalf("expected executable path, got %#v", args)
	}
	base := filepath.Base(args[0])
	if base != "bash" && base != "sh" {
		t.Fatalf("expected bash or sh, got %q", base)
	}
}

func TestResolveShellExecutable_Fallback(t *testing.T) {
	args, err := resolveShellExecutable(config.HostTerminalConfiguration{}, "/path/that/does/not/exist")
	if err != nil {
		t.Fatalf("expected fallback to succeed, got %v", err)
	}
	if !strings.HasSuffix(args[0], "/sh") {
		t.Fatalf("expected fallback to /bin/sh, got %q", args[0])
	}
}

func TestBuildEnvironmentOverrides(t *testing.T) {
	env := buildEnvironment(map[string]string{"FOO": "bar", "PATH": "/tmp"})
	foundFoo := false
	foundPath := false
	for _, entry := range env {
		if entry == "FOO=bar" {
			foundFoo = true
		}
		if entry == "PATH=/tmp" {
			foundPath = true
		}
	}
	if !foundFoo {
		t.Fatalf("expected FOO override in environment")
	}
	if !foundPath {
		t.Fatalf("expected PATH override in environment")
	}
}

func TestPostSystemHostCommand_Disabled(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg := &config.Configuration{
		AuthenticationToken:   "test-token",
		AuthenticationTokenId: "test-id",
		System: config.SystemConfiguration{
			HostTerminal: config.HostTerminalConfiguration{
				Enabled: false,
			},
		},
	}
	config.Set(cfg)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/api/system/terminal/exec", strings.NewReader(`{"command":"echo test"}`))
	c.Request.Header.Set("Content-Type", "application/json")
	c.Set("logger", newTestLogger())

	postSystemHostCommand(c)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected status 403, got %d", w.Code)
	}
}

func TestPostSystemHostCommand_Success(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg := &config.Configuration{
		AuthenticationToken:   "test-token",
		AuthenticationTokenId: "test-id",
		System: config.SystemConfiguration{
			HostTerminal: config.HostTerminalConfiguration{
				Enabled: true,
				Shell:   "/bin/sh",
			},
		},
	}
	config.Set(cfg)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/api/system/terminal/exec", strings.NewReader(`{"command":"echo success"}`))
	c.Request.Header.Set("Content-Type", "application/json")
	c.Set("logger", newTestLogger())

	postSystemHostCommand(c)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}

	var resp hostCommandResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.ExitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", resp.ExitCode)
	}
	if strings.TrimSpace(resp.Stdout) != "success" {
		t.Fatalf("expected stdout 'success', got %q", resp.Stdout)
	}
}

func TestPostSystemHostCommand_CommandDisabled(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg := &config.Configuration{
		AuthenticationToken:   "test-token",
		AuthenticationTokenId: "test-id",
		System: config.SystemConfiguration{
			HostTerminal: config.HostTerminalConfiguration{
				Enabled:          true,
				Shell:            "/bin/sh",
				DisabledCommands: []string{"rm", "echo sensitive"},
			},
		},
	}
	config.Set(cfg)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/api/system/terminal/exec", strings.NewReader(`{"command":"rm -rf /"}`))
	c.Request.Header.Set("Content-Type", "application/json")
	c.Set("logger", newTestLogger())

	postSystemHostCommand(c)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected status 403, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "command execution is disabled") {
		t.Fatalf("expected disabled command message, got %q", w.Body.String())
	}

	// ensure exact command matching also blocks full command string entries
	w2 := httptest.NewRecorder()
	c2, _ := gin.CreateTestContext(w2)
	c2.Request = httptest.NewRequest(http.MethodPost, "/api/system/terminal/exec", strings.NewReader(`{"command":"echo sensitive"}`))
	c2.Request.Header.Set("Content-Type", "application/json")
	c2.Set("logger", newTestLogger())

	postSystemHostCommand(c2)

	if w2.Code != http.StatusForbidden {
		t.Fatalf("expected status 403 for exact command match, got %d", w2.Code)
	}
}
