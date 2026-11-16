package router

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/mythicalltd/featherwings/config"
	"github.com/mythicalltd/featherwings/internal/metrics"
	"github.com/mythicalltd/featherwings/remote"
	"github.com/mythicalltd/featherwings/server"
)

func setObservabilityConfig(t *testing.T, mc config.MetricsConfiguration) {
	t.Helper()
	cfg, err := config.NewAtPath("")
	if err != nil {
		t.Fatal(err)
	}
	cfg.AuthenticationToken = "node-token"
	cfg.System.Data = t.TempDir()
	cfg.Health.MinFreeDiskMb = 0
	cfg.Metrics = mc
	config.Set(cfg)
}

func stubHealthDeps(t *testing.T, dockerErr, panelErr error, sftp bool) {
	t.Helper()
	prevPing, prevProbe := dockerPing, probePanel
	dockerPing = func(context.Context) error { return dockerErr }
	probePanel = func(context.Context, *config.Configuration) error { return panelErr }
	metrics.SetSFTPListening(sftp)
	panelProbe.mu.Lock()
	panelProbe.at = panelProbe.at.AddDate(-1, 0, 0)
	panelProbe.mu.Unlock()
	readinessCache.mu.Lock()
	readinessCache.at = readinessCache.at.AddDate(-1, 0, 0)
	readinessCache.mu.Unlock()
	t.Cleanup(func() {
		dockerPing, probePanel = prevPing, prevProbe
		metrics.SetSFTPListening(false)
	})
}

func newObservabilityRouter(t *testing.T) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	observeManager(server.NewEmptyManager(nil))
	r.Use(requestMetrics())
	r.GET("/health/live", getHealthLive)
	r.GET("/health/ready", getHealthReady)
	r.GET("/metrics", getMetrics)
	return r
}

func doRequest(h http.Handler, path, auth, remoteAddr string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	if remoteAddr != "" {
		req.RemoteAddr = remoteAddr
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

func TestMetricsAccess(t *testing.T) {
	cases := []struct {
		name     string
		cfg      config.MetricsConfiguration
		auth, ip string
		loopback bool
		want     int
	}{
		{"disabled", config.MetricsConfiguration{}, "", "127.0.0.1", true, http.StatusNotFound},
		{"unprotected public", config.MetricsConfiguration{Enabled: true}, "", "10.0.0.1", false, http.StatusNotFound},
		{"unprotected loopback listener", config.MetricsConfiguration{Enabled: true}, "", "127.0.0.1", true, 0},
		{"missing token", config.MetricsConfiguration{Enabled: true, Token: "s3cret"}, "", "10.0.0.1", false, http.StatusUnauthorized},
		{"wrong token", config.MetricsConfiguration{Enabled: true, Token: "s3cret"}, "Bearer nope", "10.0.0.1", false, http.StatusUnauthorized},
		{"empty bearer", config.MetricsConfiguration{Enabled: true, Token: "s3cret"}, "Bearer ", "10.0.0.1", false, http.StatusUnauthorized},
		{"right token", config.MetricsConfiguration{Enabled: true, Token: "s3cret"}, "Bearer s3cret", "10.0.0.1", false, 0},
		{"ip allowed", config.MetricsConfiguration{Enabled: true, AllowedIPs: []string{"10.0.0.0/8"}}, "", "10.1.2.3", false, 0},
		{"ip exact", config.MetricsConfiguration{Enabled: true, AllowedIPs: []string{"192.168.1.5"}}, "", "192.168.1.5", false, 0},
		{"ip denied", config.MetricsConfiguration{Enabled: true, AllowedIPs: []string{"10.0.0.0/8"}}, "", "192.168.1.5", false, http.StatusForbidden},
		{"ip and token both required", config.MetricsConfiguration{Enabled: true, Token: "s3cret", AllowedIPs: []string{"10.0.0.0/8"}}, "", "10.1.2.3", false, http.StatusUnauthorized},
		{"ip and token both ok", config.MetricsConfiguration{Enabled: true, Token: "s3cret", AllowedIPs: []string{"10.0.0.0/8"}}, "Bearer s3cret", "10.1.2.3", false, 0},
	}
	for _, tc := range cases {
		if got := metricsAccess(tc.cfg, tc.auth, tc.ip, tc.loopback); got != tc.want {
			t.Errorf("%s: got %d, want %d", tc.name, got, tc.want)
		}
	}
}

func TestMetricsListenerProtected(t *testing.T) {
	if !MetricsListenerProtected(config.MetricsConfiguration{Host: "127.0.0.1"}) {
		t.Error("loopback listener should count as protected")
	}
	if MetricsListenerProtected(config.MetricsConfiguration{Host: "0.0.0.0"}) {
		t.Error("public listener without token or allowlist must not count as protected")
	}
	if !MetricsListenerProtected(config.MetricsConfiguration{Host: "0.0.0.0", Token: "x"}) {
		t.Error("public listener with a token should count as protected")
	}
}

func TestGetMetricsOnMainAPI(t *testing.T) {
	r := newObservabilityRouter(t)
	stubHealthDeps(t, nil, nil, true)

	setObservabilityConfig(t, config.MetricsConfiguration{})
	if w := doRequest(r, "/metrics", "", ""); w.Code != http.StatusNotFound {
		t.Fatalf("disabled: got %d", w.Code)
	}

	setObservabilityConfig(t, config.MetricsConfiguration{Enabled: true})
	if w := doRequest(r, "/metrics", "", ""); w.Code != http.StatusNotFound {
		t.Fatalf("enabled without protection on the main API: got %d", w.Code)
	}

	setObservabilityConfig(t, config.MetricsConfiguration{Enabled: true, Token: "s3cret", PerServer: true})
	if w := doRequest(r, "/metrics", "Bearer node-token", ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("node token must not grant metrics access: got %d", w.Code)
	}
	w := doRequest(r, "/metrics", "Bearer s3cret", "")
	if w.Code != http.StatusOK {
		t.Fatalf("right token: got %d", w.Code)
	}
	body := w.Body.String()
	for _, want := range []string{
		"featherwings_http_requests_total",
		"featherwings_servers{state=\"running\"}",
		"featherwings_websocket_connections",
		"featherwings_transfers_in_progress{direction=\"incoming\"}",
		"featherwings_backups_total{result=\"failure\"}",
		"featherwings_sftp_sessions",
		"featherwings_docker_up",
		"go_goroutines",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics output is missing %s", want)
		}
	}

	setObservabilityConfig(t, config.MetricsConfiguration{Enabled: true, Token: "s3cret", Port: 9100})
	if w := doRequest(r, "/metrics", "Bearer s3cret", ""); w.Code != http.StatusNotFound {
		t.Fatalf("main API must not serve metrics when a dedicated port is set: got %d", w.Code)
	}
}

func TestMetricsHandlerDedicatedListener(t *testing.T) {
	h := MetricsHandler()
	stubHealthDeps(t, nil, nil, true)

	setObservabilityConfig(t, config.MetricsConfiguration{Enabled: true, Host: "127.0.0.1", Port: 9100})
	if w := doRequest(h, "/metrics", "", "127.0.0.1:5555"); w.Code != http.StatusOK {
		t.Fatalf("loopback listener without auth: got %d", w.Code)
	}

	setObservabilityConfig(t, config.MetricsConfiguration{Enabled: true, Host: "0.0.0.0", Port: 9100, AllowedIPs: []string{"10.0.0.0/8"}})
	if w := doRequest(h, "/metrics", "", "192.168.0.9:5555"); w.Code != http.StatusForbidden {
		t.Fatalf("ip outside allowlist: got %d", w.Code)
	}
	if w := doRequest(h, "/metrics", "", "10.0.0.9:5555"); w.Code != http.StatusOK {
		t.Fatalf("ip inside allowlist: got %d", w.Code)
	}
	if w := doRequest(h, "/health/live", "", "192.168.0.9:5555"); w.Code != http.StatusOK {
		t.Fatalf("liveness on dedicated listener: got %d", w.Code)
	}
}

func decodeHealth(t *testing.T, w *httptest.ResponseRecorder) HealthResponse {
	t.Helper()
	var resp HealthResponse
	b, _ := io.ReadAll(w.Body)
	if err := json.Unmarshal(b, &resp); err != nil {
		t.Fatalf("invalid health body %q: %v", b, err)
	}
	return resp
}

func TestHealthLive(t *testing.T) {
	r := newObservabilityRouter(t)
	setObservabilityConfig(t, config.MetricsConfiguration{})
	w := doRequest(r, "/health/live", "", "")
	if w.Code != http.StatusOK || decodeHealth(t, w).Status != "ok" {
		t.Fatalf("got %d %s", w.Code, w.Body.String())
	}
}

func TestHealthReady(t *testing.T) {
	r := newObservabilityRouter(t)
	setObservabilityConfig(t, config.MetricsConfiguration{})

	stubHealthDeps(t, nil, nil, true)
	w := doRequest(r, "/health/ready", "", "")
	resp := decodeHealth(t, w)
	if w.Code != http.StatusOK || resp.Status != "ok" {
		t.Fatalf("all healthy: got %d %s", w.Code, w.Body.String())
	}
	for _, name := range []string{"docker", "data_directory", "disk_space", "sftp", "panel"} {
		c, ok := resp.Checks[name]
		if !ok || c.Status != "ok" {
			t.Errorf("check %s: %+v", name, c)
		}
		if c.Message != "" {
			t.Errorf("unauthenticated request must not see check messages, %s has %q", name, c.Message)
		}
	}

	w = doRequest(r, "/health/ready", "Bearer node-token", "")
	if resp := decodeHealth(t, w); resp.Checks["docker"].Message == "" {
		t.Errorf("node token should see check messages: %s", w.Body.String())
	}

	// A non-critical failure degrades but stays ready.
	stubHealthDeps(t, nil, errors.New("connection refused"), true)
	w = doRequest(r, "/health/ready", "Bearer node-token", "")
	resp = decodeHealth(t, w)
	if w.Code != http.StatusOK || resp.Status != "degraded" || resp.Checks["panel"].Status != "fail" {
		t.Fatalf("panel down: got %d %s", w.Code, w.Body.String())
	}

	// A critical failure makes the node unavailable.
	stubHealthDeps(t, errors.New("cannot connect to the docker daemon"), nil, false)
	w = doRequest(r, "/health/ready", "", "")
	resp = decodeHealth(t, w)
	if w.Code != http.StatusServiceUnavailable || resp.Status != "unavailable" || resp.Checks["docker"].Status != "fail" || resp.Checks["sftp"].Status != "fail" {
		t.Fatalf("docker and sftp down: got %d %s", w.Code, w.Body.String())
	}

	// A data directory that cannot be written to fails readiness.
	stubHealthDeps(t, nil, nil, true)
	cfg := config.Get()
	cfg.System.Data = "/nonexistent/featherwings-health"
	config.Set(cfg)
	stubHealthDeps(t, nil, nil, true)
	if w := doRequest(r, "/health/ready", "", ""); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("missing data directory: got %d", w.Code)
	}
}

func TestPanelContactSkipsProbe(t *testing.T) {
	setObservabilityConfig(t, config.MetricsConfiguration{})
	cfg := config.Get()
	cfg.Health.PanelContactMaxAge = 300
	config.Set(cfg)
	stubHealthDeps(t, nil, errors.New("probe should not run"), true)
	metrics.RecordPanelResponse(http.StatusOK, nil)
	if _, err := checkPanel(context.Background(), config.Get()); err != nil {
		t.Fatalf("recent panel contact should pass without probing: %v", err)
	}
}

func TestPerServerMetrics(t *testing.T) {
	setObservabilityConfig(t, config.MetricsConfiguration{Enabled: true, Token: "s3cret", PerServer: true})
	stubHealthDeps(t, nil, nil, true)
	s, err := server.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	settings, _ := json.Marshal(map[string]string{"uuid": "11111111-2222-3333-4444-555555555555"})
	if err := s.SyncWithConfiguration(remote.ServerConfigurationResponse{Settings: settings, ProcessConfiguration: &remote.ProcessConfiguration{}}); err != nil {
		t.Fatal(err)
	}
	s.Environment = runningEnvironment{}
	m := server.NewEmptyManager(nil)
	m.Add(s)

	gin.SetMode(gin.TestMode)
	r := gin.New()
	observeManager(m)
	r.GET("/metrics", getMetrics)
	body := doRequest(r, "/metrics", "Bearer s3cret", "").Body.String()
	for _, want := range []string{
		`featherwings_servers{state="running"} 1`,
		`featherwings_server_state{server="11111111-2222-3333-4444-555555555555",state="running"} 1`,
		`featherwings_server_state{server="11111111-2222-3333-4444-555555555555",state="offline"} 0`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics output is missing %s", want)
		}
	}
}
