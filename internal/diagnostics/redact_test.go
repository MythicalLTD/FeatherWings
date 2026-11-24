package diagnostics

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mythicalltd/featherwings/config"
)

func redactTestConfig() *config.Configuration {
	cfg := &config.Configuration{}
	cfg.AuthenticationToken = "node-secret-token-value"
	cfg.Token.Token = "node-secret-token-value"
	cfg.Metrics.Token = "metrics-bearer-value"
	cfg.PanelLocation = "https://panel.example.com"
	cfg.Api.Host = "0.0.0.0"
	cfg.System.Sftp.Address = "0.0.0.0"
	return cfg
}

const testJWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl"

// The node's tokens, JWTs and token query parameters are removed from the whole
// report, including the included logs.
func TestRedactReportRemovesTokens(t *testing.T) {
	report := strings.Join([]string{
		"Panel Location: {redacted}",
		"INFO: request GET /api/servers/x/ws?token=" + testJWT + " 101",
		"DEBUG: download /download/file?%74oken=abc.def&server=x",
		"DEBUG: header Authorization: Bearer node-secret-token-value",
		"metrics token metrics-bearer-value",
		"panel at https://panel.example.com/api/remote and panel.example.com",
		"listening on 0.0.0.0:8080",
	}, "\n")

	got := redactReport(report, redactTestConfig(), false)
	for _, secret := range []string{testJWT, "abc.def", "node-secret-token-value", "metrics-bearer-value", "panel.example.com"} {
		if strings.Contains(got, secret) {
			t.Errorf("report still contains %q:\n%s", secret, got)
		}
	}
	for _, keep := range []string{"&server=x", "listening on 0.0.0.0:8080", "?token={redacted}", "%74oken={redacted}"} {
		if !strings.Contains(got, keep) {
			t.Errorf("report does not contain %q:\n%s", keep, got)
		}
	}
}

// Endpoints stay in the report when they should be included, but the tokens
// are still removed.
func TestRedactReportKeepsEndpointsWhenIncluded(t *testing.T) {
	got := redactReport("panel https://panel.example.com token node-secret-token-value", redactTestConfig(), true)
	if !strings.Contains(got, "https://panel.example.com") {
		t.Errorf("endpoint was removed although it should be included: %s", got)
	}
	if strings.Contains(got, "node-secret-token-value") {
		t.Errorf("token was not removed: %s", got)
	}
}

// Other query parameters are left alone.
func TestRedactTokenParamsOnlyTouchesToken(t *testing.T) {
	in := "/a?tokens=1&mytoken=2&token=3&x=4"
	want := "/a?tokens=1&mytoken=2&token={redacted}&x=4"
	if got := redactTokenParams(in); got != want {
		t.Fatalf("redactTokenParams(%q) = %q, expected %q", in, got, want)
	}
}

// A paste service answering with an oversized body is not read into memory.
func TestUploadReportRejectsOversizedResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"success":true,"url":"` + strings.Repeat("a", maxUploadResponseSize) + `"}`))
	}))
	defer srv.Close()

	if _, err := UploadReport(context.Background(), srv.URL, "report"); err == nil || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("UploadReport() error = %v, expected a size error", err)
	}
}

func TestUploadReportReturnsURL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"success":true,"url":"https://paste.example/abc"}`))
	}))
	defer srv.Close()

	u, err := UploadReport(context.Background(), srv.URL, "report")
	if err != nil || u != "https://paste.example/abc" {
		t.Fatalf("UploadReport() = %q, %v", u, err)
	}
}
