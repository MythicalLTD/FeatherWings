package cmd

import (
	"strings"
	"testing"
)

func TestSummarizeCertbotErrorPort80(t *testing.T) {
	output := "Could not bind TCP port 80 because it is already in use by another process on this system"
	got := summarizeCertbotError(output, nil)
	if !strings.Contains(got, "Port 80 is already in use") {
		t.Fatalf("unexpected summary: %q", got)
	}
}

func TestSummarizeCertbotErrorChallengeFailure(t *testing.T) {
	output := `Certbot failed to authenticate some domains (authenticator: standalone). The Certificate Authority reported these problems:
  Domain: cacapipi.mythical.systems
  Type:   unauthorized
  Detail: 207.120.37.170: Invalid response from http://cacapipi.mythical.systems/.well-known/acme-challenge/test: 409

Hint: The Certificate Authority failed to download the challenge files from the temporary standalone webserver started by Certbot on port 80.

Ask for help or search for solutions at https://community.letsencrypt.org. See the logfile /var/log/letsencrypt/letsencrypt.log or re-run Certbot with -v for more details.`
	got := summarizeCertbotError(output, fmtExitStatus())
	if !strings.Contains(got, "Invalid response from http://cacapipi.mythical.systems") {
		t.Fatalf("unexpected summary: %q", got)
	}
	if strings.Contains(got, "community.letsencrypt.org") {
		t.Fatalf("summary should not include boilerplate: %q", got)
	}
}

func TestFormatCertbotFailureMessageHTTP409(t *testing.T) {
	summary, hint := formatCertbotFailureMessage("Detail: 207.120.37.170: Invalid response from http://node.example.com/.well-known/acme-challenge/x: 409", fmtExitStatus())
	if !strings.Contains(summary, "409") {
		t.Fatalf("unexpected summary: %q", summary)
	}
	if !strings.Contains(hint, "HTTP 409") {
		t.Fatalf("unexpected hint: %q", hint)
	}
}

func TestExtractCertbotDetailSkipsBoilerplate(t *testing.T) {
	got := extractCertbotDetail("Ask for help at https://community.letsencrypt.org\nDetail: DNS problem: NXDOMAIN")
	if got != "DNS problem: NXDOMAIN" {
		t.Fatalf("unexpected detail: %q", got)
	}
}

func fmtExitStatus() error {
	return errExitStatus{}
}

type errExitStatus struct{}

func (errExitStatus) Error() string { return "exit status 1" }

func TestDefaultCertbotIssuanceConfigStandalone(t *testing.T) {
	cfg := defaultCertbotIssuanceConfig()
	if cfg.method != certbotMethodStandalone {
		t.Fatalf("unexpected method: %q", cfg.method)
	}
}

func TestCertbotMethodLabel(t *testing.T) {
	if certbotMethodLabel(certbotMethodNginx) != "nginx plugin" {
		t.Fatal("unexpected nginx label")
	}
}

func TestParsePortListenerProcesses(t *testing.T) {
	output := `LISTEN 0 511 0.0.0.0:80 0.0.0.0:* users:(("nginx",pid=1234,fd=6))
LISTEN 0 511 [::]:443 [::]:* users:(("nginx",pid=1234,fd=7))`
	got := parsePortListenerProcesses(output)
	if len(got) != 1 || got[0] != "nginx" {
		t.Fatalf("unexpected listeners: %#v", got)
	}
}

func TestMapProcessesToSystemdUnitsUnknownProcess(t *testing.T) {
	got := mapProcessesToSystemdUnits([]string{"unknown"})
	if len(got) != 0 {
		t.Fatalf("expected no units for unknown process, got %#v", got)
	}
}

func TestCertbotPluginPackagesIncludesNginx(t *testing.T) {
	pkgs := certbotPluginPackages()
	foundCertbot := false
	for _, pkg := range pkgs {
		if pkg == "certbot" {
			foundCertbot = true
		}
	}
	if !foundCertbot {
		t.Fatalf("expected certbot package in %#v", pkgs)
	}
}
