package cmd

import (
	"strings"
	"testing"
)

func TestBuildConfigureOAuthConsentURL(t *testing.T) {
	url, err := buildConfigureOAuthConsentURL("https://panel.example.com/", "http://203.0.113.42:3847/callback")
	if err != nil {
		t.Fatalf("buildConfigureOAuthConsentURL() error = %v", err)
	}

	if !strings.HasPrefix(url, "https://panel.example.com/dashboard/account/oauth2/api/new?") {
		t.Fatalf("unexpected consent URL prefix: %q", url)
	}
	if !strings.Contains(url, "mode=server") {
		t.Fatal("expected mode=server in consent URL")
	}
	if !strings.Contains(url, "callbackurl=http%3A%2F%2F203.0.113.42%3A3847%2Fcallback") {
		t.Fatal("expected encoded public callback URL in consent URL")
	}
	if !strings.Contains(url, "appName=FeatherWings") {
		t.Fatal("expected appName in consent URL")
	}

	junkURL, err := buildConfigureOAuthConsentURL(
		"https://testingpanel.mythical.systems/admin/nodes/8/edit?tab=wings",
		"http://212.87.213.118:37155/callback",
	)
	if err != nil {
		t.Fatalf("buildConfigureOAuthConsentURL() with junk path error = %v", err)
	}
	if !strings.HasPrefix(junkURL, "https://testingpanel.mythical.systems/dashboard/account/oauth2/api/new?") {
		t.Fatalf("unexpected consent URL with pasted path: %q", junkURL)
	}
	if strings.Contains(junkURL, "admin/nodes") {
		t.Fatalf("consent URL should not contain pasted panel path: %q", junkURL)
	}
}
