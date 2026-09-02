package cmd

import "testing"

func TestBuildOAuthCallbackURL(t *testing.T) {
	t.Parallel()

	if got := buildOAuthCallbackURL("203.0.113.42", 36997); got != "http://203.0.113.42:36997/callback" {
		t.Fatalf("unexpected callback URL: %q", got)
	}
	if got := buildOAuthCallbackURL("2001:db8::1", 8080); got != "http://[2001:db8::1]:8080/callback" {
		t.Fatalf("unexpected ipv6 callback URL: %q", got)
	}
}

func TestNormalizeOAuthCallbackHost(t *testing.T) {
	t.Parallel()

	host, err := normalizeOAuthCallbackHost("http://203.0.113.42:36997/callback")
	if err != nil {
		t.Fatalf("normalizeOAuthCallbackHost() error = %v", err)
	}
	if host != "203.0.113.42" {
		t.Fatalf("normalizeOAuthCallbackHost() = %q", host)
	}
}

func TestIsPrivateIPv4(t *testing.T) {
	t.Parallel()

	if !isPrivateIPv4("10.0.0.5") {
		t.Fatal("expected 10.0.0.5 to be private")
	}
	if isPrivateIPv4("203.0.113.42") {
		t.Fatal("expected 203.0.113.42 to be public")
	}
}

func TestSelectOAuthCallbackHostNonInteractive(t *testing.T) {
	t.Parallel()

	selection, err := selectOAuthCallbackHostNonInteractive([]oauthCallbackHostOption{
		{Host: "203.0.113.42", Source: "outbound"},
	})
	if err != nil {
		t.Fatalf("selectOAuthCallbackHostNonInteractive() error = %v", err)
	}
	if selection.Host != "203.0.113.42" || selection.Source != "outbound" {
		t.Fatalf("unexpected selection: %+v", selection)
	}

	selection, err = selectOAuthCallbackHostNonInteractive([]oauthCallbackHostOption{
		{Host: "203.0.113.42", Source: "outbound"},
		{Host: "198.51.100.10", Source: "interface"},
	})
	if err != nil {
		t.Fatalf("expected outbound host to win, got error: %v", err)
	}
	if selection.Host != "203.0.113.42" {
		t.Fatalf("expected outbound host, got %+v", selection)
	}

	_, err = selectOAuthCallbackHostNonInteractive([]oauthCallbackHostOption{
		{Host: "203.0.113.42", Source: "interface"},
		{Host: "198.51.100.10", Source: "interface"},
	})
	if err == nil {
		t.Fatal("expected error when multiple interface hosts are detected without outbound IP")
	}
}

func TestDiscoverOAuthCallbackHostsDedupes(t *testing.T) {
	t.Parallel()

	candidates := []oauthCallbackHostOption{}
	seen := map[string]struct{}{}
	add := func(host, source string) {
		if _, ok := seen[host]; ok {
			return
		}
		seen[host] = struct{}{}
		candidates = append(candidates, oauthCallbackHostOption{Host: host, Source: source})
	}
	add("203.0.113.42", "outbound")
	add("203.0.113.42", "interface")
	add("198.51.100.10", "interface")

	if len(candidates) != 2 {
		t.Fatalf("expected 2 candidates, got %d", len(candidates))
	}
}
