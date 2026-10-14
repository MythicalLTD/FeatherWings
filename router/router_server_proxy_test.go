package router

import (
	"strings"
	"testing"
)

func TestValidateProxyDomain(t *testing.T) {
	valid := []string{
		"example.com",
		"sub.example.com",
		"a",
		"localhost",
		"my-server.local",
		"xn--nxasmq6b.example",
	}
	for _, d := range valid {
		if err := validateProxyDomain(d); err != nil {
			t.Errorf("expected %q to be valid, got error: %v", d, err)
		}
	}

	invalid := []string{
		"",
		"example.com\n",
		"bad domain.com",
		"..",
		"../etc/nginx/sites-enabled/default",
		"example..com",
		".example.com",
		"example.com.",
		"a/b",
		"a\\b",
		"server_name evil;",
		"a;rm -rf /",
		strings.Repeat("a", 64) + ".com",
		strings.Repeat("a", 254),
	}
	for _, d := range invalid {
		if err := validateProxyDomain(d); err == nil {
			t.Errorf("expected %q to be rejected", d)
		}
	}
}

func TestValidateProxyIP(t *testing.T) {
	valid := []string{"127.0.0.1", "10.0.0.1", "0.0.0.0", "::1", "2001:db8::1", "fe80::1"}
	for _, ip := range valid {
		if err := validateProxyIP(ip); err != nil {
			t.Errorf("expected %q to be a valid IP, got error: %v", ip, err)
		}
	}

	invalid := []string{"", "not-an-ip", "example.com", "127.0.0.1; rm", "999.1.1.1", "127.0.0.1\n", "1.2.3"}
	for _, ip := range invalid {
		if err := validateProxyIP(ip); err == nil {
			t.Errorf("expected %q to be rejected", ip)
		}
	}
}

func TestValidateProxyPort(t *testing.T) {
	valid := []string{"1", "22", "80", "443", "25565", "65535"}
	for _, p := range valid {
		if err := validateProxyPort(p); err != nil {
			t.Errorf("expected %q to be a valid port, got error: %v", p, err)
		}
	}

	invalid := []string{"", "0", "65536", "abc", "80\n", "80;", "-1", "1e3", "1 2"}
	for _, p := range invalid {
		if err := validateProxyPort(p); err == nil {
			t.Errorf("expected %q to be rejected", p)
		}
	}
}

func TestSafeProxySlugIsIdentityForValidDomainsAndContainsNoTraversal(t *testing.T) {
	// Valid domains must map to themselves so existing nginx config files stay
	// discoverable by create/delete.
	for _, d := range []string{"example.com", "sub.example.com", "my-server.local"} {
		if got := safeProxySlug(d); got != d {
			t.Errorf("safeProxySlug(%q) = %q, want identity", d, got)
		}
	}

	// Hostile input must never yield a path separator or a ".." segment.
	for _, in := range []string{"../etc/nginx", "a/b", "..", "a..b", "/", "a\\b", "\x00"} {
		got := safeProxySlug(in)
		if strings.ContainsAny(got, "/\\") || strings.Contains(got, "..") {
			t.Errorf("safeProxySlug(%q) = %q contains traversal characters", in, got)
		}
	}
}
