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

// legacyHTTPProxyConfig and legacyTLSProxyConfig are the server blocks as they were generated before the upstream
// headers were added. The new output must equal them once the added lines are removed, so nothing else changed.
const legacyHTTPProxyConfig = "server {\n\t\tlisten 80;\n\t\tserver_name example.com;\n\n" +
	"\t\tlocation / {\n\t\t\tproxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n\t\t\tproxy_set_header Host $http_host;\n" +
	"\t\t\tproxy_pass http://127.0.0.1:25565;\n\t\t}\n\n" +
	"\t\tlocation /.well-known/acme-challenge/ {\n\t\t\tproxy_set_header Host $host;\n\t\t\tproxy_pass http://127.0.0.1:81$request_uri;\n\t\t}\n\t}"

const legacyTLSProxyConfig = "server {\n\tlisten 80;\n\tserver_name example.com;\n\treturn 301 https://$server_name$request_uri;\n}\n\n" +
	"server {\n\tlisten 443 ssl http2;\n\tserver_name example.com;\n\n" +
	"\tssl_certificate /srv/server_certs/example.com/cert.pem;\n\tssl_certificate_key /srv/server_certs/example.com/key.pem;\n" +
	"\tssl_session_cache shared:SSL:10m;\n\tssl_protocols TLSv1.2 TLSv1.3;\n" +
	"\tssl_ciphers \"ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384\";\n" +
	"\tssl_prefer_server_ciphers on;\n\n" +
	"\tlocation / {\n\t\tproxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n\t\tproxy_set_header Host $http_host;\n" +
	"\t\tproxy_pass http://127.0.0.1:25565;\n\t}\n\n" +
	"\tlocation /.well-known/acme-challenge/ {\n\t\tproxy_set_header Host $host;\n\t\tproxy_pass http://127.0.0.1:81$request_uri;\n\t}\n}"

var addedProxyUpstreamLines = []string{
	"proxy_http_version 1.1;",
	"proxy_set_header Upgrade $http_upgrade;",
	"proxy_set_header Connection $http_connection;",
	"proxy_set_header X-Forwarded-Proto $scheme;",
}

// withoutAddedProxyLines drops the header lines this change adds.
func withoutAddedProxyLines(conf string) string {
	var kept []string
	for _, line := range strings.Split(conf, "\n") {
		trimmed := strings.TrimSpace(line)
		drop := false
		for _, added := range addedProxyUpstreamLines {
			if trimmed == added {
				drop = true
				break
			}
		}
		if !drop {
			kept = append(kept, line)
		}
	}
	return strings.Join(kept, "\n")
}

func TestProxyConfigsForwardWebSocketAndSchemeHeaders(t *testing.T) {
	const upstream = "127.0.0.1:25565"
	configs := map[string]string{
		"http": buildHTTPProxyConfig("example.com", upstream),
		"tls":  buildTLSProxyConfig("example.com", "/srv/server_certs/example.com/cert.pem", "/srv/server_certs/example.com/key.pem", upstream),
	}
	for name, conf := range configs {
		for _, want := range addedProxyUpstreamLines {
			if !strings.Contains(conf, want) {
				t.Errorf("%s config is missing %q:\n%s", name, want, conf)
			}
		}
		// The ACME helper location must stay untouched: it talks plain HTTP/1.0 to the local challenge server.
		acme := conf[strings.Index(conf, "location /.well-known/acme-challenge/"):]
		for _, added := range addedProxyUpstreamLines {
			if strings.Contains(acme, added) {
				t.Errorf("%s config: %q must not appear in the ACME location", name, added)
			}
		}
		// No map block is required in nginx.conf, so the config must not reference a variable that has to be defined elsewhere.
		if strings.Contains(conf, "$connection_upgrade") {
			t.Errorf("%s config references $connection_upgrade, which needs a map in the http context", name)
		}
	}
	if !strings.Contains(configs["http"], "proxy_set_header X-Forwarded-Proto $scheme;") || !strings.Contains(configs["tls"], "listen 443 ssl http2;") {
		t.Error("unexpected proxy config layout")
	}
}

func TestProxyConfigsOnlyDifferFromLegacyByTheAddedHeaders(t *testing.T) {
	const upstream = "127.0.0.1:25565"
	if got := withoutAddedProxyLines(buildHTTPProxyConfig("example.com", upstream)); got != legacyHTTPProxyConfig {
		t.Errorf("http config changed beyond the added headers.\n got:\n%s\nwant:\n%s", got, legacyHTTPProxyConfig)
	}
	tls := buildTLSProxyConfig("example.com", "/srv/server_certs/example.com/cert.pem", "/srv/server_certs/example.com/key.pem", upstream)
	if got := withoutAddedProxyLines(tls); got != legacyTLSProxyConfig {
		t.Errorf("tls config changed beyond the added headers.\n got:\n%s\nwant:\n%s", got, legacyTLSProxyConfig)
	}
}

func TestProxyConfigsBracketIPv6Upstream(t *testing.T) {
	conf := buildHTTPProxyConfig("example.com", proxyTargetHost("2001:db8::1")+":8080")
	if !strings.Contains(conf, "proxy_pass http://[2001:db8::1]:8080;") {
		t.Errorf("IPv6 upstream not bracketed:\n%s", conf)
	}
}
