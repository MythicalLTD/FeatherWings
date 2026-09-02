package cmd

import (
	"strings"
	"testing"
)

func TestBuildConfigureNodeRequest(t *testing.T) {
	ipv4 := "203.0.113.10"
	req := buildConfigureNodeRequest(configureNodeForm{
		Name:         "node-1",
		Description:  "Primary node",
		FQDN:         "node.example.com",
		LocationID:   3,
		Public:       true,
		Scheme:       "https",
		BehindProxy:  true,
		PublicIPv4:   ipv4,
		MemoryMiB:    8192,
		DiskMiB:      40960,
		UploadSizeMB: 100,
		DaemonListen: 8443,
		DaemonSFTP:   2022,
		FastDLPort:   80,
		DaemonBase:   "/var/lib/featherpanel/volumes",
	})

	if req.Name != "node-1" || req.LocationID != 3 || req.Public != 1 || req.BehindProxy != 1 {
		t.Fatalf("unexpected request: %+v", req)
	}
	if req.PublicIPv4 == nil || *req.PublicIPv4 != ipv4 {
		t.Fatalf("unexpected public ipv4: %+v", req.PublicIPv4)
	}
	if req.DaemonType != "featherwings" {
		t.Fatalf("unexpected daemon type: %q", req.DaemonType)
	}
}

func TestDefaultConfigureNodeFormUsesNodeIP(t *testing.T) {
	form := defaultConfigureNodeForm("203.0.113.42")
	if form.PublicIPv4 != "203.0.113.42" {
		t.Fatalf("PublicIPv4 = %q", form.PublicIPv4)
	}
	if form.FQDN == "" {
		t.Fatalf("expected default FQDN from hostname")
	}
	if form.MemoryMiB <= 0 || form.DiskMiB <= 0 {
		t.Fatalf("expected detected resources, got memory=%d disk=%d", form.MemoryMiB, form.DiskMiB)
	}
}

func TestPanelURLAnalysis(t *testing.T) {
	scheme, host, isIP := panelURLAnalysis("http://212.87.213.118:8721")
	if scheme != "http" || host != "212.87.213.118" || !isIP {
		t.Fatalf("unexpected analysis: %q %q %v", scheme, host, isIP)
	}

	scheme, host, isIP = panelURLAnalysis("https://panel.example.com")
	if scheme != "https" || host != "panel.example.com" || isIP {
		t.Fatalf("unexpected analysis: %q %q %v", scheme, host, isIP)
	}
}

func TestConfigurePanelUsesHTTPS(t *testing.T) {
	if configurePanelUsesHTTPS("http://212.87.213.118:8721") {
		t.Fatal("expected http panel url")
	}
	if !configurePanelUsesHTTPS("https://panel.example.com") {
		t.Fatal("expected https panel url")
	}
}

func TestConfigurePanelHostIsIP(t *testing.T) {
	if !configurePanelHostIsIP("http://212.87.213.118:8721") {
		t.Fatal("expected ip panel url")
	}
	if configurePanelHostIsIP("https://panel.example.com") {
		t.Fatal("expected hostname panel url")
	}
}

func TestLetsEncryptCertificatePaths(t *testing.T) {
	fullchain, privkey := letsEncryptCertificatePaths("node.example.com")
	if !strings.HasSuffix(fullchain, "/etc/letsencrypt/live/node.example.com/fullchain.pem") {
		t.Fatalf("unexpected fullchain path: %s", fullchain)
	}
	if !strings.HasSuffix(privkey, "/etc/letsencrypt/live/node.example.com/privkey.pem") {
		t.Fatalf("unexpected privkey path: %s", privkey)
	}
}

func TestDefaultConfigureNodeFormPorts(t *testing.T) {
	form := defaultConfigureNodeForm("")
	if form.DaemonListen != 8443 || form.DaemonSFTP != 2022 || form.FastDLPort != 80 {
		t.Fatalf("unexpected default ports: %+v", form)
	}
	if form.DaemonBase != defaultConfigureDaemonBase {
		t.Fatalf("unexpected daemon base: %q", form.DaemonBase)
	}
}
