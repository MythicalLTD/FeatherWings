package cmd

import (
	"testing"
)

func TestDomainPointsToServer(t *testing.T) {
	if !domainPointsToServer([]string{"203.0.113.10", "198.51.100.2"}, "203.0.113.10") {
		t.Fatal("expected matching server IP")
	}
	if domainPointsToServer([]string{"203.0.113.10"}, "203.0.113.42") {
		t.Fatal("expected mismatch")
	}
}

func TestDomainACMETXTName(t *testing.T) {
	if got := domainACMETXTName("node.example.com"); got != "_acme-challenge.node.example.com" {
		t.Fatalf("unexpected txt name: %q", got)
	}
}

func TestBuildDomainDNSReportNoServerIP(t *testing.T) {
	report := buildDomainDNSReport("example.com", "")
	if report.PointsToServer {
		t.Fatal("expected no match without server IP")
	}
}

func TestDNSRecordHostLabel(t *testing.T) {
	if got := dnsRecordHostLabel("cacapipi.mythical.systems"); got != "cacapipi" {
		t.Fatalf("unexpected host label: %q", got)
	}
}

func TestReadACMEChallengeFile(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/challenge.json"
	if err := writeCertbotHook(path, `{"name":"_acme-challenge.example.com","value":"token"}`); err != nil {
		t.Fatal(err)
	}
	challenge, err := readACMEChallengeFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if challenge.Name != "_acme-challenge.example.com" || challenge.Value != "token" {
		t.Fatalf("unexpected challenge: %+v", challenge)
	}
}
