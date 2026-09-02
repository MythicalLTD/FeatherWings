package cmd

import (
	"context"
	"encoding/json"
	"bytes"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/charmbracelet/huh"
)

type certbotChallengeType string

const (
	certbotChallengeHTTP certbotChallengeType = "http"
	certbotChallengeDNS  certbotChallengeType = "dns"
)

type domainDNSReport struct {
	Domain         string
	ServerIP       string
	IPv4Records    []string
	IPv6Records    []string
	PointsToServer bool
	LookupError    string
}

type acmeDNSChallenge struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

func domainACMETXTName(domain string) string {
	domain = strings.TrimSpace(domain)
	return "_acme-challenge." + strings.TrimSuffix(domain, ".")
}

func resolveDomainIPv4(domain string) ([]string, error) {
	ips, err := net.LookupIP(domain)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]struct{})
	var records []string
	for _, ip := range ips {
		v4 := ip.To4()
		if v4 == nil {
			continue
		}
		value := v4.String()
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		records = append(records, value)
	}
	sort.Strings(records)
	return records, nil
}

func resolveDomainIPv6(domain string) ([]string, error) {
	ips, err := net.LookupIP(domain)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]struct{})
	var records []string
	for _, ip := range ips {
		if ip.To4() != nil {
			continue
		}
		value := ip.String()
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		records = append(records, value)
	}
	sort.Strings(records)
	return records, nil
}

func domainPointsToServer(records []string, serverIP string) bool {
	serverIP = strings.TrimSpace(serverIP)
	if serverIP == "" {
		return false
	}
	for _, record := range records {
		if record == serverIP {
			return true
		}
	}
	return false
}

func buildDomainDNSReport(domain, serverIP string) domainDNSReport {
	report := domainDNSReport{
		Domain:   strings.TrimSpace(domain),
		ServerIP: strings.TrimSpace(serverIP),
	}
	if report.Domain == "" {
		report.LookupError = "domain is empty"
		return report
	}

	ipv4, err4 := resolveDomainIPv4(report.Domain)
	if err4 != nil {
		report.LookupError = err4.Error()
	} else {
		report.IPv4Records = ipv4
	}

	ipv6, err6 := resolveDomainIPv6(report.Domain)
	if err6 == nil {
		report.IPv6Records = ipv6
	}

	report.PointsToServer = domainPointsToServer(report.IPv4Records, report.ServerIP)
	return report
}

func renderDomainDNSReport(report domainDNSReport) string {
	lines := []string{
		lipConfigureTeal().Bold(true).Render("Domain DNS check"),
		"",
		fmt.Sprintf("%s %s", lipConfigureMuted().Render("domain"), lipConfigureInk().Render(report.Domain)),
		fmt.Sprintf("%s %s", lipConfigureMuted().Render("this server"), lipConfigureInk().Render(emptyFallback(report.ServerIP, "unknown"))),
		"",
	}

	if report.LookupError != "" {
		lines = append(lines, lipConfigureWarn().Render("DNS lookup failed: "+report.LookupError))
	} else if len(report.IPv4Records) == 0 {
		lines = append(lines, lipConfigureWarn().Render("No IPv4 A records found for this domain"))
	} else {
		status := lipConfigureErr().Render("does not point here")
		if report.PointsToServer {
			status = lipConfigureOK().Render("points to this server")
		}
		lines = append(lines, fmt.Sprintf("%s %s (%s)", lipConfigureMuted().Render("A records"), lipConfigureInk().Render(strings.Join(report.IPv4Records, ", ")), status))
	}

	if len(report.IPv6Records) > 0 {
		lines = append(lines, fmt.Sprintf("%s %s", lipConfigureMuted().Render("AAAA records"), lipConfigureInk().Render(strings.Join(report.IPv6Records, ", "))))
	}

	if report.ServerIP != "" && !report.PointsToServer {
		lines = append(lines, "", lipConfigureMuted().Render("Add or update this DNS record at your provider:"))
		lines = append(lines, lipConfigureInk().Render("  Type:  A"))
		lines = append(lines, lipConfigureInk().Render("  Name:  "+dnsRecordHostLabel(report.Domain)))
		lines = append(lines, lipConfigureInk().Render("  Value: "+report.ServerIP))
		lines = append(lines, lipConfigureMuted().Render("  Full hostname: "+report.Domain))
	}

	return lipConfigureFrame().Width(72).Render(strings.Join(lines, "\n"))
}

func dnsRecordHostLabel(domain string) string {
	parts := strings.Split(strings.TrimSuffix(strings.TrimSpace(domain), "."), ".")
	if len(parts) <= 2 {
		return domain
	}
	return parts[0]
}

func renderDNSTXTInstructions(name, value string) string {
	lines := []string{
		lipConfigureTeal().Bold(true).Render("DNS TXT verification"),
		"",
		lipConfigureMuted().Render("Add this TXT record at your DNS provider:"),
		"",
		lipConfigureInk().Render("  Type:  TXT"),
		lipConfigureInk().Render("  Name:  "+name),
		lipConfigureInk().Render("  Value: "+value),
		lipConfigureMuted().Render("  TTL:   300 (or automatic)"),
		"",
		lipConfigureMuted().Render("DNS changes can take a few minutes to propagate."),
	}
	return lipConfigureFrame().Width(72).Render(strings.Join(lines, "\n"))
}

func emptyFallback(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

type certbotVerificationChoice string

const (
	certbotVerificationHTTP    certbotVerificationChoice = "http"
	certbotVerificationDNS     certbotVerificationChoice = "dns"
	certbotVerificationRecheck certbotVerificationChoice = "recheck"
	certbotVerificationCancel  certbotVerificationChoice = "cancel"
)

func promptCertbotVerificationSetup(domain, serverIP string) (certbotIssuanceConfig, error) {
	if !configureUIEnabled() {
		report := buildDomainDNSReport(domain, serverIP)
		cfg := defaultCertbotIssuanceConfig()
		if !report.PointsToServer {
			return cfg, fmt.Errorf("domain %s does not point to this server (%s); resolved A records: %v", domain, serverIP, report.IPv4Records)
		}
		return cfg, nil
	}

	for {
		report := buildDomainDNSReport(domain, serverIP)
		if configureUIEnabled() {
			clearConfigureScreen()
		}
		fmt.Println()
		fmt.Println(renderDomainDNSReport(report))
		fmt.Println()

		defaultChoice := certbotVerificationHTTP
		httpLabel := "HTTP verification (port 80)"
		if report.PointsToServer {
			httpLabel += " (recommended)"
		} else {
			defaultChoice = certbotVerificationDNS
			httpLabel += " — requires DNS pointing here first"
		}

		choice := defaultChoice
		err := huh.NewForm(
			huh.NewGroup(
				huh.NewSelect[certbotVerificationChoice]().
					Title("How should Let's Encrypt verify this domain?").
					Description("HTTP needs port 80 reachable on this machine. DNS TXT works behind proxies and CDNs.").
					Options(
						huh.NewOption(httpLabel, certbotVerificationHTTP),
						huh.NewOption("DNS TXT verification (works with CDN/proxy)", certbotVerificationDNS),
						huh.NewOption("Re-check DNS", certbotVerificationRecheck),
						huh.NewOption("Cancel setup", certbotVerificationCancel),
					).
					Value(&choice),
			),
		).Run()
		if err != nil {
			if err == huh.ErrUserAborted {
				return certbotIssuanceConfig{}, fmt.Errorf("configure cancelled")
			}
			return certbotIssuanceConfig{}, err
		}

		switch choice {
		case certbotVerificationRecheck:
			continue
		case certbotVerificationCancel:
			return certbotIssuanceConfig{}, fmt.Errorf("configure cancelled")
		case certbotVerificationDNS:
			cfg := defaultCertbotIssuanceConfig()
			cfg.challenge = certbotChallengeDNS
			return cfg, nil
		default:
			cfg := defaultCertbotIssuanceConfig()
			cfg.challenge = certbotChallengeHTTP
			if !report.PointsToServer {
				proceed := false
				err := huh.NewForm(
					huh.NewGroup(
						huh.NewConfirm().
							Title("DNS does not point to this server yet").
							Description("HTTP verification will likely fail until the A record points here. Continue anyway or choose DNS TXT verification instead.").
							Value(&proceed),
					),
				).Run()
				if err != nil {
					if err == huh.ErrUserAborted {
						return certbotIssuanceConfig{}, fmt.Errorf("configure cancelled")
					}
					return certbotIssuanceConfig{}, err
				}
				if !proceed {
					continue
				}
			}
			return cfg, nil
		}
	}
}

func txtRecordPublished(name, expected string) bool {
	expected = strings.TrimSpace(expected)
	if expected == "" {
		return false
	}
	records, err := net.LookupTXT(name)
	if err != nil {
		return false
	}
	for _, record := range records {
		if strings.TrimSpace(record) == expected {
			return true
		}
	}
	return false
}

func waitForTXTPropagation(ctx context.Context, name, value string) error {
	if configureUIEnabled() {
		clearConfigureScreen()
		fmt.Println()
		fmt.Println(lipConfigureFrame().Width(72).Render(strings.Join([]string{
			lipConfigureTeal().Bold(true).Render("Checking DNS TXT record"),
			"",
			lipConfigureMuted().Render("Waiting for public DNS to publish:"),
			lipConfigureInk().Render(name),
		}, "\n")))
		fmt.Println()
	}

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	deadline := time.Now().Add(10 * time.Minute)
	for {
		if txtRecordPublished(name, value) {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if time.Now().After(deadline) {
				return fmt.Errorf("timed out waiting for TXT record %s", name)
			}
			if configureUIEnabled() {
				fmt.Printf("\r%s %s   ", lipConfigureMuted().Render("…"), lipConfigureInk().Render("still waiting for DNS propagation"))
			} else {
				fmt.Printf("%s still waiting for TXT record %s\n", lipConfigureMuted().Render("…"), name)
			}
		}
	}
}

func waitForChallengeFile(ctx context.Context, path string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		if _, err := os.Stat(path); err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timed out waiting for certbot DNS challenge")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
}

func readACMEChallengeFile(path string) (acmeDNSChallenge, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return acmeDNSChallenge{}, err
	}
	var challenge acmeDNSChallenge
	if err := json.Unmarshal(raw, &challenge); err != nil {
		return acmeDNSChallenge{}, err
	}
	if strings.TrimSpace(challenge.Name) == "" || strings.TrimSpace(challenge.Value) == "" {
		return acmeDNSChallenge{}, fmt.Errorf("invalid challenge payload")
	}
	return challenge, nil
}

const certbotManualAuthHook = `#!/bin/sh
set -e
WORK_DIR="$FEATHERWINGS_CERTBOT_WORK"
NAME="_acme-challenge.${CERTBOT_DOMAIN}"
printf '{"name":"%s","value":"%s"}\n' "$NAME" "${CERTBOT_VALIDATION}" > "$WORK_DIR/challenge.json"
ELAPSED=0
while [ ! -f "$WORK_DIR/proceed" ]; do
  sleep 2
  ELAPSED=$((ELAPSED + 2))
  if [ "$ELAPSED" -ge 1800 ]; then
    echo "timed out waiting for DNS TXT record" >&2
    exit 1
  fi
done
exit 0
`

const certbotManualCleanupHook = `#!/bin/sh
exit 0
`

func writeCertbotHook(path, content string) error {
	if err := os.WriteFile(path, []byte(content), 0o700); err != nil {
		return err
	}
	return nil
}

func runCertbotCommandWithEnv(ctx context.Context, extraEnv []string, args ...string) (string, error) {
	var output bytes.Buffer
	cmd := exec.CommandContext(ctx, "certbot", args...)
	cmd.Stdout = &output
	cmd.Stderr = &output
	cmd.Env = append(os.Environ(), extraEnv...)
	err := cmd.Run()
	return output.String(), err
}

func promptDNSTXTRecordSetup(challenge acmeDNSChallenge) error {
	for {
		if configureUIEnabled() {
			clearConfigureScreen()
		}
		fmt.Println()
		fmt.Println(renderDNSTXTInstructions(challenge.Name, challenge.Value))
		fmt.Println()

		ready := false
		err := huh.NewForm(
			huh.NewGroup(
				huh.NewConfirm().
					Title("I've added the DNS TXT record").
					Description("FeatherWings will check public DNS before continuing with Let's Encrypt.").
					Value(&ready),
			),
		).Run()
		if err != nil {
			if err == huh.ErrUserAborted {
				return fmt.Errorf("configure cancelled")
			}
			return err
		}
		if ready {
			return nil
		}
		fmt.Println(lipConfigureMuted().Render("Add the TXT record at your DNS provider, then choose Yes when it is ready."))
		fmt.Println()
	}
}

func requestLetsEncryptCertificateDNS(ctx context.Context, domain, email string, reporter *configureReporter) error {
	domain = strings.TrimSpace(domain)
	email = strings.TrimSpace(email)
	if domain == "" {
		return fmt.Errorf("domain is required for certificate issuance")
	}
	if email == "" {
		return fmt.Errorf("an email address is required for Let's Encrypt")
	}

	workDir, err := os.MkdirTemp("", "featherwings-certbot-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(workDir)

	authHook := filepath.Join(workDir, "auth.sh")
	cleanupHook := filepath.Join(workDir, "cleanup.sh")
	challengePath := filepath.Join(workDir, "challenge.json")
	proceedPath := filepath.Join(workDir, "proceed")

	if err := writeCertbotHook(authHook, certbotManualAuthHook); err != nil {
		return err
	}
	if err := writeCertbotHook(cleanupHook, certbotManualCleanupHook); err != nil {
		return err
	}

	if configureUIEnabled() {
		clearConfigureScreen()
		fmt.Println()
		fmt.Println(lipConfigureMuted().Render("Preparing DNS challenge with Certbot…"))
		fmt.Println()
	}

	reporter.SetStatus("Starting DNS TXT verification…")
	reporter.Detail("Certbot will provide a TXT record to publish")

	errCh := make(chan error, 1)
	go func() {
		output, runErr := runCertbotCommandWithEnv(ctx, []string{"FEATHERWINGS_CERTBOT_WORK=" + workDir},
			"certonly",
			"--manual",
			"--preferred-challenges", "dns",
			"-d", domain,
			"--non-interactive",
			"--agree-tos",
			"-m", email,
			"--manual-auth-hook", authHook,
			"--manual-cleanup-hook", cleanupHook,
		)
		if runErr != nil {
			errCh <- newCertbotUserError(output, runErr)
			return
		}
		if !letsEncryptCertificateExists(domain) {
			errCh <- fmt.Errorf("certbot finished but no certificate was found for %s", domain)
			return
		}
		errCh <- nil
	}()

	if err := waitForChallengeFile(ctx, challengePath, 2*time.Minute); err != nil {
		return err
	}

	challenge, err := readACMEChallengeFile(challengePath)
	if err != nil {
		return err
	}

	if configureUIEnabled() {
		if err := promptDNSTXTRecordSetup(challenge); err != nil {
			return err
		}
	}

	reporter.SetStatus("Checking DNS TXT record…")
	reporter.Detail(challenge.Name)
	if err := waitForTXTPropagation(ctx, challenge.Name, challenge.Value); err != nil {
		return err
	}
	reporter.Detail("TXT record found in public DNS")

	if err := os.WriteFile(proceedPath, []byte("1"), 0o600); err != nil {
		return err
	}

	if err := <-errCh; err != nil {
		return err
	}

	fullchain, _ := letsEncryptCertificatePaths(domain)
	reporter.Detail("Certificate saved to " + fullchain)
	return nil
}
