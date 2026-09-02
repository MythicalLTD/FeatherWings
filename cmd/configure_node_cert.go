package cmd

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/charmbracelet/huh"
)

const letsEncryptLiveDir = "/etc/letsencrypt/live"

type certbotIssuanceMethod string

const (
	certbotMethodStandalone certbotIssuanceMethod = "standalone"
	certbotMethodNginx      certbotIssuanceMethod = "nginx"
	certbotMethodWebroot    certbotIssuanceMethod = "webroot"
)

type certbotIssuanceConfig struct {
	method    certbotIssuanceMethod
	webroot   string
	challenge certbotChallengeType
}

type certbotRecoveryAction string

const (
	certbotRecoveryRetry        certbotRecoveryAction = "retry"
	certbotRecoveryStopAndRetry certbotRecoveryAction = "stop_retry"
	certbotRecoveryNginx        certbotRecoveryAction = "nginx"
	certbotRecoveryWebroot      certbotRecoveryAction = "webroot"
	certbotRecoveryDNS          certbotRecoveryAction = "dns"
	certbotRecoveryRecheck      certbotRecoveryAction = "recheck"
	certbotRecoveryChangeDomain certbotRecoveryAction = "change_domain"
	certbotRecoveryCancel       certbotRecoveryAction = "cancel"
)

func letsEncryptCertificatePaths(domain string) (fullchain, privkey string) {
	domain = strings.TrimSpace(domain)
	dir := filepath.Join(letsEncryptLiveDir, domain)
	return filepath.Join(dir, "fullchain.pem"), filepath.Join(dir, "privkey.pem")
}

func letsEncryptCertificateExists(domain string) bool {
	fullchain, privkey := letsEncryptCertificatePaths(domain)
	st1, err1 := os.Stat(fullchain)
	st2, err2 := os.Stat(privkey)
	return err1 == nil && err2 == nil && !st1.IsDir() && !st2.IsDir()
}

func certbotInstalled() bool {
	_, err := exec.LookPath("certbot")
	return err != nil
}

func tcpPortInUse(port int) bool {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return true
	}
	_ = ln.Close()
	return false
}

func nginxServiceActive() bool {
	return systemdUnitActive("nginx")
}

func defaultWebrootPath() string {
	for _, path := range []string{"/var/www/html", "/usr/share/nginx/html"} {
		if info, err := os.Stat(path); err == nil && info.IsDir() {
			return path
		}
	}
	return "/var/www/html"
}

func defaultCertbotIssuanceConfig() certbotIssuanceConfig {
	return certbotIssuanceConfig{
		method:    certbotMethodStandalone,
		challenge: certbotChallengeHTTP,
	}
}

func certbotMethodLabel(method certbotIssuanceMethod) string {
	switch method {
	case certbotMethodNginx:
		return "nginx plugin"
	case certbotMethodWebroot:
		return "webroot"
	default:
		return "standalone"
	}
}

func runCertbotCommand(ctx context.Context, args ...string) (string, error) {
	var output bytes.Buffer
	cmd := exec.CommandContext(ctx, "certbot", args...)
	cmd.Stdout = &output
	cmd.Stderr = &output
	err := cmd.Run()
	return output.String(), err
}

func lastMeaningfulCertbotLine(output string) string {
	lines := strings.Split(strings.TrimSpace(output), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "usage:") || strings.HasPrefix(lower, "options:") {
			continue
		}
		return line
	}
	return ""
}

func summarizeCertbotError(output string, err error) string {
	summary, hint := formatCertbotFailureMessage(output, err)
	if hint != "" {
		return summary + " — " + hint
	}
	return summary
}

func installCertbotIfNeeded(ctx context.Context, reporter *configureReporter) error {
	packages := certbotPluginPackages()
	if certbotInstalled() {
		reporter.Detail("Certbot is already installed")
		return installMissingCertbotPlugins(ctx, reporter, packages)
	}

	reporter.SetStatus("Installing Certbot and plugins…")
	if _, err := exec.LookPath("apt-get"); err == nil {
		update := exec.CommandContext(ctx, "apt-get", "update")
		var updateOut bytes.Buffer
		update.Stdout = &updateOut
		update.Stderr = &updateOut
		if err := update.Run(); err != nil {
			return fmt.Errorf("failed to refresh apt package lists: %w", err)
		}

		args := append([]string{"install", "-y"}, packages...)
		install := exec.CommandContext(ctx, "apt-get", args...)
		var installOut bytes.Buffer
		install.Stdout = &installOut
		install.Stderr = &installOut
		if err := install.Run(); err != nil {
			return fmt.Errorf("failed to install certbot packages: %w", err)
		}
		reporter.Detail("Installed " + strings.Join(packages, ", "))
		return nil
	}

	return fmt.Errorf("certbot is not installed — install certbot on this machine and try again")
}

func installMissingCertbotPlugins(ctx context.Context, reporter *configureReporter, packages []string) error {
	if _, err := exec.LookPath("apt-get"); err != nil {
		return nil
	}

	var missing []string
	for _, pkg := range packages {
		if pkg == "certbot" {
			continue
		}
		check := exec.CommandContext(ctx, "dpkg-query", "-W", "-f=${Status}", pkg)
		out, err := check.Output()
		if err != nil || !strings.Contains(string(out), "install ok installed") {
			missing = append(missing, pkg)
		}
	}
	if len(missing) == 0 {
		return nil
	}

	reporter.SetStatus("Installing Certbot plugins…")
	args := append([]string{"install", "-y"}, missing...)
	install := exec.CommandContext(ctx, "apt-get", args...)
	var installOut bytes.Buffer
	install.Stdout = &installOut
	install.Stderr = &installOut
	if err := install.Run(); err != nil {
		return fmt.Errorf("failed to install certbot plugins: %w", err)
	}
	reporter.Detail("Installed " + strings.Join(missing, ", "))
	return nil
}

func requestLetsEncryptCertificate(ctx context.Context, domain, email string, cfg certbotIssuanceConfig, reporter *configureReporter) error {
	domain = strings.TrimSpace(domain)
	email = strings.TrimSpace(email)
	if domain == "" {
		return fmt.Errorf("domain is required for certificate issuance")
	}
	if email == "" {
		return fmt.Errorf("an email address is required for Let's Encrypt")
	}

	if cfg.challenge == certbotChallengeDNS {
		return requestLetsEncryptCertificateDNS(ctx, domain, email, reporter)
	}

	reporter.SetStatus(fmt.Sprintf("Requesting certificate (%s)…", certbotMethodLabel(cfg.method)))

	args := []string{
		"certonly",
		"-d", domain,
		"--non-interactive",
		"--agree-tos",
		"-m", email,
	}

	switch cfg.method {
	case certbotMethodNginx:
		args = append(args, "--nginx")
		reporter.Detail("Using Certbot nginx plugin")
	case certbotMethodWebroot:
		webroot := strings.TrimSpace(cfg.webroot)
		if webroot == "" {
			webroot = defaultWebrootPath()
		}
		args = append(args, "--webroot", "-w", webroot)
		reporter.Detail("Using webroot at " + webroot)
	default:
		args = append(args, "--standalone", "--preferred-challenges", "http")
		reporter.Detail("Using standalone mode on port 80")
	}

	output, err := runCertbotCommand(ctx, args...)
	if err != nil {
		return newCertbotUserError(output, err)
	}

	if !letsEncryptCertificateExists(domain) {
		return fmt.Errorf("certbot finished but no certificate was found for %s", domain)
	}

	fullchain, _ := letsEncryptCertificatePaths(domain)
	reporter.Detail("Certificate saved to " + fullchain)
	return nil
}

func verifyCertbotRenewal(ctx context.Context, reporter *configureReporter) error {
	reporter.SetStatus("Checking certificate auto-renewal…")
	output, err := runCertbotCommand(ctx, "renew", "--dry-run")
	if err != nil {
		reporter.Detail("Renewal dry-run failed — check certbot timer manually")
		reporter.Detail(summarizeCertbotError(output, err))
		return nil
	}
	reporter.Detail("Auto-renewal dry-run succeeded")
	return nil
}

func runCertbotSequence(ctx context.Context, domain, email string, cfg certbotIssuanceConfig) error {
	if cfg.challenge == certbotChallengeDNS {
		return runCertbotDNSSequence(ctx, domain, email)
	}
	return runCertbotHTTPSequence(ctx, domain, email, cfg)
}

func runCertbotDNSSequence(ctx context.Context, domain, email string) error {
	preSteps := []configureSequenceStep{
		{
			label: "Install Certbot",
			work: func(reporter *configureReporter) error {
				return installCertbotIfNeeded(ctx, reporter)
			},
		},
		{
			label: "Prepare web services",
			work: func(reporter *configureReporter) error {
				reporter.Detail("DNS TXT verification does not need port 80")
				return nil
			},
		},
	}

	if configureUIEnabled() {
		if _, err := runConfigureTUI(preSteps); err != nil {
			clearConfigureScreen()
			return err
		}
		clearConfigureScreen()
	} else {
		reporter := &configureReporter{}
		for _, step := range preSteps {
			if err := step.work(reporter); err != nil {
				return err
			}
		}
	}

	if err := requestLetsEncryptCertificateDNS(ctx, domain, email, &configureReporter{}); err != nil {
		return err
	}

	if configureUIEnabled() {
		clearConfigureScreen()
		fullchain, _ := letsEncryptCertificatePaths(domain)
		fmt.Printf("%s Let's Encrypt certificate issued for %s\n", lipConfigureOK().Render("✓"), domain)
		fmt.Println(lipConfigureMuted().Render(fullchain))
		fmt.Println()
	}

	renewalSteps := []configureSequenceStep{
		{
			label: "Verify certificate auto-renewal",
			work: func(reporter *configureReporter) error {
				return verifyCertbotRenewal(ctx, reporter)
			},
		},
	}

	if configureUIEnabled() {
		_, err := runConfigureTUI(renewalSteps)
		clearConfigureScreen()
		return err
	}

	return verifyCertbotRenewal(ctx, &configureReporter{})
}

func runCertbotHTTPSequence(ctx context.Context, domain, email string, cfg certbotIssuanceConfig) error {
	session := &certbotServiceSession{}

	steps := []configureSequenceStep{
		{
			label: "Install Certbot",
			work: func(reporter *configureReporter) error {
				return installCertbotIfNeeded(ctx, reporter)
			},
		},
		{
			label: "Prepare web services",
			work: func(reporter *configureReporter) error {
				if cfg.method == certbotMethodStandalone {
					return session.prepareStandalone(ctx, reporter)
				}
				return nil
			},
		},
		{
			label: "Request Let's Encrypt certificate",
			work: func(reporter *configureReporter) error {
				defer session.restart(ctx, reporter)
				return requestLetsEncryptCertificate(ctx, domain, email, cfg, reporter)
			},
		},
		{
			label: "Verify certificate auto-renewal",
			work: func(reporter *configureReporter) error {
				return verifyCertbotRenewal(ctx, reporter)
			},
		},
	}

	if configureUIEnabled() {
		_, err := runConfigureTUI(steps)
		if err != nil {
			clearConfigureScreen()
		}
		return err
	}

	reporter := &configureReporter{}
	for _, step := range steps {
		if err := step.work(reporter); err != nil {
			return err
		}
	}
	return nil
}

func renderCertbotFailure(domain string, err error) {
	summary := err.Error()
	hint := ""
	if typed, ok := err.(*certbotUserError); ok {
		summary = typed.summary
		hint = typed.hint
	}

	lines := []string{
		lipConfigureErr().Bold(true).Render("Certificate setup needs attention"),
		"",
		fmt.Sprintf("%s %s", lipConfigureMuted().Render("domain"), lipConfigureInk().Render(domain)),
		"",
		lipConfigureInk().Render(summary),
	}
	if hint != "" {
		lines = append(lines, "", lipConfigureMuted().Render(hint))
	}

	fmt.Println()
	fmt.Println(lipConfigureFrame().Width(72).Render(strings.Join(lines, "\n")))
	fmt.Println()
}

func promptCertbotRecovery(domain string, err error, cfg certbotIssuanceConfig) (certbotRecoveryAction, certbotIssuanceConfig, string, error) {
	if configureUIEnabled() {
		clearConfigureScreen()
	}
	renderCertbotFailure(domain, err)

	options := []huh.Option[certbotRecoveryAction]{
		huh.NewOption("Stop web servers and retry (standalone)", certbotRecoveryStopAndRetry),
		huh.NewOption("Retry with the same method", certbotRecoveryRetry),
	}
	if cfg.method != certbotMethodNginx && nginxServiceActive() {
		options = append(options, huh.NewOption("Try again using the nginx plugin", certbotRecoveryNginx))
	}
	if cfg.method != certbotMethodWebroot {
		options = append(options, huh.NewOption("Try again using webroot mode", certbotRecoveryWebroot))
	}
	if cfg.challenge != certbotChallengeDNS {
		options = append(options, huh.NewOption("Try DNS TXT verification", certbotRecoveryDNS))
	}
	options = append(options,
		huh.NewOption("I already installed the certificate — check again", certbotRecoveryRecheck),
		huh.NewOption("Use a different domain", certbotRecoveryChangeDomain),
		huh.NewOption("Cancel setup", certbotRecoveryCancel),
	)

	var action certbotRecoveryAction
	formErr := huh.NewForm(
		huh.NewGroup(
			huh.NewSelect[certbotRecoveryAction]().
				Title("What would you like to do?").
				Description("Setup can continue once a valid certificate exists for this node.").
				Options(options...).
				Value(&action),
		),
	).Run()
	if formErr != nil {
		if formErr == huh.ErrUserAborted {
			return "", cfg, domain, fmt.Errorf("configure cancelled")
		}
		return "", cfg, domain, formErr
	}

	switch action {
	case certbotRecoveryStopAndRetry:
		cfg.method = certbotMethodStandalone
	case certbotRecoveryNginx:
		cfg.method = certbotMethodNginx
	case certbotRecoveryWebroot:
		cfg.method = certbotMethodWebroot
		cfg.challenge = certbotChallengeHTTP
		cfg.webroot = defaultWebrootPath()
		if !configureUIEnabled() {
			return action, cfg, domain, nil
		}
		webroot := cfg.webroot
		formErr := huh.NewForm(
			huh.NewGroup(
				huh.NewInput().
					Title("Webroot path").
					Description("Directory nginx or another web server uses to serve files for this domain").
					Value(&webroot).
					Validate(requiredNonEmpty("webroot path")),
			),
		).Run()
		if formErr != nil {
			if formErr == huh.ErrUserAborted {
				return "", cfg, domain, fmt.Errorf("configure cancelled")
			}
			return "", cfg, domain, formErr
		}
		cfg.webroot = strings.TrimSpace(webroot)
	case certbotRecoveryDNS:
		cfg.challenge = certbotChallengeDNS
		cfg.method = certbotMethodStandalone
	case certbotRecoveryChangeDomain:
		newDomain := domain
		formErr := huh.NewForm(
			huh.NewGroup(
				huh.NewInput().
					Title("Node domain").
					Description("Domain that should have a Let's Encrypt certificate on this machine").
					Value(&newDomain).
					Validate(requiredNonEmpty("domain")),
			),
		).Run()
		if formErr != nil {
			if formErr == huh.ErrUserAborted {
				return "", cfg, domain, fmt.Errorf("configure cancelled")
			}
			return "", cfg, domain, formErr
		}
		domain = strings.TrimSpace(newDomain)
		cfg = defaultCertbotIssuanceConfig()
	}

	return action, cfg, domain, nil
}

func ensureNodeTLSCertificate(ctx context.Context, domain, email, serverIP string) (string, error) {
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return "", fmt.Errorf("domain is required")
	}

	if letsEncryptCertificateExists(domain) {
		fullchain, _ := letsEncryptCertificatePaths(domain)
		fmt.Printf("%s TLS certificate found for %s\n", lipConfigureOK().Render("✓"), domain)
		fmt.Println(lipConfigureMuted().Render(fullchain))
		fmt.Println()
		return domain, nil
	}

	fmt.Println()
	fmt.Println(lipConfigureWarn().Render("No Let's Encrypt certificate was found for this domain."))
	fmt.Println(lipConfigureMuted().Render("FeatherWings needs a valid certificate when the panel uses HTTPS and this node is not behind a reverse proxy."))
	fmt.Println()

	generate := true
	err := huh.NewForm(
		huh.NewGroup(
			huh.NewConfirm().
				Title("Generate a Let's Encrypt certificate now?").
				Description(fmt.Sprintf("Certbot will issue a certificate for %s and set up automatic renewal.", domain)).
				Value(&generate),
		),
	).Run()
	if err != nil {
		if err == huh.ErrUserAborted {
			return "", fmt.Errorf("configure cancelled")
		}
		return "", err
	}
	if !generate {
		return "", fmt.Errorf("a TLS certificate is required for %s — generate one with certbot or place certificates under %s", domain, letsEncryptLiveDir)
	}

	email = strings.TrimSpace(email)
	if email == "" {
		err := huh.NewForm(
			huh.NewGroup(
				huh.NewInput().
					Title("Let's Encrypt contact email").
					Description("Used for certificate expiry notices").
					Placeholder("admin@example.com").
					Value(&email).
					Validate(requiredNonEmpty("email")),
			),
		).Run()
		if err != nil {
			if err == huh.ErrUserAborted {
				return "", fmt.Errorf("configure cancelled")
			}
			return "", err
		}
	}

	cfg, err := promptCertbotVerificationSetup(domain, serverIP)
	if err != nil {
		return "", err
	}
	if cfg.challenge == certbotChallengeHTTP && (tcpPortInUse(80) || tcpPortInUse(443)) {
		fmt.Println(lipConfigureMuted().Render("Ports 80/443 are in use — FeatherWings will stop known web servers, issue the certificate, then start them again."))
		fmt.Println()
	}

	for {
		err := runCertbotSequence(ctx, domain, email, cfg)
		if err == nil {
			return domain, nil
		}

		action, nextCfg, nextDomain, promptErr := promptCertbotRecovery(domain, err, cfg)
		if promptErr != nil {
			return "", promptErr
		}
		domain = nextDomain
		cfg = nextCfg

		switch action {
		case certbotRecoveryRecheck:
			if letsEncryptCertificateExists(domain) {
				fullchain, _ := letsEncryptCertificatePaths(domain)
				fmt.Printf("%s TLS certificate found for %s\n", lipConfigureOK().Render("✓"), domain)
				fmt.Println(lipConfigureMuted().Render(fullchain))
				fmt.Println()
				return domain, nil
			}
			fmt.Println(lipConfigureWarn().Render("Still no certificate found for " + domain))
			fmt.Println()
			continue
		case certbotRecoveryCancel:
			return "", fmt.Errorf("configure cancelled")
		default:
			cfg = nextCfg
			continue
		}
	}
}
