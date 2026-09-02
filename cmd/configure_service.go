package cmd

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/mythicalltd/featherwings/config"
)

const (
	featherwingsServiceName      = "featherwings"
	featherwingsUnitPath         = "/etc/systemd/system/featherwings.service"
	featherwingsPackageUnitPath  = "/lib/systemd/system/featherwings.service"
	featherwingsInstallBinPath   = "/usr/local/bin/featherwings"
	featherwingsDebPackageName   = "featherwings"
	systemctlTimeout             = 45 * time.Second
)

// packageManagedFeatherwings reports whether FeatherWings was installed via the
// Debian/apt package. Overridable in tests.
var packageManagedFeatherwings = isPackageManagedFeatherwings

type configureServiceResult struct {
	Installed bool
	Enabled   bool
	Started   bool
	UnitPath  string
	Binary    string
	Message   string
	Skipped   bool
}

func canInstallFeatherwingsService() bool {
	return runtime.GOOS == "linux" && os.Geteuid() == 0 && !packageManagedFeatherwings()
}

// isPackageManagedFeatherwings reports that apt/dpkg owns the systemd unit, so
// configure must not write, enable, start, or restart the service.
func isPackageManagedFeatherwings() bool {
	if _, err := os.Stat(featherwingsPackageUnitPath); err == nil {
		return true
	}
	return isFeatherwingsDebInstalled()
}

func isFeatherwingsDebInstalled() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "dpkg-query", "-W", "-f=${Status}", featherwingsDebPackageName)
	out, err := cmd.Output()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), "install ok installed")
}

func featherwingsServiceSkipResult() configureServiceResult {
	result := configureServiceResult{Skipped: true}
	switch {
	case configureFlags.NoService:
		result.Message = "skipped by --no-service"
	case packageManagedFeatherwings():
		result.Message = "apt package manages featherwings.service — left untouched"
	default:
		result.Message = "systemd service install skipped"
	}
	return result
}

func installFeatherwingsService(configPath string, progress func(string)) (configureServiceResult, error) {
	result := configureServiceResult{}
	logProgress := func(line string) {
		if progress != nil {
			progress(line)
		}
	}

	if configureFlags.NoService {
		result.Skipped = true
		result.Message = "skipped by --no-service"
		return result, nil
	}

	if packageManagedFeatherwings() {
		result.Skipped = true
		result.Message = "apt package manages featherwings.service — left untouched"
		return result, nil
	}

	if runtime.GOOS != "linux" {
		result.Skipped = true
		result.Message = "systemd install is only supported on Linux"
		return result, nil
	}

	if os.Geteuid() != 0 {
		result.Skipped = true
		result.Message = "systemd install requires root (re-run with sudo)"
		return result, nil
	}

	logProgress("stopping existing service if running")
	_ = runSystemctlQuiet("stop", featherwingsServiceName)

	logProgress("installing binary to /usr/local/bin/featherwings")
	binary, err := ensureFeatherwingsBinaryInstalled()
	if err != nil {
		return result, err
	}
	result.Binary = binary

	logProgress(fmt.Sprintf("writing %s", featherwingsUnitPath))
	unit := buildFeatherwingsUnit(binary, configPath)
	if err := os.WriteFile(featherwingsUnitPath, []byte(unit), 0o644); err != nil {
		return result, fmt.Errorf("failed to write %s: %w", featherwingsUnitPath, err)
	}

	logProgress("reloading systemd daemon")
	if err := runSystemctl("daemon-reload"); err != nil {
		return result, err
	}

	result.UnitPath = featherwingsUnitPath
	result.Installed = true

	logProgress("enabling featherwings on boot")
	if err := runSystemctl("enable", featherwingsServiceName); err != nil {
		result.Message = "unit installed but enable failed — check systemctl enable featherwings"
		return result, nil
	}
	result.Enabled = true

	logProgress("starting featherwings")
	if err := runSystemctl("restart", featherwingsServiceName); err != nil {
		result.Message = "unit installed — check journalctl -u featherwings"
		return result, nil
	}
	result.Started = true
	result.Message = "service installed, enabled, and started"
	return result, nil
}

func serviceStepResult(result configureServiceResult, err error) configureStepResult {
	step := configureStepResult{
		label:  "Installing systemd service",
		status: configureStepSuccess,
	}
	if err != nil {
		step.status = configureStepFailed
		step.details = append(step.details, err.Error())
		return step
	}
	if result.Skipped {
		step.status = configureStepSkipped
		if result.Message != "" {
			step.details = append(step.details, result.Message)
		}
		return step
	}
	if result.UnitPath != "" {
		step.details = append(step.details, fmt.Sprintf("unit → %s", result.UnitPath))
	}
	if result.Binary != "" {
		step.details = append(step.details, fmt.Sprintf("binary → %s", result.Binary))
	}
	if result.Started {
		step.details = append(step.details, "daemon-reload · enabled on boot · running")
	} else if result.Message != "" {
		step.details = append(step.details, result.Message)
	}
	return step
}

func ensureFeatherwingsBinaryInstalled() (string, error) {
	current, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("could not resolve featherwings binary: %w", err)
	}
	current, err = filepath.EvalSymlinks(current)
	if err != nil {
		return "", fmt.Errorf("could not resolve featherwings binary: %w", err)
	}

	if filepath.Clean(current) == filepath.Clean(featherwingsInstallBinPath) {
		return featherwingsInstallBinPath, nil
	}

	if err := os.MkdirAll(filepath.Dir(featherwingsInstallBinPath), 0o755); err != nil {
		return "", err
	}

	src, err := os.Open(current)
	if err != nil {
		return "", fmt.Errorf("failed to open %s: %w", current, err)
	}
	defer src.Close()

	tempPath := featherwingsInstallBinPath + ".new"
	dst, err := os.OpenFile(tempPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return "", fmt.Errorf("failed to write %s: %w", tempPath, err)
	}

	if _, err := io.Copy(dst, src); err != nil {
		_ = dst.Close()
		_ = os.Remove(tempPath)
		return "", fmt.Errorf("failed to copy binary to %s: %w", tempPath, err)
	}
	if err := dst.Close(); err != nil {
		_ = os.Remove(tempPath)
		return "", err
	}

	if err := os.Rename(tempPath, featherwingsInstallBinPath); err != nil {
		_ = os.Remove(tempPath)
		return "", fmt.Errorf("failed to install binary to %s: %w", featherwingsInstallBinPath, err)
	}

	return featherwingsInstallBinPath, nil
}

func buildFeatherwingsUnit(binaryPath, configPath string) string {
	execStart := shellQuote(binaryPath)
	if strings.TrimSpace(configPath) != "" && configPath != config.DefaultLocation {
		execStart = fmt.Sprintf("%s --config %s", shellQuote(binaryPath), shellQuote(configPath))
	}

	workDir := filepath.Dir(configPath)
	if workDir == "" || workDir == "." {
		workDir = "/etc/featherpanel"
	}

	var b strings.Builder
	b.WriteString("[Unit]\n")
	b.WriteString("Description=FeatherWings Daemon\n")
	b.WriteString("After=docker.service\n")
	b.WriteString("Requires=docker.service\n")
	b.WriteString("PartOf=docker.service\n")
	b.WriteString("\n")
	b.WriteString("[Service]\n")
	b.WriteString("User=root\n")
	b.WriteString(fmt.Sprintf("WorkingDirectory=%s\n", workDir))
	b.WriteString(fmt.Sprintf("ExecStart=%s\n", execStart))
	b.WriteString("Restart=always\n")
	b.WriteString("RestartSec=5\n")
	b.WriteString("StartLimitInterval=180\n")
	b.WriteString("StartLimitBurst=30\n")
	b.WriteString("StandardOutput=journal\n")
	b.WriteString("StandardError=journal\n")
	b.WriteString("\n")
	b.WriteString("[Install]\n")
	b.WriteString("WantedBy=multi-user.target\n")
	return b.String()
}

func shellQuote(value string) string {
	if value == "" {
		return `""`
	}
	if !strings.ContainsAny(value, " \t\"'\\$") {
		return value
	}
	return `"` + strings.NewReplacer(`"`, `\"`).Replace(value) + `"`
}

func runSystemctl(args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), systemctlTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "systemctl", args...)
	cmd.Env = append(os.Environ(),
		"SYSTEMD_COLORS=0",
		"DEBIAN_FRONTEND=noninteractive",
	)
	cmd.Stdin = nil

	out, err := cmd.CombinedOutput()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return fmt.Errorf("systemctl %s: timed out after %s", strings.Join(args, " "), systemctlTimeout)
		}
		return fmt.Errorf("systemctl %s: %s: %w", strings.Join(args, " "), strings.TrimSpace(string(out)), err)
	}
	return nil
}

func runSystemctlQuiet(args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), systemctlTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "systemctl", args...)
	cmd.Env = append(os.Environ(), "SYSTEMD_COLORS=0")
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	cmd.Stdin = nil
	return cmd.Run()
}

func promptConfigureServiceInstall() (bool, error) {
	if configureFlags.NoService {
		return false, nil
	}
	// apt ships and owns /lib/systemd/system/featherwings.service — never overlay
	// it under /etc, and never enable/start/restart from configure.
	if packageManagedFeatherwings() {
		return false, nil
	}
	if configureFlags.InstallService {
		return true, nil
	}
	if !configureUIEnabled() {
		return false, nil
	}

	install := canInstallFeatherwingsService()
	if err := promptInstallService(&install); err != nil {
		return false, err
	}
	return install, nil
}
