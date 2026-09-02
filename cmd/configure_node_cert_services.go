package cmd

import (
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"sort"
	"strings"
)

var (
	certbotKnownWebUnits = []string{"nginx", "apache2", "httpd", "caddy"}
	processToSystemdUnit = map[string]string{
		"nginx":   "nginx",
		"apache2": "apache2",
		"httpd":   "httpd",
		"caddy":   "caddy",
	}
	ssProcessPattern = regexp.MustCompile(`users:\(\("([^"]+)"`)
)

type certbotServiceSession struct {
	stoppedUnits []string
}

func systemdUnitKnown(unit string) bool {
	cmd := exec.Command("systemctl", "cat", unit)
	return cmd.Run() == nil
}

func systemdUnitActive(unit string) bool {
	cmd := exec.Command("systemctl", "is-active", "--quiet", unit)
	return cmd.Run() == nil
}

func detectPortListeners(port int) []string {
	cmd := exec.Command("ss", "-H", "-lntp", fmt.Sprintf("sport = :%d", port))
	out, err := cmd.Output()
	if err != nil {
		return nil
	}
	return parsePortListenerProcesses(string(out))
}

func parsePortListenerProcesses(ssOutput string) []string {
	seen := make(map[string]struct{})
	var processes []string
	for _, line := range strings.Split(ssOutput, "\n") {
		matches := ssProcessPattern.FindStringSubmatch(line)
		if len(matches) < 2 {
			continue
		}
		name := strings.TrimSpace(matches[1])
		if name == "" {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		processes = append(processes, name)
	}
	sort.Strings(processes)
	return processes
}

func mapProcessesToSystemdUnits(processes []string) []string {
	seen := make(map[string]struct{})
	var units []string
	for _, process := range processes {
		unit, ok := processToSystemdUnit[strings.ToLower(process)]
		if !ok || !systemdUnitKnown(unit) {
			continue
		}
		if _, exists := seen[unit]; exists {
			continue
		}
		seen[unit] = struct{}{}
		units = append(units, unit)
	}
	sort.Strings(units)
	return units
}

func activeKnownWebUnits() []string {
	var units []string
	for _, unit := range certbotKnownWebUnits {
		if systemdUnitActive(unit) {
			units = append(units, unit)
		}
	}
	return units
}

func certbotPluginPackages() []string {
	packages := []string{"certbot"}
	needsNginx := false
	needsApache := false

	if _, err := exec.LookPath("nginx"); err == nil {
		needsNginx = true
	}
	if systemdUnitKnown("nginx") {
		needsNginx = true
	}
	if systemdUnitKnown("apache2") || systemdUnitKnown("httpd") {
		needsApache = true
	}
	if _, err := exec.LookPath("apache2"); err == nil {
		needsApache = true
	}
	if _, err := exec.LookPath("httpd"); err == nil {
		needsApache = true
	}

	if needsNginx {
		packages = append(packages, "python3-certbot-nginx")
	}
	if needsApache {
		packages = append(packages, "python3-certbot-apache")
	}
	return packages
}

func (s *certbotServiceSession) unitsToStopForStandalone() []string {
	seen := make(map[string]struct{})
	var units []string

	add := func(unit string) {
		if unit == "" {
			return
		}
		if _, ok := seen[unit]; ok {
			return
		}
		if !systemdUnitActive(unit) {
			return
		}
		seen[unit] = struct{}{}
		units = append(units, unit)
	}

	for _, port := range []int{80, 443} {
		if !tcpPortInUse(port) {
			continue
		}
		for _, unit := range mapProcessesToSystemdUnits(detectPortListeners(port)) {
			add(unit)
		}
	}

	for _, unit := range activeKnownWebUnits() {
		if tcpPortInUse(80) || tcpPortInUse(443) {
			add(unit)
		}
	}

	sort.Strings(units)
	return units
}

func (s *certbotServiceSession) prepareStandalone(ctx context.Context, reporter *configureReporter) error {
	reporter.SetStatus("Preparing ports 80 and 443…")

	for _, port := range []int{80, 443} {
		if tcpPortInUse(port) {
			listeners := detectPortListeners(port)
			if len(listeners) > 0 {
				reporter.Detail(fmt.Sprintf("Port %d is used by %s", port, strings.Join(listeners, ", ")))
			} else {
				reporter.Detail(fmt.Sprintf("Port %d is in use", port))
			}
		} else {
			reporter.Detail(fmt.Sprintf("Port %d is free", port))
		}
	}

	units := s.unitsToStopForStandalone()
	if len(units) == 0 {
		if tcpPortInUse(80) {
			return fmt.Errorf("port 80 is in use but no known web service could be stopped automatically")
		}
		reporter.Detail("No web services needed to be stopped")
		return nil
	}

	for _, unit := range units {
		reporter.Detail("Stopping " + unit)
		if err := runSystemctlContext(ctx, "stop", unit); err != nil {
			return fmt.Errorf("failed to stop %s: %w", unit, err)
		}
		s.stoppedUnits = append(s.stoppedUnits, unit)
	}

	if tcpPortInUse(80) {
		return fmt.Errorf("port 80 is still in use after stopping web services")
	}
	reporter.Detail("Ports 80 and 443 are ready for Certbot standalone mode")
	return nil
}

func (s *certbotServiceSession) restart(ctx context.Context, reporter *configureReporter) {
	if len(s.stoppedUnits) == 0 {
		return
	}
	reporter.SetStatus("Restarting web services…")
	for i := len(s.stoppedUnits) - 1; i >= 0; i-- {
		unit := s.stoppedUnits[i]
		reporter.Detail("Starting " + unit)
		if err := runSystemctlContext(ctx, "start", unit); err != nil {
			reporter.Detail("Warning: failed to restart " + unit + " — run: systemctl start " + unit)
		}
	}
}

func runSystemctlContext(ctx context.Context, args ...string) error {
	cmd := exec.CommandContext(ctx, "systemctl", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		if len(out) > 0 {
			return fmt.Errorf("%s", strings.TrimSpace(string(out)))
		}
		return err
	}
	return nil
}
