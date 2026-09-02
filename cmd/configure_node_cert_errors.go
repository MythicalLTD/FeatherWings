package cmd

import (
	"io"
	"os"
	"strings"
)

const letsEncryptLogPath = "/var/log/letsencrypt/letsencrypt.log"

type certbotUserError struct {
	summary string
	hint    string
}

func (e *certbotUserError) Error() string {
	if e.hint != "" {
		return e.summary + "\n" + e.hint
	}
	return e.summary
}

func isCertbotBoilerplateLine(line string) bool {
	lower := strings.ToLower(strings.TrimSpace(line))
	if lower == "" {
		return true
	}
	boilerplate := []string{
		"community.letsencrypt.org",
		"letsencrypt.log",
		"ask for help",
		"re-run certbot with -v",
		"some challenges have failed",
		"certbot failed to authenticate some domains",
		"see the logfile",
	}
	for _, needle := range boilerplate {
		if strings.Contains(lower, needle) {
			return true
		}
	}
	return false
}

func readRecentCertbotLogTail(maxBytes int64) string {
	file, err := os.Open(letsEncryptLogPath)
	if err != nil {
		return ""
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return ""
	}

	offset := int64(0)
	if info.Size() > maxBytes {
		offset = info.Size() - maxBytes
	}
	if _, err := file.Seek(offset, io.SeekStart); err != nil {
		return ""
	}

	data, err := io.ReadAll(file)
	if err != nil {
		return ""
	}
	return string(data)
}

func extractCertbotDetail(text string) string {
	var fallback string
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || isCertbotBoilerplateLine(line) {
			continue
		}
		if strings.HasPrefix(line, "Detail:") {
			return strings.TrimSpace(strings.TrimPrefix(line, "Detail:"))
		}
		if strings.Contains(line, "Invalid response from http") {
			fallback = line
		}
	}
	return fallback
}

func extractCertbotHint(text string) string {
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Hint:") {
			return strings.TrimSpace(strings.TrimPrefix(line, "Hint:"))
		}
	}
	return ""
}

func adviceForCertbotDetail(detail string) string {
	lower := strings.ToLower(detail)
	switch {
	case strings.Contains(lower, ": 409"):
		return "HTTP 409 means another service (proxy, CDN, or panel) answered on port 80 instead of Certbot. Point the domain DNS A record directly at this node's public IP, or go back and enable reverse proxy for this node."
	case strings.Contains(lower, "invalid response"), strings.Contains(lower, "unauthorized"):
		return "Let's Encrypt could not download the challenge file. Confirm the domain DNS A record points to this machine and port 80 is open to the internet."
	case strings.Contains(lower, "dns problem"), strings.Contains(lower, "no valid a/aaaa"):
		return "DNS for this domain does not point to this machine yet. Update the A record and wait for propagation before retrying."
	case strings.Contains(lower, "connection refused"), strings.Contains(lower, "timeout"):
		return "Let's Encrypt could not reach this machine on port 80. Check firewall rules and that nothing upstream is blocking HTTP."
	}
	return ""
}

func formatCertbotFailureMessage(output string, runErr error) (summary, hint string) {
	output = strings.TrimSpace(output)
	lower := strings.ToLower(output)

	switch {
	case strings.Contains(lower, "could not bind tcp port 80"):
		return "Port 80 is already in use on this machine.", "Stop the service using port 80 or choose “Stop web servers and retry”."
	case strings.Contains(lower, "no such plugin"), strings.Contains(lower, "the requested nginx plugin"):
		return "The Certbot nginx plugin is not installed.", "FeatherWings will install python3-certbot-nginx on the next attempt."
	case strings.Contains(lower, "dns problem"):
		return "Let's Encrypt could not verify this domain via DNS.", adviceForCertbotDetail("dns problem")
	case strings.Contains(lower, "too many certificates"):
		return "Let's Encrypt rate limit hit for this domain.", "Wait before retrying or place an existing certificate under /etc/letsencrypt/live."
	case strings.Contains(lower, "invalid email"):
		return "The contact email address was rejected by Let's Encrypt.", ""
	}

	summary = extractCertbotDetail(output)
	hint = extractCertbotHint(output)

	if summary == "" {
		if logTail := readRecentCertbotLogTail(128 * 1024); logTail != "" {
			summary = extractCertbotDetail(logTail)
			if hint == "" {
				hint = extractCertbotHint(logTail)
			}
		}
	}

	if hint == "" && summary != "" {
		hint = adviceForCertbotDetail(summary)
	}

	if summary != "" {
		return summary, hint
	}

	fullText := output
	if logTail := readRecentCertbotLogTail(128 * 1024); logTail != "" {
		if fullText != "" {
			fullText += "\n"
		}
		fullText += logTail
	}

	lower = strings.ToLower(fullText)
	switch {
	case strings.Contains(lower, "could not bind tcp port 80"):
		return "Port 80 is already in use on this machine.", "Stop the service using port 80 or choose “Stop web servers and retry”."
	case strings.Contains(lower, "no such plugin"), strings.Contains(lower, "the requested nginx plugin"):
		return "The Certbot nginx plugin is not installed.", "FeatherWings will install python3-certbot-nginx on the next attempt."
	case strings.Contains(lower, "dns problem"):
		return "Let's Encrypt could not verify this domain via DNS.", adviceForCertbotDetail("dns problem")
	case strings.Contains(lower, "too many certificates"):
		return "Let's Encrypt rate limit hit for this domain.", "Wait before retrying or place an existing certificate under /etc/letsencrypt/live."
	case strings.Contains(lower, "invalid email"):
		return "The contact email address was rejected by Let's Encrypt.", ""
	}

	if line := lastMeaningfulCertbotLine(fullText); line != "" && !isCertbotBoilerplateLine(line) {
		return line, adviceForCertbotDetail(line)
	}
	if runErr != nil && strings.TrimSpace(runErr.Error()) != "" && !strings.Contains(runErr.Error(), "exit status") {
		return strings.TrimSpace(runErr.Error()), ""
	}
	return "Certbot could not issue a certificate.", "Check /var/log/letsencrypt/letsencrypt.log for details."
}

func newCertbotUserError(output string, runErr error) error {
	summary, hint := formatCertbotFailureMessage(output, runErr)
	return &certbotUserError{summary: summary, hint: hint}
}
