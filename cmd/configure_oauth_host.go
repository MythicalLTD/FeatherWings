package cmd

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/charmbracelet/huh"
)

type oauthCallbackHostOption struct {
	Host   string
	Source string
}

type oauthCallbackHostSelection struct {
	Host   string
	Source string
}

func resolveOAuthCallbackHost(ctx context.Context) (oauthCallbackHostSelection, error) {
	if host := strings.TrimSpace(configureFlags.CallbackHost); host != "" {
		normalized, err := normalizeOAuthCallbackHost(host)
		if err != nil {
			return oauthCallbackHostSelection{}, err
		}
		return oauthCallbackHostSelection{Host: normalized, Source: "manual"}, nil
	}
	if host := strings.TrimSpace(os.Getenv("FEATHERWINGS_CALLBACK_HOST")); host != "" {
		normalized, err := normalizeOAuthCallbackHost(host)
		if err != nil {
			return oauthCallbackHostSelection{}, err
		}
		return oauthCallbackHostSelection{Host: normalized, Source: "environment"}, nil
	}

	candidates, err := discoverOAuthCallbackHosts(ctx)
	if err != nil {
		return oauthCallbackHostSelection{}, err
	}

	if !configureUIEnabled() {
		return selectOAuthCallbackHostNonInteractive(candidates)
	}

	return promptOAuthCallbackHostSelection(candidates)
}

func discoverOAuthCallbackHosts(ctx context.Context) ([]oauthCallbackHostOption, error) {
	seen := make(map[string]struct{})
	var candidates []oauthCallbackHostOption

	add := func(host, source string) {
		host = strings.TrimSpace(host)
		if host == "" || isLoopbackHost(host) {
			return
		}
		if ip := net.ParseIP(host); ip != nil && isPrivateIPv4(host) {
			return
		}
		if _, ok := seen[host]; ok {
			return
		}
		seen[host] = struct{}{}
		candidates = append(candidates, oauthCallbackHostOption{Host: host, Source: source})
	}

	if ip, err := fetchPublicIPv4(ctx); err == nil {
		add(ip, "outbound")
	}
	for _, ip := range listPublicIPv4Candidates() {
		add(ip, "interface")
	}

	return candidates, nil
}

func selectOAuthCallbackHostNonInteractive(candidates []oauthCallbackHostOption) (oauthCallbackHostSelection, error) {
	switch len(candidates) {
	case 0:
		return oauthCallbackHostSelection{}, fmt.Errorf(
			"could not detect this machine's public IP — set --callback-host to this node's IP address",
		)
	case 1:
		return oauthCallbackHostSelection{
			Host:   candidates[0].Host,
			Source: candidates[0].Source,
		}, nil
	}

	for _, candidate := range candidates {
		if candidate.Source == "outbound" {
			return oauthCallbackHostSelection{
				Host:   candidate.Host,
				Source: candidate.Source,
			}, nil
		}
	}

	return oauthCallbackHostSelection{}, fmt.Errorf(
		"multiple public IPs detected (%s) — set --callback-host to this node's IP address",
		formatOAuthCallbackCandidates(candidates),
	)
}

func promptOAuthCallbackHostSelection(candidates []oauthCallbackHostOption) (oauthCallbackHostSelection, error) {
	if len(candidates) == 0 {
		host, err := promptOAuthCallbackHostManual("")
		if err != nil {
			return oauthCallbackHostSelection{}, err
		}
		return oauthCallbackHostSelection{Host: host, Source: "manual"}, nil
	}

	if len(candidates) == 1 {
		host, err := promptOAuthCallbackHostManual(candidates[0].Host)
		if err != nil {
			return oauthCallbackHostSelection{}, err
		}
		source := candidates[0].Source
		if host != candidates[0].Host {
			source = "manual"
		}
		return oauthCallbackHostSelection{Host: host, Source: source}, nil
	}

	choice := candidates[0].Host
	options := make([]huh.Option[string], 0, len(candidates)+1)
	for _, candidate := range candidates {
		label := fmt.Sprintf("%s (%s)", candidate.Host, oauthCallbackSourceLabel(candidate.Source))
		options = append(options, huh.NewOption(label, candidate.Host))
	}
	options = append(options, huh.NewOption("Enter a different IP…", "custom"))

	err := huh.NewForm(
		huh.NewGroup(
			huh.NewSelect[string]().
				Title("This machine's IP").
				Description("This must be the public IP for this node — the same address FeatherPanel uses to reach it.").
				Options(options...).
				Value(&choice),
		),
	).Run()
	if err != nil {
		if err == huh.ErrUserAborted {
			return oauthCallbackHostSelection{}, fmt.Errorf("configure cancelled")
		}
		return oauthCallbackHostSelection{}, err
	}

	if choice == "custom" {
		host, err := promptOAuthCallbackHostManual("")
		if err != nil {
			return oauthCallbackHostSelection{}, err
		}
		return oauthCallbackHostSelection{Host: host, Source: "manual"}, nil
	}

	source := "manual"
	for _, candidate := range candidates {
		if candidate.Host == choice {
			source = candidate.Source
			break
		}
	}
	return oauthCallbackHostSelection{Host: choice, Source: source}, nil
}

func promptOAuthCallbackHostManual(defaultHost string) (string, error) {
	host := defaultHost
	description := "This must be the public IP for this node."
	if defaultHost != "" {
		description = fmt.Sprintf("%s Detected: %s", description, defaultHost)
	}

	err := huh.NewForm(
		huh.NewGroup(
			huh.NewInput().
				Title("This machine's IP").
				Description(description).
				Placeholder("203.0.113.42").
				Value(&host).
				Validate(func(value string) error {
					normalized, err := normalizeOAuthCallbackHost(value)
					if err != nil {
						return err
					}
					if isLoopbackHost(normalized) {
						return fmt.Errorf("use this machine's public node IP, not 127.0.0.1")
					}
					if ip := net.ParseIP(normalized); ip != nil && isPrivateIPv4(normalized) {
						return fmt.Errorf("use this machine's public node IP, not a private address")
					}
					return nil
				}),
		),
	).Run()
	if err != nil {
		if err == huh.ErrUserAborted {
			return "", fmt.Errorf("configure cancelled")
		}
		return "", err
	}
	return normalizeOAuthCallbackHost(host)
}

func oauthCallbackSourceLabel(source string) string {
	switch source {
	case "outbound":
		return "outbound/public IP"
	case "interface":
		return "network interface"
	case "environment":
		return "environment"
	case "manual":
		return "manual"
	default:
		return source
	}
}

func formatOAuthCallbackCandidates(candidates []oauthCallbackHostOption) string {
	parts := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		parts = append(parts, fmt.Sprintf("%s [%s]", candidate.Host, oauthCallbackSourceLabel(candidate.Source)))
	}
	return strings.Join(parts, ", ")
}

func normalizeOAuthCallbackHost(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", fmt.Errorf("callback host is required")
	}

	if strings.Contains(value, "://") {
		parsed, err := url.Parse(value)
		if err != nil {
			return "", fmt.Errorf("invalid callback host: %w", err)
		}
		value = parsed.Hostname()
	}

	value = strings.TrimSuffix(value, "/")
	value = strings.TrimPrefix(value, "[")
	value = strings.TrimSuffix(value, "]")

	if value == "" {
		return "", fmt.Errorf("callback host is required")
	}
	return value, nil
}

func buildOAuthCallbackURL(host string, port int) string {
	host = strings.Trim(host, "[]")
	if strings.Contains(host, ":") {
		return fmt.Sprintf("http://[%s]:%d/callback", host, port)
	}
	return fmt.Sprintf("http://%s:%d/callback", host, port)
}

func listPublicIPv4Candidates() []string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}

	seen := make(map[string]struct{})
	var candidates []string
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipnet, ok := addr.(*net.IPNet)
			if !ok || ipnet.IP.To4() == nil {
				continue
			}
			ip := ipnet.IP.String()
			if isPrivateIPv4(ip) || isLoopbackHost(ip) {
				continue
			}
			if _, ok := seen[ip]; ok {
				continue
			}
			seen[ip] = struct{}{}
			candidates = append(candidates, ip)
		}
	}
	return candidates
}

func fetchPublicIPv4(ctx context.Context) (string, error) {
	client := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.ipify.org", nil)
	if err != nil {
		return "", err
	}

	res, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()

	body, err := io.ReadAll(io.LimitReader(res.Body, 64))
	if err != nil {
		return "", err
	}
	ip := strings.TrimSpace(string(body))
	parsed := net.ParseIP(ip)
	if parsed == nil || parsed.To4() == nil {
		return "", fmt.Errorf("invalid public IP response")
	}
	return parsed.String(), nil
}

func isPrivateIPv4(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	parsed = parsed.To4()
	if parsed == nil {
		return false
	}
	return parsed.IsPrivate() || parsed.IsLinkLocalUnicast() || parsed.IsLoopback()
}

func isLoopbackHost(host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
