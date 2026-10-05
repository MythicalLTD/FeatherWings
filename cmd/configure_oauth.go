package cmd

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/charmbracelet/huh"
	"github.com/mythicalltd/featherwings/config"
)

const configureOAuthTimeout = 10 * time.Minute

type configureOAuthCredentials struct {
	PublicKey         string
	PrivateKey        string
	AuthorizationCode string
}

func resolveJoinDataViaOAuth() (string, error) {
	panelURL, err := promptConfigurePanelURL()
	if err != nil {
		return "", err
	}

	fmt.Println()
	fmt.Println(lipConfigureMuted().Render("Authorize FeatherWings in your browser to continue."))
	fmt.Println()

	credentials, callbackHost, err := runConfigureOAuth(panelURL)
	if err != nil {
		return "", err
	}

	apiKey := credentials.PublicKey
	if apiKey == "" {
		apiKey = credentials.PrivateKey
	}

	validateCtx, validateCancel := context.WithTimeout(context.Background(), 2*time.Minute)
	clientInfo, err := config.ValidateAPIClient(validateCtx, panelURL, credentials.PublicKey, configureFlags.AllowInsecure)
	validateCancel()
	if err != nil {
		return "", err
	}

	fmt.Printf("%s Authorized as %s\n\n", lipConfigureOK().Render("✓"), clientInfo.Username)

	panel := config.NewPanelAPI(panelURL, apiKey, configureFlags.AllowInsecure)
	nodeInput, err := promptConfigureNodeDetails(context.Background(), panel, callbackHost.Host, clientInfo)
	if err != nil {
		return "", err
	}

	apiCtx, apiCancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer apiCancel()

	node, err := panel.CreateNode(apiCtx, nodeInput)
	if err != nil {
		return "", err
	}

	fmt.Printf("%s Created node %q (%s)\n\n", lipConfigureOK().Render("✓"), node.Name, node.UUID)

	joinData, err := panel.GetNodeJoinData(apiCtx, node.ID)
	if err != nil {
		return "", err
	}

	if err := maybeRevokeOAuthAPIKey(apiCtx, panel, clientInfo); err != nil {
		fmt.Printf("%s %v\n\n", lipConfigureWarn().Render("!"), err)
	}

	return joinData, nil
}

func runConfigureOAuth(panelURL string) (configureOAuthCredentials, oauthCallbackHostSelection, error) {
	hostCtx, hostCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer hostCancel()

	nodeIPSelection, err := resolveConfigureNodeIP(hostCtx)
	if err != nil {
		return configureOAuthCredentials{}, oauthCallbackHostSelection{}, err
	}

	startCtx, startCancel := context.WithTimeout(context.Background(), 30*time.Second)
	device, err := config.StartOAuth2Device(startCtx, panelURL, buildConfigureOAuthDevicePayload(), configureFlags.AllowInsecure)
	startCancel()
	if err != nil {
		return configureOAuthCredentials{}, oauthCallbackHostSelection{}, err
	}

	if nodeIPSelection.Host != "" {
		fmt.Printf("%s Using node IP %s\n", lipConfigureOK().Render("✓"), lipConfigureInk().Render(nodeIPSelection.Host))
	} else {
		fmt.Printf("%s Could not auto-detect a public node IP; you can enter the node FQDN during setup.\n", lipConfigureWarn().Render("!"))
	}
	fmt.Println()
	fmt.Println(lipConfigureMuted().Render("Open this URL in your browser and approve the request:"))
	fmt.Println()
	fmt.Println(lipConfigureInk().Render(device.VerificationURIComplete))
	fmt.Println()
	fmt.Printf("%s Code: %s\n", lipConfigureMuted().Render("Device authorization"), lipConfigureInk().Bold(true).Render(device.UserCode))
	fmt.Println(lipConfigureMuted().Render("No inbound callback port is required; this CLI will poll FeatherPanel for approval."))
	fmt.Println()

	if err := openConfigureBrowser(device.VerificationURIComplete); err == nil {
		fmt.Println(lipConfigureMuted().Render("Opened your browser — waiting for approval…"))
	} else {
		fmt.Println(lipConfigureMuted().Render("Waiting for approval…"))
	}
	fmt.Println()

	deadline := time.Now().Add(configureOAuthTimeout)
	pollEvery := time.Duration(device.Interval) * time.Second
	if pollEvery <= 0 {
		pollEvery = 5 * time.Second
	}

	for {
		if time.Now().After(deadline) {
			return configureOAuthCredentials{}, oauthCallbackHostSelection{}, fmt.Errorf("timed out waiting for FeatherPanel authorization")
		}

		timer := time.NewTimer(pollEvery)
		select {
		case <-timer.C:
		}

		pollCtx, pollCancel := context.WithTimeout(context.Background(), 30*time.Second)
		result, err := config.PollOAuth2Device(pollCtx, panelURL, device.DeviceCode, configureFlags.AllowInsecure)
		pollCancel()
		if err != nil {
			return configureOAuthCredentials{}, oauthCallbackHostSelection{}, err
		}

		switch result.Status {
		case "approved":
			if result.Credentials == nil {
				return configureOAuthCredentials{}, oauthCallbackHostSelection{}, fmt.Errorf("OAuth device authorization did not include API credentials")
			}
			return configureOAuthCredentials{
				PublicKey:         strings.TrimSpace(result.Credentials.PublicKey),
				PrivateKey:        strings.TrimSpace(result.Credentials.PrivateKey),
				AuthorizationCode: strings.TrimSpace(result.Credentials.AuthorizationCode),
			}, nodeIPSelection, nil
		case "authorization_pending":
			// Keep polling.
		case "slow_down":
			if result.Interval > 0 {
				pollEvery = time.Duration(result.Interval) * time.Second
			} else {
				pollEvery += 2 * time.Second
			}
		case "access_denied":
			return configureOAuthCredentials{}, oauthCallbackHostSelection{}, fmt.Errorf("panel authorization denied")
		case "expired_token":
			return configureOAuthCredentials{}, oauthCallbackHostSelection{}, fmt.Errorf("OAuth device code expired")
		default:
			return configureOAuthCredentials{}, oauthCallbackHostSelection{}, fmt.Errorf("unexpected OAuth device authorization status: %s", result.Status)
		}
	}
}

func resolveConfigureNodeIP(ctx context.Context) (oauthCallbackHostSelection, error) {
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
	if err != nil || len(candidates) == 0 {
		return oauthCallbackHostSelection{}, nil
	}
	for _, candidate := range candidates {
		if candidate.Source == "outbound" {
			return oauthCallbackHostSelection{Host: candidate.Host, Source: candidate.Source}, nil
		}
	}
	return oauthCallbackHostSelection{Host: candidates[0].Host, Source: candidates[0].Source}, nil
}

func buildConfigureOAuthDevicePayload() map[string]string {
	hostname, err := os.Hostname()
	if err != nil || strings.TrimSpace(hostname) == "" {
		hostname = "node"
	}

	return map[string]string{
		"name":        fmt.Sprintf("FeatherWings on %s", hostname),
		"appName":     "FeatherWings",
		"description": "Authorize FeatherWings CLI to register this machine as a game server node",
	}
}

func buildConfigureOAuthConsentURL(panelURL, callbackURL string) (string, error) {
	hostname, err := os.Hostname()
	if err != nil || strings.TrimSpace(hostname) == "" {
		hostname = "node"
	}

	values := url.Values{}
	values.Set("name", fmt.Sprintf("FeatherWings on %s", hostname))
	values.Set("callbackurl", callbackURL)
	values.Set("mode", "server")
	values.Set("appName", "FeatherWings")
	values.Set("description", "Authorize FeatherWings CLI to register this machine as a game server node")

	consentPath := "/dashboard/account/oauth2/api/new?" + values.Encode()
	return config.NormalizePanelURL(panelURL) + consentPath, nil
}

func openConfigureBrowser(target string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "linux":
		cmd = exec.Command("xdg-open", target)
	case "darwin":
		cmd = exec.Command("open", target)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", target)
	default:
		return fmt.Errorf("unsupported platform")
	}
	cmd.Stdout = nil
	cmd.Stderr = nil
	return cmd.Start()
}

func promptConfigureNodeDetails(ctx context.Context, panel *config.PanelAPI, nodeIP string, clientInfo *config.PanelAPIClientInfo) (config.CreatePanelNodeRequest, error) {
	if strings.TrimSpace(configureFlags.NodeName) != "" &&
		strings.TrimSpace(configureFlags.NodeFQDN) != "" &&
		configureFlags.LocationID > 0 {
		form := defaultConfigureNodeForm(nodeIP)
		form.Name = strings.TrimSpace(configureFlags.NodeName)
		form.FQDN = strings.TrimSpace(configureFlags.NodeFQDN)
		form.LocationID = configureFlags.LocationID
		return buildConfigureNodeRequest(form), nil
	}

	if !configureUIEnabled() {
		return config.CreatePanelNodeRequest{}, fmt.Errorf("missing --node-name, --node-fqdn, and --location-id for non-interactive quick setup")
	}

	locations, err := panel.ListGameLocations(ctx)
	if err != nil {
		return config.CreatePanelNodeRequest{}, err
	}

	return promptConfigureNodeFields(ctx, panel, locations, nodeIP, clientInfo)
}

func maybeRevokeOAuthAPIKey(ctx context.Context, panel *config.PanelAPI, clientInfo *config.PanelAPIClientInfo) error {
	if clientInfo == nil || clientInfo.ID <= 0 {
		return nil
	}

	revoke, err := promptRevokeOAuthAPIKey(clientInfo.Name)
	if err != nil {
		return err
	}
	if !revoke {
		fmt.Println(lipConfigureMuted().Render("Keeping temporary OAuth API key on the panel."))
		fmt.Println()
		return nil
	}

	if err := panel.DeleteAPIClient(ctx, clientInfo.ID); err != nil {
		return fmt.Errorf("could not delete temporary OAuth API key %q: %w", clientInfo.Name, err)
	}

	fmt.Printf("%s Deleted temporary OAuth API key %q\n\n", lipConfigureOK().Render("✓"), clientInfo.Name)
	return nil
}

func promptRevokeOAuthAPIKey(keyName string) (bool, error) {
	if configureFlags.KeepOAuthKey {
		return false, nil
	}
	if !configureUIEnabled() {
		return true, nil
	}

	revoke := true
	description := "Recommended — the node is registered and this key is no longer needed."
	if strings.TrimSpace(keyName) != "" {
		description = fmt.Sprintf("%s (%s)", description, keyName)
	}

	err := huh.NewForm(
		huh.NewGroup(
			huh.NewConfirm().
				Title("Delete the temporary OAuth API key?").
				Description(description).
				Value(&revoke),
		),
	).Run()
	if err != nil {
		if err == huh.ErrUserAborted {
			return false, fmt.Errorf("configure cancelled")
		}
		return false, err
	}
	return revoke, nil
}
