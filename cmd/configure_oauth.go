package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
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

type configureOAuthCallbackPayload struct {
	Success           bool   `json:"success"`
	TokenType         string `json:"token_type"`
	PublicKey         string `json:"public_key"`
	PrivateKey        string `json:"private_key"`
	AuthorizationCode string `json:"authorization_code"`
	IssuedAt          string `json:"issued_at"`
	Error             string `json:"error"`
	ErrorDescription  string `json:"error_description"`
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

	callbackSelection, err := resolveOAuthCallbackHost(hostCtx)
	if err != nil {
		return configureOAuthCredentials{}, oauthCallbackHostSelection{}, err
	}

	resultCh, callbackURL, cleanup, err := startConfigureOAuthCallbackServer(callbackSelection.Host)
	if err != nil {
		return configureOAuthCredentials{}, oauthCallbackHostSelection{}, err
	}
	defer cleanup()

	consentURL, err := buildConfigureOAuthConsentURL(panelURL, callbackURL)
	if err != nil {
		return configureOAuthCredentials{}, oauthCallbackHostSelection{}, err
	}

	fmt.Printf("%s Using node IP %s\n", lipConfigureOK().Render("✓"), lipConfigureInk().Render(callbackSelection.Host))
	fmt.Println(lipConfigureMuted().Render("FeatherPanel will send credentials to:"))
	fmt.Println(lipConfigureInk().Render(callbackURL))
	fmt.Println(lipConfigureMuted().Render("Ensure this port is open in your firewall and reachable from the panel."))
	fmt.Println()
	fmt.Println(lipConfigureMuted().Render("Open this URL in your browser and approve the request:"))
	fmt.Println()
	fmt.Println(lipConfigureInk().Render(consentURL))
	fmt.Println()

	if err := openConfigureBrowser(consentURL); err == nil {
		fmt.Println(lipConfigureMuted().Render("Opened your browser — waiting for panel delivery…"))
	} else {
		fmt.Println(lipConfigureMuted().Render("Waiting for panel delivery…"))
	}
	fmt.Println()

	select {
	case result := <-resultCh:
		if result.err != nil {
			return configureOAuthCredentials{}, oauthCallbackHostSelection{}, result.err
		}
		return result.credentials, callbackSelection, nil
	case <-time.After(configureOAuthTimeout):
		return configureOAuthCredentials{}, oauthCallbackHostSelection{}, fmt.Errorf("timed out waiting for FeatherPanel authorization")
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

type configureOAuthCallbackResult struct {
	credentials configureOAuthCredentials
	err         error
}

func startConfigureOAuthCallbackServer(callbackHost string) (<-chan configureOAuthCallbackResult, string, func(), error) {
	listener, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		return nil, "", nil, fmt.Errorf("failed to start OAuth callback listener: %w", err)
	}

	resultCh := make(chan configureOAuthCallbackResult, 1)
	var delivered sync.Once
	deliver := func(result configureOAuthCallbackResult) {
		delivered.Do(func() {
			resultCh <- result
		})
	}

	handlePayload := func(payload configureOAuthCallbackPayload) {
		if !payload.Success {
			message := strings.TrimSpace(payload.ErrorDescription)
			if message == "" {
				message = strings.TrimSpace(payload.Error)
			}
			if message == "" {
				message = "authorization denied"
			}
			deliver(configureOAuthCallbackResult{err: fmt.Errorf("panel authorization denied: %s", message)})
			return
		}

		if strings.TrimSpace(payload.PublicKey) == "" || strings.TrimSpace(payload.PrivateKey) == "" {
			deliver(configureOAuthCallbackResult{err: fmt.Errorf("OAuth callback did not include API credentials")})
			return
		}

		deliver(configureOAuthCallbackResult{
			credentials: configureOAuthCredentials{
				PublicKey:         strings.TrimSpace(payload.PublicKey),
				PrivateKey:        strings.TrimSpace(payload.PrivateKey),
				AuthorizationCode: strings.TrimSpace(payload.AuthorizationCode),
			},
		})
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var payload configureOAuthCallbackPayload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			deliver(configureOAuthCallbackResult{err: fmt.Errorf("invalid OAuth callback payload: %w", err)})
			writeOAuthCallbackAck(w)
			return
		}
		handlePayload(payload)
		writeOAuthCallbackAck(w)
	})

	server := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		_ = server.Serve(listener)
	}()

	addr, ok := listener.Addr().(*net.TCPAddr)
	if !ok {
		_ = listener.Close()
		return nil, "", nil, fmt.Errorf("failed to resolve OAuth callback port")
	}

	callbackURL := buildOAuthCallbackURL(callbackHost, addr.Port)
	cleanup := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
		_ = listener.Close()
	}

	return resultCh, callbackURL, cleanup, nil
}

func writeOAuthCallbackAck(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"received":true}`))
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
