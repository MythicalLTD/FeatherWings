package cmd

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/mythicalltd/featherwings/config"
	"github.com/spf13/cobra"
)

var configureFlags struct {
	JoinData       string
	ConfigPath     string
	Override       bool
	Quiet          bool
	AllowInsecure  bool
	InstallService bool
	NoService      bool
	PanelURL       string
	NodeName       string
	NodeFQDN       string
	LocationID     int
	KeepOAuthKey   bool
	CallbackHost   string
}

type configureMode int

const (
	configureModeJoin configureMode = iota
	configureModeOAuth
)

func newConfigureCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "configure",
		Short: "Configure FeatherWings using panel join-data",
		Long:  "Configure FeatherWings for FeatherPanel using join-data or interactive quick setup. Run without flags in a terminal for the setup wizard.",
		RunE:  configureCmdRun,
		SilenceUsage: true,
	}

	cmd.Flags().StringVar(&configureFlags.JoinData, "join-data", "", "Base64-encoded bootstrap YAML from FeatherPanel")
	cmd.Flags().StringVarP(&configureFlags.ConfigPath, "config", "c", config.DefaultLocation, "Path to write config.yml")
	cmd.Flags().BoolVar(&configureFlags.Override, "override", false, "Replace an existing configuration file")
	cmd.Flags().BoolVarP(&configureFlags.Quiet, "quiet", "q", false, "Suppress animated output")
	cmd.Flags().BoolVar(&configureFlags.AllowInsecure, "allow-insecure", false, "Skip TLS certificate verification when fetching config from the panel")
	cmd.Flags().BoolVar(&configureFlags.InstallService, "install-service", false, "Install, enable, and start the featherwings systemd unit without prompting")
	cmd.Flags().BoolVar(&configureFlags.NoService, "no-service", false, "Skip systemd service installation")
	cmd.Flags().StringVar(&configureFlags.PanelURL, "panel-url", "", "FeatherPanel base URL for non-interactive quick setup")
	cmd.Flags().StringVar(&configureFlags.NodeName, "node-name", "", "Node name for non-interactive quick setup")
	cmd.Flags().StringVar(&configureFlags.NodeFQDN, "node-fqdn", "", "Node FQDN for non-interactive quick setup")
	cmd.Flags().IntVar(&configureFlags.LocationID, "location-id", 0, "Game location ID for non-interactive quick setup")
	cmd.Flags().BoolVar(&configureFlags.KeepOAuthKey, "keep-oauth-key", false, "Keep the temporary OAuth API key on the panel after setup")
	cmd.Flags().StringVar(&configureFlags.CallbackHost, "callback-host", "", "Public IP of this node for OAuth setup")

	return cmd
}

func configureCmdRun(_ *cobra.Command, _ []string) error {
	ui := newConfigureUI()

	mode, err := resolveConfigureMode()
	if err != nil {
		return err
	}

	var joinData string
	switch mode {
	case configureModeOAuth:
		joinData, err = resolveJoinDataViaOAuth()
	case configureModeJoin:
		joinData, err = resolveJoinDataDirect()
	default:
		return fmt.Errorf("unsupported configure mode")
	}
	if err != nil {
		return err
	}

	return runConfigureWithJoinData(ui, joinData)
}

func resolveConfigureMode() (configureMode, error) {
	if configureUIEnabled() {
		return promptConfigureMode()
	}

	hasJoinData := strings.TrimSpace(configureFlags.JoinData) != "" || strings.TrimSpace(os.Getenv("FEATHERWINGS_JOIN_DATA")) != ""
	hasPanelURL := strings.TrimSpace(configureFlags.PanelURL) != ""

	if hasJoinData {
		return configureModeJoin, nil
	}
	if hasPanelURL {
		return configureModeOAuth, nil
	}
	return 0, fmt.Errorf("missing --join-data (or FEATHERWINGS_JOIN_DATA) or --panel-url")
}

func resolveJoinDataDirect() (string, error) {
	joinData := strings.TrimSpace(configureFlags.JoinData)
	if joinData == "" {
		joinData = strings.TrimSpace(os.Getenv("FEATHERWINGS_JOIN_DATA"))
	}
	if joinData == "" {
		var err error
		joinData, err = promptConfigureJoinData()
		if err != nil {
			return "", err
		}
	}
	return joinData, nil
}

func runConfigureWithJoinData(ui *configureUI, joinData string) error {
	configPath := configureFlags.ConfigPath
	if _, err := os.Stat(configPath); err == nil && !configureFlags.Override {
		override, err := promptConfigureOverride(configPath)
		if err != nil {
			return err
		}
		configureFlags.Override = override
	} else if err != nil && !os.IsNotExist(err) {
		return err
	}

	installService, err := promptConfigureServiceInstall()
	if err != nil {
		return err
	}

	var (
		rawYAML       []byte
		runtimeYAML   []byte
		bootstrap     *config.JoinBootstrap
		wroteFull     bool
		runtimeBytes  int
		serviceResult configureServiceResult
	)

	steps := []struct {
		label string
		work  func(*configureReporter) error
	}{
		{
			label: "Decoding join data",
			work: func(r *configureReporter) error {
				var err error
				rawYAML, err = decodeJoinData(joinData)
				if err != nil {
					return err
				}
				r.Detail(fmt.Sprintf("decoded %d bytes of join YAML", len(rawYAML)))
				r.Detail(fmt.Sprintf("target config → %s", configPath))
				return nil
			},
		},
		{
			label: "Validating join data",
			work: func(r *configureReporter) error {
				var err error
				if config.IsFullWingsConfig(rawYAML) {
					wroteFull = true
					runtimeYAML = rawYAML
					bootstrap, err = config.ParseJoinBootstrap(rawYAML)
					if err != nil {
						return err
					}
					if err := bootstrap.ValidateJoin(); err != nil {
						return err
					}
					r.Detail("join-data contains a full runtime config")
					r.Detail(fmt.Sprintf("uuid %s", bootstrap.UUID))
					r.Detail(fmt.Sprintf("panel %s", bootstrap.Remote))
					r.Detail(fmt.Sprintf("token %s", maskConfigureSecret(bootstrap.TokenID)))
					return nil
				}

				bootstrap, err = config.ParseJoinBootstrap(rawYAML)
				if err != nil {
					return err
				}
				if err := bootstrap.ValidateJoin(); err != nil {
					return err
				}
				r.Detail(fmt.Sprintf("uuid %s", bootstrap.UUID))
				r.Detail(fmt.Sprintf("panel %s", bootstrap.Remote))
				r.Detail(fmt.Sprintf("token %s", maskConfigureSecret(bootstrap.TokenID)))
				return nil
			},
		},
		{
			label: "Verifying panel token",
			work: func(r *configureReporter) error {
				if wroteFull && bootstrap == nil {
					return fmt.Errorf("join-data: missing bootstrap credentials")
				}
				if bootstrap == nil {
					return fmt.Errorf("join-data: missing bootstrap credentials")
				}

				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()

				if err := config.VerifyJoinCredentials(ctx, bootstrap, configureFlags.AllowInsecure); err != nil {
					return err
				}
				r.Detail("panel accepted node credentials")
				return nil
			},
		},
		{
			label: "Fetching runtime config",
			work: func(r *configureReporter) error {
				if wroteFull {
					r.Detail("using embedded runtime config")
					return nil
				}

				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
				defer cancel()

				var err error
				runtimeYAML, err = config.FetchRuntimeConfigYAML(ctx, bootstrap, configureFlags.AllowInsecure)
				if err != nil {
					return err
				}
				runtimeBytes = len(runtimeYAML)
				r.Detail(fmt.Sprintf("received %d bytes from /api/remote/config", runtimeBytes))
				return nil
			},
		},
		{
			label: "Writing bootstrap config",
			work: func(r *configureReporter) error {
				if err := os.MkdirAll(filepath.Dir(configPath), 0o700); err != nil {
					return err
				}
				if err := config.WriteRawConfig(configPath, runtimeYAML); err != nil {
					return err
				}
				r.Detail(fmt.Sprintf("saved → %s", configPath))
				return nil
			},
		},
		{
			label: "Validating written config",
			work: func(r *configureReporter) error {
				if err := config.FromFile(configPath); err != nil {
					return fmt.Errorf("written config failed validation: %w", err)
				}
				r.Detail("config loads successfully")
				return nil
			},
		},
	}

	completed, err := ui.runSequence(steps)
	if err != nil {
		return err
	}

	if installService {
		var installErr error
		serviceResult, installErr = installFeatherwingsService(configPath, nil)
		completed = append(completed, serviceStepResult(serviceResult, installErr))
		if installErr != nil {
			summary := loadConfigureSummary(configPath, bootstrap)
			summary.Service = serviceResult
			ui.renderFinal(summary, completed)
			return installErr
		}
	}

	summary := loadConfigureSummary(configPath, bootstrap)
	summary.Service = serviceResult
	ui.renderFinal(summary, completed)
	return nil
}

func decodeJoinData(joinData string) ([]byte, error) {
	normalized := strings.TrimSpace(joinData)
	normalized = strings.Trim(normalized, `"'`)

	raw, err := base64.StdEncoding.DecodeString(normalized)
	if err != nil {
		return nil, fmt.Errorf("invalid join-data: expected base64-encoded YAML from FeatherPanel")
	}
	return raw, nil
}

func maskConfigureSecret(value string) string {
	if value == "" {
		return "****"
	}
	if len(value) <= 4 {
		return strings.Repeat("*", len(value))
	}
	return value[:2] + strings.Repeat("*", len(value)-4) + value[len(value)-2:]
}
