package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/charmbracelet/huh"
	"github.com/charmbracelet/lipgloss"
	"github.com/mythicalltd/featherwings/config"
	"github.com/mythicalltd/featherwings/system"
)

const configureTagline = "Joining game node to FeatherPanel…"

var configureSpinnerFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

type configureStepStatus int

const (
	configureStepPending configureStepStatus = iota
	configureStepRunning
	configureStepSuccess
	configureStepWarning
	configureStepFailed
	configureStepSkipped
)

type configureStepResult struct {
	label   string
	status  configureStepStatus
	details []string
}

type configureReporter struct {
	mu      sync.Mutex
	status  string
	details []string
}

func (r *configureReporter) SetStatus(status string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.status = status
}

func (r *configureReporter) Detail(line string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.details = append(r.details, line)
}

func (r *configureReporter) snapshot() (status string, details []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.status, append([]string(nil), r.details...)
}

type configureUI struct {
	enabled bool
}

func newConfigureUI() *configureUI {
	return &configureUI{enabled: configureUIEnabled()}
}

func configureUIEnabled() bool {
	if configureFlags.Quiet {
		return false
	}
	fi, err := os.Stdout.Stat()
	if err != nil || fi.Mode()&os.ModeCharDevice == 0 {
		return false
	}
	return true
}

func (ui *configureUI) runSequence(steps []struct {
	label string
	work  func(*configureReporter) error
}) ([]configureStepResult, error) {
	if !ui.enabled {
		for _, step := range steps {
			if err := step.work(&configureReporter{}); err != nil {
				return nil, err
			}
		}
		return nil, nil
	}

	seq := make([]configureSequenceStep, len(steps))
	for i, step := range steps {
		seq[i] = configureSequenceStep{label: step.label, work: step.work}
	}
	return runConfigureTUI(seq)
}

func (ui *configureUI) renderFinal(summary configureSummary, completed []configureStepResult) {
	if !ui.enabled {
		fmt.Printf("Successfully configured FeatherWings → %s\n", summary.ConfigPath)
		if summary.Service.Started {
			fmt.Println("featherwings service is running")
		} else if summary.Service.Installed {
			fmt.Println("featherwings service installed — run: systemctl start featherwings")
		}
		return
	}

	clearConfigureScreen()

	width := 72
	fmt.Println(renderConfigureBanner(width, configureTagline))
	fmt.Println()
	fmt.Println(renderConfigureChecklist(width, completed, ""))
	fmt.Println()
	fmt.Println(renderConfigureSuccessPanel(width, summary))
	fmt.Println()
}

func clearConfigureScreen() {
	fmt.Print("\033[2J\033[H")
}

func (ui *configureUI) renderSuccess(summary configureSummary) {
	ui.renderFinal(summary, nil)
}

func renderConfigureBanner(width int, tagline string) string {
	return lipConfigureFrame().
		Width(width).
		Align(lipgloss.Center).
		Render(lipgloss.JoinVertical(lipgloss.Center,
			lipConfigureTeal().Bold(true).Render("FeatherWings"),
			"",
			lipConfigureMuted().Italic(true).Render(tagline),
			lipConfigureInk().Render("Configure · panel join flow"),
		))
}

func renderConfigureChecklist(width int, completed []configureStepResult, active string) string {
	rows := []string{
		lipConfigureTeal().Bold(true).Render("Panel join sequence"),
		"",
	}
	for _, step := range completed {
		rows = append(rows, configureStepLine(step.label, step.status))
		for _, detail := range step.details {
			rows = append(rows, configureDetailLine(detail, step.status))
		}
	}
	if active != "" {
		rows = append(rows, fmt.Sprintf("  %s %s",
			lipConfigureTeal().Bold(true).Render("◉"),
			lipConfigureInk().Bold(true).Render(active),
		))
	}
	return lipConfigureFrame().Width(width).Render(strings.Join(rows, "\n"))
}

func renderConfigureSuccessPanel(width int, summary configureSummary) string {
	rows := []string{
		lipConfigureOK().Bold(true).Render("Node configured successfully"),
		"",
		fmt.Sprintf("%s  %s", lipConfigureMuted().Render("node"), lipConfigureTeal().Render(summary.NodeUUID)),
		fmt.Sprintf("%s %s", lipConfigureMuted().Render("panel"), lipConfigureInk().Render(summary.PanelURL)),
		fmt.Sprintf("%s %s", lipConfigureMuted().Render("config"), lipConfigureInk().Render("→ "+summary.ConfigPath)),
		fmt.Sprintf("%s %s", lipConfigureMuted().Render("api"), lipConfigureOK().Render(fmt.Sprintf(":%d", summary.APIPort))+lipConfigureMuted().Render(fmt.Sprintf(" (v%s)", summary.Version))),
	}

	switch {
	case summary.Service.Started:
		rows = append(rows, "", lipConfigureOK().Render("service installed · enabled · running"))
		rows = append(rows, lipConfigureMuted().Render("check status: systemctl status featherwings"))
	case summary.Service.Installed:
		rows = append(rows, "", lipConfigureWarn().Render("service installed — not running yet"))
		rows = append(rows, lipConfigureMuted().Render("start with: systemctl start featherwings"))
	case summary.Service.Skipped:
		if summary.Service.Message != "" {
			rows = append(rows, "", lipConfigureMuted().Render(summary.Service.Message))
		}
	default:
		rows = append(rows, "", lipConfigureMuted().Render("start the daemon: systemctl start featherwings"))
	}

	return lipConfigureFrame().Width(width).Render(
		lipgloss.JoinVertical(lipgloss.Left, append([]string{
			lipConfigureTeal().Bold(true).Render(" ready "),
			"",
		}, rows...)...),
	)
}

func configureStepLine(label string, status configureStepStatus) string {
	glyph := "?"
	style := lipConfigureInk()
	switch status {
	case configureStepSuccess:
		glyph = lipConfigureTeal().Bold(true).Render("✓")
	case configureStepWarning:
		glyph = lipConfigureWarn().Bold(true).Render("!")
		style = lipConfigureWarn()
	case configureStepFailed:
		glyph = lipConfigureErr().Bold(true).Render("✗")
		style = lipConfigureErr()
	case configureStepSkipped:
		glyph = lipConfigureMuted().Render("–")
		style = lipConfigureMuted()
	}
	return fmt.Sprintf("  %s %s", glyph, style.Render(label))
}

func configureDetailLine(detail string, status configureStepStatus) string {
	prefix := lipConfigureMuted().Render("›")
	switch status {
	case configureStepWarning:
		prefix = lipConfigureWarn().Render("!")
	case configureStepFailed:
		prefix = lipConfigureErr().Render("×")
	case configureStepSkipped:
		prefix = lipConfigureMuted().Render("-")
	}
	return fmt.Sprintf("      %s %s", prefix, lipConfigureMuted().Render(detail))
}

type configureSummary struct {
	NodeUUID        string
	PanelURL        string
	ConfigPath      string
	APIPort         int
	Version         string
	Service         configureServiceResult
}

func promptInstallService(install *bool) error {
	err := huh.NewForm(
		huh.NewGroup(
			huh.NewConfirm().
				Title("Install the featherwings systemd service?").
				Description("Writes /etc/systemd/system/featherwings.service, runs daemon-reload, enables on boot, and starts the daemon.").
				Value(install),
		),
	).Run()
	if err == huh.ErrUserAborted {
		return fmt.Errorf("configure cancelled")
	}
	return err
}

func promptConfigureJoinData() (string, error) {
	if !configureUIEnabled() {
		return "", fmt.Errorf("missing --join-data (or FEATHERWINGS_JOIN_DATA environment variable)")
	}

	fmt.Println()
	fmt.Println(lipConfigureFrame().Width(72).Render(strings.Join([]string{
		lipConfigureTeal().Bold(true).Render("Manual setup"),
		"",
		lipConfigureMuted().Render("Paste the base64 join-data from Admin → Nodes → Wings tab."),
	}, "\n")))
	fmt.Println()

	var joinData string
	err := huh.NewForm(
		huh.NewGroup(
			huh.NewInput().
				Title("Paste join-data").
				Description("Base64 bootstrap YAML from FeatherPanel").
				Value(&joinData).
				Validate(func(value string) error {
					if strings.TrimSpace(value) == "" {
						return fmt.Errorf("join-data cannot be empty")
					}
					if _, err := decodeJoinData(value); err != nil {
						return fmt.Errorf("invalid join-data — expected base64 YAML from FeatherPanel")
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
	return strings.TrimSpace(joinData), nil
}

func promptConfigureOverride(configPath string) (bool, error) {
	if !configureUIEnabled() {
		return false, fmt.Errorf("config already exists at %s (use --override to replace it)", configPath)
	}

	override := false
	err := huh.NewForm(
		huh.NewGroup(
			huh.NewConfirm().
				Title("Override existing configuration?").
				Description(configPath).
				Value(&override),
		),
	).Run()
	if err != nil {
		if err == huh.ErrUserAborted {
			return false, fmt.Errorf("configure cancelled")
		}
		return false, err
	}
	if !override {
		return false, fmt.Errorf("aborted — configuration file already exists")
	}
	return true, nil
}

func promptConfigureMode() (configureMode, error) {
	fmt.Println()
	fmt.Println(lipConfigureFrame().Width(72).Render(strings.Join([]string{
		lipConfigureTeal().Bold(true).Render("Welcome to FeatherWings setup"),
		"",
		lipConfigureMuted().Render("Connect this machine to FeatherPanel as a game server node."),
	}, "\n")))
	fmt.Println()

	choice := "manual"
	err := huh.NewForm(
		huh.NewGroup(
			huh.NewSelect[string]().
				Title("How do you want to set up this node?").
				Description("Manual setup uses join-data from the panel. Automatic only needs your panel URL.").
				Options(
					huh.NewOption("Manual (Join data)", "manual"),
					huh.NewOption("Automatic (OAuth2)", "oauth"),
				).
				Value(&choice),
		),
	).Run()
	if err != nil {
		if err == huh.ErrUserAborted {
			return 0, fmt.Errorf("configure cancelled")
		}
		return 0, err
	}

	return configureModeFromChoice(choice), nil
}

func configureModeFromChoice(choice string) configureMode {
	switch choice {
	case "oauth":
		return configureModeOAuth
	default:
		return configureModeJoin
	}
}

func promptConfigurePanelURL() (string, error) {
	if !configureUIEnabled() {
		panelURL := strings.TrimSpace(configureFlags.PanelURL)
		if panelURL == "" {
			return "", fmt.Errorf("missing --panel-url for quick setup")
		}
		return config.NormalizePanelURL(panelURL), nil
	}

	panelURL := strings.TrimSpace(configureFlags.PanelURL)
	err := huh.NewForm(
		huh.NewGroup(
			huh.NewInput().
				Title("FeatherPanel URL").
				Description("Base URL only — paths are stripped automatically (e.g. https://panel.example.com)").
				Placeholder("https://panel.example.com").
				Value(&panelURL).
				Validate(func(value string) error {
					value = strings.TrimSpace(value)
					if value == "" {
						return fmt.Errorf("panel URL is required")
					}
					if !strings.HasPrefix(value, "http://") && !strings.HasPrefix(value, "https://") {
						return fmt.Errorf("panel URL must start with http:// or https://")
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
	return config.NormalizePanelURL(panelURL), nil
}


func promptConfigureLocation(ctx context.Context, panel *config.PanelAPI, locations []config.PanelLocation) (int, error) {
	choice := "create"
	if len(locations) > 0 {
		choice = fmt.Sprintf("%d", locations[0].ID)
	}

	options := make([]huh.Option[string], 0, len(locations)+1)
	for _, location := range locations {
		label := location.Name
		if strings.TrimSpace(location.FlagCode) != "" {
			label = fmt.Sprintf("%s [%s]", location.Name, strings.ToUpper(location.FlagCode))
		}
		options = append(options, huh.NewOption(label, fmt.Sprintf("%d", location.ID)))
	}
	options = append(options, huh.NewOption("Create new game location…", "create"))

	err := huh.NewForm(
		huh.NewGroup(
			huh.NewSelect[string]().
				Title("Game location").
				Description("Select an existing location or create a new one.").
				Options(options...).
				Value(&choice),
		),
	).Run()
	if err != nil {
		if err == huh.ErrUserAborted {
			return 0, fmt.Errorf("configure cancelled")
		}
		return 0, err
	}

	if choice == "create" {
		return promptConfigureCreateLocation(ctx, panel)
	}

	var locationID int
	if _, err := fmt.Sscanf(choice, "%d", &locationID); err != nil || locationID < 1 {
		return 0, fmt.Errorf("invalid location selection")
	}
	return locationID, nil
}

func promptConfigureCreateLocation(ctx context.Context, panel *config.PanelAPI) (int, error) {
	name := ""
	description := ""
	flagCode := ""

	err := huh.NewForm(
		huh.NewGroup(
			huh.NewInput().
				Title("Location name").
				Description("Shown in Admin → Locations").
				Value(&name).
				Validate(func(value string) error {
					if len(strings.TrimSpace(value)) < 2 {
						return fmt.Errorf("location name must be at least 2 characters")
					}
					return nil
				}),
			huh.NewInput().
				Title("Description").
				Description("Optional description for this location").
				Value(&description),
			huh.NewInput().
				Title("Flag code").
				Description("Optional country flag code, e.g. us, at, al").
				Placeholder("us").
				Value(&flagCode),
		),
	).Run()
	if err != nil {
		if err == huh.ErrUserAborted {
			return 0, fmt.Errorf("configure cancelled")
		}
		return 0, err
	}

	location, err := panel.CreateLocation(ctx, config.CreatePanelLocationRequest{
		Name:        strings.TrimSpace(name),
		Type:        "game",
		Description: strings.TrimSpace(description),
		FlagCode:    strings.ToLower(strings.TrimSpace(flagCode)),
	})
	if err != nil {
		return 0, err
	}

	fmt.Printf("%s Created location %q\n\n", lipConfigureOK().Render("✓"), location.Name)
	return location.ID, nil
}

func loadConfigureSummary(configPath string, bootstrap *config.JoinBootstrap) configureSummary {
	summary := configureSummary{
		ConfigPath: configPath,
		Version:    system.Version,
	}
	if bootstrap != nil {
		summary.NodeUUID = bootstrap.UUID
		summary.PanelURL = bootstrap.Remote
		if bootstrap.Api.Port > 0 {
			summary.APIPort = bootstrap.Api.Port
		}
	}
	if err := config.FromFile(configPath); err == nil {
		cfg := config.Get()
		if cfg.Uuid != "" {
			summary.NodeUUID = cfg.Uuid
		}
		if cfg.PanelLocation != "" {
			summary.PanelURL = cfg.PanelLocation
		}
		if cfg.Api.Port > 0 {
			summary.APIPort = cfg.Api.Port
		}
	}
	return summary
}

func lipConfigureFrame() lipgloss.Style {
	return lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("86")).
		Padding(0, 1)
}

func lipConfigureTeal() lipgloss.Style {
	return lipgloss.NewStyle().Foreground(lipgloss.Color("86"))
}

func lipConfigureInk() lipgloss.Style {
	return lipgloss.NewStyle().Foreground(lipgloss.Color("255"))
}

func lipConfigureMuted() lipgloss.Style {
	return lipgloss.NewStyle().Foreground(lipgloss.Color("245"))
}

func lipConfigureOK() lipgloss.Style {
	return lipgloss.NewStyle().Foreground(lipgloss.Color("42"))
}

func lipConfigureWarn() lipgloss.Style {
	return lipgloss.NewStyle().Foreground(lipgloss.Color("214"))
}

func lipConfigureErr() lipgloss.Style {
	return lipgloss.NewStyle().Foreground(lipgloss.Color("196"))
}
