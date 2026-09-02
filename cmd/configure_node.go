package cmd

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/charmbracelet/huh"
	"github.com/mythicalltd/featherwings/config"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/mem"
)

const defaultConfigureDaemonBase = "/var/lib/featherpanel/volumes"

var configureDataDirectoryOptions = []struct {
	label string
	path  string
}{
	{label: "FeatherPanel default (/var/lib/featherpanel/volumes)", path: defaultConfigureDaemonBase},
	{label: "FeatherWings default (/var/lib/featherwings/volumes)", path: "/var/lib/featherwings/volumes"},
	{label: "Enter a custom path…", path: "custom"},
}

type configureNodeForm struct {
	Name               string
	Description        string
	FQDN               string
	LocationID         int
	Public             bool
	Scheme             string
	BehindProxy        bool
	PublicIPv4         string
	PublicIPv6         string
	MemoryMiB          int
	MemoryOverallocate int
	DiskMiB            int
	DiskOverallocate   int
	UploadSizeMB       int
	DaemonListen       int
	DaemonSFTP         int
	FastDLPort         int
	DaemonBase         string
}

func defaultConfigureNodeForm(nodeIP string) configureNodeForm {
	hostname, _ := os.Hostname()
	hostname = strings.TrimSpace(hostname)
	if hostname == "" {
		hostname = "node.local"
	}

	memoryMiB, diskMiB := detectConfigureNodeResources()

	return configureNodeForm{
		Name:         hostname,
		FQDN:         hostname,
		Public:       true,
		Scheme:       "https",
		PublicIPv4:   strings.TrimSpace(nodeIP),
		MemoryMiB:    memoryMiB,
		DiskMiB:      diskMiB,
		UploadSizeMB: 100,
		DaemonListen: 8443,
		DaemonSFTP:   2022,
		FastDLPort:   80,
		DaemonBase:   defaultConfigureDaemonBase,
	}
}

func detectConfigureNodeResources() (memoryMiB, diskMiB int) {
	if vm, err := mem.VirtualMemory(); err == nil && vm.Total > 0 {
		memoryMiB = int(vm.Total / 1024 / 1024)
	}
	if usage, err := disk.Usage("/"); err == nil && usage.Total > 0 {
		diskMiB = int(usage.Total / 1024 / 1024)
	}
	return memoryMiB, diskMiB
}

func buildConfigureNodeRequest(form configureNodeForm) config.CreatePanelNodeRequest {
	req := config.CreatePanelNodeRequest{
		Name:               strings.TrimSpace(form.Name),
		Description:        strings.TrimSpace(form.Description),
		FQDN:               strings.TrimSpace(form.FQDN),
		LocationID:         form.LocationID,
		Public:             boolToPanelFlag(form.Public),
		Scheme:             strings.TrimSpace(form.Scheme),
		BehindProxy:        boolToPanelFlag(form.BehindProxy),
		Memory:             form.MemoryMiB,
		MemoryOverallocate: form.MemoryOverallocate,
		Disk:               form.DiskMiB,
		DiskOverallocate:   form.DiskOverallocate,
		UploadSize:         form.UploadSizeMB,
		DaemonListen:       form.DaemonListen,
		DaemonSFTP:         form.DaemonSFTP,
		FastDLPort:         form.FastDLPort,
		DaemonBase:         strings.TrimSpace(form.DaemonBase),
		DaemonType:         "featherwings",
	}
	if ipv4 := strings.TrimSpace(form.PublicIPv4); ipv4 != "" {
		req.PublicIPv4 = &ipv4
	}
	if ipv6 := strings.TrimSpace(form.PublicIPv6); ipv6 != "" {
		req.PublicIPv6 = &ipv6
	}
	return req
}

func boolToPanelFlag(value bool) int {
	if value {
		return 1
	}
	return 0
}

func panelURLAnalysis(rawURL string) (scheme, hostname string, hostIsIP bool) {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return "", "", false
	}
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Host == "" {
		return "", "", false
	}
	hostname = parsed.Hostname()
	return parsed.Scheme, hostname, net.ParseIP(hostname) != nil
}

func configurePanelUsesHTTPS(panelBaseURL string) bool {
	scheme, _, _ := panelURLAnalysis(panelBaseURL)
	return scheme == "https"
}

func configurePanelHostIsIP(panelBaseURL string) bool {
	_, _, hostIsIP := panelURLAnalysis(panelBaseURL)
	return hostIsIP
}

func promptConfigureNodeFields(ctx context.Context, panel *config.PanelAPI, locations []config.PanelLocation, nodeIP string, clientInfo *config.PanelAPIClientInfo) (config.CreatePanelNodeRequest, error) {
	form := defaultConfigureNodeForm(nodeIP)

	panelInfo, err := panel.GetSystemSettings(ctx)
	if err != nil {
		return config.CreatePanelNodeRequest{}, err
	}

	fmt.Println()
	fmt.Println(renderConfigurePanelInfoBanner(panel.BaseURL, panelInfo))
	fmt.Println()

	locationID, err := promptConfigureLocation(ctx, panel, locations)
	if err != nil {
		return config.CreatePanelNodeRequest{}, err
	}
	form.LocationID = locationID

	daemonListen := strconv.Itoa(form.DaemonListen)
	daemonSFTP := strconv.Itoa(form.DaemonSFTP)
	err = huh.NewForm(
		huh.NewGroup(
			huh.NewInput().
				Title("Daemon API port").
				Description("Port FeatherPanel uses to talk to FeatherWings on this machine").
				Value(&daemonListen).
				Validate(portNumber("daemon API port")),
			huh.NewInput().
				Title("SFTP port").
				Description("Port used for server file access").
				Value(&daemonSFTP).
				Validate(portNumber("SFTP port")),
		),
	).Run()
	if err != nil {
		if err == huh.ErrUserAborted {
			return config.CreatePanelNodeRequest{}, fmt.Errorf("configure cancelled")
		}
		return config.CreatePanelNodeRequest{}, err
	}
	form.DaemonListen = mustAtoi(daemonListen)
	form.DaemonSFTP = mustAtoi(daemonSFTP)

	if err := promptConfigureNodeNetwork(ctx, &form, panel.BaseURL, nodeIP, clientInfo); err != nil {
		return config.CreatePanelNodeRequest{}, err
	}

	dataDirChoice := defaultConfigureDaemonBase
	err = huh.NewForm(
		huh.NewGroup(
			huh.NewSelect[string]().
				Title("Game server data directory").
				Description("Where volumes for game servers are stored on this machine").
				Options(
					huh.NewOption(configureDataDirectoryOptions[0].label, configureDataDirectoryOptions[0].path),
					huh.NewOption(configureDataDirectoryOptions[1].label, configureDataDirectoryOptions[1].path),
					huh.NewOption(configureDataDirectoryOptions[2].label, "custom"),
				).
				Value(&dataDirChoice),
		),
	).Run()
	if err != nil {
		if err == huh.ErrUserAborted {
			return config.CreatePanelNodeRequest{}, fmt.Errorf("configure cancelled")
		}
		return config.CreatePanelNodeRequest{}, err
	}
	if dataDirChoice == "custom" {
		customPath := defaultConfigureDaemonBase
		err = huh.NewForm(
			huh.NewGroup(
				huh.NewInput().
					Title("Custom data directory").
					Description("Absolute path on this machine").
					Value(&customPath).
					Validate(requiredNonEmpty("data directory")),
			),
		).Run()
		if err != nil {
			if err == huh.ErrUserAborted {
				return config.CreatePanelNodeRequest{}, fmt.Errorf("configure cancelled")
			}
			return config.CreatePanelNodeRequest{}, err
		}
		form.DaemonBase = strings.TrimSpace(customPath)
	} else {
		form.DaemonBase = dataDirChoice
	}

	if form.Description == "" && panelInfo != nil && panelInfo.AppName != "" {
		form.Description = fmt.Sprintf("Game node for %s", panelInfo.AppName)
	}

	fmt.Println()
	fmt.Println(lipConfigureFrame().Width(72).Render(strings.Join([]string{
		lipConfigureTeal().Bold(true).Render("Node details"),
		"",
		lipConfigureMuted().Render("Review the detected values below before creating the node."),
		renderConfigureNodeDefaultSummary(form),
	}, "\n")))
	fmt.Println()

	publicChoice := "true"
	if !form.Public {
		publicChoice = "false"
	}

	memory := strconv.Itoa(form.MemoryMiB)
	memoryOverallocate := strconv.Itoa(form.MemoryOverallocate)
	diskMiB := strconv.Itoa(form.DiskMiB)
	diskOverallocate := strconv.Itoa(form.DiskOverallocate)
	uploadSize := strconv.Itoa(form.UploadSizeMB)
	fastDLPort := strconv.Itoa(form.FastDLPort)

	err = huh.NewForm(
		huh.NewGroup(
			huh.NewInput().
				Title("Node name").
				Description("Display name shown in FeatherPanel").
				Value(&form.Name).
				Validate(requiredNonEmpty("node name")),
			huh.NewInput().
				Title("Description").
				Description("Optional note for this node").
				Value(&form.Description),
		),
		huh.NewGroup(
			huh.NewSelect[string]().
				Title("Visibility").
				Description("Whether this node appears in server deployment lists").
				Options(
					huh.NewOption("Public", "true"),
					huh.NewOption("Private", "false"),
				).
				Value(&publicChoice),
			huh.NewInput().
				Title("Public IPv4").
				Description("This machine's public IP — must match what FeatherPanel uses to reach it").
				Placeholder("203.0.113.42").
				Value(&form.PublicIPv4),
			huh.NewInput().
				Title("Public IPv6").
				Description("Optional public IPv6 address").
				Value(&form.PublicIPv6),
		),
		huh.NewGroup(
			huh.NewInput().
				Title("Memory limit").
				Description("Total allocatable memory for game servers on this node (MiB)").
				Value(&memory).
				Validate(positiveInteger("memory limit")),
			huh.NewInput().
				Title("Memory overallocate").
				Description("Optional extra memory allocation percentage").
				Value(&memoryOverallocate).
				Validate(nonNegativeInteger("memory overallocate")),
			huh.NewInput().
				Title("Disk limit").
				Description("Total allocatable disk for game servers on this node (MiB)").
				Value(&diskMiB).
				Validate(positiveInteger("disk limit")),
			huh.NewInput().
				Title("Disk overallocate").
				Description("Optional extra disk allocation percentage").
				Value(&diskOverallocate).
				Validate(nonNegativeInteger("disk overallocate")),
			huh.NewInput().
				Title("FastDL port").
				Description("Port used for FastDL downloads").
				Value(&fastDLPort).
				Validate(portNumber("FastDL port")),
			huh.NewInput().
				Title("Max upload size").
				Description("Maximum file upload size in megabytes").
				Value(&uploadSize).
				Validate(positiveInteger("max upload size")),
		),
	).Run()
	if err != nil {
		if err == huh.ErrUserAborted {
			return config.CreatePanelNodeRequest{}, fmt.Errorf("configure cancelled")
		}
		return config.CreatePanelNodeRequest{}, err
	}

	form.Public = publicChoice == "true"
	form.MemoryMiB = mustAtoi(memory)
	form.MemoryOverallocate = mustAtoi(memoryOverallocate)
	form.DiskMiB = mustAtoi(diskMiB)
	form.DiskOverallocate = mustAtoi(diskOverallocate)
	form.UploadSizeMB = mustAtoi(uploadSize)
	form.FastDLPort = mustAtoi(fastDLPort)

	return buildConfigureNodeRequest(form), nil
}

func promptConfigureNodeNetwork(ctx context.Context, form *configureNodeForm, panelBaseURL string, nodeIP string, clientInfo *config.PanelAPIClientInfo) error {
	behindProxy := false
	err := huh.NewForm(
		huh.NewGroup(
			huh.NewConfirm().
				Title("Use a reverse proxy for this node?").
				Description("Enable if Cloudflare, nginx, or another proxy terminates TLS in front of FeatherWings on this machine.").
				Value(&behindProxy),
		),
	).Run()
	if err != nil {
		if err == huh.ErrUserAborted {
			return fmt.Errorf("configure cancelled")
		}
		return err
	}

	form.BehindProxy = behindProxy
	panelHTTPS := configurePanelUsesHTTPS(panelBaseURL)
	panelHostIsIP := configurePanelHostIsIP(panelBaseURL)

	if behindProxy {
		form.Scheme = "https"
		form.FQDN = ""
		return promptConfigureNodeFQDN(form, "Domain served by your reverse proxy (e.g. node.example.com)")
	}

	if !panelHTTPS || panelHostIsIP {
		form.Scheme = "http"
		if nodeIP != "" && !isLoopbackHost(nodeIP) {
			form.FQDN = nodeIP
		}
		description := "Your panel uses HTTP or an IP address — the node FQDN should match how the panel reaches this machine."
		if panelBaseURL != "" {
			description = fmt.Sprintf("%s Panel URL: %s", description, panelBaseURL)
		}
		return promptConfigureNodeFQDN(form, description)
	}

	form.Scheme = "https"
	form.FQDN = ""
	if err := promptConfigureNodeFQDN(form, "Domain for this node — FeatherPanel uses HTTPS, so provide a hostname with a valid TLS certificate on this machine."); err != nil {
		return err
	}

	email := ""
	if clientInfo != nil {
		email = strings.TrimSpace(clientInfo.UserEmail)
	}
	updatedDomain, err := ensureNodeTLSCertificate(ctx, form.FQDN, email, nodeIP)
	if err != nil {
		return err
	}
	form.FQDN = updatedDomain
	return nil
}

func promptConfigureNodeFQDN(form *configureNodeForm, description string) error {
	err := huh.NewForm(
		huh.NewGroup(
			huh.NewInput().
				Title("Node FQDN").
				Description(description).
				Value(&form.FQDN).
				Validate(requiredNonEmpty("node FQDN")),
		),
	).Run()
	if err != nil {
		if err == huh.ErrUserAborted {
			return fmt.Errorf("configure cancelled")
		}
		return err
	}
	form.FQDN = strings.TrimSpace(form.FQDN)
	return nil
}

func renderConfigurePanelInfoBanner(panelBaseURL string, info *config.PanelSystemInfo) string {
	if info == nil {
		return lipConfigureFrame().Width(72).Render(
			lipConfigureMuted().Render("Connected to FeatherPanel"),
		)
	}

	version := strings.TrimSpace(info.CoreVersion)
	if version == "" {
		version = strings.TrimSpace(info.AppVersion)
	}
	if version == "" {
		version = "unknown"
	}

	lines := []string{
		lipConfigureTeal().Bold(true).Render(info.AppName),
		"",
		fmt.Sprintf("%s %s", lipConfigureMuted().Render("version"), lipConfigureInk().Render(version)),
		fmt.Sprintf("%s %s", lipConfigureMuted().Render("panel"), lipConfigureInk().Render(panelBaseURL)),
	}
	if info.Hostname != "" {
		lines = append(lines, fmt.Sprintf("%s %s", lipConfigureMuted().Render("panel host"), lipConfigureInk().Render(info.Hostname)))
	}

	return lipConfigureFrame().Width(72).Render(strings.Join(lines, "\n"))
}

func renderConfigureNodeDefaultSummary(form configureNodeForm) string {
	lines := []string{
		fmt.Sprintf("%s %s", lipConfigureMuted().Render("detected memory"), lipConfigureInk().Render(fmt.Sprintf("%d MiB", form.MemoryMiB))),
		fmt.Sprintf("%s %s", lipConfigureMuted().Render("detected disk"), lipConfigureInk().Render(fmt.Sprintf("%d MiB", form.DiskMiB))),
		fmt.Sprintf("%s %s:%d", lipConfigureMuted().Render("daemon api"), lipConfigureInk().Render(form.Scheme), form.DaemonListen),
		fmt.Sprintf("%s %s", lipConfigureMuted().Render("sftp"), lipConfigureInk().Render(strconv.Itoa(form.DaemonSFTP))),
	}
	if form.PublicIPv4 != "" {
		lines = append(lines, fmt.Sprintf("%s %s", lipConfigureMuted().Render("node IP"), lipConfigureInk().Render(form.PublicIPv4)))
	}
	if form.FQDN != "" {
		lines = append(lines, fmt.Sprintf("%s %s", lipConfigureMuted().Render("fqdn"), lipConfigureInk().Render(form.FQDN)))
	}
	if form.DaemonBase != "" {
		lines = append(lines, fmt.Sprintf("%s %s", lipConfigureMuted().Render("data dir"), lipConfigureInk().Render(form.DaemonBase)))
	}
	return strings.Join(lines, "\n")
}

func requiredNonEmpty(label string) func(string) error {
	return func(value string) error {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%s is required", label)
		}
		return nil
	}
}

func positiveInteger(label string) func(string) error {
	return func(value string) error {
		n, err := strconv.Atoi(strings.TrimSpace(value))
		if err != nil || n <= 0 {
			return fmt.Errorf("%s must be a positive number", label)
		}
		return nil
	}
}

func nonNegativeInteger(label string) func(string) error {
	return func(value string) error {
		n, err := strconv.Atoi(strings.TrimSpace(value))
		if err != nil || n < 0 {
			return fmt.Errorf("%s must be zero or greater", label)
		}
		return nil
	}
}

func portNumber(label string) func(string) error {
	return func(value string) error {
		n, err := strconv.Atoi(strings.TrimSpace(value))
		if err != nil || n < 1 || n > 65535 {
			return fmt.Errorf("%s must be between 1 and 65535", label)
		}
		return nil
	}
}

func mustAtoi(value string) int {
	n, _ := strconv.Atoi(strings.TrimSpace(value))
	return n
}
