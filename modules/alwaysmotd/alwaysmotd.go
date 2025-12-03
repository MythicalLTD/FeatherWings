package alwaysmotd

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"image"
	_ "image/gif"
	_ "image/jpeg"
	"image/png"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"emperror.dev/errors"
	"github.com/apex/log"
	"golang.org/x/sync/semaphore"

	"github.com/mythicalltd/featherwings/environment"
	"github.com/mythicalltd/featherwings/modules"
	wserver "github.com/mythicalltd/featherwings/server"
)

// AlwaysMOTD is the main module implementation
type AlwaysMOTD struct {
	mu            sync.RWMutex
	enabled       bool
	config        *Config
	ctx           context.Context
	cancel        context.CancelFunc
	wg            sync.WaitGroup
	serverManager *wserver.Manager

	// Server tracking
	serverStatus       map[int]*ServerStatus
	redirectedPorts    map[int]int // TCP redirects: port -> motdPort
	redirectedUDPPorts map[int]int // UDP redirects: port -> bedrockMotdPort
	motdServers        map[string]*MotdServer
	bedrockMotdServers map[string]*BedrockMotdServer

	// Logger
	logger *log.Entry
}

// ServerStatus tracks the status of a server port
type ServerStatus struct {
	State       string
	LastChecked time.Time
	LastChanged time.Time
}

// Ensure AlwaysMOTD implements Module interface
var _ modules.Module = (*AlwaysMOTD)(nil)

// New creates a new AlwaysMOTD module instance
func New() *AlwaysMOTD {
	return &AlwaysMOTD{
		config:             DefaultConfig(),
		serverStatus:       make(map[int]*ServerStatus),
		redirectedPorts:    make(map[int]int),
		redirectedUDPPorts: make(map[int]int),
		motdServers:        make(map[string]*MotdServer),
		bedrockMotdServers: make(map[string]*BedrockMotdServer),
		logger:             log.WithField("module", "AlwaysMOTD"),
	}
}

// Name returns the module name
func (a *AlwaysMOTD) Name() string {
	return "AlwaysMOTD"
}

// Description returns the module description
func (a *AlwaysMOTD) Description() string {
	return "Provides custom MOTD for Minecraft servers based on their state (offline, suspended, installing, starting)"
}

// Enabled returns whether the module is enabled
func (a *AlwaysMOTD) Enabled() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.enabled
}

// GetConfig returns the current configuration
func (a *AlwaysMOTD) GetConfig() interface{} {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.config
}

// SetConfig updates the module configuration
// If the module is enabled, it will reload to apply the new configuration
func (a *AlwaysMOTD) SetConfig(config interface{}) error {
	a.mu.Lock()
	wasEnabled := a.enabled
	a.mu.Unlock()

	var cfg *Config
	var ok bool

	cfg, ok = config.(*Config)
	if !ok {
		// Try to convert from map via JSON
		cfgBytes, err := json.Marshal(config)
		if err != nil {
			return errors.Wrap(err, "failed to marshal config")
		}
		cfg = &Config{} // Initialize the pointer
		if err := json.Unmarshal(cfgBytes, cfg); err != nil {
			return errors.Wrap(err, "failed to unmarshal config")
		}
	}

	if err := a.ValidateConfig(cfg); err != nil {
		return err
	}

	a.mu.Lock()
	a.config = cfg
	a.mu.Unlock()

	// If module is enabled, reload it to apply the new configuration
	if wasEnabled {
		if err := a.reload(); err != nil {
			return errors.Wrap(err, "failed to reload module with new configuration")
		}
	}

	return nil
}

// reload restarts the module with the current configuration
// This is called when config is updated while the module is enabled
func (a *AlwaysMOTD) reload() error {
	a.mu.RLock()
	if !a.enabled {
		a.mu.RUnlock()
		return nil // Nothing to reload
	}
	serverManager := a.serverManager
	parentCtx := context.Background() // Use background context for reload
	a.mu.RUnlock()

	// Disable first (this will cancel the old context)
	if err := a.Disable(parentCtx); err != nil {
		return errors.Wrap(err, "failed to disable module for reload")
	}

	// Re-enable with new config
	// Create a new context with server manager
	newCtx := context.WithValue(parentCtx, "server_manager", serverManager)
	if err := a.Enable(newCtx); err != nil {
		return errors.Wrap(err, "failed to re-enable module after reload")
	}

	a.logger.Info("module configuration reloaded successfully")
	return nil
}

// ValidateConfig validates the configuration
func (a *AlwaysMOTD) ValidateConfig(config interface{}) error {
	var cfg *Config
	var ok bool

	cfg, ok = config.(*Config)
	if !ok {
		cfgBytes, err := json.Marshal(config)
		if err != nil {
			return errors.Wrap(err, "failed to marshal config")
		}
		cfg = &Config{} // Initialize the pointer
		if err := json.Unmarshal(cfgBytes, cfg); err != nil {
			return errors.Wrap(err, "failed to unmarshal config")
		}
	}

	if cfg.PortRange.Start == 0 || cfg.PortRange.End == 0 {
		return errors.New("portRange.start and portRange.end are required")
	}
	if cfg.Motd.Port == 0 {
		return errors.New("motd.port is required")
	}

	requiredStates := []string{"offline", "suspended", "installing", "starting"}
	for _, state := range requiredStates {
		if cfg.Motd.States[state] == nil {
			return fmt.Errorf("missing MOTD state: %s", state)
		}
	}

	return nil
}

// Enable starts the module
func (a *AlwaysMOTD) Enable(ctx context.Context) error {
	a.mu.Lock()
	if a.enabled {
		a.mu.Unlock()
		return errors.New("module is already enabled")
	}

	if err := a.ValidateConfig(a.config); err != nil {
		a.mu.Unlock()
		return errors.Wrap(err, "invalid configuration")
	}

	// Get server manager from context
	serverManager, ok := ctx.Value("server_manager").(*wserver.Manager)
	if !ok {
		a.mu.Unlock()
		return errors.New("server manager not found in context")
	}

	a.serverManager = serverManager
	a.ctx, a.cancel = context.WithCancel(ctx)
	a.enabled = true
	a.mu.Unlock() // Release lock early - initialization can happen without lock

	// Initialize MOTD servers (without lock)
	if err := a.initializeMotdServers(); err != nil {
		a.mu.Lock()
		a.enabled = false
		a.mu.Unlock()
		return errors.Wrap(err, "failed to initialize MOTD servers")
	}

	// Cleanup iptables (without lock)
	if err := a.cleanupIptables(); err != nil {
		a.logger.WithError(err).Warn("failed to cleanup iptables")
	}

	// Initial status update - do this synchronously to set up redirects immediately
	// This ensures offline servers get MOTD right away
	if err := a.updateServerStatus(); err != nil {
		a.logger.WithError(err).Error("failed initial server status update")
		// Don't fail enable if initial update fails, but log it
	}

	// Start status monitoring (without lock)
	a.wg.Add(1)
	go a.monitorLoop()

	a.logger.Info("AlwaysMOTD module enabled")
	return nil
}

// Disable stops the module
func (a *AlwaysMOTD) Disable(ctx context.Context) error {
	a.mu.Lock()
	if !a.enabled {
		a.mu.Unlock()
		return errors.New("module is already disabled")
	}

	a.enabled = false
	if a.cancel != nil {
		a.cancel()
	}

	// Get references to servers before releasing lock
	servers := make(map[string]*MotdServer)
	for state, server := range a.motdServers {
		servers[state] = server
	}
	bedrockServers := make(map[string]*BedrockMotdServer)
	for state, server := range a.bedrockMotdServers {
		bedrockServers[state] = server
	}
	a.mu.Unlock() // Release lock early

	// Close Java Edition MOTD servers (without lock)
	for state, server := range servers {
		if err := server.Close(); err != nil {
			a.logger.WithError(err).WithField("state", state).Error("failed to close MOTD server")
		}
	}

	// Close Bedrock Edition MOTD servers (without lock)
	for state, server := range bedrockServers {
		if err := server.Close(); err != nil {
			a.logger.WithError(err).WithField("state", state).Error("failed to close Bedrock MOTD server")
		}
	}

	// Cleanup iptables (without lock)
	if err := a.cleanupIptables(); err != nil {
		a.logger.WithError(err).Warn("failed to cleanup iptables")
	}

	// Wait for goroutines to finish with timeout
	done := make(chan struct{})
	go func() {
		a.wg.Wait()
		close(done)
	}()

	// Use a timeout context for waiting
	waitCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	select {
	case <-done:
		// All goroutines finished
	case <-waitCtx.Done():
		// Timeout - log but don't fail
		a.logger.Warn("timeout waiting for module goroutines to finish, continuing with disable")
	}

	a.logger.Info("AlwaysMOTD module disabled")
	return nil
}

// initializeMotdServers creates MOTD servers for each state
func (a *AlwaysMOTD) initializeMotdServers() error {
	for state, stateConfig := range a.config.Motd.States {
		// Calculate port for this state: basePort + stateOffset
		// Example: offline=25560+0=25560, suspended=25560+1=25561, etc.
		port := a.config.Motd.Port + a.getStatePortOffset(state)

		// Java Edition server (TCP) - only if enabled
		if a.config.Motd.JavaEnabled {
			// Load favicon if enabled and URL is specified
			var javaFavicon string
			if a.config.Motd.Java.FaviconEnabled && a.config.Motd.Java.FaviconURL != "" {
				// Load favicon with timeout to avoid blocking initialization
				iconChan := make(chan string, 1)
				errChan := make(chan error, 1)
				go func() {
					icon, err := a.loadServerIcon(a.config.Motd.Java.FaviconURL)
					if err != nil {
						errChan <- err
					} else {
						iconChan <- icon
					}
				}()

				// Wait for icon with timeout (don't block initialization)
				select {
				case javaFavicon = <-iconChan:
					// Icon loaded successfully
				case err := <-errChan:
					a.logger.WithError(err).Warn("failed to load Java favicon, continuing without it")
				case <-time.After(3 * time.Second):
					a.logger.Warn("Java favicon loading timed out, continuing without it")
				}
			}
			server := NewMotdServer(port, stateConfig, &a.config.Motd.Java, javaFavicon)
			if err := server.Start(); err != nil {
				return errors.Wrapf(err, "failed to start MOTD server for state %s", state)
			}
			a.motdServers[state] = server
			a.logger.WithFields(log.Fields{
				"state":   state,
				"port":    port,
				"edition": "java",
			}).Info("MOTD server initialized")
		}

		// Bedrock Edition server (UDP) - only if enabled
		if a.config.Motd.BedrockEnabled {
			bedrockPort := port + 100
			bedrockServer := NewBedrockMotdServer(bedrockPort, stateConfig, &a.config.Motd.Bedrock)
			if err := bedrockServer.Start(); err != nil {
				// Log error but don't fail - Bedrock support is optional
				a.logger.WithError(err).WithFields(log.Fields{
					"state":   state,
					"port":    bedrockPort,
					"edition": "bedrock",
				}).Warn("failed to start Bedrock MOTD server, continuing without Bedrock support")
			} else {
				a.bedrockMotdServers[state] = bedrockServer
				a.logger.WithFields(log.Fields{
					"state":   state,
					"port":    bedrockPort,
					"edition": "bedrock",
				}).Info("Bedrock MOTD server initialized")
			}
		}
	}

	return nil
}

// loadServerIcon loads a server icon from either a URL or file path
// Returns base64 encoded PNG data URI or empty string on error
func (a *AlwaysMOTD) loadServerIcon(source string) (string, error) {
	var imageData []byte
	var err error

	// Check if it's a URL
	if strings.HasPrefix(source, "http://") || strings.HasPrefix(source, "https://") {
		// Fetch from URL
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		req, err := http.NewRequestWithContext(ctx, "GET", source, nil)
		if err != nil {
			return "", errors.Wrap(err, "failed to create request")
		}

		req.Header.Set("User-Agent", "FeatherWings/1.0")

		client := &http.Client{Timeout: 10 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			return "", errors.Wrap(err, "failed to fetch image from URL")
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return "", errors.Errorf("failed to fetch image: HTTP %d", resp.StatusCode)
		}

		imageData, err = io.ReadAll(resp.Body)
		if err != nil {
			return "", errors.Wrap(err, "failed to read image data")
		}
	} else {
		// Read from file system
		if _, err := os.Stat(source); err != nil {
			return "", errors.Wrap(err, "server icon file not found")
		}

		imageData, err = os.ReadFile(source)
		if err != nil {
			return "", errors.Wrap(err, "failed to read server icon file")
		}
	}

	// Decode image
	img, _, err := image.Decode(bytes.NewReader(imageData))
	if err != nil {
		return "", errors.Wrap(err, "failed to decode image")
	}

	// Resize to 64x64 if needed
	bounds := img.Bounds()
	width := bounds.Dx()
	height := bounds.Dy()

	if width != 64 || height != 64 {
		a.logger.WithFields(log.Fields{
			"width":  width,
			"height": height,
		}).Info("resizing server icon to 64x64")

		// Create a new 64x64 RGBA image
		resized := image.NewRGBA(image.Rect(0, 0, 64, 64))

		// Simple nearest-neighbor scaling
		xRatio := float64(width) / 64.0
		yRatio := float64(height) / 64.0

		for y := 0; y < 64; y++ {
			for x := 0; x < 64; x++ {
				srcX := int(float64(x) * xRatio)
				srcY := int(float64(y) * yRatio)
				if srcX >= width {
					srcX = width - 1
				}
				if srcY >= height {
					srcY = height - 1
				}
				resized.Set(x, y, img.At(bounds.Min.X+srcX, bounds.Min.Y+srcY))
			}
		}

		img = resized
	}

	// Encode as PNG
	var pngData bytes.Buffer
	if err := png.Encode(&pngData, img); err != nil {
		return "", errors.Wrap(err, "failed to encode image as PNG")
	}

	// Encode as base64 data URI
	base64Data := base64.StdEncoding.EncodeToString(pngData.Bytes())
	return "data:image/png;base64," + base64Data, nil
}

// getStatePortOffset returns the port offset for a state
func (a *AlwaysMOTD) getStatePortOffset(state string) int {
	offsets := map[string]int{
		"offline":    0,
		"suspended":  1,
		"installing": 2,
		"starting":   3,
	}
	return offsets[state]
}

// monitorLoop runs the periodic status check
func (a *AlwaysMOTD) monitorLoop() {
	defer a.wg.Done()

	ticker := time.NewTicker(time.Duration(a.config.Monitoring.CheckInterval) * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-a.ctx.Done():
			return
		case <-ticker.C:
			if err := a.updateServerStatus(); err != nil {
				a.logger.WithError(err).Error("failed to update server status")
			}
		}
	}
}

// updateServerStatus checks and updates the status of all servers
func (a *AlwaysMOTD) updateServerStatus() error {
	if a.serverManager == nil {
		return errors.New("server manager not available")
	}

	servers := a.serverManager.All()
	now := time.Now()
	sem := semaphore.NewWeighted(int64(10)) // maxConcurrentRequests
	var wg sync.WaitGroup

	// Process all ports from all servers
	portsToCheck := make(map[int]string) // port -> server UUID

	for _, server := range servers {
		cfg := server.Config()
		allocations := cfg.Allocations

		// Check default allocation
		if allocations.DefaultMapping != nil {
			port := allocations.DefaultMapping.Port
			if port >= a.config.PortRange.Start && port <= a.config.PortRange.End {
				portsToCheck[port] = server.ID()
			}
		}

		// Check all mappings
		for _, ports := range allocations.Mappings {
			for _, port := range ports {
				if port >= a.config.PortRange.Start && port <= a.config.PortRange.End {
					portsToCheck[port] = server.ID()
				}
			}
		}
	}

	for port, serverID := range portsToCheck {
		wg.Add(1)
		go func(p int, sid string) {
			defer wg.Done()
			if err := sem.Acquire(a.ctx, 1); err != nil {
				return
			}
			defer sem.Release(1)

			a.processPortStatus(p, sid, now)
		}(port, serverID)
	}

	wg.Wait()
	return nil
}

// detectServerState detects the current state of a server
func (a *AlwaysMOTD) detectServerState(serverID string) string {
	if a.serverManager == nil {
		return "offline"
	}

	server, exists := a.serverManager.Get(serverID)
	if !exists {
		return "offline"
	}

	// Use read lock to safely access server config
	cfg := server.Config()

	// Check if suspended
	if cfg.Suspended {
		return "suspended"
	}

	// Check if installing
	if server.IsInstalling() {
		return "installing"
	}

	// Check environment state (this should be fast, just reading a value)
	state := server.Environment.State()
	switch state {
	case environment.ProcessRunningState:
		return "running"
	case environment.ProcessStartingState:
		return "starting"
	case environment.ProcessOfflineState:
		return "offline"
	default:
		return "offline"
	}
}

// processPortStatus processes the status for a single port
func (a *AlwaysMOTD) processPortStatus(port int, serverID string, now time.Time) {
	a.mu.Lock()
	prevStatus := a.serverStatus[port]
	a.mu.Unlock()

	isStale := prevStatus != nil && now.Sub(prevStatus.LastChecked) > time.Duration(a.config.Monitoring.CheckInterval*2)*time.Millisecond

	if prevStatus != nil && prevStatus.State == "running" && !isStale {
		return
	}

	state := a.detectServerState(serverID)
	prevState := ""
	if prevStatus != nil {
		prevState = prevStatus.State
	}

	a.mu.Lock()
	a.serverStatus[port] = &ServerStatus{
		State:       state,
		LastChecked: now,
		LastChanged: now,
	}
	if prevStatus != nil && prevStatus.State == state {
		a.serverStatus[port].LastChanged = prevStatus.LastChanged
	}
	a.mu.Unlock()

	if prevState == "" {
		a.logger.WithFields(log.Fields{
			"port":  port,
			"state": state,
		}).Debug("port status detected")
		if state != "running" {
			if a.config.Motd.JavaEnabled {
				a.redirectPortToMotd(port, state)
			}
			// Bind Bedrock server directly to server port (more reliable than UDP redirects).
			// We intentionally do NOT use UDP iptables redirects for Bedrock, as RakNet status
			// pings are sensitive to NAT and may result in clients showing \"locating server\".
			if a.config.Motd.BedrockEnabled {
				a.bindBedrockToServerPort(port, state)
			}
		}
	} else if state != prevState {
		a.logger.WithFields(log.Fields{
			"port":      port,
			"prevState": prevState,
			"state":     state,
		}).Info("port state changed")
		if state == "running" {
			// Run in background to avoid blocking
			if a.config.Motd.JavaEnabled {
				go a.removeRedirect(port)
			}
			if a.config.Motd.BedrockEnabled {
				// For Bedrock we only bind directly to the server port, no UDP iptables redirects.
				go a.unbindBedrockFromServerPort(port)
			}
		} else {
			// Run in background to avoid blocking
			go func() {
				if a.config.Motd.JavaEnabled {
					a.removeRedirect(port)
					a.redirectPortToMotd(port, state)
				}
				if a.config.Motd.BedrockEnabled {
					// Rebind Bedrock MOTD server directly to server port for the new state.
					a.unbindBedrockFromServerPort(port)
					a.bindBedrockToServerPort(port, state)
				}
			}()
		}
	}
}

// executeIptables executes an iptables command
func (a *AlwaysMOTD) executeIptables(command string) error {
	// Use background context with timeout to avoid cancellation issues
	// Don't use a.ctx here as it might be cancelled
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "sh", "-c", command)
	cmd.Stdout = nil
	cmd.Stderr = nil

	err := cmd.Run()
	if err != nil {
		// Check context errors first
		if ctx.Err() == context.DeadlineExceeded {
			return errors.Wrap(err, "iptables command timed out after 10 seconds")
		}
		if ctx.Err() == context.Canceled {
			return errors.Wrap(err, "iptables command was cancelled")
		}

		// Check if process was killed (signal: killed)
		if exitError, ok := err.(*exec.ExitError); ok {
			if exitError.ProcessState != nil {
				// Check if process was killed by signal
				if !exitError.ProcessState.Exited() {
					return errors.Wrap(err, "iptables command was killed (likely permission issue or system limit)")
				}
				// Process exited with non-zero status
				return errors.Wrapf(err, "iptables command failed (exit code: %d)", exitError.ExitCode())
			}
		}

		// Generic error
		return errors.Wrap(err, "iptables command failed")
	}
	return nil
}

// redirectPortToMotd redirects a port to the appropriate MOTD server
func (a *AlwaysMOTD) redirectPortToMotd(port int, state string) {
	motdPort := a.config.Motd.Port + a.getStatePortOffset(state)

	a.mu.Lock()
	currentRedirect := a.redirectedPorts[port]
	a.mu.Unlock()

	if currentRedirect == motdPort {
		return
	}

	// First remove any existing redirect for this port
	if currentRedirect != 0 {
		removeCmd := fmt.Sprintf("iptables -t nat -D PREROUTING -p tcp --dport %d -j REDIRECT --to-port %d 2>/dev/null || true", port, currentRedirect)
		_ = a.executeIptables(removeCmd) // Ignore errors, rule might not exist
	}

	// Add new redirect rule (use -I to insert at beginning, or check if exists first)
	// Try to add rule, ignore if it already exists
	command := fmt.Sprintf("iptables -t nat -C PREROUTING -p tcp --dport %d -j REDIRECT --to-port %d 2>/dev/null || iptables -t nat -A PREROUTING -p tcp --dport %d -j REDIRECT --to-port %d", port, motdPort, port, motdPort)
	if err := a.executeIptables(command); err != nil {
		// Log but don't fail - iptables might not be available or might need different permissions
		// The module can still function without iptables redirects (MOTD servers will still work)
		a.logger.WithError(err).WithFields(log.Fields{
			"port":     port,
			"motdPort": motdPort,
			"state":    state,
		}).Warn("failed to redirect port via iptables (MOTD server is still running, but port redirect may not work)")
		// Don't return - still mark as redirected in our tracking
		// This allows the module to continue functioning even if iptables fails
	}

	a.mu.Lock()
	a.redirectedPorts[port] = motdPort
	a.mu.Unlock()

	a.logger.WithFields(log.Fields{
		"port":     port,
		"motdPort": motdPort,
		"state":    state,
	}).Debug("port redirected")
}

// removeRedirect removes a port redirect
func (a *AlwaysMOTD) removeRedirect(port int) {
	a.mu.Lock()
	currentRedirect := a.redirectedPorts[port]
	a.mu.Unlock()

	if currentRedirect == 0 {
		return
	}

	// Try to remove, but don't fail if rule doesn't exist
	command := fmt.Sprintf("iptables -t nat -D PREROUTING -p tcp --dport %d -j REDIRECT --to-port %d 2>/dev/null || true", port, currentRedirect)
	if err := a.executeIptables(command); err != nil {
		// Log but continue - rule might not exist or iptables might not be available
		a.logger.WithError(err).WithFields(log.Fields{
			"port": port,
		}).Debug("failed to remove redirect (rule may not exist)")
	}

	a.mu.Lock()
	delete(a.redirectedPorts, port)
	a.mu.Unlock()

	a.logger.WithField("port", port).Debug("redirect removed")
}

// redirectUDPPortToMotd redirects a UDP port to the appropriate Bedrock MOTD server
func (a *AlwaysMOTD) redirectUDPPortToMotd(port int, state string) {
	bedrockMotdPort := a.config.Motd.Port + a.getStatePortOffset(state) + 100

	a.mu.Lock()
	currentRedirect := a.redirectedUDPPorts[port]
	a.mu.Unlock()

	if currentRedirect == bedrockMotdPort {
		return
	}

	// First remove any existing redirect for this port
	if currentRedirect != 0 {
		// Try both REDIRECT and DNAT in case either was used
		removeCmd1 := fmt.Sprintf("iptables -t nat -D PREROUTING -p udp --dport %d -j REDIRECT --to-port %d 2>/dev/null || true", port, currentRedirect)
		removeCmd2 := fmt.Sprintf("iptables -t nat -D PREROUTING -p udp --dport %d -j DNAT --to-destination 127.0.0.1:%d 2>/dev/null || true", port, currentRedirect)
		_ = a.executeIptables(removeCmd1)
		_ = a.executeIptables(removeCmd2)
	}

	// Use REDIRECT for UDP (simpler and handles source port automatically)
	// REDIRECT automatically rewrites the source port in responses
	redirectCmd := fmt.Sprintf("iptables -t nat -C PREROUTING -p udp --dport %d -j REDIRECT --to-port %d 2>/dev/null || iptables -t nat -A PREROUTING -p udp --dport %d -j REDIRECT --to-port %d", port, bedrockMotdPort, port, bedrockMotdPort)
	if err := a.executeIptables(redirectCmd); err != nil {
		a.logger.WithError(err).WithFields(log.Fields{
			"port":            port,
			"bedrockMotdPort": bedrockMotdPort,
			"state":           state,
		}).Warn("failed to redirect UDP port via iptables (Bedrock MOTD server is still running, but port redirect may not work)")
	}

	a.mu.Lock()
	a.redirectedUDPPorts[port] = bedrockMotdPort
	a.mu.Unlock()

	a.logger.WithFields(log.Fields{
		"port":            port,
		"bedrockMotdPort": bedrockMotdPort,
		"state":           state,
		"protocol":        "udp",
	}).Debug("UDP port redirected")

	// Set server port mapping in Bedrock MOTD server so it knows which server port to use in server info
	a.mu.RLock()
	bedrockServer, exists := a.bedrockMotdServers[state]
	a.mu.RUnlock()
	if exists {
		bedrockServer.SetServerPortMapping(bedrockMotdPort, port)
	}
}

// removeUDPRedirect removes a UDP port redirect
func (a *AlwaysMOTD) removeUDPRedirect(port int) {
	a.mu.Lock()
	currentRedirect := a.redirectedUDPPorts[port]
	a.mu.Unlock()

	if currentRedirect == 0 {
		return
	}

	// Try to remove, but don't fail if rule doesn't exist
	// Try both REDIRECT and DNAT in case either was used
	command1 := fmt.Sprintf("iptables -t nat -D PREROUTING -p udp --dport %d -j REDIRECT --to-port %d 2>/dev/null || true", port, currentRedirect)
	command2 := fmt.Sprintf("iptables -t nat -D PREROUTING -p udp --dport %d -j DNAT --to-destination 127.0.0.1:%d 2>/dev/null || true", port, currentRedirect)
	command3 := fmt.Sprintf("iptables -t nat -D OUTPUT -p udp --dport %d -j DNAT --to-destination 127.0.0.1:%d 2>/dev/null || true", port, currentRedirect)
	_ = a.executeIptables(command1)
	_ = a.executeIptables(command2)
	_ = a.executeIptables(command3)
	command := command1 // Use REDIRECT as primary
	if err := a.executeIptables(command); err != nil {
		// Log but continue - rule might not exist or iptables might not be available
		a.logger.WithError(err).WithFields(log.Fields{
			"port":     port,
			"protocol": "udp",
		}).Debug("failed to remove UDP redirect (rule may not exist)")
	}

	a.mu.Lock()
	delete(a.redirectedUDPPorts, port)
	a.mu.Unlock()

	a.logger.WithFields(log.Fields{
		"port":     port,
		"protocol": "udp",
	}).Debug("UDP redirect removed")
}

// bindBedrockToServerPort binds Bedrock MOTD server directly to server port when offline
// This is more reliable than UDP redirects
func (a *AlwaysMOTD) bindBedrockToServerPort(port int, state string) {
	a.mu.RLock()
	bedrockServer, exists := a.bedrockMotdServers[state]
	a.mu.RUnlock()

	if !exists {
		return
	}

	if err := bedrockServer.BindToPort(port, state); err != nil {
		a.logger.WithError(err).WithFields(log.Fields{
			"port":  port,
			"state": state,
		}).Debug("failed to bind Bedrock server to port (port may be in use)")
	} else {
		a.logger.WithFields(log.Fields{
			"port":  port,
			"state": state,
		}).Debug("Bedrock server bound to server port")
	}
}

// unbindBedrockFromServerPort unbinds Bedrock MOTD server from server port
func (a *AlwaysMOTD) unbindBedrockFromServerPort(port int) {
	a.mu.RLock()
	servers := make([]*BedrockMotdServer, 0, len(a.bedrockMotdServers))
	for _, server := range a.bedrockMotdServers {
		servers = append(servers, server)
	}
	a.mu.RUnlock()

	for _, server := range servers {
		server.UnbindFromPort(port)
	}
}

// cleanupIptables removes all iptables redirects (both TCP and UDP)
func (a *AlwaysMOTD) cleanupIptables() error {
	// Flush all PREROUTING rules (this removes both TCP and UDP redirects)
	command := "iptables -t nat -F PREROUTING"
	if err := a.executeIptables(command); err != nil {
		return errors.Wrap(err, "failed to cleanup iptables")
	}

	a.mu.Lock()
	a.redirectedPorts = make(map[int]int)
	a.redirectedUDPPorts = make(map[int]int)
	a.mu.Unlock()

	return nil
}
