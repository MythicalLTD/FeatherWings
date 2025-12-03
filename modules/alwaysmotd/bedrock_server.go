package alwaysmotd

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"emperror.dev/errors"
	"github.com/apex/log"
	"github.com/sandertv/gophertunnel/minecraft"
	"github.com/sandertv/gophertunnel/minecraft/protocol/packet"
)

// BedrockMotdServer handles Bedrock Edition (Pocket Edition) server list queries
// Uses gophertunnel library for RakNet protocol handling
type BedrockMotdServer struct {
	port          int
	config        *StateConfig
	bedrockConfig *BedrockConfig
	listener      *minecraft.Listener
	boundPorts    map[int]*minecraft.Listener // Track listeners bound to server ports
	boundPortsMu  sync.RWMutex
	serverPorts   map[int]int // Track which server ports this MOTD server handles: bedrockMotdPort -> serverPort
	serverPortsMu sync.RWMutex
	ctx           context.Context
	cancel        context.CancelFunc
	wg            sync.WaitGroup
	logger        *log.Entry
}

// NewBedrockMotdServer creates a new Bedrock MOTD server instance
func NewBedrockMotdServer(port int, config *StateConfig, bedrockConfig *BedrockConfig) *BedrockMotdServer {
	ctx, cancel := context.WithCancel(context.Background())
	return &BedrockMotdServer{
		port:          port,
		config:        config,
		bedrockConfig: bedrockConfig,
		ctx:           ctx,
		cancel:        cancel,
		boundPorts:    make(map[int]*minecraft.Listener),
		serverPorts:   make(map[int]int),
		logger:        log.WithField("port", port).WithField("edition", "bedrock"),
	}
}

// SetServerPortMapping sets the mapping from Bedrock MOTD port to server port
// This is needed when using redirects to know which server port a packet is for
func (s *BedrockMotdServer) SetServerPortMapping(bedrockMotdPort int, serverPort int) {
	s.serverPortsMu.Lock()
	defer s.serverPortsMu.Unlock()
	s.serverPorts[bedrockMotdPort] = serverPort
}

// Start starts the Bedrock MOTD server using gophertunnel
func (s *BedrockMotdServer) Start() error {
	// Extract server name from description/MOTD
	serverName := s.extractDescriptionText()
	if serverName == "" {
		// As a last resort, fall back to a generic name
		serverName = "FeatherPanel"
	}

	// Create listener using gophertunnel
	maxPlayers := int(s.config.MaxPlayers)
	if maxPlayers == 0 {
		maxPlayers = 1
	}
	listener, err := minecraft.ListenConfig{
		MaximumPlayers:         maxPlayers,
		StatusProvider:         minecraft.NewStatusProvider(serverName, fmt.Sprintf("%d", maxPlayers)),
		AuthenticationDisabled: true, // Allow offline connections so we can show a disconnect screen
	}.Listen("raknet", fmt.Sprintf(":%d", s.port))
	if err != nil {
		return errors.Wrapf(err, "failed to start Bedrock MOTD server on port %d", s.port)
	}

	s.listener = listener
	s.logger.Info("Bedrock MOTD server started")

	// Update status provider with current config
	s.updateStatusProvider()

	s.wg.Add(1)
	go s.handleConnections()

	return nil
}

// updateStatusProvider updates the listener's status provider with current config
func (s *BedrockMotdServer) updateStatusProvider() {
	if s.listener == nil {
		return
	}

	serverName := s.extractDescriptionText()
	if serverName == "" {
		serverName = s.config.Version
		if serverName == "" {
			serverName = "FeatherPanel"
		}
	}

	// The listener's status provider is set at creation, but we can update it
	// by recreating the listener if needed, or we handle it in connection handler
}

// handleConnections handles incoming connections
func (s *BedrockMotdServer) handleConnections() {
	defer s.wg.Done()

	for {
		select {
		case <-s.ctx.Done():
			return
		default:
			// Set accept deadline to allow checking context
			conn, err := s.listener.Accept()
			if err != nil {
				select {
				case <-s.ctx.Done():
					return
				default:
					s.logger.WithError(err).Debug("failed to accept Bedrock connection")
					time.Sleep(100 * time.Millisecond)
					continue
				}
			}

			// Handle connection in goroutine
			s.wg.Add(1)
			go s.handleConnection(conn.(*minecraft.Conn), s.port)
		}
	}
}

// handleConnection handles a single Bedrock connection
func (s *BedrockMotdServer) handleConnection(conn *minecraft.Conn, serverPort int) {
	defer s.wg.Done()
	defer conn.Close()

	// Determine actual server port
	actualServerPort := s.getServerPort(serverPort)

	// Wait for client to fully connect before sending disconnect
	// Use configurable wait time
	waitTime := 100 * time.Millisecond // Default
	if s.bedrockConfig != nil {
		waitTime = time.Duration(s.bedrockConfig.ConnectionWaitTime) * time.Millisecond
		if waitTime == 0 {
			waitTime = 100 * time.Millisecond
		}
	}
	time.Sleep(waitTime)

	// Server is offline - send disconnect message with disconnect screen shown
	disconnectMsg := s.getDisconnectMessage()

	// Log the message being sent for debugging
	s.logger.WithFields(log.Fields{
		"clientAddr":  conn.RemoteAddr().String(),
		"serverPort":  actualServerPort,
		"displayName": conn.IdentityData().DisplayName,
		"message":     disconnectMsg,
		"messageLen":  len(disconnectMsg),
	}).Debug("Preparing to send Bedrock disconnect message")

	err := conn.WritePacket(&packet.Disconnect{
		HideDisconnectionScreen: false, // Show disconnect screen with our custom message
		Message:                 disconnectMsg,
	})
	if err != nil {
		s.logger.WithError(err).WithFields(log.Fields{
			"clientAddr": conn.RemoteAddr().String(),
			"serverPort": actualServerPort,
			"message":    disconnectMsg,
		}).Warn("failed to send disconnect packet")
		return
	}

	// Wait a bit to ensure the packet is sent and processed before closing
	// Use configurable wait time
	disconnectWaitTime := 400 * time.Millisecond // Default - increased for better reliability
	if s.bedrockConfig != nil {
		disconnectWaitTime = time.Duration(s.bedrockConfig.DisconnectWaitTime) * time.Millisecond
		if disconnectWaitTime == 0 {
			disconnectWaitTime = 400 * time.Millisecond
		}
	}
	time.Sleep(disconnectWaitTime)

	s.logger.WithFields(log.Fields{
		"clientAddr":  conn.RemoteAddr().String(),
		"serverPort":  actualServerPort,
		"displayName": conn.IdentityData().DisplayName,
	}).Debug("Bedrock disconnect sent, closing connection")
}

// getServerPort determines the actual server port from the MOTD port
func (s *BedrockMotdServer) getServerPort(motdPort int) int {
	s.serverPortsMu.RLock()
	defer s.serverPortsMu.RUnlock()

	if serverPort, exists := s.serverPorts[motdPort]; exists {
		return serverPort
	}

	// If not found, check if motdPort is itself a server port (bound directly)
	s.boundPortsMu.RLock()
	if _, isBound := s.boundPorts[motdPort]; isBound {
		s.boundPortsMu.RUnlock()
		return motdPort
	}
	s.boundPortsMu.RUnlock()

	// Fallback to MOTD port
	return motdPort
}

// getDisconnectMessage gets the disconnect message from config and formats it for Bedrock
// Extracts text from descriptions and applies formatting based on config
func (s *BedrockMotdServer) getDisconnectMessage() string {
	var rawMessage string

	// Check for Bedrock-specific description first
	if s.config.BedrockDescription != nil {
		rawMessage = s.extractPlainText(s.config.BedrockDescription)
	}

	// Fall back to regular description if no Bedrock-specific one
	if rawMessage == "" {
		rawMessage = s.extractPlainText(s.config.Description)
	}

	if rawMessage == "" {
		rawMessage = "Server is offline"
	}

	// Trim whitespace but preserve internal formatting
	rawMessage = strings.TrimSpace(rawMessage)

	// Format based on config
	format := "large"
	prefix := "\n\n"
	suffix := "\n\n"
	if s.bedrockConfig != nil {
		format = s.bedrockConfig.DisconnectMessageFormat
		if format == "" {
			format = "large"
		}
		if s.bedrockConfig.DisconnectMessagePrefix != "" {
			prefix = s.bedrockConfig.DisconnectMessagePrefix
		}
		if s.bedrockConfig.DisconnectMessageSuffix != "" {
			suffix = s.bedrockConfig.DisconnectMessageSuffix
		}
	}

	// Check if message already has color codes - if so, don't double-format
	hasColorCodes := strings.Contains(rawMessage, "§") || strings.Contains(rawMessage, "\u00A7")

	var formatted string
	if hasColorCodes {
		// Message already has formatting, just add prefix/suffix
		formatted = fmt.Sprintf("%s%s%s", prefix, rawMessage, suffix)
	} else {
		// Message has no formatting, apply based on format type
		switch format {
		case "bold":
			// Make it bold and red
			formatted = fmt.Sprintf("%s§l§c%s§r%s", prefix, rawMessage, suffix)
		case "large":
			// Make it bold, red, and add spacing for visibility
			formatted = fmt.Sprintf("%s§l§c%s§r%s", prefix, rawMessage, suffix)
			// Add extra newlines for "large" format if using defaults
			if prefix == "\n\n" && s.bedrockConfig != nil && s.bedrockConfig.DisconnectMessagePrefix == "" {
				formatted = "\n\n" + formatted
			}
			if suffix == "\n\n" && s.bedrockConfig != nil && s.bedrockConfig.DisconnectMessageSuffix == "" {
				formatted = formatted + "\n\n"
			}
		case "normal":
			// Just use the message as-is with prefix/suffix
			formatted = fmt.Sprintf("%s%s%s", prefix, rawMessage, suffix)
		default:
			// Default to large
			formatted = fmt.Sprintf("\n\n§l§c%s§r\n\n", rawMessage)
		}
	}

	return formatted
}

// extractPlainText extracts text from description (string or JSON component)
// Preserves color codes for Bedrock (Bedrock supports them in disconnect messages)
func (s *BedrockMotdServer) extractPlainText(desc interface{}) string {
	switch v := desc.(type) {
	case string:
		// Preserve color codes - Bedrock supports them
		// Replace \n with actual newlines
		return strings.ReplaceAll(v, "\\n", "\n")
	case map[string]interface{}:
		// Extract from JSON component structure, preserving color codes
		var result strings.Builder

		// Check for "text" field
		if text, ok := v["text"].(string); ok && text != "" {
			result.WriteString(strings.ReplaceAll(text, "\\n", "\n"))
		}

		// Check for "extra" array
		if extra, ok := v["extra"].([]interface{}); ok {
			for _, item := range extra {
				if itemMap, ok := item.(map[string]interface{}); ok {
					if text, ok := itemMap["text"].(string); ok {
						result.WriteString(strings.ReplaceAll(text, "\\n", "\n"))
					}
				} else if text, ok := item.(string); ok {
					result.WriteString(strings.ReplaceAll(text, "\\n", "\n"))
				}
			}
		}

		return result.String()
	default:
		return ""
	}
}

// extractDescriptionText extracts a clean, single-line name for the Bedrock server list.
// It prefers BedrockDescription if present, otherwise falls back to the generic Description.
// Color codes and newlines are stripped so the list shows a readable title (e.g. "SERVER OFFLINE").
func (s *BedrockMotdServer) extractDescriptionText() string {
	// Prefer Bedrock-specific description if available
	var source interface{} = s.config.Description
	if s.config.BedrockDescription != nil {
		source = s.config.BedrockDescription
	}

	// Use extractPlainText to pull full text (including extras), then strip colors/newlines
	raw := s.extractPlainText(source)
	if raw == "" {
		return ""
	}

	// Strip color codes (§x) and collapse newlines to spaces for a clean list entry
	var result strings.Builder
	runes := []rune(raw)
	for i := 0; i < len(runes); i++ {
		if runes[i] == '§' && i+1 < len(runes) {
			i++ // skip code char
			continue
		}
		if runes[i] == '\n' || (i < len(runes)-1 && runes[i] == '\\' && runes[i+1] == 'n') {
			result.WriteRune(' ')
			if runes[i] == '\\' {
				i++ // skip 'n'
			}
			continue
		}
		result.WriteRune(runes[i])
	}
	name := strings.TrimSpace(result.String())

	// Use only the first "word" chunk to keep it short if it's very long
	if len(name) > 48 {
		name = name[:48]
	}

	return name
}

// BindToPort binds the Bedrock server to a specific server port (for when server is offline)
// This allows the server to respond directly from the server port without redirects
func (s *BedrockMotdServer) BindToPort(serverPort int, state string) error {
	s.boundPortsMu.Lock()
	defer s.boundPortsMu.Unlock()

	// Check if already bound
	if _, exists := s.boundPorts[serverPort]; exists {
		return nil // Already bound
	}

	// Extract server name from description/MOTD
	serverName := s.extractDescriptionText()
	if serverName == "" {
		// As a last resort, fall back to a generic name
		serverName = "FeatherPanel"
	}

	// Create listener bound to server port
	maxPlayers := int(s.config.MaxPlayers)
	if maxPlayers == 0 {
		maxPlayers = 1
	}
	listener, err := minecraft.ListenConfig{
		MaximumPlayers:         maxPlayers,
		StatusProvider:         minecraft.NewStatusProvider(serverName, fmt.Sprintf("%d", maxPlayers)),
		AuthenticationDisabled: true, // Allow offline connections so we can show a disconnect screen
	}.Listen("raknet", fmt.Sprintf(":%d", serverPort))
	if err != nil {
		// Port might be in use - log but don't fail
		s.logger.WithError(err).WithField("serverPort", serverPort).Debug("could not bind to server port (may be in use)")
		return nil // Don't fail - redirects will handle it
	}

	s.boundPorts[serverPort] = listener

	// Track which server port this bound port corresponds to
	s.serverPortsMu.Lock()
	s.serverPorts[serverPort] = serverPort // When bound to server port, serverPort maps to itself
	s.serverPortsMu.Unlock()

	s.logger.WithField("serverPort", serverPort).Info("Bedrock server bound to server port")

	// Start handling connections on this port
	s.wg.Add(1)
	go s.handleBoundConnections(listener, serverPort)

	return nil
}

// handleBoundConnections handles connections on a bound port
func (s *BedrockMotdServer) handleBoundConnections(listener *minecraft.Listener, serverPort int) {
	defer s.wg.Done()

	for {
		select {
		case <-s.ctx.Done():
			return
		default:
			conn, err := listener.Accept()
			if err != nil {
				select {
				case <-s.ctx.Done():
					return
				default:
					time.Sleep(100 * time.Millisecond)
					continue
				}
			}

			s.wg.Add(1)
			go s.handleConnection(conn.(*minecraft.Conn), serverPort)
		}
	}
}

// UnbindFromPort unbinds from a server port
func (s *BedrockMotdServer) UnbindFromPort(serverPort int) {
	s.boundPortsMu.Lock()
	defer s.boundPortsMu.Unlock()

	if listener, exists := s.boundPorts[serverPort]; exists {
		listener.Close()
		delete(s.boundPorts, serverPort)
		s.logger.WithField("serverPort", serverPort).Info("Bedrock server unbound from server port")
	}
}

// Close stops the Bedrock MOTD server
func (s *BedrockMotdServer) Close() error {
	s.cancel()

	// Close main listener
	if s.listener != nil {
		if err := s.listener.Close(); err != nil {
			return err
		}
	}

	// Close all bound port listeners
	s.boundPortsMu.Lock()
	for port, listener := range s.boundPorts {
		listener.Close()
		s.logger.WithField("port", port).Debug("closed bound port listener")
	}
	s.boundPorts = make(map[int]*minecraft.Listener)
	s.boundPortsMu.Unlock()

	s.wg.Wait()
	return nil
}
