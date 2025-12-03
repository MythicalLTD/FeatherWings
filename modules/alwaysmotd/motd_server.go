package alwaysmotd

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"

	"emperror.dev/errors"
	"github.com/apex/log"
)

// MotdServer handles Minecraft protocol connections and serves custom MOTD
type MotdServer struct {
	port    int
	config  *StateConfig
	favicon string
	server  net.Listener
	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	logger  *log.Entry
}

// NewMotdServer creates a new MOTD server instance
func NewMotdServer(port int, config *StateConfig, favicon string) *MotdServer {
	ctx, cancel := context.WithCancel(context.Background())
	return &MotdServer{
		port:    port,
		config:  config,
		favicon: favicon,
		ctx:     ctx,
		cancel:  cancel,
		logger:  log.WithField("port", port),
	}
}

// Start starts the MOTD server
func (s *MotdServer) Start() error {
	listener, err := net.Listen("tcp", net.JoinHostPort("0.0.0.0", fmt.Sprintf("%d", s.port)))
	if err != nil {
		return errors.Wrapf(err, "failed to listen on port %d", s.port)
	}

	s.server = listener
	s.logger.Info("MOTD server started")

	s.wg.Add(1)
	go s.acceptConnections()

	return nil
}

// acceptConnections accepts incoming connections
func (s *MotdServer) acceptConnections() {
	defer s.wg.Done()

	for {
		select {
		case <-s.ctx.Done():
			return
		default:
			conn, err := s.server.Accept()
			if err != nil {
				if !errors.Is(err, net.ErrClosed) {
					s.logger.WithError(err).Error("failed to accept connection")
				}
				return
			}

			s.wg.Add(1)
			go s.handleConnection(conn)
		}
	}
}

// handleConnection handles a single client connection
func (s *MotdServer) handleConnection(conn net.Conn) {
	defer s.wg.Done()
	defer conn.Close()

	var buffer []byte
	state := "handshake"

	for {
		select {
		case <-s.ctx.Done():
			return
		default:
			// Read data
			readBuf := make([]byte, 4096)
			n, err := conn.Read(readBuf)
			if err != nil {
				return
			}

			buffer = append(buffer, readBuf[:n]...)

			// Process packets
			for len(buffer) > 0 {
				length, lengthBytes, ok := readVarInt(buffer, 0)
				if !ok {
					return
				}

				packetLength := int(length)
				totalLength := lengthBytes + packetLength

				if len(buffer) < totalLength {
					break
				}

				// Save the full packet before slicing buffer
				fullPacket := make([]byte, totalLength)
				copy(fullPacket, buffer[:totalLength])

				packet := buffer[lengthBytes:totalLength]
				buffer = buffer[totalLength:]

				packetID, idBytes, ok := readVarInt(packet, 0)
				if !ok {
					continue
				}

				// Handle handshake
				if state == "handshake" && packetID == 0x00 {
					if len(packet) > idBytes {
						nextState := packet[len(packet)-1]
						if nextState == 1 {
							state = "status"
						} else {
							state = "login"
						}
					}
				} else if state == "status" && packetID == 0x00 {
					// Status request - send response immediately with status info
					s.sendStatusResponse(conn)
				} else if state == "status" && packetID == 0x01 {
					// Ping request - don't respond to make server show as unhealthy/trying to connect
					// Not responding to ping makes the client mark it as unhealthy
					// Close connection to indicate server is not actually available
					return
				} else if state == "login" && packetID == 0x00 {
					// Login attempt - send disconnect
					s.sendDisconnect(conn)
					return
				}
			}
		}
	}
}

// sendStatusResponse sends a status response to the client
func (s *MotdServer) sendStatusResponse(conn net.Conn) {
	// Parse description - can be string or JSON text component
	description, rawDescription := s.parseDescription(s.config.Description)

	response := StatusResponse{
		Version: VersionInfo{
			Name:     s.config.Version,
			Protocol: s.config.Protocol,
		},
		Players: PlayersInfo{
			Max:    s.config.MaxPlayers,
			Online: s.config.OnlinePlayers,
		},
		Description:    description,
		DescriptionRaw: rawDescription,
	}

	if s.favicon != "" {
		response.Favicon = s.favicon
	}

	packet, err := createStatusPacket(response)
	if err != nil {
		s.logger.WithError(err).Error("failed to create status packet")
		return
	}

	conn.Write(packet)
}

// parseDescription converts description config to DescriptionInfo
// Returns both the DescriptionInfo struct and the raw JSON map for direct use
// Supports:
// 1. Simple string
// 2. Minecraft color codes (e.g., "§4Red text§r\n§aGreen text")
// 3. JSON text component format
func (s *MotdServer) parseDescription(desc interface{}) (DescriptionInfo, interface{}) {
	switch v := desc.(type) {
	case string:
		// Check if it contains Minecraft color codes
		if strings.Contains(v, "§") || strings.Contains(v, "\u00A7") || strings.Contains(v, "\\n") {
			// Parse Minecraft color codes - return raw JSON map for direct use
			parsed := parseMinecraftColorCodes(v)
			return s.parseJSONComponent(parsed), parsed
		}
		// Simple string - convert to text component
		info := DescriptionInfo{Text: v}
		rawJSON := map[string]interface{}{"text": v}
		return info, rawJSON
	case map[string]interface{}:
		// JSON text component format - use raw map directly
		return s.parseJSONComponent(v), v
	default:
		// Fallback to empty
		info := DescriptionInfo{Text: ""}
		rawJSON := map[string]interface{}{"text": ""}
		return info, rawJSON
	}
}

// parseJSONComponent converts a JSON component map to DescriptionInfo
func (s *MotdServer) parseJSONComponent(v map[string]interface{}) DescriptionInfo {
	info := DescriptionInfo{}
	if text, ok := v["text"].(string); ok {
		info.Text = text
	}
	if extra, ok := v["extra"].([]interface{}); ok {
		info.Extra = make([]map[string]interface{}, 0, len(extra))
		for _, item := range extra {
			if itemMap, ok := item.(map[string]interface{}); ok {
				info.Extra = append(info.Extra, itemMap)
			}
		}
	}
	if color, ok := v["color"].(string); ok {
		info.Color = color
	}
	if bold, ok := v["bold"].(bool); ok {
		info.Bold = bold
	}
	if italic, ok := v["italic"].(bool); ok {
		info.Italic = italic
	}
	if underlined, ok := v["underlined"].(bool); ok {
		info.Underlined = underlined
	}
	if strikethrough, ok := v["strikethrough"].(bool); ok {
		info.Strikethrough = strikethrough
	}
	if obfuscated, ok := v["obfuscated"].(bool); ok {
		info.Obfuscated = obfuscated
	}
	return info
}

// sendDisconnect sends a disconnect message to the client
func (s *MotdServer) sendDisconnect(conn net.Conn) {
	var message string

	// Extract text from description (can be string or JSON object)
	switch v := s.config.Description.(type) {
	case string:
		message = v
	case map[string]interface{}:
		if text, ok := v["text"].(string); ok {
			message = text
		}
		// If it's a JSON component, we could use the full structure, but for disconnect
		// we'll just use the text for simplicity
	}

	if message == "" {
		message = "Server is currently unavailable"
	}

	packet, err := createDisconnectPacket(message)
	if err != nil {
		s.logger.WithError(err).Error("failed to create disconnect packet")
		return
	}

	conn.Write(packet)
}

// Close stops the MOTD server
func (s *MotdServer) Close() error {
	s.cancel()
	if s.server != nil {
		if err := s.server.Close(); err != nil {
			return err
		}
	}
	s.wg.Wait()
	return nil
}
