package alwaysmotd

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
)

// writeVarInt writes a variable-length integer to a buffer
func writeVarInt(value int32) []byte {
	var buf bytes.Buffer
	for {
		temp := byte(value & 0x7F)
		value >>= 7
		if value != 0 {
			temp |= 0x80
		}
		buf.WriteByte(temp)
		if value == 0 {
			break
		}
	}
	return buf.Bytes()
}

// readVarInt reads a variable-length integer from a buffer
func readVarInt(data []byte, offset int) (int32, int, bool) {
	var numRead int
	var result int32
	var read byte

	for {
		if offset+numRead >= len(data) {
			return 0, 0, false
		}
		read = data[offset+numRead]
		value := int32(read & 0x7F)
		result |= value << (7 * numRead)
		numRead++
		if numRead > 5 {
			return 0, 0, false
		}
		if (read & 0x80) == 0 {
			break
		}
	}
	return result, numRead, true
}

// writeString writes a string as a VarInt length followed by UTF-8 bytes
func writeString(str string) []byte {
	strBytes := []byte(str)
	length := writeVarInt(int32(len(strBytes)))
	return append(length, strBytes...)
}

// createPacket creates a Minecraft protocol packet
func createPacket(packetID int32, data []byte) []byte {
	idBuf := writeVarInt(packetID)
	payload := append(idBuf, data...)
	lengthBuf := writeVarInt(int32(len(payload)))
	return append(lengthBuf, payload...)
}

// StatusResponse represents a Minecraft server status response
type StatusResponse struct {
	Version        VersionInfo     `json:"version"`
	Players        PlayersInfo     `json:"players"`
	Description    DescriptionInfo `json:"description"`
	DescriptionRaw interface{}     `json:"-"` // Raw JSON description for direct use
	Favicon        string          `json:"favicon,omitempty"`
}

// VersionInfo contains version information
type VersionInfo struct {
	Name     string `json:"name"`
	Protocol int    `json:"protocol"`
}

// PlayersInfo contains player count information
type PlayersInfo struct {
	Max    int        `json:"max"`
	Online int        `json:"online"`
	Sample []struct{} `json:"sample"`
}

// DescriptionInfo contains the server description/MOTD
// Can be a simple string or a JSON text component with formatting
type DescriptionInfo struct {
	Text  string                   `json:"text,omitempty"`
	Extra []map[string]interface{} `json:"extra,omitempty"`
	// Support for full JSON text component structure
	Color         string `json:"color,omitempty"`
	Bold          bool   `json:"bold,omitempty"`
	Italic        bool   `json:"italic,omitempty"`
	Underlined    bool   `json:"underlined,omitempty"`
	Strikethrough bool   `json:"strikethrough,omitempty"`
	Obfuscated    bool   `json:"obfuscated,omitempty"`
}

// createStatusPacket creates a status response packet
func createStatusPacket(response StatusResponse) ([]byte, error) {
	// Handle description - prefer raw JSON if available, otherwise build from DescriptionInfo
	var descriptionJSON interface{}

	if response.DescriptionRaw != nil {
		// Use raw JSON description directly (preserves full structure)
		descriptionJSON = response.DescriptionRaw
	} else {
		// Build proper JSON text component from DescriptionInfo
		hasExtra := len(response.Description.Extra) > 0
		hasFormatting := response.Description.Color != "" || response.Description.Bold ||
			response.Description.Italic || response.Description.Underlined ||
			response.Description.Strikethrough || response.Description.Obfuscated

		if response.Description.Text != "" || hasExtra || hasFormatting {
			// Build proper JSON text component
			desc := make(map[string]interface{})
			// Always include text field - use empty string if not set but we have extra/formatting
			desc["text"] = response.Description.Text

			if hasExtra {
				desc["extra"] = response.Description.Extra
			}
			if response.Description.Color != "" {
				desc["color"] = response.Description.Color
			}
			if response.Description.Bold {
				desc["bold"] = true
			}
			if response.Description.Italic {
				desc["italic"] = true
			}
			if response.Description.Underlined {
				desc["underlined"] = true
			}
			if response.Description.Strikethrough {
				desc["strikethrough"] = true
			}
			if response.Description.Obfuscated {
				desc["obfuscated"] = true
			}
			descriptionJSON = desc
		} else {
			// Fallback to simple text
			descriptionJSON = map[string]interface{}{"text": response.Description.Text}
		}
	}

	// Create response with proper description format
	responseMap := map[string]interface{}{
		"version":     response.Version,
		"players":     response.Players,
		"description": descriptionJSON,
	}

	if response.Favicon != "" {
		responseMap["favicon"] = response.Favicon
	}

	jsonData, err := json.Marshal(responseMap)
	if err != nil {
		return nil, err
	}
	responseData := writeString(string(jsonData))
	return createPacket(0x00, responseData), nil
}

// createDisconnectPacket creates a disconnect packet for login attempts
func createDisconnectPacket(message string) ([]byte, error) {
	disconnectMsg := map[string]interface{}{
		"text":  message,
		"color": "red",
		"bold":  true,
	}
	jsonData, err := json.Marshal(disconnectMsg)
	if err != nil {
		return nil, err
	}
	messageData := writeString(string(jsonData))
	return createPacket(0x00, messageData), nil
}

// readInt32 reads a 32-bit integer from a buffer
func readInt32(data []byte, offset int) (int32, bool) {
	if offset+4 > len(data) {
		return 0, false
	}
	return int32(binary.BigEndian.Uint32(data[offset:])), true
}
