package alwaysmotd

import (
	"strings"
)

// Minecraft color code to JSON color mapping
var colorCodeMap = map[rune]string{
	'0': "black",
	'1': "dark_blue",
	'2': "dark_green",
	'3': "dark_aqua",
	'4': "dark_red",
	'5': "dark_purple",
	'6': "gold",
	'7': "gray",
	'8': "dark_gray",
	'9': "blue",
	'a': "green",
	'b': "aqua",
	'c': "red",
	'd': "light_purple",
	'e': "yellow",
	'f': "white",
}

// parseMinecraftColorCodes converts Minecraft color code format to JSON text components
// Supports: §0-§f for colors, §r for reset, §l for bold, §o for italic, §n for underlined, §m for strikethrough, §k for obfuscated
// Also supports \n for newlines
func parseMinecraftColorCodes(input string) map[string]interface{} {
	if !strings.Contains(input, "§") && !strings.Contains(input, "\u00A7") && !strings.Contains(input, "\\n") {
		// No color codes or newlines, return simple text
		return map[string]interface{}{
			"text": input,
		}
	}

	// Replace \u00A7 with § for easier parsing
	input = strings.ReplaceAll(input, "\u00A7", "§")
	// Replace \n with actual newline
	input = strings.ReplaceAll(input, "\\n", "\n")

	var result []map[string]interface{}
	var currentText strings.Builder
	currentColor := ""
	currentBold := false
	currentItalic := false
	currentUnderlined := false
	currentStrikethrough := false
	currentObfuscated := false
	resetAfterNext := false // Track if we need to explicitly reset formatting in next component

	runes := []rune(input)
	for i := 0; i < len(runes); i++ {
		r := runes[i]

		if r == '§' && i+1 < len(runes) {
			// Save current text if any
			if currentText.Len() > 0 {
				component := map[string]interface{}{
					"text": currentText.String(),
				}
				if currentColor != "" {
					component["color"] = currentColor
				}
				if currentBold {
					component["bold"] = true
				}
				if currentItalic {
					component["italic"] = true
				}
				if currentUnderlined {
					component["underlined"] = true
				}
				if currentStrikethrough {
					component["strikethrough"] = true
				}
				if currentObfuscated {
					component["obfuscated"] = true
				}
				// If we had a reset before this text, explicitly clear formatting to prevent inheritance
				if resetAfterNext {
					// Explicitly set formatting to false to prevent inheritance from parent components
					// This ensures that after §r, formatting doesn't carry over
					component["bold"] = false
					component["italic"] = false
					component["underlined"] = false
					component["strikethrough"] = false
					component["obfuscated"] = false
					// Only set color if we have one - if reset cleared it, don't include color field
					// This allows Minecraft to use default text color
					resetAfterNext = false
				}
				result = append(result, component)
				currentText.Reset()
			}

			// Process color code
			code := runes[i+1]
			i++ // Skip the code character

			switch code {
			case 'r':
				// Reset all formatting - text before reset was already saved above
				// Clear all formatting for all future text segments
				currentColor = ""
				currentBold = false
				currentItalic = false
				currentUnderlined = false
				currentStrikethrough = false
				currentObfuscated = false
				// Mark that the next component should explicitly reset formatting
				resetAfterNext = true
			case 'l':
				currentBold = true
			case 'o':
				currentItalic = true
			case 'n':
				currentUnderlined = true
			case 'm':
				currentStrikethrough = true
			case 'k':
				currentObfuscated = true
			default:
				// Check if it's a color code
				if color, ok := colorCodeMap[code]; ok {
					currentColor = color
					// Color codes reset formatting except the color itself
					currentBold = false
					currentItalic = false
					currentUnderlined = false
					currentStrikethrough = false
					currentObfuscated = false
				}
			}
		} else if r == '\n' {
			// Newline - save current text and start new component
			if currentText.Len() > 0 {
				component := map[string]interface{}{
					"text": currentText.String(),
				}
				if currentColor != "" {
					component["color"] = currentColor
				}
				if currentBold {
					component["bold"] = true
				}
				if currentItalic {
					component["italic"] = true
				}
				if currentUnderlined {
					component["underlined"] = true
				}
				if currentStrikethrough {
					component["strikethrough"] = true
				}
				if currentObfuscated {
					component["obfuscated"] = true
				}
				// Handle reset flag
				if resetAfterNext {
					component["bold"] = false
					component["italic"] = false
					component["underlined"] = false
					component["strikethrough"] = false
					component["obfuscated"] = false
					resetAfterNext = false
				}
				result = append(result, component)
				currentText.Reset()
			}
			// Add newline as separate component
			result = append(result, map[string]interface{}{
				"text": "\n",
			})
		} else {
			currentText.WriteRune(r)
		}
	}

	// Add remaining text
	if currentText.Len() > 0 {
		component := map[string]interface{}{
			"text": currentText.String(),
		}
		if currentColor != "" {
			component["color"] = currentColor
		}
		if currentBold {
			component["bold"] = true
		}
		if currentItalic {
			component["italic"] = true
		}
		if currentUnderlined {
			component["underlined"] = true
		}
		if currentStrikethrough {
			component["strikethrough"] = true
		}
		if currentObfuscated {
			component["obfuscated"] = true
		}
		// Handle reset flag
		if resetAfterNext {
			component["bold"] = false
			component["italic"] = false
			component["underlined"] = false
			component["strikethrough"] = false
			component["obfuscated"] = false
			resetAfterNext = false
		}
		result = append(result, component)
	}

	if len(result) == 0 {
		return map[string]interface{}{
			"text": "",
		}
	}

	if len(result) == 1 {
		return result[0]
	}

	// For multiple components, use the first as base and rest in extra
	first := result[0]
	rest := result[1:]

	// If first component has no text, use empty string
	if _, ok := first["text"]; !ok {
		first["text"] = ""
	}

	if len(rest) > 0 {
		first["extra"] = rest
	}

	return first
}
