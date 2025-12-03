package alwaysmotd

// Config represents the configuration for the AlwaysMOTD module
type Config struct {
	PortRange  PortRangeConfig  `json:"portRange" yaml:"portRange"`
	Motd       MotdConfig       `json:"motd" yaml:"motd"`
	Monitoring MonitoringConfig `json:"monitoring" yaml:"monitoring"`
	Logging    LoggingConfig    `json:"logging" yaml:"logging"`
}

// PortRangeConfig defines the port range to monitor
type PortRangeConfig struct {
	Start int `json:"start" yaml:"start"`
	End   int `json:"end" yaml:"end"`
}

// MotdConfig contains MOTD server configuration
type MotdConfig struct {
	// Base port for MOTD servers. Each state gets its own port:
	// - Java Edition: basePort + stateOffset (e.g., 25560 + 0 = 25560 for offline)
	// - Bedrock Edition: basePort + stateOffset + 100 (e.g., 25560 + 0 + 100 = 25660 for offline)
	// This allows multiple states to run simultaneously without port conflicts
	Port   int                     `json:"port" yaml:"port"`
	States map[string]*StateConfig `json:"states" yaml:"states"`

	// Edition support
	JavaEnabled    bool `json:"javaEnabled" yaml:"javaEnabled" default:"true"`       // Enable Java Edition MOTD
	BedrockEnabled bool `json:"bedrockEnabled" yaml:"bedrockEnabled" default:"true"` // Enable Bedrock Edition MOTD

	// Edition-specific settings
	Java    JavaConfig    `json:"java" yaml:"java"`
	Bedrock BedrockConfig `json:"bedrock" yaml:"bedrock"`
}

// StateConfig defines the MOTD configuration for a specific server state
type StateConfig struct {
	Version       string      `json:"version" yaml:"version"`
	Protocol      int         `json:"protocol" yaml:"protocol"`
	MaxPlayers    int         `json:"maxPlayers" yaml:"maxPlayers"`
	OnlinePlayers int         `json:"onlinePlayers" yaml:"onlinePlayers"`
	Description   interface{} `json:"description" yaml:"description"` // Can be string or JSON text component

	// Edition-specific overrides
	JavaDescription    interface{} `json:"javaDescription" yaml:"javaDescription"`       // Optional Java-specific message
	BedrockDescription interface{} `json:"bedrockDescription" yaml:"bedrockDescription"` // Optional Bedrock-specific message
}

// JavaConfig contains Java Edition specific settings
type JavaConfig struct {
	// Disconnect message formatting
	DisconnectMessageFormat string `json:"disconnectMessageFormat" yaml:"disconnectMessageFormat"` // Format: "bold", "large", "normal"
	DisconnectMessagePrefix string `json:"disconnectMessagePrefix" yaml:"disconnectMessagePrefix"` // Prefix to add before message
	DisconnectMessageSuffix string `json:"disconnectMessageSuffix" yaml:"disconnectMessageSuffix"` // Suffix to add after message

	// Connection handling
	StatusResponseDelay int `json:"statusResponseDelay" yaml:"statusResponseDelay"` // Milliseconds to delay status response (0 = immediate)
	DisconnectDelay     int `json:"disconnectDelay" yaml:"disconnectDelay"`         // Milliseconds to delay disconnect after sending

	// Protocol settings
	ProtocolVersion int `json:"protocolVersion" yaml:"protocolVersion"` // Protocol version (0 = use from state config)

	// Minecraft version string for Java Edition
	MinecraftVersion string `json:"minecraftVersion" yaml:"minecraftVersion"`

	// Favicon settings
	FaviconEnabled bool   `json:"faviconEnabled" yaml:"faviconEnabled"` // Enable favicon in server list
	FaviconURL     string `json:"faviconURL" yaml:"faviconURL"`         // Favicon URL or file path (PNG, 64x64 recommended)

	// Response behavior
	ShowAsUnhealthy bool `json:"showAsUnhealthy" yaml:"showAsUnhealthy"` // Make server appear unhealthy in server list (don't respond to ping)
}

// BedrockConfig contains Bedrock Edition specific settings
type BedrockConfig struct {
	// Disconnect message formatting
	DisconnectMessageFormat string `json:"disconnectMessageFormat" yaml:"disconnectMessageFormat"` // Format: "bold", "large", "normal"
	DisconnectMessagePrefix string `json:"disconnectMessagePrefix" yaml:"disconnectMessagePrefix"` // Prefix to add before message
	DisconnectMessageSuffix string `json:"disconnectMessageSuffix" yaml:"disconnectMessageSuffix"` // Suffix to add after message

	// Connection handling
	ConnectionWaitTime int `json:"connectionWaitTime" yaml:"connectionWaitTime"` // Milliseconds to wait before sending disconnect
	DisconnectWaitTime int `json:"disconnectWaitTime" yaml:"disconnectWaitTime"` // Milliseconds to wait after sending disconnect before closing

	// Protocol version (0 = auto-detect from client)
	ProtocolVersion int `json:"protocolVersion" yaml:"protocolVersion"`

	// Minecraft version string for Bedrock
	MinecraftVersion string `json:"minecraftVersion" yaml:"minecraftVersion"`
}

// MonitoringConfig contains monitoring settings
type MonitoringConfig struct {
	CheckInterval int `json:"checkInterval" yaml:"checkInterval"` // milliseconds
}

// LoggingConfig contains logging settings
type LoggingConfig struct {
	Level string `json:"level" yaml:"level"` // error, warn, info, debug
}

// DefaultConfig returns a default configuration
func DefaultConfig() *Config {
	return &Config{
		PortRange: PortRangeConfig{
			Start: 25565,
			End:   25800,
		},
		Motd: MotdConfig{
			// Base port for MOTD servers. Each state gets: basePort + offset (Java) or basePort + offset + 100 (Bedrock)
			// Example: offline=25560 (Java), 25660 (Bedrock); suspended=25561 (Java), 25661 (Bedrock)
			Port:           25560,
			JavaEnabled:    true, // Java Edition MOTD enabled by default
			BedrockEnabled: true, // Bedrock Edition MOTD enabled by default
			Java: JavaConfig{
				DisconnectMessageFormat: "bold",
				DisconnectMessagePrefix: "§c",
				DisconnectMessageSuffix: "§r",
				StatusResponseDelay:     0,                                                    // Immediate
				DisconnectDelay:         100,                                                  // Small delay to ensure packet is sent
				ProtocolVersion:         0,                                                    // Use from state config
				MinecraftVersion:        "",                                                   // Use from state config
				FaviconEnabled:          true,                                                 // Enable favicon by default
				FaviconURL:              "https://cdn.mythical.systems/featherpanel/logo.png", // Default favicon URL
				ShowAsUnhealthy:         true,                                                 // Don't respond to ping to show as unhealthy
			},
			Bedrock: BedrockConfig{
				DisconnectMessageFormat: "large",
				DisconnectMessagePrefix: "\n\n§l§c",
				DisconnectMessageSuffix: "§r\n\n",
				ConnectionWaitTime:      150,       // Wait for connection to establish
				DisconnectWaitTime:      400,       // Wait to ensure packet is sent
				ProtocolVersion:         0,         // Auto-detect from client
				MinecraftVersion:        "1.20.81", // Default Bedrock version
			},
			States: map[string]*StateConfig{
				"offline": {
					Version:       "FeatherPanel",
					Protocol:      773,
					MaxPlayers:    20,
					OnlinePlayers: 0,
					Description: map[string]interface{}{
						"text": "",
						"extra": []interface{}{
							map[string]interface{}{"text": "§4§l✖ ", "bold": true, "color": "dark_red"},
							map[string]interface{}{"text": "§cServer is ", "color": "red"},
							map[string]interface{}{"text": "§4§lOFFLINE", "bold": true, "color": "dark_red"},
							map[string]interface{}{"text": "§r\n"},
							map[string]interface{}{"text": "§7Please check back later!", "color": "gray"},
						},
					},
					JavaDescription:    "§4§l✖ §cServer is §4§lOFFLINE§r\n§7Please check back later!",
					BedrockDescription: "§l§cSERVER OFFLINE§r\n\n§7Please check back later!",
				},
				"suspended": {
					Version:       "FeatherPanel",
					Protocol:      773,
					MaxPlayers:    20,
					OnlinePlayers: 0,
					Description: map[string]interface{}{
						"text": "",
						"extra": []interface{}{
							map[string]interface{}{"text": "§6§l⚠ ", "bold": true, "color": "gold"},
							map[string]interface{}{"text": "§eServer is ", "color": "yellow"},
							map[string]interface{}{"text": "§6§lSUSPENDED", "bold": true, "color": "gold"},
							map[string]interface{}{"text": "§r\n"},
							map[string]interface{}{"text": "§7Contact an administrator for assistance.", "color": "gray"},
						},
					},
					JavaDescription:    "§6§l⚠ §eServer is §6§lSUSPENDED§r\n§7Contact an administrator for assistance.",
					BedrockDescription: "§l§eSERVER SUSPENDED§r\n\n§7Contact an administrator for assistance.",
				},
				"installing": {
					Version:       "FeatherPanel",
					Protocol:      773,
					MaxPlayers:    20,
					OnlinePlayers: 0,
					Description: map[string]interface{}{
						"text": "",
						"extra": []interface{}{
							map[string]interface{}{"text": "§b§l⚙ ", "bold": true, "color": "aqua"},
							map[string]interface{}{"text": "§3Server is ", "color": "dark_aqua"},
							map[string]interface{}{"text": "§b§lINSTALLING", "bold": true, "color": "aqua"},
							map[string]interface{}{"text": "§r\n"},
							map[string]interface{}{"text": "§7Please wait while we set things up...", "color": "gray"},
						},
					},
					JavaDescription:    "§b§l⚙ §3Server is §b§lINSTALLING§r\n§7Please wait while we set things up...",
					BedrockDescription: "§l§bSERVER INSTALLING§r\n\n§7Please wait while we set things up...",
				},
				"starting": {
					Version:       "FeatherPanel",
					Protocol:      773,
					MaxPlayers:    20,
					OnlinePlayers: 0,
					Description: map[string]interface{}{
						"text": "",
						"extra": []interface{}{
							map[string]interface{}{"text": "§a§l▶ ", "bold": true, "color": "green"},
							map[string]interface{}{"text": "§2Server is ", "color": "dark_green"},
							map[string]interface{}{"text": "§a§lSTARTING", "bold": true, "color": "green"},
							map[string]interface{}{"text": "§r\n"},
							map[string]interface{}{"text": "§7We'll be ready in just a moment!", "color": "gray"},
						},
					},
					JavaDescription:    "§a§l▶ §2Server is §a§lSTARTING§r\n§7We'll be ready in just a moment!",
					BedrockDescription: "§l§aSERVER STARTING§r\n\n§7We'll be ready in just a moment!",
				},
			},
		},
		Monitoring: MonitoringConfig{
			CheckInterval: 10000, // 10 seconds
		},
		Logging: LoggingConfig{
			Level: "info",
		},
	}
}
