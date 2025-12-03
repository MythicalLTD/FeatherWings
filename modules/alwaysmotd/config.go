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
	Port       int                     `json:"port" yaml:"port"`
	ServerIcon string                  `json:"serverIcon" yaml:"serverIcon"`
	States     map[string]*StateConfig `json:"states" yaml:"states"`
}

// StateConfig defines the MOTD configuration for a specific server state
type StateConfig struct {
	Version       string      `json:"version" yaml:"version"`
	Protocol      int         `json:"protocol" yaml:"protocol"`
	MaxPlayers    int         `json:"maxPlayers" yaml:"maxPlayers"`
	OnlinePlayers int         `json:"onlinePlayers" yaml:"onlinePlayers"`
	Description   interface{} `json:"description" yaml:"description"` // Can be string or JSON text component
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
			Port:       25560,
			ServerIcon: "https://cdn.mythical.systems/featherpanel/logo.png",
			States: map[string]*StateConfig{
				"offline": {
					Version:       "FeatherPanel",
					Protocol:      773,
					MaxPlayers:    0,
					OnlinePlayers: 0,
					Description:   "§4§l✖ §cServer is §4§lOFFLINE§r\n§7Please check back later!",
				},
				"suspended": {
					Version:       "FeatherPanel",
					Protocol:      773,
					MaxPlayers:    0,
					OnlinePlayers: 0,
					Description:   "§6§l⚠ §eServer is §6§lSUSPENDED§r\n§7Contact an administrator for assistance.",
				},
				"installing": {
					Version:       "FeatherPanel",
					Protocol:      773,
					MaxPlayers:    0,
					OnlinePlayers: 0,
					Description:   "§b§l⚙ §3Server is §b§lINSTALLING§r\n§7Please wait while we set things up...",
				},
				"starting": {
					Version:       "FeatherPanel",
					Protocol:      773,
					MaxPlayers:    0,
					OnlinePlayers: 0,
					Description:   "§a§l▶ §2Server is §a§lSTARTING§r\n§7We'll be ready in just a moment!",
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
