package router

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/apex/log"
	"github.com/gin-gonic/gin"
	"gopkg.in/yaml.v3"

	"github.com/mythicalltd/featherwings/config"
	"github.com/mythicalltd/featherwings/internal/selfupdate"
	"github.com/mythicalltd/featherwings/router/middleware"
)

const configRestartTimeout = 30 * time.Second

// ConfigPatchRequest defines the payload for patching specific config values using dot notation.
type ConfigPatchRequest struct {
	Updates map[string]interface{} `json:"updates" binding:"required"` // Map of dot-notation paths to values, e.g. {"api.port": 8080, "system.root_directory": "/var/lib/featherpanel"}
	Restart bool                   `json:"restart,omitempty"`          // Whether to restart wings after update
}

// ConfigPutRequest defines the payload for replacing the entire configuration file.
type ConfigPutRequest struct {
	Content string `json:"content" binding:"required"` // Raw YAML content - the entire config file
	Restart bool   `json:"restart,omitempty"`          // Whether to restart wings after update
}

// ConfigUpdateResponse conveys the outcome of a configuration update.
type ConfigUpdateResponse struct {
	Applied      bool   `json:"applied"`
	Restarted    bool   `json:"restarted,omitempty"`
	ErrorMessage string `json:"error_message,omitempty"`
}

// ConfigSchemaField describes a single configuration field.
type ConfigSchemaField struct {
	Key         string              `json:"key"`
	Type        string              `json:"type"`
	Description string              `json:"description,omitempty"`
	Default     interface{}         `json:"default,omitempty"`
	Required    bool                `json:"required,omitempty"`
	Fields      []ConfigSchemaField `json:"fields,omitempty"` // For nested structures
}

// ConfigSchemaResponse provides a schema describing all configurable fields.
type ConfigSchemaResponse struct {
	Fields []ConfigSchemaField `json:"fields"`
}

// getConfigRaw returns the raw YAML configuration file with comments preserved.
// @Summary Get raw configuration
// @Description Returns the complete wings configuration file as raw YAML with all comments preserved. Returns YAML format with proper Content-Type header.
// @Tags Configuration
// @Produce application/x-yaml
// @Produce text/yaml
// @Success 200 {string} string "Raw YAML configuration file"
// @Failure 500 {object} ErrorResponse
// @Security NodeToken
// @Router /api/config [get]
func getConfigRaw(c *gin.Context) {
	cfg := config.Get()

	// Get the config path
	configPath := cfg.Path()
	if configPath == "" {
		configPath = config.DefaultLocation
	}

	// Read raw config with comments
	content, err := config.ReadRawConfig(configPath)
	if err != nil {
		middleware.CaptureAndAbort(c, err)
		return
	}

	// Return as YAML with proper headers
	c.Header("Content-Type", "application/x-yaml; charset=utf-8")
	c.Data(http.StatusOK, "application/x-yaml", content)
}

// putConfigRaw replaces the entire wings configuration file with new YAML content.
// @Summary Replace entire configuration
// @Description Replaces the entire wings configuration file with new YAML content. All comments and formatting are preserved. Optionally restarts wings after update.
// @Tags Configuration
// @Accept json
// @Produce json
// @Param request body router.ConfigPutRequest true "Full configuration file content"
// @Success 200 {object} router.ConfigUpdateResponse
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Security NodeToken
// @Router /api/config [put]
func putConfigRaw(c *gin.Context) {
	cfg := config.Get()

	if cfg.IgnorePanelConfigUpdates {
		c.JSON(http.StatusOK, ConfigUpdateResponse{
			Applied: false,
		})
		return
	}

	var req ConfigPutRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, ErrorResponse{Error: "invalid request payload"})
		return
	}

	// Get the config path
	configPath := cfg.Path()
	if configPath == "" {
		configPath = config.DefaultLocation
	}

	// Only validate basic YAML syntax - don't validate against struct
	// This allows writing ANY valid YAML file, preserving all fields and comments
	var testNode yaml.Node
	if err := yaml.Unmarshal([]byte(req.Content), &testNode); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, ErrorResponse{
			Error: "invalid YAML syntax: " + err.Error(),
		})
		return
	}

	// Write the raw YAML content directly - this preserves EVERYTHING:
	// - All comments
	// - All formatting
	// - All fields (even ones not in the struct)
	// - Custom YAML structure
	if err := config.WriteRawConfig(configPath, []byte(req.Content)); err != nil {
		middleware.CaptureAndAbort(c, err)
		return
	}

	// Try to reload configuration from file to update the in-memory state
	// If this fails, we still return success since the file was written
	// The error will be logged but won't prevent the update
	if err := config.FromFile(configPath); err != nil {
		log.WithError(err).Warn("config file written successfully but failed to reload - wings may need restart")
		// Don't fail the request - file was written successfully
	}

	response := ConfigUpdateResponse{
		Applied: true,
	}

	// Handle restart if requested
	if req.Restart {
		restartCmd := config.Get().System.Updates.RestartCommand
		if restartCmd == "" {
			restartCmd = "systemctl restart featherwings"
		}

		restartTriggered := queueConfigRestartCommand(restartCmd)
		response.Restarted = restartTriggered
		if !restartTriggered {
			response.ErrorMessage = "restart command is not configured"
		}
	}

	c.JSON(http.StatusOK, response)
}

// patchConfig updates specific configuration values using dot notation paths.
// @Summary Patch configuration values
// @Description Updates specific configuration values using dot notation (e.g., "api.port", "system.root_directory"). Preserves comments and other values.
// @Tags Configuration
// @Accept json
// @Produce json
// @Param request body router.ConfigPatchRequest true "Configuration patch request"
// @Success 200 {object} router.ConfigUpdateResponse
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Security NodeToken
// @Router /api/config/patch [patch]
func patchConfig(c *gin.Context) {
	cfg := config.Get()

	if cfg.IgnorePanelConfigUpdates {
		c.JSON(http.StatusOK, ConfigUpdateResponse{
			Applied: false,
		})
		return
	}

	var req ConfigPatchRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, ErrorResponse{Error: "invalid request payload"})
		return
	}

	// Get the config path
	configPath := cfg.Path()
	if configPath == "" {
		configPath = config.DefaultLocation
	}

	// Read the current config file to preserve comments
	rawYAML, err := config.ReadRawConfig(configPath)
	if err != nil {
		middleware.CaptureAndAbort(c, err)
		return
	}

	// Parse YAML into node tree to preserve comments
	var rootNode yaml.Node
	if err := yaml.Unmarshal(rawYAML, &rootNode); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, ErrorResponse{
			Error: "failed to parse existing config: " + err.Error(),
		})
		return
	}

	// Apply all updates using dot notation
	for path, value := range req.Updates {
		if err := config.UpdateYAMLNode(&rootNode, path, value); err != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, ErrorResponse{
				Error: "failed to update path '" + path + "': " + err.Error(),
			})
			return
		}
	}

	// Marshal back to YAML (preserves comments)
	updatedYAML, err := yaml.Marshal(&rootNode)
	if err != nil {
		middleware.CaptureAndAbort(c, err)
		return
	}

	// Write the updated config
	if err := config.WriteRawConfig(configPath, updatedYAML); err != nil {
		middleware.CaptureAndAbort(c, err)
		return
	}

	// Try to reload configuration from file
	if err := config.FromFile(configPath); err != nil {
		log.WithError(err).Warn("config file updated successfully but failed to reload - wings may need restart")
		// Don't fail the request - file was written successfully
	}

	response := ConfigUpdateResponse{
		Applied: true,
	}

	// Handle restart if requested
	if req.Restart {
		restartCmd := config.Get().System.Updates.RestartCommand
		if restartCmd == "" {
			restartCmd = "systemctl restart featherwings"
		}

		restartTriggered := queueConfigRestartCommand(restartCmd)
		response.Restarted = restartTriggered
		if !restartTriggered {
			response.ErrorMessage = "restart command is not configured"
		}
	}

	c.JSON(http.StatusOK, response)
}

// queueConfigRestartCommand queues a restart command similar to self-update restarts.
func queueConfigRestartCommand(command string) bool {
	command = strings.TrimSpace(command)
	if command == "" {
		return false
	}

	go func(cmd string) {
		ctx, cancel := context.WithTimeout(context.Background(), configRestartTimeout)
		defer cancel()
		output, err := selfupdate.RunRestartCommand(ctx, cmd)
		fields := log.Fields{"command": cmd}
		if output != "" {
			fields["output"] = output
		}
		if err != nil {
			log.WithError(err).WithFields(fields).Error("config update restart command failed")
			return
		}
		log.WithFields(fields).Info("config update restart command executed successfully")
	}(command)

	return true
}

// getConfigSchema returns a schema describing all configurable fields.
// @Summary Get configuration schema
// @Description Returns a schema describing all configurable fields in the wings configuration, useful for building GUIs.
// @Tags Configuration
// @Produce json
// @Success 200 {object} router.ConfigSchemaResponse
// @Security NodeToken
// @Router /api/config/schema [get]
func getConfigSchema(c *gin.Context) {
	schema := generateConfigSchema()
	c.JSON(http.StatusOK, ConfigSchemaResponse{
		Fields: schema,
	})
}

// generateConfigSchema generates a schema describing all configuration fields.
func generateConfigSchema() []ConfigSchemaField {
	return []ConfigSchemaField{
		{
			Key:         "app_name",
			Type:        "string",
			Description: "Application name",
			Default:     "FeatherPanel",
		},
		{
			Key:         "uuid",
			Type:        "string",
			Description: "Unique identifier for this node in the Panel",
			Required:    true,
		},
		{
			Key:         "token_id",
			Type:        "string",
			Description: "Identifier for the authentication token",
			Required:    true,
		},
		{
			Key:         "token",
			Type:        "string",
			Description: "Authentication token for API requests",
			Required:    true,
		},
		{
			Key:         "debug",
			Type:        "boolean",
			Description: "Enable debug mode",
			Default:     false,
		},
		{
			Key:         "api",
			Type:        "object",
			Description: "API server configuration",
			Fields: []ConfigSchemaField{
				{
					Key:         "host",
					Type:        "string",
					Description: "Interface to bind the API server to",
					Default:     "0.0.0.0",
				},
				{
					Key:         "port",
					Type:        "integer",
					Description: "Port to bind the API server to",
					Default:     8080,
				},
				{
					Key:         "docs",
					Type:        "object",
					Description: "API documentation settings",
					Fields: []ConfigSchemaField{
						{
							Key:         "enabled",
							Type:        "boolean",
							Description: "Enable Swagger/OpenAPI documentation",
							Default:     true,
						},
					},
				},
				{
					Key:         "ssl",
					Type:        "object",
					Description: "SSL/TLS configuration",
					Fields: []ConfigSchemaField{
						{
							Key:         "enabled",
							Type:        "boolean",
							Description: "Enable SSL/TLS",
							Default:     false,
						},
						{
							Key:         "cert",
							Type:        "string",
							Description: "Path to SSL certificate file",
						},
						{
							Key:         "key",
							Type:        "string",
							Description: "Path to SSL private key file",
						},
					},
				},
				{
					Key:         "upload_limit",
					Type:        "integer",
					Description: "Maximum file upload size in MiB",
					Default:     100,
				},
				{
					Key:         "trusted_proxies",
					Type:        "array",
					Description: "List of trusted proxy IP addresses",
				},
				{
					Key:         "ignore_certificate_errors",
					Type:        "boolean",
					Description: "Ignore TLS certificate verification errors",
					Default:     false,
				},
			},
		},
		{
			Key:         "system",
			Type:        "object",
			Description: "System configuration",
			Fields: []ConfigSchemaField{
				{
					Key:         "root_directory",
					Type:        "string",
					Description: "Root directory for all featherpanel data",
					Default:     "/var/lib/featherpanel",
				},
				{
					Key:         "log_directory",
					Type:        "string",
					Description: "Directory for log files",
					Default:     "/var/log/featherpanel",
				},
				{
					Key:         "data",
					Type:        "string",
					Description: "Directory for server data",
					Default:     "/var/lib/featherpanel/volumes",
				},
				{
					Key:         "archive_directory",
					Type:        "string",
					Description: "Directory for server archives",
					Default:     "/var/lib/featherpanel/archives",
				},
				{
					Key:         "backup_directory",
					Type:        "string",
					Description: "Directory for backups",
					Default:     "/var/lib/featherpanel/backups",
				},
				{
					Key:         "tmp_directory",
					Type:        "string",
					Description: "Directory for temporary files",
					Default:     "/tmp/featherpanel",
				},
				{
					Key:         "username",
					Type:        "string",
					Description: "System user for server files",
					Default:     "featherpanel",
				},
				{
					Key:         "timezone",
					Type:        "string",
					Description: "Timezone for this instance",
				},
				{
					Key:         "disk_check_interval",
					Type:        "integer",
					Description: "Interval in seconds for disk space checks",
					Default:     150,
				},
				{
					Key:         "activity_send_interval",
					Type:        "integer",
					Description: "Interval in seconds for sending activity data",
					Default:     60,
				},
				{
					Key:         "activity_send_count",
					Type:        "integer",
					Description: "Number of activity events per batch",
					Default:     100,
				},
				{
					Key:         "check_permissions_on_boot",
					Type:        "boolean",
					Description: "Check file permissions when server boots",
					Default:     true,
				},
				{
					Key:         "enable_log_rotate",
					Type:        "boolean",
					Description: "Enable automatic log rotation",
					Default:     true,
				},
				{
					Key:         "websocket_log_count",
					Type:        "integer",
					Description: "Number of log lines to send on websocket connect",
					Default:     150,
				},
				{
					Key:         "sftp",
					Type:        "object",
					Description: "SFTP server configuration",
					Fields: []ConfigSchemaField{
						{
							Key:         "bind_address",
							Type:        "string",
							Description: "SFTP bind address",
							Default:     "0.0.0.0",
						},
						{
							Key:         "bind_port",
							Type:        "integer",
							Description: "SFTP bind port",
							Default:     2022,
						},
						{
							Key:         "read_only",
							Type:        "boolean",
							Description: "Enable read-only mode",
							Default:     false,
						},
					},
				},
				{
					Key:         "crash_detection",
					Type:        "object",
					Description: "Crash detection settings",
					Fields: []ConfigSchemaField{
						{
							Key:         "enabled",
							Type:        "boolean",
							Description: "Enable crash detection",
							Default:     true,
						},
						{
							Key:         "detect_clean_exit_as_crash",
							Type:        "boolean",
							Description: "Detect clean exits as crashes",
							Default:     true,
						},
						{
							Key:         "timeout",
							Type:        "integer",
							Description: "Timeout between crashes in seconds",
							Default:     60,
						},
					},
				},
				{
					Key:         "backups",
					Type:        "object",
					Description: "Backup settings",
					Fields: []ConfigSchemaField{
						{
							Key:         "write_limit",
							Type:        "integer",
							Description: "Disk I/O write limit for backups in MiB/s (0 = unlimited)",
							Default:     0,
						},
						{
							Key:         "compression_level",
							Type:        "string",
							Description: "Compression level: none, best_speed, best_compression",
							Default:     "best_speed",
						},
						{
							Key:         "remove_backups_on_server_delete",
							Type:        "boolean",
							Description: "Delete backups when server is deleted",
							Default:     true,
						},
					},
				},
				{
					Key:         "transfers",
					Type:        "object",
					Description: "Transfer settings",
					Fields: []ConfigSchemaField{
						{
							Key:         "download_limit",
							Type:        "integer",
							Description: "Network I/O download limit in MiB/s (0 = unlimited)",
							Default:     0,
						},
					},
				},
				{
					Key:         "updates",
					Type:        "object",
					Description: "Update settings",
					Fields: []ConfigSchemaField{
						{
							Key:         "enable_url",
							Type:        "boolean",
							Description: "Enable URL-based updates",
							Default:     true,
						},
						{
							Key:         "allow_api",
							Type:        "boolean",
							Description: "Allow API-triggered updates",
							Default:     true,
						},
						{
							Key:         "disable_checksum",
							Type:        "boolean",
							Description: "Disable checksum verification",
							Default:     true,
						},
						{
							Key:         "restart_command",
							Type:        "string",
							Description: "Command to execute after update",
							Default:     "systemctl restart featherwings",
						},
						{
							Key:         "repo_owner",
							Type:        "string",
							Description: "GitHub repository owner",
							Default:     "mythicalltd",
						},
						{
							Key:         "repo_name",
							Type:        "string",
							Description: "GitHub repository name",
							Default:     "featherwings",
						},
					},
				},
			},
		},
		{
			Key:         "docker",
			Type:        "object",
			Description: "Docker configuration",
			Fields: []ConfigSchemaField{
				{
					Key:         "network",
					Type:        "object",
					Description: "Docker network configuration",
					Fields: []ConfigSchemaField{
						{
							Key:         "interface",
							Type:        "string",
							Description: "Network interface",
							Default:     "172.19.0.1",
						},
						{
							Key:         "name",
							Type:        "string",
							Description: "Network name",
							Default:     "featherpanel_nw",
						},
						{
							Key:         "driver",
							Type:        "string",
							Description: "Network driver",
							Default:     "bridge",
						},
					},
				},
				{
					Key:         "tmpfs_size",
					Type:        "integer",
					Description: "Size for /tmp directory in MB",
					Default:     100,
				},
				{
					Key:         "container_pid_limit",
					Type:        "integer",
					Description: "Maximum processes per container",
					Default:     512,
				},
				{
					Key:         "enable_native_kvm",
					Type:        "boolean",
					Description: "Enable native KVM support",
				},
			},
		},
		{
			Key:         "remote",
			Type:        "string",
			Description: "Panel API URL",
			Required:    true,
		},
		{
			Key:         "remote_query",
			Type:        "object",
			Description: "Remote query configuration",
			Fields: []ConfigSchemaField{
				{
					Key:         "timeout",
					Type:        "integer",
					Description: "Request timeout in seconds",
					Default:     30,
				},
				{
					Key:         "boot_servers_per_page",
					Type:        "integer",
					Description: "Servers per page when booting",
					Default:     50,
				},
			},
		},
		{
			Key:         "allowed_mounts",
			Type:        "array",
			Description: "List of allowed mount points",
		},
		{
			Key:         "allowed_origins",
			Type:        "array",
			Description: "List of allowed CORS origins",
		},
		{
			Key:         "ignore_panel_config_updates",
			Type:        "boolean",
			Description: "Ignore configuration updates from panel",
			Default:     false,
		},
	}
}
