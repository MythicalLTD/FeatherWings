package router

import (
	"fmt"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/mythicalltd/featherwings/config"
	"github.com/mythicalltd/featherwings/fastdl"
	"github.com/mythicalltd/featherwings/router/middleware"
)

// FastDLConfigResponse represents the FastDL configuration for a server
type FastDLConfigResponse struct {
	Enabled   bool   `json:"enabled"`
	Directory string `json:"directory"`
	URL       string `json:"url,omitempty"`
	// Command is a helper string showing how to use the FastDL URL
	// in a typical Source-engine based game (e.g. CS:GO, CS2, TF2).
	// Panels can display this directly to the user.
	Command string `json:"command,omitempty"`
}

// getServerFastDL returns the FastDL configuration for a server.
// @Summary Get server FastDL configuration
// @Tags Servers
// @Produce json
// @Param server path string true "Server identifier"
// @Success 200 {object} FastDLConfigResponse
// @Failure 404 {object} ErrorResponse
// @Security NodeToken
// @Router /api/servers/{server}/fastdl [get]
func getServerFastDL(c *gin.Context) {
	s := ExtractServer(c)
	cfg := s.Config()

	// Apply a user-friendly default directory if none is set.
	// This makes FastDL "just work" in /fastdl for new servers.
	effectiveDir := cfg.FastDL.Directory
	if effectiveDir == "" {
		effectiveDir = "fastdl"
	}

	response := FastDLConfigResponse{
		Enabled:   cfg.FastDL.Enabled,
		Directory: effectiveDir,
	}

	// Build FastDL URL if enabled
	if cfg.FastDL.Enabled {
		wingsCfg := config.Get()
		fastdlCfg := wingsCfg.System.FastDL
		
		// FastDL uses HTTP only (no SSL) via nginx
		baseURL := strings.TrimSuffix(wingsCfg.PanelLocation, "/api")
		// Extract hostname from panel location
		panelURL := strings.TrimPrefix(baseURL, "http://")
		panelURL = strings.TrimPrefix(panelURL, "https://")
		if idx := strings.Index(panelURL, "/"); idx > 0 {
			panelURL = panelURL[:idx]
		}
		
		// Build URL: http://hostname:port/{server-uuid}/{directory}
		response.URL = "http://" + panelURL
		if fastdlCfg.Port != 80 {
			response.URL += ":" + fmt.Sprintf("%d", fastdlCfg.Port)
		}
		response.URL += "/" + s.ID()
		if effectiveDir != "" {
			response.URL += "/" + strings.TrimPrefix(effectiveDir, "/")
		}

		// Build a helpful example command that can be shown in the Panel.
		// This is intentionally generic and matches common Source-engine usage.
		// Example: sv_downloadurl "http://example.com:80/uuid/csgo"
		response.Command = fmt.Sprintf(`sv_downloadurl "%s"`, response.URL)
	}

	c.JSON(http.StatusOK, response)
}

// putServerFastDL updates the FastDL configuration for a server.
// @Summary Update server FastDL configuration
// @Tags Servers
// @Accept json
// @Produce json
// @Param server path string true "Server identifier"
// @Param config body FastDLConfigResponse true "FastDL configuration"
// @Success 200 {object} FastDLConfigResponse
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Security NodeToken
// @Router /api/servers/{server}/fastdl [put]
func putServerFastDL(c *gin.Context) {
	s := ExtractServer(c)

	var data FastDLConfigResponse
	if err := c.BindJSON(&data); err != nil {
		middleware.CaptureAndAbort(c, err)
		return
	}

	// Validate directory path (prevent path traversal)
	if data.Directory != "" {
		// Clean the path and ensure it doesn't contain dangerous patterns
		cleaned := filepath.Clean(data.Directory)
		if strings.HasPrefix(cleaned, "..") || strings.Contains(cleaned, "..") {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
				"error": "Invalid directory path: path traversal not allowed",
			})
			return
		}
		data.Directory = cleaned
	}

	// Update server configuration
	s.Config().SetFastDL(data.Enabled, data.Directory)

	// Regenerate nginx config if FastDL is enabled
	cfg := config.Get()
	if cfg.System.FastDL.Enabled {
		manager := middleware.ExtractManager(c)
		if err := fastdl.GenerateNginxConfig(manager); err != nil {
			s.Log().WithError(err).Warn("failed to regenerate nginx config after FastDL update")
		} else {
			fastdl.ReloadNginx()
		}
	}

	// Return updated configuration
	getServerFastDL(c)
}

// postServerFastDLEnable enables FastDL for a server with optional directory.
// @Summary Enable FastDL for server
// @Tags Servers
// @Accept json
// @Produce json
// @Param server path string true "Server identifier"
// @Param config body FastDLConfigResponse false "FastDL configuration (directory optional)"
// @Success 200 {object} FastDLConfigResponse
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Security NodeToken
// @Router /api/servers/{server}/fastdl/enable [post]
func postServerFastDLEnable(c *gin.Context) {
	s := ExtractServer(c)

	var data struct {
		Directory string `json:"directory"`
	}
	c.BindJSON(&data)

	// Default directory to "fastdl" if not provided, so users get a predictable location.
	if data.Directory == "" {
		data.Directory = "fastdl"
	}

	// Validate directory (prevent path traversal)
	cleaned := filepath.Clean(data.Directory)
	if strings.HasPrefix(cleaned, "..") || strings.Contains(cleaned, "..") {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"error": "Invalid directory path: path traversal not allowed",
		})
		return
	}
	data.Directory = cleaned

	// Update server configuration
	s.Config().SetFastDL(true, data.Directory)

	// Regenerate nginx config if FastDL is enabled
	cfg := config.Get()
	if cfg.System.FastDL.Enabled {
		manager := middleware.ExtractManager(c)
		if err := fastdl.GenerateNginxConfig(manager); err != nil {
			s.Log().WithError(err).Warn("failed to regenerate nginx config after FastDL enable")
		} else {
			fastdl.ReloadNginx()
		}
	}

	getServerFastDL(c)
}

// postServerFastDLDisable disables FastDL for a server.
// @Summary Disable FastDL for server
// @Tags Servers
// @Produce json
// @Param server path string true "Server identifier"
// @Success 200 {object} FastDLConfigResponse
// @Failure 404 {object} ErrorResponse
// @Security NodeToken
// @Router /api/servers/{server}/fastdl/disable [post]
func postServerFastDLDisable(c *gin.Context) {
	s := ExtractServer(c)

	// Update server configuration
	s.Config().SetFastDL(false, "")

	// Regenerate nginx config if FastDL is enabled
	cfg := config.Get()
	if cfg.System.FastDL.Enabled {
		manager := middleware.ExtractManager(c)
		if err := fastdl.GenerateNginxConfig(manager); err != nil {
			s.Log().WithError(err).Warn("failed to regenerate nginx config after FastDL disable")
		} else {
			fastdl.ReloadNginx()
		}
	}

	getServerFastDL(c)
}
