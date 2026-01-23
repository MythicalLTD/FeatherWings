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

	response := FastDLConfigResponse{
		Enabled:   cfg.FastDL.Enabled,
		Directory: cfg.FastDL.Directory,
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
		if cfg.FastDL.Directory != "" {
			response.URL += "/" + strings.TrimPrefix(cfg.FastDL.Directory, "/")
		}
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

	// Validate directory if provided
	if data.Directory != "" {
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
