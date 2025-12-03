package router

import (
	"context"
	"net/http"

	"emperror.dev/errors"
	"github.com/gin-gonic/gin"

	"github.com/mythicalltd/featherwings/router/middleware"
)

// ModuleInfo represents module information in API responses
type ModuleInfo struct {
	Name        string      `json:"name"`
	Description string      `json:"description"`
	Enabled     bool        `json:"enabled"`
	Config      interface{} `json:"config,omitempty"`
}

// ModuleListResponse contains a list of modules
type ModuleListResponse struct {
	Data []ModuleInfo `json:"data"`
}

// ModuleConfigRequest represents a configuration update request
type ModuleConfigRequest struct {
	Config interface{} `json:"config" binding:"required"`
}

// getModules returns a list of all registered modules
// @Summary List modules
// @Tags Modules
// @Produce json
// @Success 200 {object} router.ModuleListResponse
// @Failure 500 {object} ErrorResponse
// @Security NodeToken
// @Router /api/modules [get]
func getModules(c *gin.Context) {
	moduleManager := middleware.ExtractModuleManager(c)
	moduleList := moduleManager.List()

	data := make([]ModuleInfo, 0, len(moduleList))
	for _, module := range moduleList {
		data = append(data, ModuleInfo{
			Name:        module.Name(),
			Description: module.Description(),
			Enabled:     module.Enabled(),
		})
	}

	c.JSON(http.StatusOK, ModuleListResponse{Data: data})
}

// getModuleConfig returns the configuration for a specific module
// @Summary Get module configuration
// @Tags Modules
// @Produce json
// @Param module path string true "Module name"
// @Success 200 {object} router.ModuleInfo
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Security NodeToken
// @Router /api/modules/{module}/config [get]
func getModuleConfig(c *gin.Context) {
	moduleManager := middleware.ExtractModuleManager(c)
	moduleName := c.Param("module")

	module, exists := moduleManager.Get(moduleName)
	if !exists {
		middleware.CaptureAndAbort(c, errors.Errorf("module %s not found", moduleName))
		return
	}

	c.JSON(http.StatusOK, ModuleInfo{
		Name:        module.Name(),
		Description: module.Description(),
		Enabled:     module.Enabled(),
		Config:      module.GetConfig(),
	})
}

// putModuleConfig updates the configuration for a specific module
// @Summary Update module configuration
// @Tags Modules
// @Accept json
// @Produce json
// @Param module path string true "Module name"
// @Param config body router.ModuleConfigRequest true "Module configuration"
// @Success 200 {object} router.ModuleInfo
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Security NodeToken
// @Router /api/modules/{module}/config [put]
func putModuleConfig(c *gin.Context) {
	moduleManager := middleware.ExtractModuleManager(c)
	moduleName := c.Param("module")

	module, exists := moduleManager.Get(moduleName)
	if !exists {
		middleware.CaptureAndAbort(c, errors.Errorf("module %s not found", moduleName))
		return
	}

	var req ModuleConfigRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		middleware.CaptureAndAbort(c, errors.Wrap(err, "invalid request body"))
		return
	}

	if err := module.ValidateConfig(req.Config); err != nil {
		middleware.CaptureAndAbort(c, errors.Wrap(err, "invalid configuration"))
		return
	}

	if err := module.SetConfig(req.Config); err != nil {
		middleware.CaptureAndAbort(c, errors.Wrap(err, "failed to set configuration"))
		return
	}

	// Persist config to database
	if err := moduleManager.SaveModuleConfig(moduleName, module.GetConfig()); err != nil {
		// Log but don't fail the request
		middleware.ExtractLogger(c).WithError(err).Warn("failed to save module config to database")
	}

	c.JSON(http.StatusOK, ModuleInfo{
		Name:        module.Name(),
		Description: module.Description(),
		Enabled:     module.Enabled(),
		Config:      module.GetConfig(),
	})
}

// postModuleEnable enables a module
// @Summary Enable module
// @Tags Modules
// @Produce json
// @Param module path string true "Module name"
// @Success 200 {object} router.ModuleInfo
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Security NodeToken
// @Router /api/modules/{module}/enable [post]
func postModuleEnable(c *gin.Context) {
	moduleManager := middleware.ExtractModuleManager(c)
	moduleName := c.Param("module")

	// Add server manager to context for modules that need it
	ctx := context.WithValue(c.Request.Context(), "server_manager", middleware.ExtractManager(c))

	if err := moduleManager.Enable(ctx, moduleName); err != nil {
		middleware.CaptureAndAbort(c, err)
		return
	}

	module, _ := moduleManager.Get(moduleName)
	c.JSON(http.StatusOK, ModuleInfo{
		Name:        module.Name(),
		Description: module.Description(),
		Enabled:     module.Enabled(),
	})
}

// postModuleDisable disables a module
// @Summary Disable module
// @Tags Modules
// @Produce json
// @Param module path string true "Module name"
// @Success 200 {object} router.ModuleInfo
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Security NodeToken
// @Router /api/modules/{module}/disable [post]
func postModuleDisable(c *gin.Context) {
	moduleManager := middleware.ExtractModuleManager(c)
	moduleName := c.Param("module")

	if err := moduleManager.Disable(c.Request.Context(), moduleName); err != nil {
		middleware.CaptureAndAbort(c, err)
		return
	}

	module, _ := moduleManager.Get(moduleName)
	c.JSON(http.StatusOK, ModuleInfo{
		Name:        module.Name(),
		Description: module.Description(),
		Enabled:     module.Enabled(),
	})
}
