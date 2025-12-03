package router

import (
	"net/http"
	"strconv"

	"github.com/apex/log"
	"github.com/gin-gonic/gin"

	"github.com/mythicalltd/featherwings/firewall"
	"github.com/mythicalltd/featherwings/internal/models"
	"github.com/mythicalltd/featherwings/router/middleware"
)

// getFirewallManager returns a firewall manager instance
func getFirewallManager() *firewall.Manager {
	return firewall.NewManager()
}

// FirewallRuleRequest represents a request to create or update a firewall rule
type FirewallRuleRequest struct {
	RemoteIP   string                  `json:"remote_ip" binding:"required"`
	ServerPort int                     `json:"server_port" binding:"required,min=1,max=65535"`
	Priority   int                     `json:"priority" binding:"min=0,max=10000"`
	Type       models.FirewallRuleType `json:"type" binding:"required,oneof=allow block"`
	Protocol   string                  `json:"protocol" binding:"omitempty,oneof=tcp udp"`
}

// FirewallRuleResponse represents a firewall rule in API responses
type FirewallRuleResponse struct {
	Data models.FirewallRule `json:"data"`
}

// FirewallRulesListResponse represents a list of firewall rules
type FirewallRulesListResponse struct {
	Data []models.FirewallRule `json:"data"`
}

// getFirewallRules returns all firewall rules for a server
// @Summary List firewall rules for a server
// @Tags Firewall
// @Produce json
// @Param server path string true "Server identifier"
// @Success 200 {object} router.FirewallRulesListResponse
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Security NodeToken
// @Router /api/servers/{server}/firewall [get]
func getFirewallRules(c *gin.Context) {
	s := middleware.ExtractServer(c)
	serverUUID := s.ID()

	rules, err := getFirewallManager().GetRules(serverUUID)
	if err != nil {
		middleware.CaptureAndAbort(c, err)
		return
	}

	c.JSON(http.StatusOK, FirewallRulesListResponse{Data: rules})
}

// getFirewallRule returns a specific firewall rule
// @Summary Get a firewall rule
// @Tags Firewall
// @Produce json
// @Param server path string true "Server identifier"
// @Param rule path int true "Rule ID"
// @Success 200 {object} router.FirewallRuleResponse
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Security NodeToken
// @Router /api/servers/{server}/firewall/{rule} [get]
func getFirewallRule(c *gin.Context) {
	ruleIDStr := c.Param("rule")
	ruleID, err := strconv.ParseUint(ruleIDStr, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "invalid rule ID"})
		return
	}

	s := middleware.ExtractServer(c)
	serverUUID := s.ID()

	rule, err := getFirewallManager().GetRuleByID(uint(ruleID))
	if err != nil {
		middleware.CaptureAndAbort(c, err)
		return
	}

	// Verify the rule belongs to this server
	if rule.ServerUUID != serverUUID {
		c.JSON(http.StatusNotFound, ErrorResponse{Error: "firewall rule not found"})
		return
	}

	c.JSON(http.StatusOK, FirewallRuleResponse{Data: *rule})
}

// postFirewallRule creates a new firewall rule
// @Summary Create a firewall rule
// @Tags Firewall
// @Accept json
// @Produce json
// @Param server path string true "Server identifier"
// @Param rule body router.FirewallRuleRequest true "Firewall rule configuration"
// @Success 201 {object} router.FirewallRuleResponse
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Security NodeToken
// @Router /api/servers/{server}/firewall [post]
func postFirewallRule(c *gin.Context) {
	s := middleware.ExtractServer(c)
	serverUUID := s.ID()

	var req FirewallRuleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: err.Error()})
		return
	}

	// Validate IP address
	if err := firewall.ValidateIP(req.RemoteIP); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: err.Error()})
		return
	}

	// Validate that the server has access to the requested port
	allocations := s.Config().Allocations
	if !firewall.ValidatePortForServer(&allocations, req.ServerPort) {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error: "server does not have access to the specified port",
		})
		return
	}

	// Set default protocol if not provided
	if req.Protocol == "" {
		req.Protocol = "tcp"
	}

	// Set default priority if not provided
	if req.Priority == 0 {
		req.Priority = 100
	}

	rule := &models.FirewallRule{
		ServerUUID: serverUUID,
		RemoteIP:   req.RemoteIP,
		ServerPort: req.ServerPort,
		Priority:   req.Priority,
		Type:       req.Type,
		Protocol:   req.Protocol,
	}

	if err := getFirewallManager().CreateRule(rule); err != nil {
		log.WithError(err).Error("failed to create firewall rule")
		middleware.CaptureAndAbort(c, err)
		return
	}

	c.JSON(http.StatusCreated, FirewallRuleResponse{Data: *rule})
}

// putFirewallRule updates an existing firewall rule
// @Summary Update a firewall rule
// @Tags Firewall
// @Accept json
// @Produce json
// @Param server path string true "Server identifier"
// @Param rule path int true "Rule ID"
// @Param rule body router.FirewallRuleRequest true "Firewall rule configuration"
// @Success 200 {object} router.FirewallRuleResponse
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Security NodeToken
// @Router /api/servers/{server}/firewall/{rule} [put]
func putFirewallRule(c *gin.Context) {
	ruleIDStr := c.Param("rule")
	ruleID, err := strconv.ParseUint(ruleIDStr, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "invalid rule ID"})
		return
	}

	s := middleware.ExtractServer(c)
	serverUUID := s.ID()

	// Verify the rule belongs to this server
	existingRule, err := getFirewallManager().GetRuleByID(uint(ruleID))
	if err != nil {
		middleware.CaptureAndAbort(c, err)
		return
	}

	if existingRule.ServerUUID != serverUUID {
		c.JSON(http.StatusNotFound, ErrorResponse{Error: "firewall rule not found"})
		return
	}

	var req FirewallRuleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: err.Error()})
		return
	}

	// Validate IP address if provided
	if req.RemoteIP != "" {
		if err := firewall.ValidateIP(req.RemoteIP); err != nil {
			c.JSON(http.StatusBadRequest, ErrorResponse{Error: err.Error()})
			return
		}
	}

	// Validate that the server has access to the requested port if port is being updated
	if req.ServerPort != 0 {
		allocations := s.Config().Allocations
		if !firewall.ValidatePortForServer(&allocations, req.ServerPort) {
			c.JSON(http.StatusBadRequest, ErrorResponse{
				Error: "server does not have access to the specified port",
			})
			return
		}
	}

	// Build update object
	updates := &models.FirewallRule{
		RemoteIP:   req.RemoteIP,
		ServerPort: req.ServerPort,
		Priority:   req.Priority,
		Type:       req.Type,
		Protocol:   req.Protocol,
	}

	if err := getFirewallManager().UpdateRule(uint(ruleID), updates); err != nil {
		middleware.CaptureAndAbort(c, err)
		return
	}

	// Fetch updated rule
	updatedRule, err := getFirewallManager().GetRuleByID(uint(ruleID))
	if err != nil {
		middleware.CaptureAndAbort(c, err)
		return
	}

	c.JSON(http.StatusOK, FirewallRuleResponse{Data: *updatedRule})
}

// deleteFirewallRule deletes a firewall rule
// @Summary Delete a firewall rule
// @Tags Firewall
// @Produce json
// @Param server path string true "Server identifier"
// @Param rule path int true "Rule ID"
// @Success 204 "No Content"
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Security NodeToken
// @Router /api/servers/{server}/firewall/{rule} [delete]
func deleteFirewallRule(c *gin.Context) {
	ruleIDStr := c.Param("rule")
	ruleID, err := strconv.ParseUint(ruleIDStr, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "invalid rule ID"})
		return
	}

	s := middleware.ExtractServer(c)
	serverUUID := s.ID()

	// Verify the rule belongs to this server
	rule, err := getFirewallManager().GetRuleByID(uint(ruleID))
	if err != nil {
		middleware.CaptureAndAbort(c, err)
		return
	}

	if rule.ServerUUID != serverUUID {
		c.JSON(http.StatusNotFound, ErrorResponse{Error: "firewall rule not found"})
		return
	}

	if err := getFirewallManager().DeleteRule(uint(ruleID)); err != nil {
		middleware.CaptureAndAbort(c, err)
		return
	}

	c.Status(http.StatusNoContent)
}

// postSyncFirewallRules syncs all firewall rules for a server to iptables
// @Summary Sync firewall rules to iptables
// @Tags Firewall
// @Produce json
// @Param server path string true "Server identifier"
// @Success 202 {object} map[string]interface{} "Sync started"
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Security NodeToken
// @Router /api/servers/{server}/firewall/sync [post]
func postSyncFirewallRules(c *gin.Context) {
	s := middleware.ExtractServer(c)
	serverUUID := s.ID()

	// Run sync in background to avoid timeout issues
	go func() {
		if err := getFirewallManager().SyncRules(serverUUID); err != nil {
			log.WithError(err).WithField("server", serverUUID).Error("failed to sync firewall rules in background")
		}
	}()

	// Return immediately with accepted status
	c.JSON(http.StatusAccepted, gin.H{"message": "firewall rules sync started"})
}

// getFirewallRulesByPort returns firewall rules for a specific port
// @Summary List firewall rules for a server port
// @Tags Firewall
// @Produce json
// @Param server path string true "Server identifier"
// @Param port path int true "Server port"
// @Success 200 {object} router.FirewallRulesListResponse
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Security NodeToken
// @Router /api/servers/{server}/firewall/port/{port} [get]
func getFirewallRulesByPort(c *gin.Context) {
	portStr := c.Param("port")
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "invalid port number"})
		return
	}

	s := middleware.ExtractServer(c)
	serverUUID := s.ID()

	rules, err := getFirewallManager().GetRulesByPort(serverUUID, port)
	if err != nil {
		middleware.CaptureAndAbort(c, err)
		return
	}

	c.JSON(http.StatusOK, FirewallRulesListResponse{Data: rules})
}
