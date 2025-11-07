package router

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/mythicalltd/featherwings/config"

	"emperror.dev/errors"
	"github.com/apex/log"
	"github.com/gin-gonic/gin"

	"github.com/mythicalltd/featherwings/router/downloader"
	"github.com/mythicalltd/featherwings/router/middleware"
	"github.com/mythicalltd/featherwings/router/tokens"
	"github.com/mythicalltd/featherwings/server"
	"github.com/mythicalltd/featherwings/server/transfer"
)

// getServer returns metadata for a single server in the collection.
// @Summary Get server
// @Tags Servers
// @Produce json
// @Param server path string true "Server identifier"
// @Success 200 {object} server.APIResponse
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Security NodeToken
// @Router /api/servers/{server} [get]
func getServer(c *gin.Context) {
	c.JSON(http.StatusOK, ExtractServer(c).ToAPIResponse())
}

// getServerLogs returns the logs for a given server instance.
// @Summary Tail server logs
// @Tags Servers
// @Produce json
// @Param server path string true "Server identifier"
// @Param size query int false "Number of lines" minimum(1) maximum(100)
// @Success 200 {object} router.ServerLogResponse
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Security NodeToken
// @Router /api/servers/{server}/logs [get]
func getServerLogs(c *gin.Context) {
	s := middleware.ExtractServer(c)

	l, _ := strconv.Atoi(c.DefaultQuery("size", "100"))
	if l <= 0 {
		l = 100
	} else if l > 100 {
		l = 100
	}

	out, err := s.ReadLogfile(l)
	if err != nil {
		middleware.CaptureAndAbort(c, err)
		return
	}

	c.JSON(http.StatusOK, ServerLogResponse{Data: out})
}

// getServerInstallLogs reads the installation log file for a server and returns the portion after the script output section header.
// @Summary Retrieve server install logs
// @Tags Servers
// @Produce json
// @Param server path string true "Server identifier"
// @Success 200 {object} router.ServerInstallLogResponse
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Security NodeToken
// @Router /api/servers/{server}/install-logs [get]
func getServerInstallLogs(c *gin.Context) {
	s := middleware.ExtractServer(c)
	ID := s.ID()

	filename := filepath.Join(config.Get().System.LogDirectory, "install", ID+".log")

	content, err := os.ReadFile(filename)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to read the log for the installation process."})
		return
	}

	// Try to find the script output section
	parts := strings.SplitN(string(content), "| Script Output\n| ------------------------------\n", 2)
	var output string
	if len(parts) == 2 {
		output = parts[1]
	} else {
		// If header not found, return full file
		output = string(content)
	}

	c.JSON(http.StatusOK, ServerInstallLogResponse{Data: output})
}

// postServerPower handles a request to control the power state of a server.
// @Summary Execute server power action
// @Tags Servers
// @Accept json
// @Param server path string true "Server identifier"
// @Param payload body router.ServerPowerRequest true "Power action"
// @Success 202 {string} string "Accepted"
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Failure 422 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Security NodeToken
// @Router /api/servers/{server}/power [post]
func postServerPower(c *gin.Context) {
	s := ExtractServer(c)

	var data struct {
		Action      server.PowerAction `json:"action"`
		WaitSeconds int                `json:"wait_seconds"`
	}

	if err := c.BindJSON(&data); err != nil {
		return
	}

	if !data.Action.IsValid() {
		c.AbortWithStatusJSON(http.StatusUnprocessableEntity, gin.H{
			"error": "The power action provided was not valid, should be one of \"stop\", \"start\", \"restart\", \"kill\"",
		})
		return
	}

	// Because we route all of the actual bootup process to a separate thread we need to
	// check the suspension status here, otherwise the user will hit the endpoint and then
	// just sit there wondering why it returns a success but nothing actually happens.
	//
	// We don't really care about any of the other actions at this point, they'll all result
	// in the process being stopped, which should have happened anyways if the server is suspended.
	if (data.Action == server.PowerActionStart || data.Action == server.PowerActionRestart) && s.IsSuspended() {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"error": "Cannot start or restart a server that is suspended.",
		})
		return
	}

	// Pass the actual heavy processing off to a separate thread to handle so that
	// we can immediately return a response from the server. Some of these actions
	// can take quite some time, especially stopping or restarting.
	go func(s *server.Server) {
		if data.WaitSeconds < 0 || data.WaitSeconds > 300 {
			data.WaitSeconds = 30
		}
		if err := s.HandlePowerAction(data.Action, data.WaitSeconds); err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				s.Log().WithField("action", data.Action).WithField("error", err).Warn("could not process server power action")
			} else if errors.Is(err, server.ErrIsRunning) {
				// Do nothing, this isn't something we care about for logging,
			} else {
				s.Log().WithFields(log.Fields{"action": data.Action, "wait_seconds": data.WaitSeconds, "error": err}).
					Error("encountered error processing a server power action in the background")
			}
		}
	}(s)

	c.Status(http.StatusAccepted)
}

// postServerCommands sends an array of commands to a running server instance.
// @Summary Send console commands
// @Tags Servers
// @Accept json
// @Param server path string true "Server identifier"
// @Param payload body router.ServerCommandsRequest true "Commands"
// @Success 204 "No Content"
// @Failure 400 {object} ErrorResponse
// @Failure 502 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Security NodeToken
// @Router /api/servers/{server}/commands [post]
func postServerCommands(c *gin.Context) {
	s := ExtractServer(c)

	if running, err := s.Environment.IsRunning(c.Request.Context()); err != nil {
		middleware.CaptureAndAbort(c, err)
		return
	} else if !running {
		c.AbortWithStatusJSON(http.StatusBadGateway, gin.H{
			"error": "Cannot send commands to a stopped server instance.",
		})
		return
	}

	var data struct {
		Commands []string `json:"commands"`
	}
	// BindJSON sends 400 if the request fails, all we need to do is return
	if err := c.BindJSON(&data); err != nil {
		return
	}

	for _, command := range data.Commands {
		if err := s.Environment.SendCommand(command); err != nil {
			s.Log().WithFields(log.Fields{"command": command, "error": err}).Warn("failed to send command to server instance")
		}
	}

	c.Status(http.StatusNoContent)
}

// postServerSync triggers a re-sync of the given server against the panel.
// @Summary Sync server state
// @Tags Servers
// @Param server path string true "Server identifier"
// @Success 204 "No Content"
// @Failure 500 {object} ErrorResponse
// @Security NodeToken
// @Router /api/servers/{server}/sync [post]
func postServerSync(c *gin.Context) {
	s := ExtractServer(c)

	if err := s.Sync(); err != nil {
		middleware.CaptureAndAbort(c, err)
	} else {
		c.Status(http.StatusNoContent)
	}
}

// postServerInstall performs a server installation in a background thread.
// @Summary Trigger server install
// @Tags Servers
// @Param server path string true "Server identifier"
// @Success 202 {string} string "Accepted"
// @Failure 500 {object} ErrorResponse
// @Security NodeToken
// @Router /api/servers/{server}/install [post]
func postServerInstall(c *gin.Context) {
	s := ExtractServer(c)

	go func(s *server.Server) {
		s.Log().Info("syncing server state with remote source before executing installation process")
		if err := s.Sync(); err != nil {
			s.Log().WithField("error", err).Error("failed to sync server state with Panel")
			return
		}

		if err := s.Install(); err != nil {
			s.Log().WithField("error", err).Error("failed to execute server installation process")
		}
	}(s)

	c.Status(http.StatusAccepted)
}

// postServerReinstall reinstalls a server.
// @Summary Reinstall server
// @Tags Servers
// @Param server path string true "Server identifier"
// @Success 202 {string} string "Accepted"
// @Failure 409 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Security NodeToken
// @Router /api/servers/{server}/reinstall [post]
func postServerReinstall(c *gin.Context) {
	s := ExtractServer(c)

	if s.ExecutingPowerAction() {
		c.AbortWithStatusJSON(http.StatusConflict, gin.H{
			"error": "Cannot execute server reinstall event while another power action is running.",
		})
		return
	}

	go func(s *server.Server) {
		if err := s.Reinstall(); err != nil {
			s.Log().WithField("error", err).Error("failed to complete server re-install process")
		}
	}(s)

	c.Status(http.StatusAccepted)
}

// deleteServer deletes a server from the wings daemon and dissociates its objects.
// @Summary Delete server
// @Tags Servers
// @Param server path string true "Server identifier"
// @Success 204 "No Content"
// @Failure 500 {object} ErrorResponse
// @Security NodeToken
// @Router /api/servers/{server} [delete]
func deleteServer(c *gin.Context) {
	s := middleware.ExtractServer(c)
	ID := s.ID()
	// Immediately suspend the server to prevent a user from attempting
	// to start it while this process is running.
	s.Config().SetSuspended(true)

	// Notify all websocket clients that the server is being deleted.
	// This is useful for two reasons, one to tell clients not to bother
	// retrying to connect to the websocket.  And two, for transfers when
	// the server has been successfully transferred to another node, and
	// the client needs to switch to the new node.
	if s.IsTransferring() {
		s.Events().Publish(server.TransferStatusEvent, transfer.StatusCompleted)
	}
	s.Events().Publish(server.DeletedEvent, nil)

	s.CleanupForDestroy()

	// Remove any pending remote file downloads for the server.
	for _, dl := range downloader.ByServer(s.ID()) {
		dl.Cancel()
	}

	// Remove the install log from this server
	filename := filepath.Join(config.Get().System.LogDirectory, "install", ID+".log")
	err := os.Remove(filename)
	if err != nil {
		log.WithFields(log.Fields{"server_id": ID, "error": err}).Warn("failed to remove server install log during deletion process")
	}

	// Remove all server backups unless config setting is specified
	if config.Get().System.Backups.RemoveBackupsOnServerDelete == true {
		if err := s.RemoveAllServerBackups(); err != nil {
			middleware.CaptureAndAbort(c, err)
			return
		}
	}

	// Destroy the environment; in Docker this will handle a running container and
	// forcibly terminate it before removing the container, so we do not need to handle
	// that here.
	if err := s.Environment.Destroy(); err != nil {
		middleware.CaptureAndAbort(c, err)
		return
	}

	// Once the environment is terminated, remove the server files from the system. This is
	// done in a separate process since failure is not the end of the world and can be
	// manually cleaned up after the fact.
	//
	// In addition, servers with large amounts of files can take some time to finish deleting,
	// so we don't want to block the HTTP call while waiting on this.
	go func(s *server.Server) {
		fs := s.Filesystem()
		p := fs.Path()
		_ = fs.UnixFS().Close()
		if err := os.RemoveAll(p); err != nil {
			log.WithFields(log.Fields{"path": p, "error": err}).Warn("failed to remove server files during deletion process")
		}
	}(s)

	middleware.ExtractManager(c).Remove(func(server *server.Server) bool {
		return server.ID() == s.ID()
	})

	c.Status(http.StatusNoContent)
}

// postServerDenyWSTokens adds websocket JTIs to the deny list preventing reuse.
// @Summary Invalidate websocket tokens
// @Tags Servers
// @Accept json
// @Param server path string true "Server identifier"
// @Param payload body router.ServerDenyTokenRequest true "Tokens"
// @Success 204 "No Content"
// @Failure 400 {object} ErrorResponse
// @Security NodeToken
// @Router /api/servers/{server}/ws/deny [post]
func postServerDenyWSTokens(c *gin.Context) {
	var data struct {
		JTIs []string `json:"jtis"`
	}

	if err := c.BindJSON(&data); err != nil {
		return
	}

	for _, jti := range data.JTIs {
		tokens.DenyJTI(jti)
	}

	c.Status(http.StatusNoContent)
}

// deleteAllServerBackups removes all backups for the specified server.
// @Summary Delete all server backups
// @Tags Servers
// @Param server path string true "Server identifier"
// @Success 204 "No Content"
// @Failure 500 {object} ErrorResponse
// @Security NodeToken
// @Router /api/servers/{server}/deleteAllBackups [delete]
func deleteAllServerBackups(c *gin.Context) {
	s := ExtractServer(c)

	if err := s.RemoveAllServerBackups(); err != nil {
		middleware.CaptureAndAbort(c, err)
	} else {
		c.Status(http.StatusNoContent)
	}
}
