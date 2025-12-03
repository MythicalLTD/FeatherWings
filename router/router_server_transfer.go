package router

import (
	"context"
	"net/http"
	"strings"
	"time"

	"emperror.dev/errors"
	"github.com/gin-gonic/gin"

	"github.com/mythicalltd/featherwings/environment"
	"github.com/mythicalltd/featherwings/firewall"
	"github.com/mythicalltd/featherwings/router/middleware"
	"github.com/mythicalltd/featherwings/server"
	"github.com/mythicalltd/featherwings/server/transfer"
)

// postServerTransfer handles the start of a transfer for a server.
// @Summary Initiate server transfer
// @Tags Transfers
// @Accept json
// @Param server path string true "Server identifier"
// @Param payload body ServerTransferRequest true "Transfer request"
// @Success 202 {string} string "Accepted"
// @Failure 400 {object} ErrorResponse
// @Failure 409 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Security NodeToken
// @Router /api/servers/{server}/transfer [post]
func postServerTransfer(c *gin.Context) {
	var data ServerTransferRequest
	if err := c.BindJSON(&data); err != nil {
		return
	}

	s := ExtractServer(c)

	// Check if the server is already being transferred.
	// There will be another endpoint for resetting this value either by deleting the
	// server, or by canceling the transfer.
	if s.IsTransferring() {
		c.AbortWithStatusJSON(http.StatusConflict, gin.H{
			"error": "A transfer is already in progress for this server.",
		})
		return
	}

	manager := middleware.ExtractManager(c)

	notifyPanelOfFailure := func() {
		if err := manager.Client().SetTransferStatus(context.Background(), s.ID(), false); err != nil {
			s.Log().WithField("subsystem", "transfer").
				WithField("status", false).
				WithError(err).
				Error("failed to set transfer status")
		}

		s.Events().Publish(server.TransferStatusEvent, "failure")
		s.SetTransferring(false)
	}

	// Block the server from starting while we are transferring it.
	s.SetTransferring(true)

	// Ensure the server is offline. Sometimes a "No such container" error gets through
	// which means the server is already stopped. We can ignore that.
	if s.Environment.State() != environment.ProcessOfflineState {
		if err := s.Environment.WaitForStop(
			s.Context(),
			time.Second*15,
			false,
		); err != nil && !strings.Contains(strings.ToLower(err.Error()), "no such container") {
			s.SetTransferring(false)
			middleware.CaptureAndAbort(c, errors.Wrap(err, "failed to stop server for transfer"))
			return
		}
	}

	// Create a new transfer instance for this server.
	trnsfr := transfer.New(context.Background(), s)
	transfer.Outgoing().Add(trnsfr)

	go func() {
		defer transfer.Outgoing().Remove(trnsfr)

		if _, err := trnsfr.PushArchiveToTarget(data.URL, data.Token); err != nil {
			notifyPanelOfFailure()

			if err == context.Canceled {
				trnsfr.Log().Debug("canceled")
				trnsfr.SendMessage("Canceled.")
				return
			}

			trnsfr.Log().WithError(err).Error("failed to push archive to target")
			return
		}

		// Transfer successful - clean up firewall rules since server is moving to another node
		firewallMgr := firewall.NewManager()
		if err := firewallMgr.DeleteAllRulesForServer(s.ID()); err != nil {
			trnsfr.Log().WithError(err).Warn("failed to delete firewall rules after successful transfer")
		} else {
			trnsfr.Log().Info("cleaned up firewall rules after successful transfer")
		}

		// DO NOT NOTIFY THE PANEL OF SUCCESS HERE. The only node that should send
		// a success status is the destination node.  When we send a failure status,
		// the panel will automatically cancel the transfer and attempt to reset
		// the server state on the destination node, we just need to make sure
		// we clean up our statuses for failure.

		trnsfr.Log().Debug("transfer complete")
	}()

	c.Status(http.StatusAccepted)
}

// deleteServerTransfer cancels an outgoing transfer for a server.
// @Summary Cancel server transfer
// @Tags Transfers
// @Param server path string true "Server identifier"
// @Success 202 {string} string "Accepted"
// @Failure 409 {object} ErrorResponse
// @Security NodeToken
// @Router /api/servers/{server}/transfer [delete]
func deleteServerTransfer(c *gin.Context) {
	s := ExtractServer(c)

	if !s.IsTransferring() {
		c.AbortWithStatusJSON(http.StatusConflict, gin.H{
			"error": "Server is not currently being transferred.",
		})
		return
	}

	trnsfr := transfer.Outgoing().Get(s.ID())
	if trnsfr == nil {
		c.AbortWithStatusJSON(http.StatusConflict, gin.H{
			"error": "Server is not currently being transferred.",
		})
		return
	}

	trnsfr.Cancel()

	c.Status(http.StatusAccepted)
}
