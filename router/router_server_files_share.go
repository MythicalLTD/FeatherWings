package router

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"emperror.dev/errors"
	"github.com/gin-gonic/gin"

	"github.com/mythicalltd/featherwings/internal/tempfiles"
	"github.com/mythicalltd/featherwings/router/middleware"
	"github.com/mythicalltd/featherwings/router/sharer"
)

// getServerShareJobs lists active temp upload share jobs for a server.
// @Summary List file share jobs
// @Tags Server Files
// @Produce json
// @Param server path string true "Server identifier"
// @Success 200 {object} ServerShareStatusResponse
// @Security NodeToken
// @Router /api/servers/{server}/files/share [get]
func getServerShareJobs(c *gin.Context) {
	s := ExtractServer(c)
	c.JSON(http.StatusOK, ServerShareStatusResponse{Shares: sharer.ByServer(s.ID())})
}

// postServerShareFile uploads a server file as a temp upload and returns a public share URL.
// @Summary Share server file via temp uploads
// @Tags Server Files
// @Accept json
// @Produce json
// @Param server path string true "Server identifier"
// @Param payload body ServerShareFileRequest true "Share request"
// @Success 200 {object} tempfiles.Result
// @Success 202 {object} RemoteShareAcceptedResponse "Background share"
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Security NodeToken
// @Router /api/servers/{server}/files/share [post]
func postServerShareFile(c *gin.Context) {
	s := ExtractServer(c)
	var data ServerShareFileRequest
	if err := c.BindJSON(&data); err != nil {
		return
	}

	path := strings.TrimLeft(data.File, "/")
	if path == "" {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"error": "A file path is required.",
		})
		return
	}
	if data.TTLDays != 1 && data.TTLDays != 5 {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"error": "ttl_days must be 1 or 5.",
		})
		return
	}
	if data.Password != "" && len(data.Password) < 4 {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"error": "password must be at least 4 characters.",
		})
		return
	}
	if data.DeleteKey != "" && len(data.DeleteKey) < 8 {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"error": "delete_key must be at least 8 characters.",
		})
		return
	}

	if err := s.Filesystem().IsIgnored(path); err != nil {
		middleware.CaptureAndAbort(c, err)
		return
	}

	f, st, err := s.Filesystem().File(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			c.AbortWithStatusJSON(http.StatusNotFound, gin.H{
				"error": "The requested resource was not found on the system.",
			})
			return
		}
		if strings.Contains(err.Error(), "filesystem: is a directory") {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
				"error": "Cannot share a directory.",
			})
			return
		}
		middleware.CaptureAndAbort(c, err)
		return
	}
	_ = f.Close()

	if st.IsDir() {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"error": "Cannot share a directory.",
		})
		return
	}
	if st.Mode()&os.ModeNamedPipe != 0 {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"error": "Cannot share files of this type.",
		})
		return
	}

	client := tempfiles.New(data.Token)
	if st.Size() > client.MaxBytes() {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"error": "File exceeds the maximum size allowed for temp uploads.",
		})
		return
	}
	if st.Size() <= 0 {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"error": "Cannot share an empty file.",
		})
		return
	}

	if len(sharer.ByServer(s.ID())) >= 3 {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"error": "This server has reached its limit of 3 simultaneous file shares. Please wait for one to complete before trying again.",
		})
		return
	}

	job := sharer.New(s, sharer.Request{
		File:      path,
		TTLDays:   data.TTLDays,
		Password:  data.Password,
		DeleteKey: data.DeleteKey,
		Token:     data.Token,
	})

	// Small files run in the foreground by default; large files always run in the background.
	background := st.Size() >= tempfiles.BackgroundMinBytes || data.Background
	if data.Foreground && st.Size() < tempfiles.BackgroundMinBytes {
		background = false
	}

	run := func() error {
		s.Log().WithField("share_id", job.Identifier).WithField("file", path).Info("starting temp upload share")
		if err := job.Execute(); err != nil {
			s.Log().WithField("share_id", job.Identifier).WithField("error", err).Error("failed to share file via temp uploads")
			return err
		}
		s.Log().WithField("share_id", job.Identifier).WithField("file", filepath.Base(path)).Info("completed temp upload share")
		return nil
	}

	if background {
		go func() {
			_ = run()
		}()
		c.JSON(http.StatusAccepted, RemoteShareAcceptedResponse{Identifier: job.Identifier})
		return
	}

	if err := run(); err != nil {
		middleware.CaptureAndAbort(c, err)
		return
	}

	_, _, _, result := job.Snapshot()
	if result == nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"error": "Share completed without a result.",
		})
		return
	}
	c.JSON(http.StatusOK, result)
}

// deleteServerShareJob cancels a background temp upload share job.
// @Summary Cancel file share job
// @Tags Server Files
// @Param server path string true "Server identifier"
// @Param share path string true "Share job identifier"
// @Success 204 "No Content"
// @Security NodeToken
// @Router /api/servers/{server}/files/share/{share} [delete]
func deleteServerShareJob(c *gin.Context) {
	s := ExtractServer(c)
	if job := sharer.ByID(c.Param("share")); job != nil && job.BelongsTo(s) {
		job.Cancel()
	}
	c.Status(http.StatusNoContent)
}
