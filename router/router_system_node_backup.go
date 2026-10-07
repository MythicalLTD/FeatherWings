package router

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/mythicalltd/featherwings/router/middleware"
	"github.com/mythicalltd/featherwings/system/nodebackup"
)

type nodeBackupCreateRequest struct {
	Mode      string `json:"mode"`
	Migration bool   `json:"migration"`
	Quiesce   *bool  `json:"quiesce"`
}

type nodeBackupRestoreRequest struct {
	UUID string `json:"uuid"`
}

// postSystemNodeBackup starts an asynchronous whole-node backup.
// @Summary Create node backup
// @Tags System
// @Accept json
// @Produce json
// @Param payload body nodeBackupCreateRequest true "Node backup request"
// @Success 202 {object} nodebackup.Info
// @Failure 400 {object} ErrorResponse
// @Failure 409 {object} ErrorResponse
// @Security NodeToken
// @Router /api/system/node-backup [post]
func postSystemNodeBackup(c *gin.Context) {
	var data nodeBackupCreateRequest
	if err := c.BindJSON(&data); err != nil {
		return
	}
	mode, err := nodebackup.ValidateMode(data.Mode)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	quiesce := true
	if data.Quiesce != nil {
		quiesce = *data.Quiesce
	}
	mgr := nodebackup.Default()
	mgr.SetStopper(middleware.ExtractManager(c))
	info, err := mgr.StartCreate(c.Request.Context(), mode, data.Migration, quiesce)
	if err != nil {
		if strings.Contains(err.Error(), "already in progress") {
			c.AbortWithStatusJSON(http.StatusConflict, gin.H{"error": err.Error()})
			return
		}
		middleware.CaptureAndAbort(c, err)
		return
	}
	c.JSON(http.StatusAccepted, info)
}

// getSystemNodeBackups lists local node backup archives.
// @Summary List node backups
// @Tags System
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Security NodeToken
// @Router /api/system/node-backups [get]
func getSystemNodeBackups(c *gin.Context) {
	list, err := nodebackup.List()
	if err != nil {
		middleware.CaptureAndAbort(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"data":   list,
		"active": nodebackup.Default().ActiveUUID(),
	})
}

// getSystemNodeBackup returns metadata for one node backup.
// @Summary Get node backup
// @Tags System
// @Produce json
// @Param backup path string true "Backup UUID"
// @Success 200 {object} nodebackup.Info
// @Failure 404 {object} ErrorResponse
// @Security NodeToken
// @Router /api/system/node-backups/{backup} [get]
func getSystemNodeBackup(c *gin.Context) {
	id := c.Param("backup")
	if _, err := uuid.Parse(id); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid backup uuid"})
		return
	}
	info, err := nodebackup.ReadMeta(id)
	if err != nil {
		if os.IsNotExist(err) {
			c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": "node backup not found"})
			return
		}
		middleware.CaptureAndAbort(c, err)
		return
	}
	if st, err := os.Stat(info.Path); err == nil {
		info.Bytes = st.Size()
	}
	c.JSON(http.StatusOK, info)
}

// getSystemNodeBackupDownload streams a completed node backup archive.
// @Summary Download node backup
// @Tags System
// @Produce application/gzip
// @Param backup path string true "Backup UUID"
// @Success 200 {file} binary
// @Failure 404 {object} ErrorResponse
// @Security NodeToken
// @Router /api/system/node-backups/{backup}/download [get]
func getSystemNodeBackupDownload(c *gin.Context) {
	id := c.Param("backup")
	if _, err := uuid.Parse(id); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid backup uuid"})
		return
	}
	info, err := nodebackup.ReadMeta(id)
	if err != nil {
		if os.IsNotExist(err) {
			c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": "node backup not found"})
			return
		}
		middleware.CaptureAndAbort(c, err)
		return
	}
	if info.Status != nodebackup.StatusCompleted {
		c.AbortWithStatusJSON(http.StatusConflict, gin.H{"error": "backup is not ready for download", "status": info.Status})
		return
	}
	if _, err := os.Stat(info.Path); err != nil {
		c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": "archive file missing"})
		return
	}
	c.Header("Content-Disposition", `attachment; filename="`+filepath.Base(info.Filename)+`"`)
	c.File(info.Path)
}

// deleteSystemNodeBackup removes a local node backup.
// @Summary Delete node backup
// @Tags System
// @Param backup path string true "Backup UUID"
// @Success 204
// @Failure 404 {object} ErrorResponse
// @Security NodeToken
// @Router /api/system/node-backups/{backup} [delete]
func deleteSystemNodeBackup(c *gin.Context) {
	id := c.Param("backup")
	if _, err := uuid.Parse(id); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid backup uuid"})
		return
	}
	if _, err := nodebackup.ReadMeta(id); err != nil {
		if os.IsNotExist(err) {
			c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": "node backup not found"})
			return
		}
		middleware.CaptureAndAbort(c, err)
		return
	}
	if nodebackup.Default().ActiveUUID() == id {
		c.AbortWithStatusJSON(http.StatusConflict, gin.H{"error": "cannot delete an in-progress backup"})
		return
	}
	if err := nodebackup.Delete(id); err != nil {
		middleware.CaptureAndAbort(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

// postSystemNodeBackupRestore restores a completed local node backup onto this host.
// @Summary Restore node backup
// @Tags System
// @Accept json
// @Produce json
// @Param payload body nodeBackupRestoreRequest true "Restore request"
// @Success 200 {object} map[string]string
// @Failure 400 {object} ErrorResponse
// @Security NodeToken
// @Router /api/system/node-backup/restore [post]
func postSystemNodeBackupRestore(c *gin.Context) {
	var data nodeBackupRestoreRequest
	if err := c.BindJSON(&data); err != nil {
		return
	}
	if _, err := uuid.Parse(data.UUID); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid backup uuid"})
		return
	}
	if err := nodebackup.Restore(c.Request.Context(), data.UUID); err != nil {
		middleware.CaptureAndAbort(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"message": "node backup restored; restart featherwings to apply configuration changes",
		"uuid":    data.UUID,
	})
}
