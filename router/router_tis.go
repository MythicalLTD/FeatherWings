package router

import (
	"fmt"
	"net/http"
	"time"

	"emperror.dev/errors"
	"github.com/apex/log"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"github.com/mythicalltd/featherwings/internal/database"
	"github.com/mythicalltd/featherwings/internal/models"
	"github.com/mythicalltd/featherwings/router/middleware"
)

const (
	confirmationThreshold = 3
)

// HashSubmissionRequest defines the payload for submitting a hash report
type HashSubmissionRequest struct {
	Hash            string                 `json:"hash" binding:"required"`
	FileName        string                 `json:"fileName" binding:"required"`
	DetectionType   string                 `json:"detectionType" binding:"required"`
	ServerIdentifier string                `json:"serverIdentifier" binding:"required"`
	Metadata        map[string]interface{} `json:"metadata,omitempty"`
}

// HashSubmissionResponse conveys the outcome of a hash submission
type HashSubmissionResponse struct {
	Success        bool `json:"success"`
	Confirmed      bool `json:"confirmed"`
	DetectionCount int  `json:"detectionCount"`
}

// HashCheckRequest defines the payload for checking multiple hashes
type HashCheckRequest struct {
	Hashes []string `json:"hashes" binding:"required"`
}

// HashMatch represents a matched hash from the database
type HashMatch struct {
	Hash          string `json:"hash"`
	DetectionType string `json:"detection_type"`
	FileName      string `json:"file_name"`
}

// HashCheckResponse returns the results of a hash check
type HashCheckResponse struct {
	Matches      []HashMatch `json:"matches"`
	TotalChecked int         `json:"totalChecked"`
}

// TISStatsResponse contains system statistics
type TISStatsResponse struct {
	TotalHashes        int64                    `json:"totalHashes"`
	TotalServers       int64                    `json:"totalServers"`
	UnconfirmedHashes  int64                    `json:"unconfirmedHashes"`
	RecentDetections   int64                    `json:"recentDetections"`
	TopDetectionTypes  []DetectionTypeStat      `json:"topDetectionTypes"`
}

// DetectionTypeStat represents a detection type with its count
type DetectionTypeStat struct {
	DetectionType string `json:"detection_type"`
	Count         int64  `json:"count"`
}

// processConfirmedHash moves a hash from unconfirmed to confirmed status
func processConfirmedHash(hash string, data HashSubmissionRequest) error {
	db := database.Instance()

	// Start a transaction
	tx := db.Begin()
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	// Insert or update in malicious_hashes
	var maliciousHash models.MaliciousHash
	result := tx.Where("hash = ?", hash).First(&maliciousHash)
	
	if errors.Is(result.Error, gorm.ErrRecordNotFound) {
		// Create new record
		maliciousHash = models.MaliciousHash{
			Hash:          hash,
			FileName:      data.FileName,
			DetectionType: data.DetectionType,
			SourceServer:  data.ServerIdentifier,
			Metadata:      models.TISMetadata(data.Metadata),
			TimesDetected: 1,
		}
		if err := tx.Create(&maliciousHash).Error; err != nil {
			tx.Rollback()
			return errors.Wrap(err, "failed to create malicious hash")
		}
	} else if result.Error != nil {
		tx.Rollback()
		return errors.Wrap(result.Error, "failed to query malicious hash")
	} else {
		// Update existing record
		maliciousHash.LastSeen = time.Now().UTC()
		maliciousHash.TimesDetected++
		// Merge metadata
		if maliciousHash.Metadata == nil {
			maliciousHash.Metadata = models.TISMetadata{}
		}
		for k, v := range data.Metadata {
			maliciousHash.Metadata[k] = v
		}
		if err := tx.Save(&maliciousHash).Error; err != nil {
			tx.Rollback()
			return errors.Wrap(err, "failed to update malicious hash")
		}
	}

	// Insert or update in flagged_servers
	var flaggedServer models.FlaggedServer
	result = tx.Where("server_id = ?", data.ServerIdentifier).First(&flaggedServer)
	
	if errors.Is(result.Error, gorm.ErrRecordNotFound) {
		// Create new record
		flaggedServer = models.FlaggedServer{
			ServerID:       data.ServerIdentifier,
			DetectionTypes: models.DetectionTypes{data.DetectionType},
			LastHash:       hash,
			Metadata:       models.TISMetadata(data.Metadata),
			TimesFlagged:   1,
		}
		if err := tx.Create(&flaggedServer).Error; err != nil {
			tx.Rollback()
			return errors.Wrap(err, "failed to create flagged server")
		}
	} else if result.Error != nil {
		tx.Rollback()
		return errors.Wrap(result.Error, "failed to query flagged server")
	} else {
		// Update existing record
		flaggedServer.LastFlagged = time.Now().UTC()
		flaggedServer.TimesFlagged++
		flaggedServer.LastHash = hash
		
		// Add detection type if not already present
		detectionTypes := flaggedServer.DetectionTypes
		found := false
		for _, dt := range detectionTypes {
			if dt == data.DetectionType {
				found = true
				break
			}
		}
		if !found {
			detectionTypes = append(detectionTypes, data.DetectionType)
			flaggedServer.DetectionTypes = detectionTypes
		}
		
		// Merge metadata
		if flaggedServer.Metadata == nil {
			flaggedServer.Metadata = models.TISMetadata{}
		}
		for k, v := range data.Metadata {
			flaggedServer.Metadata[k] = v
		}
		
		if err := tx.Save(&flaggedServer).Error; err != nil {
			tx.Rollback()
			return errors.Wrap(err, "failed to update flagged server")
		}
	}

	// Remove from unconfirmed_hashes
	if err := tx.Where("hash = ?", hash).Delete(&models.UnconfirmedHash{}).Error; err != nil {
		tx.Rollback()
		return errors.Wrap(err, "failed to delete unconfirmed hash")
	}

	if err := tx.Commit().Error; err != nil {
		return errors.Wrap(err, "failed to commit transaction")
	}

	log.WithFields(log.Fields{
		"hash":            hash,
		"file_name":       data.FileName,
		"detection_type":  data.DetectionType,
		"server_id":       data.ServerIdentifier,
	}).Info("hash confirmed and added to main database")

	return nil
}

// postTISHash submits a hash for tracking
// @Summary Submit hash report
// @Description Submit a hash for tracking. The hash will be stored in the unconfirmed database and automatically promoted to confirmed status once it reaches the threshold.
// @Tags TIS
// @Accept json
// @Produce json
// @Param request body router.HashSubmissionRequest true "Hash submission data"
// @Success 200 {object} router.HashSubmissionResponse
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Security NodeToken
// @Router /api/tis/hashes [post]
func postTISHash(c *gin.Context) {
	var req HashSubmissionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, ErrorResponse{
			Error: fmt.Sprintf("Invalid request: %v", err),
		})
		return
	}

	db := database.Instance()
	
	// Start transaction
	tx := db.Begin()
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	// Insert or update in unconfirmed_hashes
	var unconfirmedHash models.UnconfirmedHash
	result := tx.Where("hash = ?", req.Hash).First(&unconfirmedHash)
	
	if errors.Is(result.Error, gorm.ErrRecordNotFound) {
		// Create new record
		unconfirmedHash = models.UnconfirmedHash{
			Hash:          req.Hash,
			FileName:      req.FileName,
			DetectionType: req.DetectionType,
			SourceServer:  req.ServerIdentifier,
			Metadata:      models.TISMetadata(req.Metadata),
			TimesDetected: 1,
		}
		if err := tx.Create(&unconfirmedHash).Error; err != nil {
			tx.Rollback()
			middleware.CaptureAndAbort(c, errors.Wrap(err, "failed to create unconfirmed hash"))
			return
		}
	} else if result.Error != nil {
		tx.Rollback()
		middleware.CaptureAndAbort(c, errors.Wrap(result.Error, "failed to query unconfirmed hash"))
		return
	} else {
		// Update existing record
		unconfirmedHash.LastSeen = time.Now().UTC()
		unconfirmedHash.TimesDetected++
		// Merge metadata
		if unconfirmedHash.Metadata == nil {
			unconfirmedHash.Metadata = models.TISMetadata{}
		}
		for k, v := range req.Metadata {
			unconfirmedHash.Metadata[k] = v
		}
		if err := tx.Save(&unconfirmedHash).Error; err != nil {
			tx.Rollback()
			middleware.CaptureAndAbort(c, errors.Wrap(err, "failed to update unconfirmed hash"))
			return
		}
	}

	// Check if threshold reached
	if unconfirmedHash.TimesDetected >= confirmationThreshold {
		// Process as confirmed hash
		if err := tx.Commit().Error; err != nil {
			middleware.CaptureAndAbort(c, errors.Wrap(err, "failed to commit transaction"))
			return
		}
		
		// Process confirmed hash outside transaction
		if err := processConfirmedHash(req.Hash, req); err != nil {
			middleware.CaptureAndAbort(c, err)
			return
		}
		
		log.WithFields(log.Fields{
			"hash":           req.Hash,
			"confirmed":      true,
			"detection_count": unconfirmedHash.TimesDetected,
		}).Info("hash submission processed and confirmed")
		
		c.JSON(http.StatusOK, HashSubmissionResponse{
			Success:        true,
			Confirmed:      true,
			DetectionCount: unconfirmedHash.TimesDetected,
		})
		return
	}

	// Commit transaction
	if err := tx.Commit().Error; err != nil {
		middleware.CaptureAndAbort(c, errors.Wrap(err, "failed to commit transaction"))
		return
	}

	log.WithFields(log.Fields{
		"hash":            req.Hash,
		"confirmed":       false,
		"detection_count": unconfirmedHash.TimesDetected,
	}).Info("hash submission processed")

	c.JSON(http.StatusOK, HashSubmissionResponse{
		Success:        true,
		Confirmed:      false,
		DetectionCount: unconfirmedHash.TimesDetected,
	})
}

// getTISHashes retrieves a list of confirmed malicious hashes
// @Summary Get confirmed hashes
// @Description Retrieve a list of confirmed malicious hashes (up to 1000 most recent)
// @Tags TIS
// @Produce json
// @Success 200 {array} models.MaliciousHash
// @Failure 500 {object} ErrorResponse
// @Security NodeToken
// @Router /api/tis/hashes [get]
func getTISHashes(c *gin.Context) {
	db := database.Instance()
	
	var hashes []models.MaliciousHash
	if err := db.Order("last_seen DESC").Limit(1000).Find(&hashes).Error; err != nil {
		middleware.CaptureAndAbort(c, errors.Wrap(err, "failed to fetch hashes"))
		return
	}

	log.WithFields(log.Fields{
		"count": len(hashes),
	}).Info("fetched confirmed hashes list")

	c.JSON(http.StatusOK, hashes)
}

// getTISServerStatus checks if a server has been flagged
// @Summary Check server status
// @Description Check if a server has been flagged for submitting malicious hashes
// @Tags TIS
// @Produce json
// @Param serverId path string true "Server identifier"
// @Success 200 {object} models.FlaggedServer
// @Success 200 {object} map[string]bool "Not flagged response"
// @Failure 500 {object} ErrorResponse
// @Security NodeToken
// @Router /api/tis/servers/{serverId} [get]
func getTISServerStatus(c *gin.Context) {
	serverID := c.Param("serverId")
	if serverID == "" {
		c.AbortWithStatusJSON(http.StatusBadRequest, ErrorResponse{
			Error: "server identifier is required",
		})
		return
	}

	db := database.Instance()
	
	var server models.FlaggedServer
	result := db.Where("server_id = ?", serverID).First(&server)
	
	if errors.Is(result.Error, gorm.ErrRecordNotFound) {
		log.WithFields(log.Fields{
			"server_id": serverID,
			"flagged":   false,
		}).Info("server status checked")
		
		c.JSON(http.StatusOK, gin.H{"flagged": false})
		return
	} else if result.Error != nil {
		middleware.CaptureAndAbort(c, errors.Wrap(result.Error, "failed to check server"))
		return
	}

	log.WithFields(log.Fields{
		"server_id": serverID,
		"flagged":   true,
	}).Info("server status checked")

	c.JSON(http.StatusOK, server)
}

// getTISStats retrieves system statistics
// @Summary Get statistics
// @Description Retrieve system statistics including total hashes, servers, and detection types
// @Tags TIS
// @Produce json
// @Success 200 {object} router.TISStatsResponse
// @Failure 500 {object} ErrorResponse
// @Security NodeToken
// @Router /api/tis/stats [get]
func getTISStats(c *gin.Context) {
	db := database.Instance()
	
	stats := TISStatsResponse{}
	
	// Total confirmed hashes
	if err := db.Model(&models.MaliciousHash{}).Count(&stats.TotalHashes).Error; err != nil {
		middleware.CaptureAndAbort(c, errors.Wrap(err, "failed to count total hashes"))
		return
	}
	
	// Total flagged servers
	if err := db.Model(&models.FlaggedServer{}).Count(&stats.TotalServers).Error; err != nil {
		middleware.CaptureAndAbort(c, errors.Wrap(err, "failed to count total servers"))
		return
	}
	
	// Unconfirmed hashes
	if err := db.Model(&models.UnconfirmedHash{}).Count(&stats.UnconfirmedHashes).Error; err != nil {
		middleware.CaptureAndAbort(c, errors.Wrap(err, "failed to count unconfirmed hashes"))
		return
	}
	
	// Recent detections (last 24 hours)
	twentyFourHoursAgo := time.Now().UTC().Add(-24 * time.Hour)
	if err := db.Model(&models.MaliciousHash{}).
		Where("last_seen > ?", twentyFourHoursAgo).
		Count(&stats.RecentDetections).Error; err != nil {
		middleware.CaptureAndAbort(c, errors.Wrap(err, "failed to count recent detections"))
		return
	}
	
	// Top detection types
	var detectionTypeStats []struct {
		DetectionType string
		Count         int64
	}
	if err := db.Model(&models.MaliciousHash{}).
		Select("detection_type, COUNT(*) as count").
		Group("detection_type").
		Order("count DESC").
		Limit(10).
		Scan(&detectionTypeStats).Error; err != nil {
		middleware.CaptureAndAbort(c, errors.Wrap(err, "failed to fetch top detection types"))
		return
	}
	
	stats.TopDetectionTypes = make([]DetectionTypeStat, len(detectionTypeStats))
	for i, dt := range detectionTypeStats {
		stats.TopDetectionTypes[i] = DetectionTypeStat{
			DetectionType: dt.DetectionType,
			Count:         dt.Count,
		}
	}

	log.WithFields(log.Fields{
		"total_hashes":        stats.TotalHashes,
		"total_servers":        stats.TotalServers,
		"unconfirmed_hashes":  stats.UnconfirmedHashes,
		"recent_detections":   stats.RecentDetections,
	}).Info("statistics fetched")

	c.JSON(http.StatusOK, stats)
}

// postTISCheckHashes checks multiple hashes against the confirmed database
// @Summary Batch hash check
// @Description Check multiple hashes against the confirmed database (max 1000 per request)
// @Tags TIS
// @Accept json
// @Produce json
// @Param request body router.HashCheckRequest true "Hashes to check"
// @Success 200 {object} router.HashCheckResponse
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Security NodeToken
// @Router /api/tis/check/hashes [post]
func postTISCheckHashes(c *gin.Context) {
	var req HashCheckRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, ErrorResponse{
			Error: fmt.Sprintf("Invalid request: %v", err),
		})
		return
	}

	if len(req.Hashes) == 0 {
		c.AbortWithStatusJSON(http.StatusBadRequest, ErrorResponse{
			Error: "hashes array cannot be empty",
		})
		return
	}

	if len(req.Hashes) > 1000 {
		c.AbortWithStatusJSON(http.StatusBadRequest, ErrorResponse{
			Error: "maximum 1000 hashes per request",
		})
		return
	}

	db := database.Instance()
	
	var matches []models.MaliciousHash
	if err := db.Where("hash IN ?", req.Hashes).
		Select("hash, detection_type, file_name").
		Find(&matches).Error; err != nil {
		middleware.CaptureAndAbort(c, errors.Wrap(err, "failed to check hashes"))
		return
	}

	result := HashCheckResponse{
		Matches:      make([]HashMatch, len(matches)),
		TotalChecked: len(req.Hashes),
	}

	for i, match := range matches {
		result.Matches[i] = HashMatch{
			Hash:          match.Hash,
			DetectionType: match.DetectionType,
			FileName:      match.FileName,
		}
	}

	log.WithFields(log.Fields{
		"checked_count": len(req.Hashes),
		"matches_found": len(matches),
	}).Info("hash check completed")

	c.JSON(http.StatusOK, result)
}

