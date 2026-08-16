package router

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"

	"github.com/mythicalltd/featherwings/router/middleware"
	"github.com/mythicalltd/featherwings/server/diff"
)

// getServerFileRevisions lists the stored revisions for a file.
func getServerFileRevisions(c *gin.Context) {
	s := ExtractServer(c)
	key := diff.NormalizePath(c.Query("file"))
	if key == "" {
		c.JSON(http.StatusOK, gin.H{"revisions": []diff.RevisionInfo{}})
		return
	}
	if err := s.Filesystem().IsIgnored("/" + key); err != nil {
		c.JSON(http.StatusOK, gin.H{"revisions": []diff.RevisionInfo{}})
		return
	}

	revisions, err := s.Diff().List(key)
	if err != nil {
		middleware.CaptureAndAbort(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"revisions": revisions})
}

// getServerFileRevisionContents returns the raw contents of one revision.
func getServerFileRevisionContents(c *gin.Context) {
	s := ExtractServer(c)
	revisionID, err := strconv.ParseInt(c.Param("revision"), 10, 64)
	if err != nil || revisionID <= 0 {
		c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": "The requested revision was not found."})
		return
	}

	revisionPath, found, err := s.Diff().RevisionPath(revisionID)
	if err != nil {
		middleware.CaptureAndAbort(c, err)
		return
	}
	if !found {
		c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": "The requested revision was not found."})
		return
	}
	if requested := c.Query("file"); requested != "" && diff.NormalizePath(requested) != revisionPath {
		c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": "The requested revision was not found for this file."})
		return
	}
	if err := s.Filesystem().IsIgnored("/" + revisionPath); err != nil {
		c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": "The requested revision was not found."})
		return
	}

	content, err := s.Diff().GetContent(revisionID)
	if err != nil {
		middleware.CaptureAndAbort(c, err)
		return
	}
	c.Data(http.StatusOK, "application/octet-stream", content)
}
