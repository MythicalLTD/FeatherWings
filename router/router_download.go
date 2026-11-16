package router

import (
	"errors"
	"io"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/mythicalltd/featherwings/router/middleware"
	"github.com/mythicalltd/featherwings/router/tokens"
	"github.com/mythicalltd/featherwings/server/backup"
)

// Download tokens are not single-use. Browsers (e.g. Chromium's download
// protection), antivirus software and download managers commonly request the
// same signed URL more than once, and a resumed or parallel download is a new
// request as well. Treating the token as single-use made those requests fail
// with a 404 partway through large downloads. A download token stays valid until
// the expiry set by the Panel, and is still subject to the scope check and the
// user denylist. Upload tokens remain single-use.

// getDownloadBackup streams a server backup archive using a signed token.
// @Summary Download server backup
// @Tags Downloads
// @Produce application/octet-stream
// @Param token query string true "Signed backup token"
// @Success 200 {file} file
// @Success 206 {file} file
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Security ServerJWT
// @Router /download/backup [get]
// @Router /download/backup [head]
func getDownloadBackup(c *gin.Context) {
	client := middleware.ExtractApiClient(c)
	manager := middleware.ExtractManager(c)

	// Get the payload from the token.
	token := tokens.BackupPayload{}
	if err := tokens.ParseToken([]byte(c.Query("token")), &token); err != nil {
		middleware.CaptureAndAbort(c, err)
		return
	}

	// Validate that the BackupUuid field is actually a UUID and not some random characters or a
	// file path.
	if _, err := uuid.Parse(token.BackupUuid); err != nil {
		middleware.CaptureAndAbort(c, err)
		return
	}

	// Get the server using the UUID from the token.
	if _, ok := manager.Get(token.ServerUuid); !ok || token.Denylisted() || !token.HasScope(tokens.BackupDownload) {
		c.AbortWithStatusJSON(http.StatusNotFound, gin.H{
			"error": "The requested resource was not found on this server.",
		})
		return
	}
	middleware.ClearDeadlines(c)

	// Locate the backup on the local disk. We check this after token validation
	// for security, but before attempting to open the file.
	b, st, err := backup.LocateLocal(client, token.BackupUuid, token.ServerUuid)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			c.AbortWithStatusJSON(http.StatusNotFound, gin.H{
				"error": "The requested backup was not found on this server.",
			})
			return
		}

		middleware.CaptureAndAbort(c, err)
		return
	}

	// The use of `os` here is safe as backups are not stored within server
	// accessible directories.
	f, err := os.Open(b.Path())
	if err != nil {
		middleware.CaptureAndAbort(c, err)
		return
	}
	defer f.Close()

	serveDownload(c, f, st.Name(), st.ModTime())
}

// getDownloadFile downloads a specific server file using a signed token.
// @Summary Download server file
// @Tags Downloads
// @Produce application/octet-stream
// @Param token query string true "Signed file token"
// @Success 200 {file} file
// @Success 206 {file} file
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Security ServerJWT
// @Router /download/file [get]
// @Router /download/file [head]
func getDownloadFile(c *gin.Context) {
	manager := middleware.ExtractManager(c)
	token := tokens.FilePayload{}
	if err := tokens.ParseToken([]byte(c.Query("token")), &token); err != nil {
		middleware.CaptureAndAbort(c, err)
		return
	}

	s, ok := manager.Get(token.ServerUuid)
	if !ok || token.Denylisted() || !token.HasScope(tokens.FileDownload) {
		c.AbortWithStatusJSON(http.StatusNotFound, gin.H{
			"error": "The requested resource was not found on this server.",
		})
		return
	}
	middleware.ClearDeadlines(c)

	if err := s.Filesystem().IsIgnored(token.FilePath); err != nil {
		middleware.CaptureAndAbort(c, err)
		return
	}

	f, st, err := s.Filesystem().File(token.FilePath)
	if err != nil {
		middleware.CaptureAndAbort(c, err)
		return
	}
	defer f.Close()
	if st.IsDir() {
		c.AbortWithStatusJSON(http.StatusNotFound, gin.H{
			"error": "The requested resource was not found on this server.",
		})
		return
	}

	serveDownload(c, f, st.Name(), st.ModTime())
}

// serveDownload writes the content of f as a file attachment. Range, If-Range
// and HEAD requests are handled by http.ServeContent, which allows clients to
// resume an interrupted download or fetch it over multiple connections.
func serveDownload(c *gin.Context, f io.ReadSeeker, name string, modTime time.Time) {
	c.Header("Content-Disposition", "attachment; filename="+strconv.Quote(name))
	// Set explicitly so ServeContent does not sniff the content type.
	c.Header("Content-Type", "application/octet-stream")

	http.ServeContent(c.Writer, c.Request, name, modTime, f)
}
