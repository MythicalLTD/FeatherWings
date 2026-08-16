package router

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"emperror.dev/errors"
	"github.com/apex/log"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"golang.org/x/sync/errgroup"

	"github.com/mythicalltd/featherwings/config"
	"github.com/mythicalltd/featherwings/internal/models"
	"github.com/mythicalltd/featherwings/internal/ufs"
	"github.com/mythicalltd/featherwings/router/downloader"
	"github.com/mythicalltd/featherwings/router/middleware"
	"github.com/mythicalltd/featherwings/router/tokens"
	"github.com/mythicalltd/featherwings/server"
	"github.com/mythicalltd/featherwings/server/filesystem"
	"github.com/mythicalltd/featherwings/server/operations"
)

// getServerFileContents returns the contents of a file on the server.
// @Summary Read file contents
// @Tags Server Files
// @Produce text/plain
// @Produce application/octet-stream
// @Param server path string true "Server identifier"
// @Param file query string true "File path"
// @Param download query bool false "Force download"
// @Success 200 {file} file
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Security NodeToken
// @Router /api/servers/{server}/files/contents [get]
func getServerFileContents(c *gin.Context) {
	s := middleware.ExtractServer(c)
	p := strings.TrimLeft(c.Query("file"), "/")
	if err := s.Filesystem().IsIgnored(p); err != nil {
		middleware.CaptureAndAbort(c, err)
		return
	}
	f, st, err := s.Filesystem().File(p)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			c.AbortWithStatusJSON(http.StatusNotFound, gin.H{
				"error":      "The requested resources was not found on the system.",
				"request_id": c.Writer.Header().Get("X-Request-Id")})
		} else if strings.Contains(err.Error(), "filesystem: is a directory") {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
				"error":      "Cannot perform that action: file is a directory.",
				"request_id": c.Writer.Header().Get("X-Request-Id"),
			})
		} else if strings.Contains(err.Error(), "bad path resolution") {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error":      "Access denied: The requested path is outside the server's root directory and cannot be accessed for security reasons.",
				"request_id": c.Writer.Header().Get("X-Request-Id"),
			})
		} else {
			middleware.CaptureAndAbort(c, err)
		}
		return
	}
	defer f.Close()
	// Don't allow a named pipe to be opened.
	//
	// @see https://github.com/pterodactyl/panel/issues/4059
	if st.Mode()&os.ModeNamedPipe != 0 {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"error": "Cannot open files of this type.",
		})
		return
	}

	c.Header("X-Mime-Type", st.Mimetype)
	c.Header("Content-Length", strconv.Itoa(int(st.Size())))
	// If a download parameter is included in the URL go ahead and attach the necessary headers
	// so that the file can be downloaded.
	if c.Query("download") != "" {
		c.Header("Content-Disposition", "attachment; filename="+strconv.Quote(st.Name()))
		c.Header("Content-Type", "application/octet-stream")
	}
	defer c.Writer.Flush()
	// If you don't do a limited reader here you will trigger a panic on write when
	// a different server process writes content to the file after you've already
	// determined the file size. This could lead to some weird content output but
	// it would technically be accurate based on the content at the time of the request.
	//
	// "http: wrote more than the declared Content-Length"
	//
	// @see https://github.com/pterodactyl/panel/issues/3131
	r := io.LimitReader(f, st.Size())
	if _, err = bufio.NewReader(r).WriteTo(c.Writer); err != nil {
		// Pretty sure this will unleash chaos on the response, but its a risk we can
		// take since a panic will at least be recovered and this should be incredibly
		// rare?
		middleware.CaptureAndAbort(c, err)
		return
	}
}

// getServerListDirectory returns the contents of a directory for a server.
// @Summary List directory contents
// @Tags Server Files
// @Produce json
// @Param server path string true "Server identifier"
// @Param directory query string true "Directory path"
// @Param directory_sizes query bool false "When true, include recursive directory_size for subfolders (cached; refreshes asynchronously)"
// @Success 200 {array} filesystem.Stat
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Security NodeToken
// @Router /api/servers/{server}/files/list-directory [get]
func getServerListDirectory(c *gin.Context) {
	s := middleware.ExtractServer(c)
	dir := c.Query("directory")
	withSizes := parseBoolWithDefault(c.Query("directory_sizes"), false)
	if stats, err := s.Filesystem().ListDirectory(dir, withSizes); err != nil {
		// If the error is that the folder does not exist return a 404.
		if errors.Is(err, os.ErrNotExist) {
			c.AbortWithStatusJSON(http.StatusNotFound, gin.H{
				"error": "The requested directory was not found on the server.",
			})
			return
		}
		middleware.CaptureAndAbort(c, err)
	} else {
		c.JSON(http.StatusOK, stats)
	}
}

// getServerArchiveList lists a single directory level inside an archive file (zip, tar, …)
// on the server without extracting the archive.
// @Summary List directory inside an archive
// @Tags Server Files
// @Produce json
// @Param server path string true "Server identifier"
// @Param directory query string false "Server directory containing the archive"
// @Param file query string true "Archive file path relative to directory"
// @Param path query string false "Path inside the archive to list (empty or . for root)"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} ErrorResponse
// @Failure 403 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Security NodeToken
// @Router /api/servers/{server}/files/archive/list [get]
func getServerArchiveList(c *gin.Context) {
	s := middleware.ExtractServer(c)
	root := c.Query("directory")
	archiveFile := strings.TrimSpace(c.Query("file"))
	if archiveFile == "" {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"error": "A file query parameter is required (path to the archive relative to directory).",
		})
		return
	}
	inner := c.Query("path")

	entries, truncated, err := s.Filesystem().ListArchiveContents(c.Request.Context(), root, archiveFile, inner)
	if err != nil {
		if filesystem.IsErrorCode(err, filesystem.ErrCodeUnknownArchive) {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
				"error": "The file is not an archive format that can be browsed, or it is not readable.",
			})
			return
		}
		if filesystem.IsErrorCode(err, filesystem.ErrCodeDenylistFile) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "Access to this archive is denied by the server file denylist.",
			})
			return
		}
		if errors.Is(err, os.ErrNotExist) {
			c.AbortWithStatusJSON(http.StatusNotFound, gin.H{
				"error": "The archive or path inside the archive was not found.",
			})
			return
		}
		middleware.CaptureAndAbort(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"contents":  entries,
		"truncated": truncated,
	})
}

// postServerArchiveExtract extracts specific paths from an on-disk archive into a destination directory.
// @Summary Extract selected paths from archive
// @Tags Server Files
// @Accept json
// @Param server path string true "Server identifier"
// @Param payload body ServerArchiveExtractRequest true "Extraction request"
// @Success 204 "No Content"
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Security NodeToken
// @Router /api/servers/{server}/files/archive/extract [post]
func postServerArchiveExtract(c *gin.Context) {
	var data ServerArchiveExtractRequest
	if err := c.BindJSON(&data); err != nil {
		return
	}
	if len(data.Entries) == 0 {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"error": "At least one archive entry path is required.",
		})
		return
	}

	s := middleware.ExtractServer(c)
	err := s.Filesystem().ExtractArchiveMembers(c.Request.Context(), data.Root, data.File, data.Destination, data.Entries)
	if err != nil {
		if filesystem.IsErrorCode(err, filesystem.ErrCodeUnknownArchive) {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
				"error": "The archive is not in a supported format or could not be read.",
			})
			return
		}
		if filesystem.IsErrorCode(err, filesystem.ErrCodeDiskSpace) {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
				"error": "This server does not have enough disk space to extract the selected files.",
			})
			return
		}
		if filesystem.IsErrorCode(err, filesystem.ErrCodeDenylistFile) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "Extraction is blocked by the file denylist.",
			})
			return
		}
		if strings.Contains(err.Error(), "too many files") {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
				"error": err.Error(),
			})
			return
		}
		middleware.CaptureAndAbort(c, err)
		return
	}

	c.Status(http.StatusNoContent)
}

// putServerRenameFiles renames (or moves) files for a server.
// @Summary Rename files
// @Tags Server Files
// @Accept json
// @Param server path string true "Server identifier"
// @Param payload body ServerRenameRequest true "Rename operations"
// @Success 204 "No Content"
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Failure 422 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Security NodeToken
// @Router /api/servers/{server}/files/rename [put]
func putServerRenameFiles(c *gin.Context) {
	s := ExtractServer(c)

	var data ServerRenameRequest
	// BindJSON sends 400 if the request fails, all we need to do is return
	if err := c.BindJSON(&data); err != nil {
		return
	}

	if len(data.Files) == 0 {
		c.AbortWithStatusJSON(http.StatusUnprocessableEntity, gin.H{
			"error": "No files to move or rename were provided.",
		})
		return
	}

	g, ctx := errgroup.WithContext(c.Request.Context())
	// Loop over the array of files passed in and perform the move or rename action against each.
	for _, p := range data.Files {
		pf := path.Join(data.Root, p.From)
		pt := path.Join(data.Root, p.To)

		g.Go(func(pf, pt string) func() error {
			return func() error {
				select {
				case <-ctx.Done():
					return ctx.Err()
				default:
					fs := s.Filesystem()
					// Ignore renames on a file that is on the denylist (both as the rename from or
					// the rename to value).
					if err := fs.IsIgnored(pf, pt); err != nil {
						return err
					}
					if err := fs.Rename(pf, pt); err != nil {
						// Return nil if the error is an is not exists.
						if errors.Is(err, os.ErrNotExist) {
							s.Log().WithField("error", err).
								WithField("from_path", pf).
								WithField("to_path", pt).
								Warn("failed to rename: source or target does not exist")
							return nil
						}
						return err
					}
					if err := s.Diff().RenameFile(pf, pt); err != nil {
						s.Log().WithError(err).WithField("from_path", pf).WithField("to_path", pt).
							Warn("failed to rename file revision history")
					}
					return nil
				}
			}
		}(pf, pt))
	}

	if err := g.Wait(); err != nil {
		if errors.Is(err, os.ErrExist) {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
				"error": "Cannot move or rename file, destination already exists.",
			})
			return
		}

		middleware.CaptureAndAbort(c, err)
		return
	}

	c.Status(http.StatusNoContent)
}

// postServerCopyFile copies a server file.
// @Summary Copy file
// @Tags Server Files
// @Accept json
// @Param server path string true "Server identifier"
// @Param payload body ServerCopyRequest true "Copy request"
// @Success 204 "No Content"
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Security NodeToken
// @Router /api/servers/{server}/files/copy [post]
func postServerCopyFile(c *gin.Context) {
	s := ExtractServer(c)

	var data ServerCopyRequest
	// BindJSON sends 400 if the request fails, all we need to do is return
	if err := c.BindJSON(&data); err != nil {
		return
	}

	if err := s.Filesystem().IsIgnored(data.Location); err != nil {
		middleware.CaptureAndAbort(c, err)
		return
	}
	if err := s.Filesystem().Copy(data.Location); err != nil {
		middleware.CaptureAndAbort(c, err)
		return
	}

	c.Status(http.StatusNoContent)
}

// postServerDeleteFiles deletes files from a server.
// @Summary Delete files
// @Tags Server Files
// @Accept json
// @Param server path string true "Server identifier"
// @Param payload body ServerDeleteRequest true "Delete request"
// @Success 204 "No Content"
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Security NodeToken
// @Router /api/servers/{server}/files/delete [post]
func postServerDeleteFiles(c *gin.Context) {
	s := ExtractServer(c)

	var data ServerDeleteRequest

	if err := c.BindJSON(&data); err != nil {
		return
	}

	if len(data.Files) == 0 {
		c.AbortWithStatusJSON(http.StatusUnprocessableEntity, gin.H{
			"error": "No files were specified for deletion.",
		})
		return
	}

	fs := s.Filesystem()

	if data.UseTrash && !data.Permanent {
		limits := filesystem.TrashLimits{}
		if data.Trash != nil {
			limits = filesystem.TrashLimits{
				MaxSizeBytes:  data.Trash.MaxSizeBytes,
				RetentionDays: data.Trash.RetentionDays,
			}
		}
		if err := fs.MoveFilesToTrash(data.Root, data.Files, limits); err != nil {
			middleware.CaptureAndAbort(c, err)
			return
		}
		for _, p := range data.Files {
			if err := s.Diff().ForgetFile(path.Join(data.Root, p)); err != nil {
				s.Log().WithError(err).WithField("path", path.Join(data.Root, p)).
					Warn("failed to forget file revision history")
			}
		}
		c.Status(http.StatusNoContent)
		return
	}

	g, ctx := errgroup.WithContext(c.Request.Context())

	// Loop over the array of files passed in and delete them. If any of the file deletions
	// fail just abort the process entirely.
	for _, p := range data.Files {
		pi := path.Join(data.Root, p)

		g.Go(func(pi string) func() error {
			return func() error {
				select {
				case <-ctx.Done():
					return ctx.Err()
				default:
					return fs.SafeDeleteRecursively(pi)
				}
			}
		}(pi))
	}

	if err := g.Wait(); err != nil {
		middleware.CaptureAndAbort(c, err)
		return
	}

	for _, p := range data.Files {
		if err := s.Diff().ForgetFile(path.Join(data.Root, p)); err != nil {
			s.Log().WithError(err).WithField("path", path.Join(data.Root, p)).
				Warn("failed to forget file revision history")
		}
	}

	c.Status(http.StatusNoContent)
}

// getServerTrash lists trashed files for a server.
func getServerTrash(c *gin.Context) {
	s := ExtractServer(c)
	limits := filesystem.TrashLimits{
		MaxSizeBytes:  parseInt64Default(c.Query("max_size_bytes"), 0),
		RetentionDays: parseIntDefault(c.Query("retention_days"), 0),
	}
	entries, total, err := s.Filesystem().ListTrash(limits)
	if err != nil {
		middleware.CaptureAndAbort(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"entries":    entries,
		"total_size": total,
	})
}

// postServerTrashRestore restores files from the trash bin.
func postServerTrashRestore(c *gin.Context) {
	s := ExtractServer(c)
	var data ServerTrashRestoreRequest
	if err := c.BindJSON(&data); err != nil {
		return
	}
	if len(data.IDs) == 0 {
		c.AbortWithStatusJSON(http.StatusUnprocessableEntity, gin.H{
			"error": "No trash entries were specified for restoration.",
		})
		return
	}
	if err := s.Filesystem().RestoreTrashEntries(data.IDs, data.Overwrite); err != nil {
		middleware.CaptureAndAbort(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

// postServerTrashDelete permanently deletes selected trash entries.
func postServerTrashDelete(c *gin.Context) {
	s := ExtractServer(c)
	var data ServerTrashDeleteRequest
	if err := c.BindJSON(&data); err != nil {
		return
	}
	if len(data.IDs) == 0 {
		c.AbortWithStatusJSON(http.StatusUnprocessableEntity, gin.H{
			"error": "No trash entries were specified for deletion.",
		})
		return
	}
	if err := s.Filesystem().DeleteTrashEntries(data.IDs); err != nil {
		middleware.CaptureAndAbort(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

// deleteServerTrash empties the entire trash bin for a server.
func deleteServerTrash(c *gin.Context) {
	s := ExtractServer(c)
	if err := s.Filesystem().EmptyTrash(); err != nil {
		middleware.CaptureAndAbort(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

func parseInt64Default(raw string, def int64) int64 {
	if raw == "" {
		return def
	}
	v, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return def
	}
	return v
}

func parseIntDefault(raw string, def int) int {
	if raw == "" {
		return def
	}
	v, err := strconv.Atoi(raw)
	if err != nil {
		return def
	}
	return v
}

// postServerWriteFile writes the contents of the request to a file on a server.
// @Summary Write file contents
// @Tags Server Files
// @Produce json
// @Param server path string true "Server identifier"
// @Param file query string true "File path"
// @Param Content-Length header int true "Content length"
// @Success 204 "No Content"
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Security NodeToken
// @Router /api/servers/{server}/files/write [post]
func postServerWriteFile(c *gin.Context) {
	s := ExtractServer(c)

	f := c.Query("file")
	f = "/" + strings.TrimLeft(f, "/")

	if err := s.Filesystem().IsIgnored(f); err != nil {
		middleware.CaptureAndAbort(c, err)
		return
	}

	// A content length of -1 means the actual length is unknown.
	if c.Request.ContentLength == -1 {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"error": "Missing Content-Length",
		})
		return
	}

	var (
		before        []byte
		after         []byte
		historyRecord bool
		body          io.Reader = c.Request.Body
	)
	history := s.Diff()
	if history.Enabled() && c.Request.ContentLength >= 0 && uint64(c.Request.ContentLength) <= history.FileSizeCap() {
		historyRecord = true
		if st, statErr := s.Filesystem().Stat(f); statErr == nil {
			if st.IsDir() || st.Size() > int64(history.FileSizeCap()) {
				historyRecord = false
			} else {
				existing, _, openErr := s.Filesystem().File(f)
				if openErr != nil {
					historyRecord = false
				} else {
					before = make([]byte, st.Size())
					if _, readErr := io.ReadFull(existing, before); readErr != nil {
						historyRecord = false
					}
					_ = existing.Close()
				}
			}
		} else if !errors.Is(statErr, os.ErrNotExist) && !strings.Contains(statErr.Error(), "not exist") {
			historyRecord = false
		}
		if historyRecord {
			var readErr error
			after, readErr = io.ReadAll(io.LimitReader(c.Request.Body, int64(history.FileSizeCap())+1))
			if readErr != nil || int64(len(after)) != c.Request.ContentLength {
				historyRecord = false
			}
			body = bytes.NewReader(after)
		}
	}

	if err := s.Filesystem().Write(f, body, c.Request.ContentLength, 0o644); err != nil {
		if filesystem.IsErrorCode(err, filesystem.ErrCodeIsDirectory) {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
				"error": "Cannot write file, name conflicts with an existing directory by the same name.",
			})
			return
		}

		middleware.CaptureAndAbort(c, err)
		return
	}

	if historyRecord {
		if _, err := history.RecordEdit(f, before, after, ""); err != nil {
			s.Log().WithError(err).WithField("path", f).Warn("failed to record file revision")
		}
	}

	c.Status(http.StatusNoContent)
}

// getServerPullingFiles returns all in-progress file downloads and their progress.
// @Summary List remote downloads
// @Tags Server Files
// @Produce json
// @Param server path string true "Server identifier"
// @Success 200 {object} ServerPullStatusResponse
// @Failure 500 {object} ErrorResponse
// @Security NodeToken
// @Router /api/servers/{server}/files/pull [get]
func getServerPullingFiles(c *gin.Context) {
	s := ExtractServer(c)
	c.JSON(http.StatusOK, ServerPullStatusResponse{Downloads: downloader.ByServer(s.ID())})
}

// postServerPullRemoteFile writes the contents of the remote URL to a file on a server.
// @Summary Pull remote file
// @Tags Server Files
// @Accept json
// @Produce json
// @Param server path string true "Server identifier"
// @Param payload body ServerPullRemoteRequest true "Remote pull request"
// @Success 200 {object} filesystem.Stat
// @Success 202 {object} RemoteDownloadAcceptedResponse "Background download"
// @Failure 400 {object} ErrorResponse
// @Failure 409 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Security NodeToken
// @Router /api/servers/{server}/files/pull [post]
func postServerPullRemoteFile(c *gin.Context) {
	s := ExtractServer(c)
	var data ServerPullRemoteRequest
	if err := c.BindJSON(&data); err != nil {
		return
	}

	// Handle the deprecated Directory field in the struct until it is removed.
	if data.Directory != "" && data.RootPath == "" {
		data.RootPath = data.Directory
	}

	u, err := url.Parse(data.URL)
	if err != nil {
		if e, ok := err.(*url.Error); ok {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
				"error": "An error occurred while parsing that URL: " + e.Err.Error(),
			})
			return
		}
		middleware.CaptureAndAbort(c, err)
		return
	}

	if err := s.Filesystem().HasSpaceErr(true); err != nil {
		middleware.CaptureAndAbort(c, err)
		return
	}
	// Do not allow more than three simultaneous remote file downloads at one time.
	if len(downloader.ByServer(s.ID())) >= 3 {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"error": "This server has reached its limit of 3 simultaneous remote file downloads at once. Please wait for one to complete before trying again.",
		})
		return
	}

	dl := downloader.New(s, downloader.DownloadRequest{
		Directory: data.RootPath,
		URL:       u,
		FileName:  data.FileName,
		UseHeader: data.UseHeader,
	})
	if err := s.Filesystem().IsIgnored(dl.Path()); err != nil {
		middleware.CaptureAndAbort(c, err)
		return
	}
	download := func() error {
		s.Log().WithField("download_id", dl.Identifier).WithField("url", u.String()).Info("starting pull of remote file to disk")
		if err := dl.Execute(); err != nil {
			s.Log().WithField("download_id", dl.Identifier).WithField("error", err).Error("failed to pull remote file")
			return err
		} else {
			s.Log().WithField("download_id", dl.Identifier).Info("completed pull of remote file")
		}
		return nil
	}
	if !data.Foreground {
		go func() {
			_ = download()
		}()
		c.JSON(http.StatusAccepted, RemoteDownloadAcceptedResponse{Identifier: dl.Identifier})
		return
	}

	if err := download(); err != nil {
		middleware.CaptureAndAbort(c, err)
		return
	}

	st, err := s.Filesystem().Stat(dl.Path())
	if err != nil {
		middleware.CaptureAndAbort(c, err)
		return
	}
	c.JSON(http.StatusOK, &st)
}

// deleteServerPullRemoteFile stops a remote file download if it exists and belongs to this server.
// @Summary Cancel remote download
// @Tags Server Files
// @Param server path string true "Server identifier"
// @Param download path string true "Download identifier"
// @Success 204 "No Content"
// @Security NodeToken
// @Router /api/servers/{server}/files/pull/{download} [delete]
func deleteServerPullRemoteFile(c *gin.Context) {
	s := ExtractServer(c)
	if dl := downloader.ByID(c.Param("download")); dl != nil && dl.BelongsTo(s) {
		dl.Cancel()
	}
	c.Status(http.StatusNoContent)
}

// postServerCreateDirectory creates a directory on a server.
// @Summary Create directory
// @Tags Server Files
// @Accept json
// @Param server path string true "Server identifier"
// @Param payload body ServerCreateDirectoryRequest true "Directory request"
// @Success 204 "No Content"
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Security NodeToken
// @Router /api/servers/{server}/files/create-directory [post]
func postServerCreateDirectory(c *gin.Context) {
	s := ExtractServer(c)

	var data ServerCreateDirectoryRequest
	// BindJSON sends 400 if the request fails, all we need to do is return
	if err := c.BindJSON(&data); err != nil {
		return
	}

	if err := s.Filesystem().CreateDirectory(data.Name, data.Path); err != nil {
		if errors.Is(err, ufs.ErrNotDirectory) {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
				"error": "Part of the path being created is not a directory (ENOTDIR).",
			})
			return
		}
		if errors.Is(err, os.ErrExist) {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
				"error": "Cannot create directory, name conflicts with an existing file by the same name.",
			})
			return
		}

		middleware.CaptureAndAbort(c, err)
		return
	}
	if err := s.Filesystem().Chown(filepath.Join(data.Path, data.Name)); err != nil {
		middleware.CaptureAndAbort(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

// postServerCompressFiles creates an archive from provided files.
// @Summary Compress files
// @Tags Server Files
// @Accept json
// @Produce json
// @Param server path string true "Server identifier"
// @Param payload body ServerArchiveRequest true "Archive request"
// @Success 200 {object} filesystem.Stat
// @Success 202 {object} FileOperationAcceptedResponse "Background operation"
// @Failure 400 {object} ErrorResponse
// @Failure 409 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Security NodeToken
// @Router /api/servers/{server}/files/compress [post]
func postServerCompressFiles(c *gin.Context) {
	s := ExtractServer(c)

	var data ServerArchiveRequest

	if err := c.BindJSON(&data); err != nil {
		return
	}

	if len(data.Files) == 0 {
		c.AbortWithStatusJSON(http.StatusUnprocessableEntity, gin.H{
			"error": "No files were passed through to be compressed.",
		})
		return
	}

	if !s.Filesystem().HasSpaceAvailable(true) {
		c.AbortWithStatusJSON(http.StatusConflict, gin.H{
			"error": "This server does not have enough available disk space to generate a compressed archive.",
		})
		return
	}

	if data.Extension == "" && data.Format != "" {
		data.Extension = archiveFormatExtension(data.Format)
	}
	if data.Extension == "" {
		data.Extension = "tar.gz"
	}

	if !fileOperationForeground(c, data.Foreground) {
		bytesTotal, filesTotal := estimateOperationPaths(s.Filesystem().Path(), data.RootPath, data.Files)
		processed := &atomic.Uint64{}
		total := &atomic.Uint64{}
		filesProcessed := &atomic.Uint64{}
		total.Store(bytesTotal)
		op := operations.Operation{
			Type:            "compress",
			Path:            cleanOperationPath(data.RootPath),
			DestinationPath: compressionDestination(data),
			StartTime:       time.Now().UTC(),
			BytesProcessed:  processed,
			BytesTotal:      total,
			FilesProcessed:  filesProcessed,
		}
		id, _ := s.Operations().Add(op)
		opCtx, _ := s.Operations().Context(id)
		go func() {
			_, _, err := s.Filesystem().CompressFiles(opCtx, data.RootPath, data.Name, data.Files, data.Extension)
			if err != nil {
				s.Operations().Fail(id, operationErrorMessage(err))
				return
			}
			processed.Store(total.Load())
			filesProcessed.Store(filesTotal)
			s.Operations().Complete(id)
		}()
		c.JSON(http.StatusAccepted, FileOperationAcceptedResponse{Identifier: id.String()})
		return
	}

	f, mimetype, err := s.Filesystem().CompressFiles(c.Request.Context(), data.RootPath, data.Name, data.Files, data.Extension)
	if err != nil {
		middleware.CaptureAndAbort(c, err)
		return
	}

	c.JSON(http.StatusOK, &filesystem.Stat{
		FileInfo: f,
		Mimetype: mimetype,
	})
}

// postServerDecompressFiles unpacks an archive that exists on the server into the provided root path.
// @Summary Decompress archive
// @Tags Server Files
// @Accept json
// @Param server path string true "Server identifier"
// @Param payload body ServerDecompressRequest true "Decompression request"
// @Success 204 "No Content"
// @Success 202 {object} FileOperationAcceptedResponse "Background operation"
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Security NodeToken
// @Router /api/servers/{server}/files/decompress [post]
func postServerDecompressFiles(c *gin.Context) {
	var data ServerDecompressRequest
	if err := c.BindJSON(&data); err != nil {
		return
	}

	s := middleware.ExtractServer(c)
	lg := middleware.ExtractLogger(c).WithFields(log.Fields{"root_path": data.RootPath, "file": data.File})

	if !fileOperationForeground(c, data.Foreground) {
		totalBytes := uint64(0)
		if st, statErr := s.Filesystem().Stat(path.Join(data.RootPath, data.File)); statErr == nil && st.Size() > 0 {
			totalBytes = uint64(st.Size())
		}
		processed := &atomic.Uint64{}
		total := &atomic.Uint64{}
		total.Store(totalBytes)
		filesProcessed := &atomic.Uint64{}
		op := operations.Operation{
			Type:            "decompress",
			Path:            cleanOperationPath(path.Join(data.RootPath, data.File)),
			DestinationPath: cleanOperationPath(data.RootPath),
			StartTime:       time.Now().UTC(),
			BytesProcessed:  processed,
			BytesTotal:      total,
			FilesProcessed:  filesProcessed,
		}
		id, _ := s.Operations().Add(op)
		opCtx, _ := s.Operations().Context(id)
		go func() {
			if err := s.Filesystem().SpaceAvailableForDecompression(opCtx, data.RootPath, data.File); err != nil {
				s.Operations().Fail(id, operationErrorMessage(err))
				return
			}
			if err := s.Filesystem().DecompressFile(opCtx, data.RootPath, data.File); err != nil {
				s.Operations().Fail(id, operationErrorMessage(err))
				return
			}
			processed.Store(total.Load())
			s.Operations().Complete(id)
		}()
		c.JSON(http.StatusAccepted, FileOperationAcceptedResponse{Identifier: id.String()})
		return
	}

	lg.Debug("checking if space is available for file decompression")
	err := s.Filesystem().SpaceAvailableForDecompression(c.Request.Context(), data.RootPath, data.File)
	if err != nil {
		if filesystem.IsErrorCode(err, filesystem.ErrCodeUnknownArchive) {
			lg.WithField("error", err).Warn("failed to decompress file: unknown archive format")
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "The archive provided is in a format Wings does not understand."})
			return
		}
		middleware.CaptureAndAbort(c, err)
		return
	}

	lg.Info("starting file decompression")
	if err := s.Filesystem().DecompressFile(c.Request.Context(), data.RootPath, data.File); err != nil {
		// If the file is busy for some reason just return a nicer error to the user since there is not
		// much we specifically can do. They'll need to stop the running server process in order to overwrite
		// a file like this.
		if strings.Contains(err.Error(), "text file busy") {
			lg.WithField("error", errors.WithStackIf(err)).Warn("failed to decompress file: text file busy")
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
				"error": "One or more files this archive is attempting to overwrite are currently in use by another process. Please try again.",
			})
			return
		}
		middleware.CaptureAndAbort(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

func fileOperationForeground(c *gin.Context, foreground *bool) bool {
	if foreground != nil {
		return *foreground
	}
	if raw := c.Query("foreground"); raw != "" {
		return parseBoolWithDefault(raw, true)
	}
	if parseBoolWithDefault(c.Query("async"), false) || parseBoolWithDefault(c.Query("background"), false) {
		return false
	}
	return true
}

func archiveFormatExtension(format string) string {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "tar_gz":
		return "tar.gz"
	case "tar_bz2":
		return "tar.bz2"
	case "tar_xz":
		return "tar.xz"
	case "seven_zip":
		return "7z"
	default:
		return strings.ReplaceAll(strings.TrimSpace(format), "_", ".")
	}
}

func compressionDestination(data ServerArchiveRequest) string {
	if data.Name == "" {
		return cleanOperationPath(data.RootPath)
	}
	extension := strings.TrimPrefix(archiveFormatExtension(data.Extension), ".")
	name := data.Name
	if extension != "" && !strings.HasSuffix(strings.ToLower(name), "."+strings.ToLower(extension)) {
		name += "." + extension
	}
	return cleanOperationPath(path.Join(data.RootPath, name))
}

func cleanOperationPath(p string) string {
	cleaned := path.Clean("/" + strings.TrimLeft(p, "/"))
	if cleaned == "." {
		return "/"
	}
	return cleaned
}

func estimateOperationPaths(root, directory string, paths []string) (uint64, uint64) {
	var bytesTotal uint64
	for _, item := range paths {
		fullPath := filepath.Join(root, filepath.FromSlash(strings.TrimLeft(path.Join(directory, item), "/")))
		info, err := os.Stat(fullPath)
		if err == nil && !info.IsDir() && info.Size() > 0 {
			bytesTotal += uint64(info.Size())
		}
	}
	return bytesTotal, uint64(len(paths))
}

func operationErrorMessage(err error) string {
	if errors.Is(err, context.Canceled) {
		return "operation canceled"
	}
	return err.Error()
}

// deleteServerFileOperation cancels an asynchronous filesystem operation.
// @Summary Cancel file operation
// @Tags Server Files
// @Param server path string true "Server identifier"
// @Param operation path string true "Operation identifier"
// @Success 204 "No Content"
// @Failure 400 {object} ErrorResponse
// @Security NodeToken
// @Router /api/servers/{server}/files/operations/{operation} [delete]
func deleteServerFileOperation(c *gin.Context) {
	id, err := uuid.Parse(c.Param("operation"))
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Invalid operation identifier."})
		return
	}
	s := middleware.ExtractServer(c)
	s.Operations().Abort(id)
	c.Status(http.StatusNoContent)
}

var errInvalidFileMode = errors.New("invalid file mode")

// postServerChmodFile updates file permissions for a batch of files.
// @Summary Change file permissions
// @Tags Server Files
// @Accept json
// @Param server path string true "Server identifier"
// @Param payload body ServerChmodRequest true "Chmod request"
// @Success 204 "No Content"
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Security NodeToken
// @Router /api/servers/{server}/files/chmod [post]
func postServerChmodFile(c *gin.Context) {
	s := ExtractServer(c)

	var data ServerChmodRequest

	if err := c.BindJSON(&data); err != nil {
		log.Debug(err.Error())
		return
	}

	if len(data.Files) == 0 {
		c.AbortWithStatusJSON(http.StatusUnprocessableEntity, gin.H{
			"error": "No files to chmod were provided.",
		})
		return
	}

	g, ctx := errgroup.WithContext(c.Request.Context())

	// Loop over the array of files passed in and perform the move or rename action against each.
	for _, file := range data.Files {
		g.Go(func(p ServerChmodFile) func() error {
			return func() error {
				select {
				case <-ctx.Done():
					return ctx.Err()
				default:
					mode, err := strconv.ParseUint(p.Mode, 8, 32)
					if err != nil {
						return errInvalidFileMode
					}

					if err := s.Filesystem().Chmod(path.Join(data.Root, p.File), os.FileMode(mode)); err != nil {
						// Return nil if the error is an is not exists.
						// NOTE: os.IsNotExist() does not work if the error is wrapped.
						if errors.Is(err, os.ErrNotExist) {
							return nil
						}

						return err
					}

					return nil
				}
			}
		}(file))
	}

	if err := g.Wait(); err != nil {
		if errors.Is(err, errInvalidFileMode) {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
				"error": "Invalid file mode.",
			})
			return
		}

		middleware.CaptureAndAbort(c, err)
		return
	}

	c.Status(http.StatusNoContent)
}

// postServerUploadFiles uploads files to a server using a signed token.
// @Summary Upload files
// @Tags Uploads
// @Accept multipart/form-data
// @Param token query string true "Signed upload token"
// @Param directory query string false "Target directory"
// @Param files formData file true "Files"
// @Success 204 "No Content"
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Security ServerJWT
// @Router /upload/file [post]
func postServerUploadFiles(c *gin.Context) {
	manager := middleware.ExtractManager(c)

	token := tokens.UploadPayload{}
	if err := tokens.ParseToken([]byte(c.Query("token")), &token); err != nil {
		middleware.CaptureAndAbort(c, err)
		return
	}

	s, ok := manager.Get(token.ServerUuid)
	if !ok || token.Denylisted() || !token.IsUniqueRequest() || !token.HasScope(tokens.FileUpload) {
		c.AbortWithStatusJSON(http.StatusNotFound, gin.H{
			"error": "The requested resource was not found on this server.",
		})
		return
	}

	form, err := c.MultipartForm()
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"error": "Failed to get multipart form data from request.",
		})
		return
	}

	headers, ok := form.File["files"]
	if !ok {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"error": "No files were found on the request body.",
		})
		return
	}

	directory := c.Query("directory")

	maxFileSize := config.Get().Api.UploadLimit
	maxFileSizeBytes := maxFileSize * 1024 * 1024
	var totalSize int64
	for _, header := range headers {
		if header.Size > maxFileSizeBytes {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
				"error": "File " + header.Filename + " is larger than the maximum file upload size of " + strconv.FormatInt(maxFileSize, 10) + " MB.",
			})
			return
		}
		totalSize += header.Size
	}

	for _, header := range headers {
		// We run this in a different method so I can use defer without any of
		// the consequences caused by calling it in a loop.
		if err := handleFileUpload(filepath.Join(directory, header.Filename), s, header); err != nil {
			middleware.CaptureAndAbort(c, err)
			return
		} else {
			s.SaveActivity(s.NewRequestActivity(token.UserUuid, c.ClientIP()), server.ActivityFileUploaded, models.ActivityMeta{
				"file":      header.Filename,
				"directory": filepath.Clean(directory),
			})
		}
	}

	c.Status(http.StatusNoContent)
}

func handleFileUpload(p string, s *server.Server, header *multipart.FileHeader) error {
	file, err := header.Open()
	if err != nil {
		return err
	}
	defer file.Close()

	if err := s.Filesystem().IsIgnored(p); err != nil {
		return err
	}

	if err := s.Filesystem().Write(p, file, header.Size, 0o644); err != nil {
		return err
	}
	return nil
}
