package router

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/apex/log"
	"github.com/gin-gonic/gin"

	"github.com/mythicalltd/featherwings/config"
	"github.com/mythicalltd/featherwings/internal/models"
	"github.com/mythicalltd/featherwings/router/middleware"
	"github.com/mythicalltd/featherwings/router/tokens"
	"github.com/mythicalltd/featherwings/server"
)

// Chunked, resumable uploads.
//
// Large files are sent as a series of raw (non-multipart) requests, each small
// enough to pass reverse proxies with a per-request body limit such as
// Cloudflare's 100 MB. The parts are appended to a staging file outside of the
// server's data directory and the finished file is copied into place through
// the server filesystem, so path containment, the denylist and the disk limit
// all apply exactly like for a normal upload.
//
//	GET    /upload/chunk?token&upload_id                       -> status (resume)
//	POST   /upload/chunk?token&upload_id&offset&total_size&file_name&directory  (body = bytes)
//	POST   /upload/chunk/complete?token&upload_id[&sha256]     -> assemble
//	DELETE /upload/chunk?token&upload_id                       -> cancel
//
// Parts must arrive in order: a part whose offset is past the stored size is
// refused with 409 and the current offset, a part that was already stored is
// acknowledged without being written again.

const (
	chunkedUploadExpiry = 24 * time.Hour
	// Open (staged) uploads one server may have at the same time.
	chunkedUploadMaxOpen = 16
)

var (
	chunkedUploadIdRegex = regexp.MustCompile(`^[A-Za-z0-9_-]{8,128}$`)
	chunkedUploadLocks   sync.Map // map[string]*sync.Mutex
	chunkedJanitorOnce   sync.Once
)

type chunkedUploadMeta struct {
	FileName  string    `json:"file_name"`
	Directory string    `json:"directory"`
	TotalSize int64     `json:"total_size"`
	UserUuid  string    `json:"user_uuid"`
	CreatedAt time.Time `json:"created_at"`
}

func (m chunkedUploadMeta) destination() string {
	return path.Join("/", filepath.ToSlash(m.Directory), m.FileName)
}

// chunkedUploadsRoot is the directory holding every staged upload. It sits next
// to the server volumes so it is on the same disk, but it is not inside any
// server's directory.
func chunkedUploadsRoot() string {
	return filepath.Join(config.Get().System.Data, ".featherwings-uploads")
}

// chunkedUploadDir returns the staging directory for one upload. The client id
// is hashed together with the server and the user so one user can never reach
// another user's upload.
func chunkedUploadDir(serverUuid, userUuid, uploadId string) string {
	sum := sha256.Sum256([]byte(serverUuid + "\x00" + userUuid + "\x00" + uploadId))
	return filepath.Join(chunkedUploadsRoot(), serverUuid, hex.EncodeToString(sum[:16]))
}

func chunkedMaxPartSize() int64 {
	return config.Get().Api.UploadLimit * 1024 * 1024
}

func lockChunkedUpload(dir string) (*sync.Mutex, bool) {
	v, _ := chunkedUploadLocks.LoadOrStore(dir, &sync.Mutex{})
	mu := v.(*sync.Mutex)
	return mu, mu.TryLock()
}

func readChunkedMeta(dir string) (*chunkedUploadMeta, error) {
	b, err := os.ReadFile(filepath.Join(dir, "meta.json"))
	if err != nil {
		return nil, err
	}
	var m chunkedUploadMeta
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

func chunkedStoredSize(dir string) int64 {
	st, err := os.Stat(filepath.Join(dir, "data"))
	if err != nil {
		return 0
	}
	return st.Size()
}

// cleanStaleChunkedUploads removes staged uploads that were not touched for
// longer than the expiry.
func cleanStaleChunkedUploads(now time.Time) {
	servers, err := os.ReadDir(chunkedUploadsRoot())
	if err != nil {
		return
	}
	for _, s := range servers {
		sdir := filepath.Join(chunkedUploadsRoot(), s.Name())
		uploads, err := os.ReadDir(sdir)
		if err != nil {
			continue
		}
		for _, u := range uploads {
			udir := filepath.Join(sdir, u.Name())
			latest := time.Time{}
			for _, f := range []string{"meta.json", "data"} {
				if st, err := os.Stat(filepath.Join(udir, f)); err == nil && st.ModTime().After(latest) {
					latest = st.ModTime()
				}
			}
			if now.Sub(latest) < chunkedUploadExpiry {
				continue
			}
			mu, ok := lockChunkedUpload(udir)
			if !ok {
				continue
			}
			if err := os.RemoveAll(udir); err != nil {
				log.WithField("path", udir).WithField("error", err).Warn("failed to remove stale chunked upload")
			}
			mu.Unlock()
			chunkedUploadLocks.Delete(udir)
		}
		_ = os.Remove(sdir) // only succeeds when empty
	}
}

func startChunkedJanitor() {
	chunkedJanitorOnce.Do(func() {
		go func() {
			cleanStaleChunkedUploads(time.Now())
			t := time.NewTicker(30 * time.Minute)
			defer t.Stop()
			for now := range t.C {
				cleanStaleChunkedUploads(now)
			}
		}()
	})
}

// chunkedUploadAuth validates the upload token. The token is not single use
// here because one upload spans many requests; it is still scoped, short lived
// and checked against the denylist.
func chunkedUploadAuth(c *gin.Context) (*server.Server, *tokens.UploadPayload, string, bool) {
	manager := middleware.ExtractManager(c)
	token := tokens.UploadPayload{}
	if err := tokens.ParseToken([]byte(c.Query("token")), &token); err != nil {
		middleware.CaptureAndAbort(c, err)
		return nil, nil, "", false
	}
	s, ok := manager.Get(token.ServerUuid)
	if !ok || token.Denylisted() || !token.HasScope(tokens.FileUpload) {
		c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": "The requested resource was not found on this server."})
		return nil, nil, "", false
	}
	id := c.Query("upload_id")
	if !chunkedUploadIdRegex.MatchString(id) {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Invalid upload_id."})
		return nil, nil, "", false
	}
	startChunkedJanitor()
	return s, &token, chunkedUploadDir(s.ID(), token.UserUuid, id), true
}

// stagedChunkedTotals returns how many uploads a server has staged and the sum
// of their declared sizes. Staged data lives outside the server's directory, so
// it is added to the disk check for a new upload.
func stagedChunkedTotals(serverDir string) (int, int64) {
	entries, err := os.ReadDir(serverDir)
	if err != nil {
		return 0, 0
	}
	var n int
	var total int64
	for _, e := range entries {
		if m, err := readChunkedMeta(filepath.Join(serverDir, e.Name())); err == nil {
			n++
			total += m.TotalSize
		}
	}
	return n, total
}

func chunkedStatus(dir string) gin.H {
	h := gin.H{"exists": false, "offset": int64(0), "max_chunk_size": chunkedMaxPartSize()}
	if m, err := readChunkedMeta(dir); err == nil {
		h["exists"] = true
		h["offset"] = chunkedStoredSize(dir)
		h["total_size"] = m.TotalSize
		h["file_name"] = m.FileName
		h["directory"] = m.Directory
	}
	return h
}

// GET /upload/chunk
func getServerChunkedUpload(c *gin.Context) {
	_, _, dir, ok := chunkedUploadAuth(c)
	if !ok {
		return
	}
	c.JSON(http.StatusOK, chunkedStatus(dir))
}

// DELETE /upload/chunk
func deleteServerChunkedUpload(c *gin.Context) {
	_, _, dir, ok := chunkedUploadAuth(c)
	if !ok {
		return
	}
	mu, locked := lockChunkedUpload(dir)
	if !locked {
		c.AbortWithStatusJSON(http.StatusConflict, gin.H{"error": "The upload is busy."})
		return
	}
	defer mu.Unlock()
	_ = os.RemoveAll(dir)
	chunkedUploadLocks.Delete(dir)
	c.Status(http.StatusNoContent)
}

func validChunkedFileName(name string) bool {
	return name != "" && name != "." && name != ".." && len(name) <= 255 &&
		!strings.ContainsAny(name, "/\\\x00")
}

// POST /upload/chunk
func postServerChunkedUpload(c *gin.Context) {
	s, token, dir, ok := chunkedUploadAuth(c)
	if !ok {
		return
	}
	middleware.ClearDeadlines(c)

	offset, err1 := strconv.ParseInt(c.Query("offset"), 10, 64)
	total, err2 := strconv.ParseInt(c.Query("total_size"), 10, 64)
	if err1 != nil || err2 != nil || offset < 0 || total < 0 {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Invalid offset or total_size."})
		return
	}
	maxPart := chunkedMaxPartSize()
	if c.Request.ContentLength > maxPart {
		c.AbortWithStatusJSON(http.StatusRequestEntityTooLarge, gin.H{"error": "Chunk is larger than the maximum chunk size.", "max_chunk_size": maxPart})
		return
	}

	mu, locked := lockChunkedUpload(dir)
	if !locked {
		c.AbortWithStatusJSON(http.StatusConflict, gin.H{"error": "Another chunk of this upload is being written.", "offset": chunkedStoredSize(dir)})
		return
	}
	defer mu.Unlock()

	meta, err := readChunkedMeta(dir)
	if err != nil {
		// First chunk: validate the destination and create the staging area.
		name := c.Query("file_name")
		if !validChunkedFileName(name) {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Invalid file_name."})
			return
		}
		meta = &chunkedUploadMeta{FileName: name, Directory: path.Clean("/" + filepath.ToSlash(c.Query("directory"))), TotalSize: total, UserUuid: token.UserUuid, CreatedAt: time.Now()}
		if err := s.Filesystem().IsIgnored(meta.destination()); err != nil {
			middleware.CaptureAndAbort(c, err)
			return
		}
		open, staged := stagedChunkedTotals(filepath.Dir(dir))
		if open >= chunkedUploadMaxOpen {
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{"error": "Too many unfinished uploads for this server. Finish or cancel some first."})
			return
		}
		if err := s.Filesystem().HasSpaceFor(total + staged); err != nil {
			middleware.CaptureAndAbort(c, err)
			return
		}
		if err := os.MkdirAll(dir, 0o700); err != nil {
			middleware.CaptureAndAbort(c, err)
			return
		}
		b, _ := json.Marshal(meta)
		if err := os.WriteFile(filepath.Join(dir, "meta.json"), b, 0o600); err != nil {
			middleware.CaptureAndAbort(c, err)
			return
		}
	} else if meta.TotalSize != total {
		c.AbortWithStatusJSON(http.StatusConflict, gin.H{"error": "total_size does not match the existing upload."})
		return
	}

	stored := chunkedStoredSize(dir)
	if offset > stored {
		c.AbortWithStatusJSON(http.StatusConflict, gin.H{"error": "Chunk offset is ahead of the stored data.", "offset": stored})
		return
	}
	if offset < stored {
		// Already have (part of) this data. A retried chunk that is fully stored
		// is acknowledged; anything overlapping the end is refused so the client
		// resends from the stored offset.
		if c.Request.ContentLength >= 0 && offset+c.Request.ContentLength <= stored {
			c.JSON(http.StatusOK, gin.H{"offset": stored, "total_size": total})
			return
		}
		c.AbortWithStatusJSON(http.StatusConflict, gin.H{"error": "Chunk overlaps stored data.", "offset": stored})
		return
	}

	f, err := os.OpenFile(filepath.Join(dir, "data"), os.O_WRONLY|os.O_CREATE, 0o600)
	if err != nil {
		middleware.CaptureAndAbort(c, err)
		return
	}
	limit := total - offset
	if maxPart < limit {
		limit = maxPart
	}
	if _, err = f.Seek(offset, io.SeekStart); err == nil {
		var n int64
		n, err = io.Copy(f, io.LimitReader(c.Request.Body, limit+1))
		if err == nil && n > limit {
			err = errChunkTooLarge
		}
	}
	if err != nil {
		_ = f.Truncate(offset)
		_ = f.Close()
		if errors.Is(err, errChunkTooLarge) {
			c.AbortWithStatusJSON(http.StatusRequestEntityTooLarge, gin.H{"error": "Chunk is larger than allowed or past total_size.", "offset": offset})
			return
		}
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Failed to store chunk.", "offset": offset})
		return
	}
	if err := f.Close(); err != nil {
		middleware.CaptureAndAbort(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"offset": chunkedStoredSize(dir), "total_size": total})
}

var errChunkTooLarge = errors.New("router: chunk too large")

// POST /upload/chunk/complete
func postServerChunkedUploadComplete(c *gin.Context) {
	s, token, dir, ok := chunkedUploadAuth(c)
	if !ok {
		return
	}
	middleware.ClearDeadlines(c)

	mu, locked := lockChunkedUpload(dir)
	if !locked {
		c.AbortWithStatusJSON(http.StatusConflict, gin.H{"error": "The upload is busy."})
		return
	}
	defer mu.Unlock()

	meta, err := readChunkedMeta(dir)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": "Upload not found."})
		return
	}
	stored := chunkedStoredSize(dir)
	if stored != meta.TotalSize {
		c.AbortWithStatusJSON(http.StatusConflict, gin.H{"error": "Upload is incomplete.", "offset": stored, "total_size": meta.TotalSize})
		return
	}

	data, err := os.Open(filepath.Join(dir, "data"))
	if err != nil && os.IsNotExist(err) && meta.TotalSize == 0 {
		data, err = os.Open(os.DevNull)
	}
	if err != nil {
		middleware.CaptureAndAbort(c, err)
		return
	}
	defer data.Close()

	hasher := sha256.New()
	dest := meta.destination()
	// Serialise completions that target the same file.
	destMu, _ := chunkedUploadLocks.LoadOrStore("dest:"+s.ID()+":"+dest, &sync.Mutex{})
	destMu.(*sync.Mutex).Lock()
	defer destMu.(*sync.Mutex).Unlock()
	tmp := path.Join(path.Dir(dest), ".fw-upload-"+filepath.Base(dir)+".part")
	if err := s.Filesystem().IsIgnored(dest, tmp); err != nil {
		middleware.CaptureAndAbort(c, err)
		return
	}
	if _, err := s.Filesystem().WriteFrom(tmp, io.TeeReader(data, hasher)); err != nil {
		middleware.CaptureAndAbort(c, err)
		return
	}
	sum := hex.EncodeToString(hasher.Sum(nil))
	if want := strings.ToLower(c.Query("sha256")); want != "" && want != sum {
		_ = s.Filesystem().Delete(tmp)
		c.AbortWithStatusJSON(http.StatusUnprocessableEntity, gin.H{"error": "Checksum mismatch.", "sha256": sum})
		return
	}
	// Like a normal upload, an existing file is replaced. The rename refuses to
	// overwrite, so the old file is removed first.
	if st, err := s.Filesystem().Stat(dest); err == nil {
		if st.IsDir() {
			_ = s.Filesystem().Delete(tmp)
			c.AbortWithStatusJSON(http.StatusConflict, gin.H{"error": "A directory with that name already exists."})
			return
		}
		_ = s.Filesystem().Delete(dest)
	}
	if err := s.Filesystem().Rename(tmp, dest); err != nil {
		_ = s.Filesystem().Delete(tmp)
		middleware.CaptureAndAbort(c, err)
		return
	}
	_ = os.RemoveAll(dir)
	chunkedUploadLocks.Delete(dir)

	s.SaveActivity(s.NewRequestActivity(token.UserUuid, c.ClientIP()), server.ActivityFileUploaded, models.ActivityMeta{
		"file":      meta.FileName,
		"directory": meta.Directory,
		"chunked":   true,
	})
	c.JSON(http.StatusOK, gin.H{"file": dest, "size": meta.TotalSize, "sha256": sum})
}
