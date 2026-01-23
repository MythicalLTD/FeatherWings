package fastdl

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/apex/log"

	"github.com/mythicalltd/featherwings/config"
	"github.com/mythicalltd/featherwings/server"
)

// FastDLHandler handles HTTP requests for the FastDL server.
type FastDLHandler struct {
	manager            *server.Manager
	basePath           string
	readOnly           bool
	enableDirListing   bool
	blockedExtensions  map[string]bool
	blockedDirectories map[string]bool
}

// NewHandler creates a new FastDL handler instance.
// NOTE: This is not used when FastDL uses nginx (which is the default).
// Kept for potential future use or if built-in server is re-enabled.
func NewHandler(m *server.Manager, basePath string, cfg config.FastDLConfiguration) *FastDLHandler {
	// Build blocked extensions map for fast lookup - use defaults
	blockedExts := make(map[string]bool)
	blockedExtensions := []string{".sma", ".amxx", ".sp", ".smx", ".cfg", ".ini", ".log", ".bak", ".dat", ".sql", ".sq3", ".so", ".dll", ".php", ".zip", ".rar", ".jar", ".sh"}
	
	for _, ext := range blockedExtensions {
		ext = strings.ToLower(strings.TrimSpace(ext))
		if ext != "" {
			blockedExts[ext] = true
		}
	}

	// Build blocked directories map for fast lookup - use defaults
	blockedDirs := make(map[string]bool)
	blockedDirectories := []string{"addons", "cfg", "logs"}
	
	for _, dir := range blockedDirectories {
		dir = strings.ToLower(strings.TrimSpace(dir))
		if dir != "" {
			blockedDirs[dir] = true
		}
	}

	return &FastDLHandler{
		manager:            m,
		basePath:            basePath,
		readOnly:            false, // Default
		enableDirListing:    true, // Default
		blockedExtensions:   blockedExts,
		blockedDirectories:  blockedDirs,
	}
}

// ServeHTTP handles incoming HTTP requests.
func (h *FastDLHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Only allow GET and HEAD methods
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	// Parse the request path
	// Expected format: /{server-uuid}/path/to/file
	path := strings.TrimPrefix(r.URL.Path, "/")
	if path == "" || path == "health" {
		// Root path or health check (handled by mux)
		w.WriteHeader(http.StatusNotFound)
		return
	}

	// Split path into server UUID and file path
	parts := strings.SplitN(path, "/", 2)
	if len(parts) < 1 {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	serverUUID := parts[0]
	filePath := ""
	if len(parts) > 1 {
		filePath = parts[1]
	}

	// Get server instance
	srv, ok := h.manager.Get(serverUUID)
	if !ok {
		log.WithFields(log.Fields{
			"server": serverUUID,
			"ip":     r.RemoteAddr,
		}).Debug("fastdl: server not found")
		w.WriteHeader(http.StatusNotFound)
		return
	}

	// Check if FastDL is enabled for this server
	cfg := srv.Config()
	if !cfg.FastDL.Enabled {
		log.WithFields(log.Fields{
			"server": serverUUID,
			"ip":     r.RemoteAddr,
		}).Debug("fastdl: disabled for server")
		w.WriteHeader(http.StatusForbidden)
		return
	}

	// Build full file path - use FastDL directory if configured
	serverBasePath := filepath.Join(h.basePath, serverUUID)
	if cfg.FastDL.Directory != "" {
		// If server has a specific FastDL directory, prepend it
		filePath = filepath.Join(cfg.FastDL.Directory, filePath)
	}
	fullPath := filepath.Join(serverBasePath, filePath)

	// Security: Ensure the path is within the server's directory
	absPath, err := filepath.Abs(fullPath)
	if err != nil {
		log.WithError(err).WithField("path", fullPath).Error("fastdl: failed to resolve absolute path")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	absBasePath, err := filepath.Abs(serverBasePath)
	if err != nil {
		log.WithError(err).WithField("path", serverBasePath).Error("fastdl: failed to resolve base path")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if !strings.HasPrefix(absPath, absBasePath) {
		log.WithFields(log.Fields{
			"requested": absPath,
			"base":      absBasePath,
		}).Warn("fastdl: path traversal attempt detected")
		w.WriteHeader(http.StatusForbidden)
		return
	}

	// Check if path contains blocked directories
	if h.isBlockedDirectory(filePath) {
		log.WithFields(log.Fields{
			"server": serverUUID,
			"path":   filePath,
			"ip":     r.RemoteAddr,
		}).Warn("fastdl: blocked directory access attempted")
		w.WriteHeader(http.StatusForbidden)
		return
	}

	// Get file info
	info, err := os.Stat(absPath)
	if err != nil {
		if os.IsNotExist(err) {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		log.WithError(err).WithField("path", absPath).Error("fastdl: failed to stat file")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Handle directory listing
	if info.IsDir() {
		if !h.enableDirListing {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		h.serveDirectoryListing(w, r, absPath, filePath, serverUUID)
		return
	}

	// Check if file extension is blocked
	if h.isBlockedExtension(absPath) {
		log.WithFields(log.Fields{
			"server": serverUUID,
			"path":   filePath,
			"ip":     r.RemoteAddr,
		}).Warn("fastdl: blocked file type access attempted")
		w.WriteHeader(http.StatusForbidden)
		return
	}

	// Serve the file
	h.serveFile(w, r, absPath, info)
}

// serveFile serves a single file to the client.
func (h *FastDLHandler) serveFile(w http.ResponseWriter, r *http.Request, filePath string, info os.FileInfo) {
	// Open the file
	file, err := os.Open(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		log.WithError(err).WithField("path", filePath).Error("fastdl: failed to open file")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	defer file.Close()

	// Set content type based on file extension
	ext := strings.ToLower(filepath.Ext(filePath))
	contentType := getContentType(ext)
	w.Header().Set("Content-Type", contentType)

	// Set content length
	w.Header().Set("Content-Length", fmt.Sprintf("%d", info.Size()))

	// Set cache headers for better performance
	w.Header().Set("Cache-Control", "public, max-age=3600")

	// Set CORS headers if needed
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, HEAD")

	// Write file content
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodGet {
		io.Copy(w, file)
	}
}

// serveDirectoryListing generates and serves an HTML directory listing.
func (h *FastDLHandler) serveDirectoryListing(w http.ResponseWriter, r *http.Request, dirPath, relativePath, serverUUID string) {
	entries, err := os.ReadDir(dirPath)
	if err != nil {
		log.WithError(err).WithField("path", dirPath).Error("fastdl: failed to read directory")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Build HTML listing
	html := "<!DOCTYPE html>\n<html><head><title>Index of /" + serverUUID + "/" + relativePath + "</title></head><body>\n"
	html += "<h1>Index of /" + serverUUID + "/" + relativePath + "</h1>\n"
	html += "<hr><pre>\n"

	// Add parent directory link if not at root
	if relativePath != "" {
		parentPath := filepath.Dir(relativePath)
		if parentPath == "." {
			parentPath = ""
		}
		html += fmt.Sprintf("<a href=\"/%s/%s\">../</a>\n", serverUUID, parentPath)
	}

	// List directory entries
	for _, entry := range entries {
		name := entry.Name()

		// Skip hidden files
		if strings.HasPrefix(name, ".") {
			continue
		}

		// Check if directory is blocked
		if entry.IsDir() && h.isBlockedDirectory(name) {
			continue
		}

		// Build link path
		linkPath := filepath.Join(relativePath, name)
		if relativePath == "" {
			linkPath = name
		}

		// Format entry
		var size string
		var icon string
		if entry.IsDir() {
			size = "-"
			icon = "📁"
		} else {
			info, err := entry.Info()
			if err == nil {
				size = formatFileSize(info.Size())
			} else {
				size = "?"
			}
			icon = "📄"
		}

		html += fmt.Sprintf("<a href=\"/%s/%s\">%s %s</a>%s\n",
			serverUUID,
			strings.ReplaceAll(linkPath, " ", "%20"),
			icon,
			name,
			strings.Repeat(" ", 50-len(name))+size,
		)
	}

	html += "</pre><hr></body></html>"

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(html))
}

// isBlockedExtension checks if a file has a blocked extension.
func (h *FastDLHandler) isBlockedExtension(filePath string) bool {
	ext := strings.ToLower(filepath.Ext(filePath))
	return h.blockedExtensions[ext]
}

// isBlockedDirectory checks if a path contains a blocked directory.
func (h *FastDLHandler) isBlockedDirectory(path string) bool {
	parts := strings.Split(strings.ToLower(path), string(filepath.Separator))
	for _, part := range parts {
		if h.blockedDirectories[part] {
			return true
		}
	}
	return false
}

// getContentType returns the MIME type for a file extension.
func getContentType(ext string) string {
	contentTypes := map[string]string{
		".bz2":  "application/x-bzip2",
		".gz":   "application/gzip",
		".jpg":  "image/jpeg",
		".jpeg": "image/jpeg",
		".png":  "image/png",
		".gif":  "image/gif",
		".txt":  "text/plain",
		".html": "text/html",
		".css":  "text/css",
		".js":   "application/javascript",
		".json": "application/json",
		".xml":  "application/xml",
		".zip":  "application/zip",
		".tar":  "application/x-tar",
		".mp3":  "audio/mpeg",
		".wav":  "audio/wav",
		".mp4":  "video/mp4",
		".avi":  "video/x-msvideo",
		".mov":  "video/quicktime",
		".pdf":  "application/pdf",
	}

	if ct, ok := contentTypes[ext]; ok {
		return ct
	}

	// Default to binary for unknown types
	return "application/octet-stream"
}

// formatFileSize formats a file size in human-readable format.
func formatFileSize(size int64) string {
	const unit = 1024
	if size < unit {
		return fmt.Sprintf("%d B", size)
	}
	div, exp := int64(unit), 0
	for n := size / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(size)/float64(div), "KMGTPE"[exp])
}
