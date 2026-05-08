package router

import (
	"bytes"
	"io"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/mythicalltd/featherwings/config"
	"github.com/mythicalltd/featherwings/internal/ufs"
	"github.com/mythicalltd/featherwings/router/middleware"
	"github.com/mythicalltd/featherwings/server"
	"github.com/mythicalltd/featherwings/server/filesystem"
)

type searchOptions struct {
	directory            string
	pattern              string
	includePatterns      []string
	excludePatterns      []string
	contentQuery         string
	contentSearchEnabled bool
	caseInsensitive      bool
	contentCaseSensitive bool
	minSize              int64
	maxSize              int64
	maxContentSize       int64
	includeOversized     bool
}

func parseCSV(v string) []string {
	if strings.TrimSpace(v) == "" {
		return []string{}
	}
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		t := strings.TrimSpace(p)
		if t != "" {
			out = append(out, t)
		}
	}
	return out
}

func parseBoolWithDefault(v string, defaultValue bool) bool {
	if v == "" {
		return defaultValue
	}
	parsed, err := strconv.ParseBool(v)
	if err != nil {
		return defaultValue
	}
	return parsed
}

func parseInt64WithDefault(v string, defaultValue int64) int64 {
	if strings.TrimSpace(v) == "" {
		return defaultValue
	}
	parsed, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return defaultValue
	}
	return parsed
}

func matchesPattern(value string, pattern string, caseInsensitive bool) bool {
	v := value
	p := pattern
	if caseInsensitive {
		v = strings.ToLower(v)
		p = strings.ToLower(p)
	}
	match, _ := filepath.Match(p, v)
	return match
}

func matchesAnyPattern(value string, patterns []string, caseInsensitive bool) bool {
	for _, p := range patterns {
		if matchesPattern(value, p, caseInsensitive) {
			return true
		}
	}
	return false
}

func pathFromSearchRoot(root string, fullPath string) string {
	if root == "/" {
		return strings.TrimPrefix(fullPath, "/")
	}
	trimmedRoot := strings.TrimSuffix(root, "/")
	relative := strings.TrimPrefix(fullPath, trimmedRoot)
	return strings.TrimPrefix(relative, "/")
}

func passesNameOrPatternFilter(fileName string, options *searchOptions) bool {
	if options.pattern == "" {
		return true
	}

	nameValue := fileName
	patternValue := options.pattern
	if options.caseInsensitive {
		nameValue = strings.ToLower(fileName)
		patternValue = strings.ToLower(options.pattern)
	}

	if strings.ContainsAny(patternValue, "*?") {
		if match, _ := filepath.Match(patternValue, nameValue); match {
			return true
		}
	} else {
		if strings.Contains(nameValue, patternValue) {
			return true
		}
		ext := filepath.Ext(nameValue)
		if strings.HasPrefix(patternValue, ".") || !strings.Contains(patternValue, ".") {
			if strings.TrimPrefix(ext, ".") == strings.TrimPrefix(patternValue, ".") {
				return true
			}
		} else if nameValue == patternValue {
			return true
		}
	}

	return false
}

func passesSizeFilter(fileSize int64, options *searchOptions) bool {
	if options.minSize > 0 && fileSize < options.minSize {
		return false
	}
	if options.maxSize > 0 && fileSize > options.maxSize {
		return false
	}
	return true
}

func fileMatchesContent(s *server.Server, fullPath string, fileSize int64, options *searchOptions) bool {
	if !options.contentSearchEnabled {
		return true
	}
	if options.maxContentSize > 0 && fileSize > options.maxContentSize {
		return options.includeOversized
	}

	f, _, err := s.Filesystem().File(fullPath)
	if err != nil {
		return false
	}
	defer f.Close()

	limit := fileSize
	if options.maxContentSize > 0 && options.maxContentSize < fileSize {
		limit = options.maxContentSize
	}

	content, err := io.ReadAll(io.LimitReader(f, limit))
	if err != nil {
		return false
	}

	needle := options.contentQuery
	haystack := content
	if options.contentCaseSensitive {
		return bytes.Contains(haystack, []byte(needle))
	}

	return strings.Contains(strings.ToLower(string(haystack)), strings.ToLower(needle))
}

// Structs needed to respond with the matched files and all their info
type customFileInfo struct {
	ufs.FileInfo
	newName string
}

func (cfi customFileInfo) Name() string {
	return cfi.newName // Return the custom name (i.e., with the directory prefix)
}

// Helper function to append matched entries
func appendMatchedEntry(matchedEntries *[]filesystem.Stat, fileInfo ufs.FileInfo, fullPath string, fileType string) {
	*matchedEntries = append(*matchedEntries, filesystem.Stat{
		FileInfo: customFileInfo{
			FileInfo: fileInfo,
			newName:  fullPath,
		},
		Mimetype: fileType,
	})
}

// getBlacklist returns the blacklisted directories from config, with fallback defaults
func getBlacklist() []string {
	if config.Get() != nil && len(config.Get().SearchRecursion.BlacklistedDirs) > 0 {
		return config.Get().SearchRecursion.BlacklistedDirs
	}
	// Fallback to default blacklist if config is not available
	return []string{"node_modules", ".wine", ".git", "appcache", "depotcache", "vendor"}
}

// Helper function to check if a directory name is in the blacklist
func isBlacklisted(dirName string) bool {
	blacklist := getBlacklist()
	for _, blacklisted := range blacklist {
		if strings.EqualFold(dirName, strings.ToLower(blacklisted)) {
			return true
		}
	}
	return false
}

// Recursive function to search through directories
func searchDirectory(s *server.Server, dir string, depth int, options *searchOptions, matchedEntries *[]filesystem.Stat, matchedDirectories *[]string, c *gin.Context) {
	if depth > config.Get().SearchRecursion.MaxRecursionDepth {
		return // Stop recursion if depth exceeds
	}

	stats, err := s.Filesystem().ListDirectory(dir)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"message": "Directory not found"})
		return
	}

	for _, fileInfo := range stats {
		fileName := fileInfo.Name()
		fileType := fileInfo.Mimetype
		fullPath := filepath.Join(dir, fileName)

		// Store directories separately
		if fileType == "inode/directory" {
			if isBlacklisted(strings.ToLower(fileName)) {
				continue // Skip blacklisted directories
			}
			*matchedDirectories = append(*matchedDirectories, fullPath)

			// Recursive search in the matched directory
			searchDirectory(s, fullPath, depth+1, options, matchedEntries, matchedDirectories, c)
		}

		relativePath := pathFromSearchRoot(options.directory, fullPath)

		if len(options.includePatterns) > 0 && !matchesAnyPattern(relativePath, options.includePatterns, options.caseInsensitive) {
			continue
		}
		if len(options.excludePatterns) > 0 && matchesAnyPattern(relativePath, options.excludePatterns, options.caseInsensitive) {
			continue
		}
		if !passesNameOrPatternFilter(fileName, options) {
			continue
		}
		if fileType != "inode/directory" && !passesSizeFilter(fileInfo.Size(), options) {
			continue
		}
		if fileType != "inode/directory" && options.contentSearchEnabled {
			if !fileMatchesContent(s, fullPath, fileInfo.Size(), options) {
				continue
			}
		}

		appendMatchedEntry(matchedEntries, fileInfo, fullPath, fileType)
	}
}

// getFilesBySearch recursively searches files within a directory based on a pattern.
// @Summary Search server files
// @Tags Server Files
// @Produce json
// @Param server path string true "Server identifier"
// @Param directory query string true "Directory path"
// @Param pattern query string true "Search pattern"
// @Success 200 {array} filesystem.Stat
// @Failure 400 {object} ErrorResponse
// @Security NodeToken
// @Router /api/servers/{server}/files/search [get]
func getFilesBySearch(c *gin.Context) {
	s := middleware.ExtractServer(c)
	dir := strings.TrimSuffix(c.Query("directory"), "/")
	if dir == "" {
		dir = "/"
	}
	pattern := c.Query("pattern")

	// Check if the pattern length is at least 3 characters
	if len(pattern) > 0 && len(pattern) < 3 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Pattern must be at least 3 characters long"})
		return
	}

	options := &searchOptions{
		directory:            dir,
		pattern:              pattern,
		includePatterns:      parseCSV(c.Query("include")),
		excludePatterns:      parseCSV(c.Query("exclude")),
		contentQuery:         c.Query("content"),
		contentSearchEnabled: strings.TrimSpace(c.Query("content")) != "",
		caseInsensitive:      parseBoolWithDefault(c.Query("case_insensitive"), true),
		contentCaseSensitive: !parseBoolWithDefault(c.Query("content_case_insensitive"), true),
		minSize:              parseInt64WithDefault(c.Query("min_size"), 0),
		maxSize:              parseInt64WithDefault(c.Query("max_size"), 0),
		maxContentSize:       parseInt64WithDefault(c.Query("max_content_size"), 5*1024*1024),
		includeOversized:     parseBoolWithDefault(c.Query("include_oversized"), false),
	}

	// Require at least one search dimension.
	if strings.TrimSpace(options.pattern) == "" &&
		len(options.includePatterns) == 0 &&
		strings.TrimSpace(options.contentQuery) == "" &&
		options.minSize == 0 &&
		options.maxSize == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "At least one filter is required"})
		return
	}

	// Prepare slices to store matched stats and directories
	matchedEntries := []filesystem.Stat{}
	matchedDirectories := []string{}

	// Start the search from the initial directory
	searchDirectory(s, dir, 0, options, &matchedEntries, &matchedDirectories, c)

	// Return all matched files with their stats and the name now included the directory
	c.JSON(http.StatusOK, matchedEntries)

}
