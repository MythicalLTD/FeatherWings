package router

import (
	"context"
	stderrors "errors"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"emperror.dev/errors"
	"github.com/apex/log"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/mythicalltd/featherwings/config"
	"github.com/mythicalltd/featherwings/router/middleware"
	"github.com/mythicalltd/featherwings/server"
	"github.com/mythicalltd/featherwings/server/backup"
)

var blockedBackupRestorePrefixes = []netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("198.18.0.0/15"),
}

type backupDownloadError string

func (e backupDownloadError) Error() string {
	return string(e)
}

// postServerBackup performs a backup against a given server instance using the provided backup adapter.
// @Summary Create server backup
// @Tags Backups
// @Accept json
// @Param server path string true "Server identifier"
// @Param payload body ServerBackupCreateRequest true "Backup request"
// @Success 202 {string} string "Accepted"
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Security NodeToken
// @Router /api/servers/{server}/backup [post]
func postServerBackup(c *gin.Context) {
	s := middleware.ExtractServer(c)
	client := middleware.ExtractApiClient(c)
	logger := middleware.ExtractLogger(c)
	var data ServerBackupCreateRequest
	if err := c.BindJSON(&data); err != nil {
		return
	}

	backupUuid, ok := parseBackupUuid(c, data.UUID)
	if !ok {
		return
	}
	var adapter backup.BackupInterface
	switch data.Adapter {
	case backup.LocalBackupAdapter:
		adapter = backup.NewLocal(client, backupUuid, s.ID(), data.Ignore)
	case backup.S3BackupAdapter:
		adapter = backup.NewS3(client, backupUuid, s.ID(), data.Ignore)
	case backup.PBSBackupAdapter:
		adapter = backup.NewPBS(client, backupUuid, s.ID(), data.Ignore)
	default:
		middleware.CaptureAndAbort(c, errors.New("router/backups: provided adapter is not valid: "+string(data.Adapter)))
		return
	}

	// Attach the server ID and the request ID to the adapter log context for easier
	// parsing in the logs.
	adapter.WithLogContext(map[string]interface{}{
		"server":     s.ID(),
		"request_id": c.GetString("request_id"),
	})

	go func(b backup.BackupInterface, s *server.Server, logger *log.Entry) {
		if err := s.Backup(b); err != nil {
			logger.WithField("error", errors.WithStackIf(err)).Error("router: failed to generate server backup")
		}
	}(adapter, s, logger)

	c.Status(http.StatusAccepted)
}

// postServerRestoreBackup restores a backup for a server, either from local disk or remote storage.
// @Summary Restore server backup
// @Tags Backups
// @Accept json
// @Param server path string true "Server identifier"
// @Param backup path string true "Backup identifier"
// @Param payload body ServerBackupRestoreRequest true "Restore request"
// @Success 202 {string} string "Accepted"
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Security NodeToken
// @Router /api/servers/{server}/backup/{backup}/restore [post]
func postServerRestoreBackup(c *gin.Context) {
	s := middleware.ExtractServer(c)
	client := middleware.ExtractApiClient(c)
	logger := middleware.ExtractLogger(c)

	var data ServerBackupRestoreRequest
	if err := c.BindJSON(&data); err != nil {
		return
	}
	backupUuid, ok := parseBackupUuid(c, c.Param("backup"))
	if !ok {
		return
	}
	if data.Adapter == backup.S3BackupAdapter && data.DownloadURL == "" {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "The download_url field is required when the backup adapter is set to S3."})
		return
	}
	if data.Adapter == backup.S3BackupAdapter {
		if err := validateBackupDownloadUrl(data.DownloadURL); err != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
	}

	s.SetRestoring(true)
	hasError := true
	defer func() {
		if !hasError {
			return
		}

		s.SetRestoring(false)
	}()

	logger.Info("processing server backup restore request")
	if data.TruncateDirectory {
		logger.Info("received \"truncate_directory\" flag in request: deleting server files")
		if err := s.Filesystem().TruncateRootDirectory(); err != nil {
			middleware.CaptureAndAbort(c, err)
			return
		}
	}

	// Now that we've cleaned up the data directory if necessary, grab the backup file
	// and attempt to restore it into the server directory.
	if data.Adapter == backup.LocalBackupAdapter {
		b, _, err := backup.LocateLocal(client, backupUuid, s.ID())
		if err != nil {
			middleware.CaptureAndAbort(c, err)
			return
		}
		go func(s *server.Server, b backup.BackupInterface, logger *log.Entry) {
			logger.Info("starting restoration process for server backup using local driver")
			if err := s.RestoreBackup(b, nil); err != nil {
				logger.WithField("error", err).Error("failed to restore local backup to server")
			}
			s.Events().Publish(server.DaemonMessageEvent, "Completed server restoration from local backup.")
			s.Events().Publish(server.BackupRestoreCompletedEvent, "")
			logger.Info("completed server restoration from local backup")
			s.SetRestoring(false)
		}(s, b, logger)
		hasError = false
		c.Status(http.StatusAccepted)
		return
	}

	if data.Adapter == backup.PBSBackupAdapter {
		b, err := backup.LocatePBS(client, backupUuid, s.ID())
		if err != nil {
			middleware.CaptureAndAbort(c, err)
			return
		}
		go func(s *server.Server, b backup.BackupInterface, logger *log.Entry) {
			logger.Info("starting restoration process for server backup using PBS driver")
			if err := s.RestoreBackup(b, nil); err != nil {
				logger.WithField("error", err).Error("failed to restore PBS backup to server")
			}
			s.Events().Publish(server.DaemonMessageEvent, "Completed server restoration from Proxmox Backup Server.")
			s.Events().Publish(server.BackupRestoreCompletedEvent, "")
			logger.Info("completed server restoration from PBS backup")
			s.SetRestoring(false)
		}(s, b, logger)
		hasError = false
		c.Status(http.StatusAccepted)
		return
	}

	// Since this is not a local backup we need to stream the archive and then
	// parse over the contents as we go in order to restore it to the server.
	httpClient := backupRestoreHttpClient()
	logger.Info("downloading backup from remote location...")
	// TODO: this will hang if there is an issue. We can't use c.Request.Context() (or really any)
	//  since it will be canceled when the request is closed which happens quickly since we push
	//  this into the background.
	//
	// For now I'm just using the server context so at least the request is canceled if
	// the server gets deleted.
	req, err := http.NewRequestWithContext(s.Context(), http.MethodGet, data.DownloadURL, nil)
	if err != nil {
		middleware.CaptureAndAbort(c, err)
		return
	}
	res, err := httpClient.Do(req)
	if err != nil {
		var downloadErr backupDownloadError
		if stderrors.As(err, &downloadErr) {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": downloadErr.Error()})
			return
		}
		middleware.CaptureAndAbort(c, err)
		return
	}
	if res.StatusCode != http.StatusOK {
		_ = res.Body.Close()
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "The provided backup link returned an invalid response status: " + res.Status})
		return
	}
	// Don't allow content types that we know are going to give us problems.
	if !isSupportedBackupRestoreContentType(res.Header.Get("Content-Type")) {
		_ = res.Body.Close()
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"error": "The provided backup link is not a supported content type. \"" + res.Header.Get("Content-Type") + "\" is not application/x-gzip.",
		})
		return
	}

	go func(s *server.Server, uuid string, logger *log.Entry) {
		logger.Info("starting restoration process for server backup using S3 driver")
		if err := s.RestoreBackup(backup.NewS3(client, uuid, s.ID(), ""), res.Body); err != nil {
			logger.WithField("error", errors.WithStack(err)).Error("failed to restore remote S3 backup to server")
		}
		s.Events().Publish(server.DaemonMessageEvent, "Completed server restoration from S3 backup.")
		s.Events().Publish(server.BackupRestoreCompletedEvent, "")
		logger.Info("completed server restoration from S3 backup")
		s.SetRestoring(false)
	}(s, backupUuid, logger)

	hasError = false
	c.Status(http.StatusAccepted)
}

// deleteServerBackup deletes a local backup of a server.
// @Summary Delete server backup
// @Tags Backups
// @Param server path string true "Server identifier"
// @Param backup path string true "Backup identifier"
// @Success 204 "No Content"
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Security NodeToken
// @Router /api/servers/{server}/backup/{backup} [delete]
func deleteServerBackup(c *gin.Context) {
	client := middleware.ExtractApiClient(c)
	serverID := middleware.ExtractServer(c).ID()
	backupUUID, ok := parseBackupUuid(c, c.Param("backup"))
	if !ok {
		return
	}

	// Prefer local archive when present (historical wings adapter).
	b, _, err := backup.LocateLocal(client, backupUUID, serverID)
	if err == nil {
		if err := b.Remove(); err != nil && !errors.Is(err, os.ErrNotExist) {
			middleware.CaptureAndAbort(c, err)
			return
		}
		c.Status(http.StatusNoContent)
		return
	}
	if !errors.Is(err, os.ErrNotExist) {
		middleware.CaptureAndAbort(c, err)
		return
	}

	// Fall back to PBS when enabled and a matching snapshot exists.
	if config.Get().System.Backups.PBS.Enabled {
		pb, perr := backup.LocatePBS(client, backupUUID, serverID)
		if perr == nil {
			if err := pb.Remove(); err != nil && !errors.Is(err, os.ErrNotExist) {
				middleware.CaptureAndAbort(c, err)
				return
			}
			c.Status(http.StatusNoContent)
			return
		}
		if !errors.Is(perr, os.ErrNotExist) {
			middleware.CaptureAndAbort(c, perr)
			return
		}
	}

	c.AbortWithStatusJSON(http.StatusNotFound, gin.H{
		"error": "The requested backup was not found on this server.",
	})
}

// getServerBackups lists local backups for the specified server.
// @Summary List server backups
// @Tags Backups
// @Produce json
// @Param server path string true "Server identifier"
// @Success 200 {object} ServerBackupListResponse
// @Failure 500 {object} ErrorResponse
// @Security NodeToken
// @Router /api/servers/{server}/backup [get]
func getServerBackups(c *gin.Context) {
	s := middleware.ExtractServer(c)

	// Path: <BackupDirectory>/<server_id>
	base := filepath.Join(config.Get().System.BackupDirectory, s.ID())

	// If the dir does not exist, return empty list
	if st, err := os.Stat(base); err != nil {
		if os.IsNotExist(err) {
			c.JSON(http.StatusOK, ServerBackupListResponse{Data: []ServerBackupDescriptor{}})
			return
		}
		middleware.CaptureAndAbort(c, err)
		return
	} else if !st.IsDir() {
		c.JSON(http.StatusOK, ServerBackupListResponse{Data: []ServerBackupDescriptor{}})
		return
	}

	entries, err := os.ReadDir(base)
	if err != nil {
		middleware.CaptureAndAbort(c, err)
		return
	}

	out := make([]ServerBackupDescriptor, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".tar.gz") {
			continue
		}
		// Extract UUID by trimming extension
		uuid := strings.TrimSuffix(name, ".tar.gz")
		info, err := e.Info()
		if err != nil {
			continue
		}
		out = append(out, ServerBackupDescriptor{
			UUID:      uuid,
			Name:      name,
			Size:      info.Size(),
			CreatedAt: info.ModTime().Format(time.RFC3339),
			Path:      filepath.Join(base, name),
		})
	}

	c.JSON(http.StatusOK, ServerBackupListResponse{Data: out})
}

func parseBackupUuid(c *gin.Context, value string) (string, bool) {
	parsed, err := uuid.Parse(value)
	if err == nil && len(value) == len(parsed.String()) && parsed.String() == strings.ToLower(value) {
		return parsed.String(), true
	}
	c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "The backup identifier must be a valid UUID."})
	return "", false
}

func validateBackupDownloadUrl(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" {
		return backupDownloadError("The provided backup link is not a valid URL.")
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return backupDownloadError("The provided backup link must use HTTP or HTTPS.")
	}
	if ip := net.ParseIP(parsed.Hostname()); ip != nil && isBlockedBackupRestoreIP(parsed.Hostname(), ip) {
		return backupDownloadError("The provided backup link resolves to a blocked address.")
	}
	return nil
}

func backupRestoreHttpClient() http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.ResponseHeaderTimeout = 30 * time.Second
	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	transport.DialContext = func(ctx context.Context, network string, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, err
		}
		if len(ips) == 0 {
			return nil, errors.New("router/backups: backup download host did not resolve to any addresses")
		}
		for _, resolved := range ips {
			if isBlockedBackupRestoreIP(host, resolved.IP) {
				return nil, backupDownloadError("The provided backup link resolves to a blocked address.")
			}
		}
		var lastErr error
		for _, resolved := range ips {
			conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(resolved.IP.String(), port))
			if err == nil {
				return conn, nil
			}
			lastErr = err
		}
		return nil, lastErr
	}
	return http.Client{
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return backupDownloadError("The provided backup link redirects too many times.")
			}
			return validateBackupDownloadUrl(req.URL.String())
		},
	}
}

func isBlockedBackupRestoreIP(host string, ip net.IP) bool {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return true
	}
	addr = addr.Unmap()
	if !addr.IsGlobalUnicast() || addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast() || isExplicitlyBlockedBackupRestoreIP(addr) {
		return !isAllowedBackupRestoreDestination(host, addr)
	}
	return false
}

func isExplicitlyBlockedBackupRestoreIP(addr netip.Addr) bool {
	for _, prefix := range blockedBackupRestorePrefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func isAllowedBackupRestoreDestination(host string, addr netip.Addr) bool {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	for _, entry := range config.Get().System.Backups.RestoreHostAllowlist {
		entry = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(entry)), ".")
		if entry == "" {
			continue
		}
		if entry == host {
			return true
		}
		if allowedAddr, err := netip.ParseAddr(entry); err == nil && allowedAddr.Unmap() == addr {
			return true
		}
		if prefix, err := netip.ParsePrefix(entry); err == nil && prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func isSupportedBackupRestoreContentType(value string) bool {
	mediaType, _, err := mime.ParseMediaType(value)
	if err != nil {
		mediaType = strings.TrimSpace(value)
	}
	switch strings.ToLower(mediaType) {
	case "application/x-gzip", "application/gzip":
		return true
	default:
		return false
	}
}
