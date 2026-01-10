package router

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/apex/log"
	"github.com/gin-gonic/gin"

	"github.com/mythicalltd/featherwings/config"
	"github.com/mythicalltd/featherwings/internal/diagnostics"
	"github.com/mythicalltd/featherwings/internal/selfupdate"
	"github.com/mythicalltd/featherwings/router/middleware"
	"github.com/mythicalltd/featherwings/router/tokens"
	"github.com/mythicalltd/featherwings/server"
	"github.com/mythicalltd/featherwings/server/installer"
	"github.com/mythicalltd/featherwings/system"
)

const restartCommandTimeout = 30 * time.Second

// getSystemInformation returns information about the system that wings is running on.
// @Summary Get system information
// @Description Returns hardware and software information about the node. Provide `v=2` to receive the full payload used by the panel.
// @Tags System
// @Produce json
// @Param v query string false "Response version" Enums(2)
// @Success 200 {object} router.SystemSummaryResponse "Default response"
// @Success 200 {object} system.Information "Extended response when v=2"
// @Failure 500 {object} ErrorResponse
// @Security NodeToken
// @Router /api/system [get]
func getSystemInformation(c *gin.Context) {
	i, err := system.GetSystemInformation()
	if err != nil {
		middleware.CaptureAndAbort(c, err)
		return
	}

	if c.Query("v") == "2" {
		c.JSON(http.StatusOK, i)
		return
	}

	c.JSON(http.StatusOK, struct {
		Architecture  string `json:"architecture"`
		CPUCount      int    `json:"cpu_count"`
		KernelVersion string `json:"kernel_version"`
		OS            string `json:"os"`
		Version       string `json:"version"`
	}{
		Architecture:  i.System.Architecture,
		CPUCount:      i.System.CPUThreads,
		KernelVersion: i.System.KernelVersion,
		OS:            i.System.OSType,
		Version:       i.Version,
	})
}

// getDiagnostics returns diagnostic output to help debug the daemon.
// @Summary Generate diagnostics bundle
// @Description Returns plain-text diagnostics output by default. Use include_endpoints to append HTTP endpoint metadata and include_logs to attach recent logs. Provide format=url to upload the report and receive a shortened URL instead of the raw content.
// @Tags System
// @Produce text/plain
// @Produce json
// @Param include_endpoints query bool false "Include endpoint metadata"
// @Param include_logs query bool false "Include daemon logs"
// @Param log_lines query int false "Number of log lines" minimum(1) maximum(500)
// @Param format query string false "Response format" Enums(text,url)
// @Param upload_api_url query string false "Override upload endpoint when format=url"
// @Success 200 {string} string "Plain-text diagnostics report. When format=url the response type is application/json with payload {\"url\":\"...\"}."
// @Failure 500 {object} ErrorResponse
// @Security NodeToken
// @Router /api/diagnostics [get]
func getDiagnostics(c *gin.Context) {
	// Optional query params: ?include_endpoints=true&include_logs=true&log_lines=300

	// Parse boolean query parameter with default
	parseBoolQuery := func(param string, defaultVal bool) bool {
		q := strings.ToLower(c.Query(param))
		switch q {
		case "true":
			return true
		case "false":
			return false
		default:
			return defaultVal
		}
	}

	includeEndpoints := parseBoolQuery("include_endpoints", false)
	includeLogs := parseBoolQuery("include_logs", true)

	// Parse log_lines query parameter with bounds
	logLines := 200
	if q := c.Query("log_lines"); q != "" {
		if n, err := strconv.Atoi(q); err == nil {
			if n > 500 {
				logLines = 500
			} else if n > 0 {
				logLines = n
			}
		}
	}

	report, err := diagnostics.GenerateDiagnosticsReport(includeEndpoints, includeLogs, logLines)
	if err != nil {
		middleware.CaptureAndAbort(c, err)
		return
	}

	responseFormat := strings.ToLower(c.DefaultQuery("format", "text"))
	switch responseFormat {
	case "", "text", "raw":
		c.Data(http.StatusOK, "text/plain; charset=utf-8", []byte(report))
	case "url":
		uploadAPIURL := c.DefaultQuery("upload_api_url", diagnostics.DefaultMclogsAPIURL)
		ctx, cancel := context.WithTimeout(c.Request.Context(), 15*time.Second)
		defer cancel()

		diagnosticsURL, err := diagnostics.UploadReport(ctx, uploadAPIURL, report)
		if err != nil {
			if errors.Is(err, diagnostics.ErrMissingUploadAPIURL) || errors.Is(err, diagnostics.ErrInvalidUploadAPIURL) {
				c.AbortWithStatusJSON(http.StatusBadRequest, ErrorResponse{Error: err.Error()})
				return
			}

			middleware.CaptureAndAbort(c, err)
			return
		}

		c.JSON(http.StatusOK, DiagnosticsUploadResponse{URL: diagnosticsURL})
	default:
		c.AbortWithStatusJSON(http.StatusBadRequest, ErrorResponse{Error: "format must be either 'text' or 'url'"})
	}
}

// getSystemIps returns list of host machine IP addresses.
// @Summary List system IP addresses
// @Tags System
// @Produce json
// @Success 200 {object} system.IpAddresses
// @Failure 500 {object} ErrorResponse
// @Security NodeToken
// @Router /api/system/ips [get]
func getSystemIps(c *gin.Context) {
	interfaces, err := system.GetSystemIps()
	if err != nil {
		middleware.CaptureAndAbort(c, err)
		return
	}

	// Append config defined ips as well
	for i := range config.Get().Docker.SystemIps {
		targetIp := config.Get().Docker.SystemIps[i]
		if slices.Contains(interfaces, targetIp) {
			continue
		}

		interfaces = append(interfaces, targetIp)
	}

	c.JSON(http.StatusOK, &system.IpAddresses{IpAddresses: interfaces})
}

// getSystemUtilization returns resource utilization info for the system wings is running on.
// @Summary Get system utilization
// @Tags System
// @Produce json
// @Success 200 {object} system.Utilization
// @Failure 500 {object} ErrorResponse
// @Security NodeToken
// @Router /api/system/utilization [get]
func getSystemUtilization(c *gin.Context) {
	cfg := config.Get()
	u, err := system.GetSystemUtilization(
		cfg.System.RootDirectory,
		cfg.System.LogDirectory,
		cfg.System.Data,
		cfg.System.ArchiveDirectory,
		cfg.System.BackupDirectory,
		cfg.System.TmpDirectory,
	)
	if err != nil {
		middleware.CaptureAndAbort(c, err)
		return
	}
	c.JSON(http.StatusOK, u)
}

// getDockerDiskUsage returns docker disk utilization.
// @Summary Get Docker disk usage
// @Tags System
// @Produce json
// @Success 200 {object} system.DockerDiskUsage
// @Failure 500 {object} ErrorResponse
// @Security NodeToken
// @Router /api/system/docker/disk [get]
func getDockerDiskUsage(c *gin.Context) {
	d, err := system.GetDockerDiskUsage(c)
	if err != nil {
		middleware.CaptureAndAbort(c, err)
		return
	}
	c.JSON(http.StatusOK, d)
}

// pruneDockerImages prunes the docker image cache.
// @Summary Prune Docker images
// @Tags System
// @Produce json
// @Success 200 {object} DockerPruneReport
// @Failure 500 {object} ErrorResponse
// @Security NodeToken
// @Router /api/system/docker/image/prune [delete]
func pruneDockerImages(c *gin.Context) {
	p, err := system.PruneDockerImages(c)
	if err != nil {
		middleware.CaptureAndAbort(c, err)
		return
	}
	c.JSON(http.StatusOK, p)
}

// getAllServers returns all servers registered and configured on this wings instance.
// @Summary List servers
// @Tags Servers
// @Produce json
// @Success 200 {array} server.APIResponse
// @Failure 500 {object} ErrorResponse
// @Security NodeToken
// @Router /api/servers [get]
func getAllServers(c *gin.Context) {
	servers := middleware.ExtractManager(c).All()
	out := make([]server.APIResponse, len(servers), len(servers))
	for i, v := range servers {
		out[i] = v.ToAPIResponse()
	}
	c.JSON(http.StatusOK, out)
}

// postCreateServer creates a new server on the wings daemon and begins the installation process for it.
// @Summary Create server
// @Tags Servers
// @Accept json
// @Produce json
// @Param server body installer.ServerDetails true "Server configuration"
// @Success 202 {string} string "Accepted"
// @Failure 400 {object} ErrorResponse
// @Failure 422 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Security NodeToken
// @Router /api/servers [post]
func postCreateServer(c *gin.Context) {
	manager := middleware.ExtractManager(c)

	details := installer.ServerDetails{}
	if err := c.BindJSON(&details); err != nil {
		return
	}

	install, err := installer.New(c.Request.Context(), manager, details)
	if err != nil {
		if installer.IsValidationError(err) {
			c.AbortWithStatusJSON(http.StatusUnprocessableEntity, gin.H{
				"error": "The data provided in the request could not be validated.",
			})
			return
		}

		middleware.CaptureAndAbort(c, err)
		return
	}

	// Plop that server instance onto the request so that it can be referenced in
	// requests from here-on out.
	manager.Add(install.Server())

	// Begin the installation process in the background to not block the request
	// cycle. If there are any errors they will be logged and communicated back
	// to the Panel where a reinstall may take place.
	go func(i *installer.Installer) {
		if err := i.Server().CreateEnvironment(); err != nil {
			i.Server().Log().WithField("error", err).Error("failed to create server environment during install process")
			return
		}

		if err := i.Server().Install(); err != nil {
			log.WithFields(log.Fields{"server": i.Server().ID(), "error": err}).Error("failed to run install process for server")
			return
		}

		if i.StartOnCompletion {
			log.WithField("server_id", i.Server().ID()).Debug("starting server after successful installation")
			if err := i.Server().HandlePowerAction(server.PowerActionStart, 30); err != nil {
				if errors.Is(err, context.DeadlineExceeded) {
					log.WithFields(log.Fields{"server_id": i.Server().ID(), "action": "start"}).Warn("could not acquire a lock while attempting to perform a power action")
				} else {
					log.WithFields(log.Fields{"server_id": i.Server().ID(), "action": "start", "error": err}).Error("encountered error processing a server power action in the background")
				}
			}
		} else {
			log.WithField("server_id", i.Server().ID()).Debug("skipping automatic start after successful server installation")
		}
	}(install)

	c.Status(http.StatusAccepted)
}

type postUpdateConfigurationResponse struct {
	Applied bool `json:"applied"`
}

func respondSelfUpdateError(c *gin.Context, err error) bool {
	if errors.Is(err, selfupdate.ErrChecksumRequired) {
		c.AbortWithStatusJSON(http.StatusBadRequest, ErrorResponse{Error: "checksum is required for direct URL updates"})
		return true
	}
	if errors.Is(err, selfupdate.ErrChecksumNotFound) {
		c.AbortWithStatusJSON(http.StatusBadGateway, ErrorResponse{Error: "checksum not found for requested binary; retry with disable_checksum=true to bypass verification"})
		return true
	}

	var httpErr *selfupdate.HTTPError
	if errors.As(err, &httpErr) {
		status := http.StatusBadGateway
		if httpErr.StatusCode == http.StatusNotFound {
			status = http.StatusBadRequest
		}

		message := fmt.Sprintf("upstream request to %s failed with status %d (%s)", httpErr.URL, httpErr.StatusCode, http.StatusText(httpErr.StatusCode))
		c.AbortWithStatusJSON(status, ErrorResponse{Error: message})
		return true
	}

	return false
}

func queueRestartCommand(command string) bool {
	command = strings.TrimSpace(command)
	if command == "" {
		return false
	}

	go func(cmd string) {
		ctx, cancel := context.WithTimeout(context.Background(), restartCommandTimeout)
		defer cancel()
		output, err := selfupdate.RunRestartCommand(ctx, cmd)
		fields := log.Fields{"command": cmd}
		if output != "" {
			fields["output"] = output
		}
		if err != nil {
			log.WithError(err).WithFields(fields).Error("self-update restart command failed")
			return
		}
		log.WithFields(fields).Info("self-update restart command executed successfully")
	}(command)

	return true
}

// postUpdateConfiguration updates the running configuration for this Wings instance.
// @Summary Update runtime configuration
// @Tags System
// @Accept json
// @Produce json
// @Param config body config.Configuration true "Updated configuration"
// @Success 200 {object} postUpdateConfigurationResponse
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Security NodeToken
// @Router /api/update [post]
func postUpdateConfiguration(c *gin.Context) {
	cfg := config.Get()

	if cfg.IgnorePanelConfigUpdates {
		c.JSON(http.StatusOK, postUpdateConfigurationResponse{
			Applied: false,
		})
		return
	}

	if err := c.BindJSON(&cfg); err != nil {
		return
	}

	// Keep the SSL certificates the same since the Panel will send through Lets Encrypt
	// default locations. However, if we picked a different location manually we don't
	// want to override that.
	//
	// If you pass through manual locations in the API call this logic will be skipped.
	if strings.HasPrefix(cfg.Api.Ssl.KeyFile, "/etc/letsencrypt/live/") {
		cfg.Api.Ssl.KeyFile = config.Get().Api.Ssl.KeyFile
		cfg.Api.Ssl.CertificateFile = config.Get().Api.Ssl.CertificateFile
	}

	// Try to write this new configuration to the disk before updating our global
	// state with it.
	if err := config.WriteToDisk(cfg); err != nil {
		middleware.CaptureAndAbort(c, err)
		return
	}
	// Since we wrote it to the disk successfully now update the global configuration
	// state to use this new configuration struct.
	config.Set(cfg)
	c.JSON(http.StatusOK, postUpdateConfigurationResponse{
		Applied: true,
	})
}

func postDeauthorizeUser(c *gin.Context) {
	var data struct {
		User    string   `json:"user"`
		Servers []string `json:"servers"`
	}

	if err := c.BindJSON(&data); err != nil {
		return
	}

	// todo: disconnect websockets more gracefully
	m := middleware.ExtractManager(c)
	if len(data.Servers) > 0 {
		for _, uuid := range data.Servers {
			if s, ok := m.Get(uuid); ok {
				s.Websockets().CancelAll()
				s.Sftp().Cancel(data.User)
				tokens.DenyForServer(s.ID(), data.User)
			}
		}
	} else {
		for _, s := range m.All() {
			s.Websockets().CancelAll()
			s.Sftp().Cancel(data.User)
		}
	}

	c.Status(http.StatusNoContent)
}

// postSystemSelfUpdate triggers a self-update for the running daemon instance.
// @Summary Trigger self-update
// @Description Triggers a Wings self-update either from GitHub or a direct URL. Requires system.updates.allow_api to be enabled.
// @Tags System
// @Accept json
// @Produce json
// @Param request body router.SelfUpdateRequest true "Self-update options"
// @Success 202 {object} router.SelfUpdateResponse "Update accepted"
// @Success 200 {object} router.SelfUpdateResponse "Already running requested version"
// @Failure 400 {object} ErrorResponse
// @Failure 403 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Security NodeToken
// @Router /api/system/self-update [post]
func postSystemSelfUpdate(c *gin.Context) {
	cfg := config.Get()
	if !cfg.System.Updates.AllowAPI {
		c.AbortWithStatusJSON(http.StatusForbidden, ErrorResponse{Error: "self-update via API is disabled"})
		return
	}

	var req SelfUpdateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, ErrorResponse{Error: "invalid request payload"})
		return
	}

	skipChecksumGitHub := cfg.System.Updates.DisableChecksum || req.DisableChecksum
	skipChecksumURL := req.DisableChecksum
	restartCommand := cfg.System.Updates.RestartCommand

	preferredBinaryName, err := selfupdate.DetermineBinaryName(cfg.System.Updates.GitHubBinaryTemplate)
	if err != nil {
		middleware.CaptureAndAbort(c, err)
		return
	}

	currentVersion := system.Version
	if currentVersion == "" {
		c.AbortWithStatusJSON(http.StatusInternalServerError, ErrorResponse{Error: "current version is not defined"})
		return
	}

	if currentVersion == "develop" && !req.Force {
		c.AbortWithStatusJSON(http.StatusBadRequest, ErrorResponse{Error: "running in development mode; set force=true to override"})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Minute)
	defer cancel()

	source := strings.ToLower(strings.TrimSpace(req.Source))
	downloadURL := strings.TrimSpace(req.URL)
	if downloadURL == "" {
		downloadURL = cfg.System.Updates.DefaultURL
	}

	if source == "url" || downloadURL != "" {
		if !cfg.System.Updates.EnableURL {
			c.AbortWithStatusJSON(http.StatusForbidden, ErrorResponse{Error: "URL-based updates are disabled"})
			return
		}
		if downloadURL == "" {
			c.AbortWithStatusJSON(http.StatusBadRequest, ErrorResponse{Error: "url is required when source=url"})
			return
		}

		checksum := strings.TrimSpace(req.SHA256)
		if checksum == "" {
			checksum = cfg.System.Updates.DefaultSHA256
		}

		if checksum == "" && !skipChecksumURL {
			c.AbortWithStatusJSON(http.StatusBadRequest, ErrorResponse{Error: "checksum is required for URL updates"})
			return
		}

		log.WithFields(log.Fields{
			"source":        "url",
			"url":           downloadURL,
			"skip_checksum": skipChecksumURL,
		}).Info("self-update requested via API")

		if err := selfupdate.UpdateFromURL(ctx, downloadURL, preferredBinaryName, checksum, skipChecksumURL); err != nil {
			if respondSelfUpdateError(c, err) {
				return
			}
			middleware.CaptureAndAbort(c, err)
			return
		}

		restartTriggered := queueRestartCommand(restartCommand)
		message := "Self-update triggered from direct URL."
		if restartTriggered {
			message += " Restart command queued."
		}

		c.JSON(http.StatusAccepted, SelfUpdateResponse{
			Message:          message,
			Source:           "url",
			CurrentVersion:   currentVersion,
			ChecksumSkipped:  skipChecksumURL,
			RestartTriggered: restartTriggered,
		})
		return
	}

	repoOwner := strings.TrimSpace(req.RepoOwner)
	if repoOwner == "" {
		repoOwner = cfg.System.Updates.RepoOwner
	}
	if repoOwner == "" {
		repoOwner = "mythicalltd"
	}

	repoName := strings.TrimSpace(req.RepoName)
	if repoName == "" {
		repoName = cfg.System.Updates.RepoName
	}
	if repoName == "" {
		repoName = "featherwings"
	}

	targetVersion := strings.TrimSpace(req.Version)
	if targetVersion != "" && !strings.HasPrefix(targetVersion, "v") && targetVersion != "develop" {
		targetVersion = "v" + targetVersion
	}

	var releaseInfo selfupdate.ReleaseInfo
	if targetVersion == "" {
		info, err := selfupdate.FetchLatestReleaseInfo(ctx, repoOwner, repoName)
		if err != nil {
			middleware.CaptureAndAbort(c, err)
			return
		}
		releaseInfo = info
		targetVersion = info.TagName
		if targetVersion == "" {
			middleware.CaptureAndAbort(c, errors.New("failed to determine latest release tag"))
			return
		}
	} else {
		info, err := selfupdate.FetchReleaseByTag(ctx, repoOwner, repoName, targetVersion)
		if err != nil {
			if respondSelfUpdateError(c, err) {
				return
			}
			middleware.CaptureAndAbort(c, err)
			return
		}
		releaseInfo = info
	}

	currentVersionTag := "v" + currentVersion
	if currentVersion == "develop" {
		currentVersionTag = currentVersion
	}

	if !req.Force && targetVersion == currentVersionTag {
		c.JSON(http.StatusOK, SelfUpdateResponse{
			Message:        "Already running target version.",
			Source:         "github",
			CurrentVersion: currentVersion,
			TargetVersion:  targetVersion,
		})
		return
	}

	log.WithFields(log.Fields{
		"source":        "github",
		"repo_owner":    repoOwner,
		"repo_name":     repoName,
		"target":        targetVersion,
		"skip_checksum": skipChecksumGitHub,
	}).Info("self-update requested via API")

	assetName, err := selfupdate.UpdateFromGitHub(ctx, repoOwner, repoName, releaseInfo, cfg.System.Updates.GitHubBinaryTemplate, skipChecksumGitHub)
	if err != nil {
		if respondSelfUpdateError(c, err) {
			return
		}
		middleware.CaptureAndAbort(c, err)
		return
	}

	restartTriggered := queueRestartCommand(restartCommand)
	message := fmt.Sprintf("Self-update triggered from GitHub release (asset: %s).", assetName)
	if restartTriggered {
		message += " Restart command queued."
	}

	c.JSON(http.StatusAccepted, SelfUpdateResponse{
		Message:          message,
		Source:           "github",
		CurrentVersion:   currentVersion,
		TargetVersion:    targetVersion,
		ChecksumSkipped:  skipChecksumGitHub,
		RestartTriggered: restartTriggered,
	})
}
