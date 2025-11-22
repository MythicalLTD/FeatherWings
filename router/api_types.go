package router

import (
	"github.com/docker/docker/api/types/image"
	"github.com/mythicalltd/featherwings/router/downloader"
	"github.com/mythicalltd/featherwings/server"
	"github.com/mythicalltd/featherwings/server/backup"
	"github.com/mythicalltd/featherwings/server/filesystem"
	"github.com/mythicalltd/featherwings/server/installer"
)

// ErrorResponse represents the common error payload returned by the API.
type ErrorResponse struct {
	Error     string `json:"error"`
	RequestID string `json:"request_id,omitempty"`
}

// SystemSummaryResponse describes the short system response used for legacy clients.
type SystemSummaryResponse struct {
	Architecture  string `json:"architecture"`
	CPUCount      int    `json:"cpu_count"`
	KernelVersion string `json:"kernel_version"`
	OS            string `json:"os"`
	Version       string `json:"version"`
}

// SelfUpdateRequest defines the payload for triggering a self-update through the API.
type SelfUpdateRequest struct {
	Source          string `json:"source,omitempty"`
	RepoOwner       string `json:"repo_owner,omitempty"`
	RepoName        string `json:"repo_name,omitempty"`
	Version         string `json:"version,omitempty"`
	Force           bool   `json:"force,omitempty"`
	URL             string `json:"url,omitempty"`
	SHA256          string `json:"sha256,omitempty"`
	DisableChecksum bool   `json:"disable_checksum,omitempty"`
}

// SelfUpdateResponse conveys the outcome of a self-update attempt.
type SelfUpdateResponse struct {
	Message          string `json:"message"`
	Source           string `json:"source"`
	CurrentVersion   string `json:"current_version"`
	TargetVersion    string `json:"target_version,omitempty"`
	ChecksumSkipped  bool   `json:"checksum_skipped"`
	RestartTriggered bool   `json:"restart_triggered"`
}

// DiagnosticsUploadResponse contains the URL to an uploaded diagnostics bundle.
type DiagnosticsUploadResponse struct {
	URL string `json:"url"`
}

// DockerPruneReport mirrors the response from Docker image prune operations.
type DockerPruneReport = image.PruneReport

// ServerLogResponse encapsulates log lines.
type ServerLogResponse struct {
	Data []string `json:"data"`
}

// ServerInstallLogResponse contains the installation log output.
type ServerInstallLogResponse struct {
	Data string `json:"data"`
}

// ServerPowerRequest defines a power action request body.
type ServerPowerRequest struct {
	Action      server.PowerAction `json:"action"`
	WaitSeconds int                `json:"wait_seconds"`
}

// ServerCommandsRequest contains commands to execute on a server.
type ServerCommandsRequest struct {
	Commands []string `json:"commands"`
}

// ServerRenameEntry represents a rename operation payload.
type ServerRenameEntry struct {
	To   string `json:"to"`
	From string `json:"from"`
}

// ServerRenameRequest holds rename operations.
type ServerRenameRequest struct {
	Root  string              `json:"root"`
	Files []ServerRenameEntry `json:"files"`
}

// ServerCopyRequest describes a copy operation.
type ServerCopyRequest struct {
	Location string `json:"location"`
}

// ServerDeleteRequest describes deleted file targets.
type ServerDeleteRequest struct {
	Root  string   `json:"root"`
	Files []string `json:"files"`
}

// ServerPullStatusResponse returns active remote downloads.
type ServerPullStatusResponse struct {
	Downloads []*downloader.Download `json:"downloads"`
}

// ServerPullRemoteRequest defines a remote transfer.
type ServerPullRemoteRequest struct {
	Directory  string `json:"directory,omitempty" binding:"required_without=RootPath"`
	RootPath   string `json:"root" binding:"required_without=Directory"`
	URL        string `json:"url" binding:"required"`
	FileName   string `json:"file_name"`
	UseHeader  bool   `json:"use_header"`
	Foreground bool   `json:"foreground"`
}

// RemoteDownloadAcceptedResponse returns the identifier for background downloads.
type RemoteDownloadAcceptedResponse struct {
	Identifier string `json:"identifier"`
}

// ServerCreateDirectoryRequest includes folder data.
type ServerCreateDirectoryRequest struct {
	Name string `json:"name"`
	Path string `json:"path"`
}

// ServerArchiveRequest holds compression options.
type ServerArchiveRequest struct {
	RootPath  string   `json:"root"`
	Files     []string `json:"files"`
	Name      string   `json:"name"`
	Extension string   `json:"extension"`
}

// ServerArchiveResponse returns metadata for generated archives.
type ServerArchiveResponse struct {
	filesystem.Stat
}

// ServerDecompressRequest carries decompression data.
type ServerDecompressRequest struct {
	RootPath string `json:"root"`
	File     string `json:"file"`
}

// ServerChmodFile describes a chmod action.
type ServerChmodFile struct {
	File string `json:"file"`
	Mode string `json:"mode"`
}

// ServerChmodRequest aggregates chmod actions.
type ServerChmodRequest struct {
	Root  string            `json:"root"`
	Files []ServerChmodFile `json:"files"`
}

// ServerDenyTokenRequest lists websocket tokens.
type ServerDenyTokenRequest struct {
	JTIs []string `json:"jtis"`
}

// ServerBackupRestoreRequest configures restore operations.
type ServerBackupRestoreRequest struct {
	Adapter           backup.AdapterType `json:"adapter" binding:"required,oneof=wings s3"`
	TruncateDirectory bool               `json:"truncate_directory"`
	DownloadURL       string             `json:"download_url"`
}

// ServerBackupDescriptor describes a backup entry.
type ServerBackupDescriptor struct {
	UUID      string `json:"uuid"`
	Name      string `json:"name"`
	Size      int64  `json:"size"`
	CreatedAt string `json:"created_at"`
	Path      string `json:"path"`
}

// ServerBackupListResponse captures backups listed for a server.
type ServerBackupListResponse struct {
	Data []ServerBackupDescriptor `json:"data"`
}

// ServerBackupCreateRequest defines the payload for creating a backup.
type ServerBackupCreateRequest struct {
	Adapter backup.AdapterType `json:"adapter" binding:"required,oneof=wings s3"`
	UUID    string             `json:"uuid" binding:"required"`
	Ignore  string             `json:"ignore"`
}

// ServerTransferRequest defines the payload for initiating a server transfer.
type ServerTransferRequest struct {
	URL    string                  `json:"url" binding:"required"`
	Token  string                  `json:"token" binding:"required"`
	Server installer.ServerDetails `json:"server"`
}
