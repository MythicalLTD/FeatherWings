package router

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/apex/log"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/mythicalltd/featherwings/config"
	"github.com/mythicalltd/featherwings/firewall"
	"github.com/mythicalltd/featherwings/router/middleware"
	"github.com/mythicalltd/featherwings/router/tokens"
	"github.com/mythicalltd/featherwings/server"
	"github.com/mythicalltd/featherwings/server/filesystem/quotas"
	"github.com/mythicalltd/featherwings/server/installer"
	"github.com/mythicalltd/featherwings/server/transfer"
)

// incomingClaims holds the IDs of servers an incoming transfer request is working
// on, from the moment the request is admitted until a failed transfer has been
// removed again. Only one request per server is admitted at a time.
//
// The source node tells the Panel about a failed transfer on its own, so a retry
// can arrive while the old container and files are still being deleted, and that
// deletion would otherwise remove the retry's copy.
var incomingClaims = transferClaims{ids: make(map[string]struct{})}

type transferClaims struct {
	mu  sync.Mutex
	ids map[string]struct{}
}

// claim reserves id and reports whether it was free.
func (tc *transferClaims) claim(id string) bool {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	if _, taken := tc.ids[id]; taken {
		return false
	}
	tc.ids[id] = struct{}{}
	return true
}

// release frees id again.
func (tc *transferClaims) release(id string) {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	delete(tc.ids, id)
}

// isPooledTransfer reports whether the source and this node share the storage
// pool named in the request. The server's data directory then belongs to the
// source as well, and already exists on this node.
func isPooledTransfer(c *gin.Context) bool {
	remotePool := config.Get().System.Transfers.StoragePool
	sourcePool := c.GetHeader("X-Storage-Pool")
	return remotePool.Enabled && remotePool.PoolName != "" && sourcePool != "" && strings.EqualFold(remotePool.PoolName, sourcePool)
}

// incomingTransferFiles lists what an incoming transfer wrote to this node, so a
// failed transfer can remove it again.
type incomingTransferFiles struct {
	// pooled is set when the data directory lives on a storage pool shared with
	// the source node. It is then the source's live data and is never deleted.
	pooled bool
	// receivedBackups are the backup files this transfer created, temporary or
	// final. Backups that were already on this node are not listed.
	receivedBackups []string
	// installLogPath is the install log written by this transfer, if any.
	installLogPath string
}

// postTransfers handles an incoming server transfer stream initiated by another node.
// @Summary Receive server transfer
// @Tags Transfers
// @Accept multipart/form-data
// @Param Authorization header string true "Bearer token"
// @Param archive formData file true "Server archive"
// @Param checksum formData string true "SHA-256 checksum"
// @Success 202 {string} string "Accepted"
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Security ServerJWT
// @Router /api/transfers [post]
func postTransfers(c *gin.Context) {
	cfg := config.Get()
	enforceChecksums := cfg.System.Transfers.PerformChecksumChecks

	auth := strings.SplitN(c.GetHeader("Authorization"), " ", 2)
	if len(auth) != 2 || auth[0] != "Bearer" {
		c.Header("WWW-Authenticate", "Bearer")
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
			"error": "The required authorization headers were not present in the request.",
		})
		return
	}

	token := tokens.TransferPayload{}
	if err := tokens.ParseToken([]byte(auth[1]), &token); err != nil {
		middleware.CaptureAndAbort(c, err)
		return
	}

	if !token.HasScope(tokens.ServerTransfer) {
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Forbidden."})
		return
	}
	middleware.ClearDeadlines(c)

	manager := middleware.ExtractManager(c)
	u, err := uuid.Parse(token.Subject)
	if err != nil {
		middleware.CaptureAndAbort(c, err)
		return
	}

	id := u.String()

	// Only one request can send the server at a time. The claim is held until this
	// request is done, including the cleanup of a failed transfer, so a retry
	// cannot start while the previous attempt is still being removed. A cleanup
	// that could not remove everything keeps the claim until Wings restarts.
	if !incomingClaims.claim(id) {
		c.AbortWithStatusJSON(http.StatusConflict, gin.H{
			"error": "A transfer of this server is already running on this node, or a failed one is still being cleaned up.",
		})
		return
	}
	keepClaim := false
	defer func() {
		if !keepClaim {
			incomingClaims.release(id)
		}
	}()

	pooled := isPooledTransfer(c)

	// Get or create a new transfer instance for this server.
	var (
		ctx    context.Context
		cancel context.CancelFunc
	)
	if transfer.Incoming().Get(id) != nil {
		c.AbortWithStatusJSON(http.StatusConflict, gin.H{
			"error": "A transfer is already in progress for this server.",
		})
		return
	}

	var trnsfr *transfer.Transfer
	{
		// A server that already exists on this instance cannot be transferred to it.
		if _, ok := manager.Get(id); ok {
			c.AbortWithStatusJSON(http.StatusConflict, gin.H{
				"error": "A server with this identifier already exists on this instance.",
			})
			return
		}

		// Unless the storage pool is shared with the source, the server's data
		// directory must not exist yet. Transfer tokens can be used until they
		// expire, and a repeated request would otherwise extract over existing
		// files and, if it failed, delete them. This also means that a failed
		// transfer only ever removes a data directory it created itself.
		dataDir := filepath.Join(cfg.System.Data, id)
		if !pooled {
			if _, err := os.Lstat(dataDir); err == nil {
				log.WithField("server", id).WithField("path", dataDir).
					Warn("refusing incoming transfer: files for this server already exist on this node")
				c.AbortWithStatusJSON(http.StatusConflict, gin.H{
					"error": "Files for this server already exist on this node.",
				})
				return
			} else if !errors.Is(err, os.ErrNotExist) {
				middleware.CaptureAndAbort(c, fmt.Errorf("failed to check for existing server files: %w", err))
				return
			}
		}

		// TODO: should this use the request context?
		trnsfr = transfer.New(c, nil)

		ctx, cancel = context.WithCancel(trnsfr.Context())
		defer cancel()

		i, err := installer.New(ctx, manager, installer.ServerDetails{
			UUID:              id,
			StartOnCompletion: false,
		})
		if err != nil {
			// Initializing the server can fail after its data directory and quota
			// were created. Neither existed before (see above), so remove them.
			if _, statErr := os.Lstat(dataDir); !pooled && statErr == nil {
				if !removeFailedTransferFiles(trnsfr.Log(), id, dataDir, incomingTransferFiles{}) {
					keepClaim = true
					trnsfr.Log().Error("could not remove the files of a failed transfer; new transfers of this server are refused until Wings is restarted")
				}
			}

			if trnsfr.Server != nil {
				if err := manager.Client().SetTransferStatus(context.Background(), trnsfr.Server.ID(), false); err != nil {
					trnsfr.Log().WithField("status", false).WithError(err).Error("failed to set transfer status")
				}
			} else {
				// No server instance yet, so just log the failure without trying to update status
				// Else this will cause: invalid memory address or nil pointer dereference
				trnsfr.Log().WithError(err).Error("failed to initialize transfer; no server instance created")
			}

			middleware.CaptureAndAbort(c, err)
			return
		}

		i.Server().SetTransferring(true)
		if !manager.AddIfMissing(i.Server()) {
			i.Server().CleanupForDestroy()
			c.AbortWithStatusJSON(http.StatusConflict, gin.H{
				"error": "A server with this identifier already exists on this instance.",
			})
			return
		}

		// We add the transfer to the list of transfers once we have a server instance to use.
		trnsfr.Server = i.Server()
		if !transfer.Incoming().Add(trnsfr) {
			manager.Remove(func(match *server.Server) bool { return match == i.Server() })
			i.Server().CleanupForDestroy()
			c.AbortWithStatusJSON(http.StatusConflict, gin.H{
				"error": "A transfer is already in progress for this server.",
			})
			return
		}
	}

	// Any errors past this point (until the transfer is complete) will abort
	// the transfer.

	// Everything this request writes to disk is tracked so that a failed transfer
	// can be removed again. Received backups are written to temporary files
	// (stagedBackups maps each final path to its temporary file) and only moved
	// into place once the whole transfer has been verified, so a backup already on
	// this node is never left half overwritten.
	var (
		successful    bool
		stagedBackups = make(map[string]string)
		written       = incomingTransferFiles{pooled: pooled}
	)
	defer func() {
		if !completeIncomingTransfer(manager, trnsfr, successful, written) {
			keepClaim = true
		}
	}()

	if pooled {
		if err := trnsfr.Server.CreateEnvironment(); err != nil {
			middleware.CaptureAndAbort(c, err)
			return
		}
		successful = true
		c.Status(http.StatusOK)
		return
	}

	mediaType, params, err := mime.ParseMediaType(c.GetHeader("Content-Type"))
	if err != nil {
		trnsfr.Log().Debug("failed to parse content type header")
		middleware.CaptureAndAbort(c, err)
		return
	}

	if !strings.HasPrefix(mediaType, "multipart/") {
		trnsfr.Log().Debug("invalid content type")
		middleware.CaptureAndAbort(c, fmt.Errorf("invalid content type \"%s\", expected \"multipart/form-data\"", mediaType))
		return
	}

	// Used to read the file and checksum from the request body.
	mr := multipart.NewReader(c.Request.Body, params["boundary"])

	// Loop through the parts of the request body and process them.
	var (
		hasArchive                bool
		archiveChecksum           string
		archiveChecksumReceived   string
		backupChecksumsCalculated = make(map[string]string)
		backupChecksumsReceived   = make(map[string]string)
	)
	// Process multipart form
out:
	for {
		select {
		case <-ctx.Done():
			break out
		default:
			p, err := mr.NextPart()
			if err == io.EOF {
				break out
			}
			if err != nil {
				middleware.CaptureAndAbort(c, err)
				return
			}

			name := p.FormName()
			switch {
			case name == "archive":
				trnsfr.Log().Debug("received archive")
				hasArchive = true

				if err := trnsfr.Server.EnsureDataDirectoryExists(); err != nil {
					middleware.CaptureAndAbort(c, err)
					return
				}

				var reader io.Reader = p
				if enforceChecksums {
					// Calculate checksum while streaming to extraction
					archiveHasher := sha256.New()
					reader = io.TeeReader(p, archiveHasher)

					// Stream directly to extraction while calculating checksum
					if err := trnsfr.Server.Filesystem().ExtractTransfer(ctx, reader); err != nil {
						middleware.CaptureAndAbort(c, err)
						return
					}

					// Store the CALCULATED checksum for later verification
					archiveChecksum = hex.EncodeToString(archiveHasher.Sum(nil))
					trnsfr.Log().Debug("archive extracted and checksum calculated")
				} else {
					// Stream directly to extraction without checksum calculation
					if err := trnsfr.Server.Filesystem().ExtractTransfer(ctx, reader); err != nil {
						middleware.CaptureAndAbort(c, err)
						return
					}
					trnsfr.Log().Debug("archive extracted (checksum verification disabled)")
				}

			case name == "checksum", strings.HasPrefix(name, "checksum_archive"):
				trnsfr.Log().Debug("received archive checksum")
				// Always consume the checksum part if present so the body is fully read.
				// Calagopus sends "checksum"; FeatherWings historically sent "checksum_archive".
				checksumData, err := io.ReadAll(p)
				if err != nil {
					middleware.CaptureAndAbort(c, err)
					return
				}
				// Store the RECEIVED checksum for verification (only used if enforceChecksums is true)
				archiveChecksumReceived = string(checksumData)
				if !enforceChecksums {
					trnsfr.Log().Debug("checksum received but verification is disabled; skipping validation")
				}

			case name == "install_logs":
				trnsfr.Log().Debug("received install logs")

				// Create install log directory if it doesn't exist
				cfg := config.Get()
				installLogDir := filepath.Join(cfg.System.LogDirectory, "install")
				if err := os.MkdirAll(installLogDir, 0755); err != nil {
					// Don't fail transfer for install logs, just log and continue
					trnsfr.Log().WithError(err).Warn("failed to create install log directory, skipping")
					break
				}

				// Use the correct install log path with server UUID
				installLogPath := filepath.Join(installLogDir, trnsfr.Server.ID()+".log")

				// Create the install log file
				installLogFile, err := os.OpenFile(installLogPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o640)
				if err != nil {
					// Don't fail transfer for install logs, just log and continue
					trnsfr.Log().WithError(err).Warn("failed to create install log file, skipping")
					break
				}
				written.installLogPath = installLogPath
				// OpenFile only applies the mode to new files, so also tighten a log
				// left by an earlier transfer.
				if err := installLogFile.Chmod(0o640); err != nil {
					trnsfr.Log().WithError(err).Warn("failed to set permissions on install log file")
				}

				// Stream the install logs to file
				if _, err := io.Copy(installLogFile, p); err != nil {
					installLogFile.Close()
					// Don't fail transfer for install logs, just log and continue
					trnsfr.Log().WithError(err).Warn("failed to stream install logs to file, skipping")
					break
				}

				if err := installLogFile.Close(); err != nil {
					// Don't fail transfer for install logs, just log and continue
					trnsfr.Log().WithError(err).Warn("failed to close install log file")
				}

				trnsfr.Log().WithField("path", installLogPath).Debug("install logs saved successfully")

			case strings.HasPrefix(name, "backup_"):
				backupNameUnsafe := strings.TrimPrefix(name, "backup_")
				// Strip all directory components
				backupName := filepath.Base(backupNameUnsafe)
				if backupName == "." || backupName == ".." || backupName == string(filepath.Separator) {
					middleware.CaptureAndAbort(c, fmt.Errorf("invalid backup name %q", backupNameUnsafe))
					return
				}
				trnsfr.Log().WithField("backup", backupName).Debug("received backup file")

				// Backups are only readable by Wings, the same as backups created on
				// this node (see backup.LocalBackup.Generate). MkdirAll leaves the mode
				// of an existing directory alone, so tighten one left by an older
				// transfer.
				cfg := config.Get()
				backupDir := filepath.Join(cfg.System.BackupDirectory, trnsfr.Server.ID())
				if err := os.MkdirAll(backupDir, 0o700); err != nil {
					middleware.CaptureAndAbort(c, fmt.Errorf("failed to create backup directory: %w", err))
					return
				}
				if err := os.Chmod(backupDir, 0o700); err != nil {
					trnsfr.Log().WithError(err).Warn("failed to set permissions on backup directory")
				}

				backupPath := filepath.Join(backupDir, backupName)
				tmpPath, checksum, err := stageReceivedBackup(backupDir, backupName, p)
				if err != nil {
					middleware.CaptureAndAbort(c, fmt.Errorf("failed to receive backup file %s: %w", backupName, err))
					return
				}
				written.receivedBackups = append(written.receivedBackups, tmpPath)
				if previous, ok := stagedBackups[backupPath]; ok {
					// The same backup was sent twice, keep the last copy.
					_ = os.Remove(previous)
				}
				stagedBackups[backupPath] = tmpPath

				if enforceChecksums {
					// Store the checksum for later verification
					backupChecksumsCalculated[backupName] = checksum
					trnsfr.Log().WithField("backup", backupName).Debug("backup streamed to disk and checksum calculated")
				} else {
					trnsfr.Log().WithField("backup", backupName).Debug("backup streamed to disk (checksum verification disabled)")
				}

			case strings.HasPrefix(name, "checksum_backup_"):
				backupName := strings.TrimPrefix(name, "checksum_backup_")
				trnsfr.Log().WithField("backup", backupName).Debug("received backup checksum")

				// Always consume the checksum part if present so the body is fully read.
				checksumData, err := io.ReadAll(p)
				if err != nil {
					middleware.CaptureAndAbort(c, err)
					return
				}
				// Store the RECEIVED checksum for verification (only used if enforceChecksums is true)
				backupChecksumsReceived[backupName] = string(checksumData)
				if !enforceChecksums {
					trnsfr.Log().WithField("backup", backupName).Debug("checksum received but verification is disabled; skipping validation")
				}
			}
		}
	}

	// Verify main archive checksum (only if enforcement is enabled)
	if enforceChecksums && hasArchive {
		if archiveChecksumReceived == "" {
			middleware.CaptureAndAbort(c, errors.New("archive checksum missing"))
			return
		}

		// Compare the calculated checksum with the received checksum
		if archiveChecksum != archiveChecksumReceived {
			trnsfr.Log().WithFields(log.Fields{
				"expected": archiveChecksumReceived,
				"actual":   archiveChecksum,
			}).Error("archive checksum mismatch")
			middleware.CaptureAndAbort(c, errors.New("archive checksum mismatch"))
			return
		}

		trnsfr.Log().Debug("archive checksum verified")
	}

	// Verify backup checksums (only if enforcement is enabled)
	if enforceChecksums {
		for backupName, calculatedChecksum := range backupChecksumsCalculated {
			receivedChecksum, exists := backupChecksumsReceived[backupName]
			if !exists {
				middleware.CaptureAndAbort(c, fmt.Errorf("checksum missing for backup %s", backupName))
				return
			}

			if calculatedChecksum != receivedChecksum {
				trnsfr.Log().WithFields(log.Fields{
					"backup":   backupName,
					"expected": receivedChecksum,
					"actual":   calculatedChecksum,
				}).Error("backup checksum mismatch")
				middleware.CaptureAndAbort(c, fmt.Errorf("backup %s checksum mismatch", backupName))
				return
			}

			trnsfr.Log().WithField("backup", backupName).Debug("backup checksum verified")
		}
	}

	if !hasArchive {
		middleware.CaptureAndAbort(c, errors.New("missing archive"))
		return
	}

	// Transfer is almost complete, we just want to ensure the environment is
	// configured correctly. We might want to not fail the transfer at this
	// stage, but we will just to be safe.

	// Ensure the server environment gets configured.
	if err := trnsfr.Server.CreateEnvironment(); err != nil {
		middleware.CaptureAndAbort(c, err)
		return
	}

	// Everything has been verified, so move the received backups into place.
	created, err := commitReceivedBackups(stagedBackups)
	written.receivedBackups = append(written.receivedBackups, created...)
	if err != nil {
		middleware.CaptureAndAbort(c, fmt.Errorf("failed to store received backups: %w", err))
		return
	}

	// Changing this causes us to notify the panel about a successful transfer,
	// rather than failing the transfer like we do by default.
	successful = true

	// The rest of the logic for ensuring the server is unlocked and everything
	// is handled in the deferred function above.
	trnsfr.Log().Debug("done!")

	c.Status(http.StatusAccepted)
}

// completeIncomingTransfer finishes receiving a transfer, telling the Panel
// whether it was successful. If it was not, everything the transfer wrote to this
// node is removed first (see cleanupFailedIncomingTransfer), since the server
// still exists on the node it was being transferred from.
//
// It reports whether the cleanup of a failed transfer removed the container and
// the data directory. If it did not, a new transfer of the server would reuse
// them, so the caller must keep refusing one.
func completeIncomingTransfer(manager *server.Manager, trnsfr *transfer.Transfer, successful bool, written incomingTransferFiles) bool {
	// Remove the transfer from the list of incoming transfers.
	transfer.Incoming().Remove(trnsfr)

	cleanedUp := true
	if !successful {
		trnsfr.Server.Events().Publish(server.TransferStatusEvent, "failure")
		// Clean up firewall rules if the transfer failed.
		if err := firewall.NewManager().DeleteAllRulesForServer(trnsfr.Server.ID()); err != nil {
			trnsfr.Log().WithError(err).Warn("failed to delete firewall rules for failed transfer")
		}
		manager.Remove(func(match *server.Server) bool {
			return match == trnsfr.Server
		})
		trnsfr.Server.CleanupForDestroy()
		// Remove the partial copy before telling the Panel, so a retry cannot race
		// the cleanup.
		if !cleanupFailedIncomingTransfer(trnsfr, written) {
			cleanedUp = false
			trnsfr.Log().Error("could not remove everything a failed transfer left on this node; new transfers of this server are refused until Wings is restarted")
		}
	}

	// Clear the transferring flag before telling the Panel, so the Panel can send
	// a power action (for example restoring a server that was running before the
	// transfer) from its success callback without being refused.
	if successful {
		trnsfr.Server.SetTransferring(false)
	}

	if err := manager.Client().SetTransferStatus(context.Background(), trnsfr.Server.ID(), successful); err != nil {
		trnsfr.Log().WithField("status", successful).WithError(err).Error("failed to set transfer status on panel")
	}

	if successful {
		trnsfr.Server.Events().Publish(server.TransferStatusEvent, "success")
	}
	return cleanedUp
}

// cleanupFailedIncomingTransfer removes everything a failed incoming transfer left
// on this node: the server's container, its data directory and quota, the backups
// and the install log received as part of the transfer, and its machine-id file.
//
// The source node keeps its own copy when a transfer fails, so nothing here is the
// only copy of the server. The exception is a shared storage pool, where the data
// directory is the source's own live data, so it is left alone when pooled.
//
// It reports whether the container and the data directory are gone.
func cleanupFailedIncomingTransfer(trnsfr *transfer.Transfer, written incomingTransferFiles) bool {
	s := trnsfr.Server
	if s == nil {
		return true
	}
	l := trnsfr.Log()
	ok := true

	if s.Environment != nil {
		if err := s.Environment.Destroy(); err != nil {
			l.WithError(err).Warn("failed to remove the container of a failed transfer")
			ok = false
		}
	}

	dataDir := ""
	if fs := s.Filesystem(); fs != nil {
		dataDir = fs.Path()
		// Release the filesystem root before its directory is removed.
		if ufs := fs.UnixFS(); ufs != nil {
			_ = ufs.Close()
		}
	}

	if !removeFailedTransferFiles(l, s.ID(), dataDir, written) {
		ok = false
	}
	return ok
}

// removeFailedTransferFiles deletes the files written for a failed incoming
// transfer of the server with the given ID, and reports whether the data directory
// is gone (always true for a pooled transfer, whose data directory is kept).
func removeFailedTransferFiles(l *log.Entry, id, dataDir string, written incomingTransferFiles) bool {
	cfg := config.Get()
	ok := true

	if !written.pooled && dataDir != "" {
		if err := os.RemoveAll(dataDir); err != nil {
			l.WithError(err).Warn("failed to delete the server files of a failed transfer")
			ok = false
		}
		if cfg.System.Quotas.Enabled {
			if err := quotas.DelQuota(id); err != nil {
				l.WithError(err).Warn("failed to remove the quota of a failed transfer")
			}
		}
	}

	for _, p := range written.receivedBackups {
		if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
			l.WithField("backup", filepath.Base(p)).WithError(err).Warn("failed to delete a backup received by a failed transfer")
		}
	}
	// Only removed when empty, so backups this node already had are kept.
	if cfg.System.BackupDirectory != "" && len(written.receivedBackups) > 0 {
		_ = os.Remove(filepath.Join(cfg.System.BackupDirectory, id))
	}

	if written.installLogPath != "" {
		if err := os.Remove(written.installLogPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			l.WithError(err).Warn("failed to delete the install log of a failed transfer")
		}
	}
	if cfg.System.MachineID.Enable && cfg.System.MachineID.Directory != "" {
		if err := os.Remove(filepath.Join(cfg.System.MachineID.Directory, id)); err != nil && !errors.Is(err, os.ErrNotExist) {
			l.WithError(err).Warn("failed to delete the machine-id file of a failed transfer")
		}
	}

	l.WithField("pooled", written.pooled).Info("removed the partial copy of a failed incoming transfer")
	return ok
}

// stageReceivedBackup writes a backup received from the source to a new temporary
// file in backupDir and returns that file's path and the backup's SHA-256 checksum.
// The file is only readable by Wings (0600). On error nothing is left behind.
//
// A backup with the same name that is already on this node stays untouched until
// commitReceivedBackups moves the temporary file into place.
func stageReceivedBackup(backupDir, name string, r io.Reader) (string, string, error) {
	// CreateTemp creates the file with mode 0600.
	f, err := os.CreateTemp(backupDir, ".transfer-"+name+"-*")
	if err != nil {
		return "", "", err
	}
	hasher := sha256.New()
	_, err = io.Copy(f, io.TeeReader(r, hasher))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(f.Name())
		return "", "", err
	}
	return f.Name(), hex.EncodeToString(hasher.Sum(nil)), nil
}

// renameFile is os.Rename, replaceable in tests.
var renameFile = os.Rename

// commitReceivedBackups moves each staged backup (keyed by its final path) into
// place, replacing a backup of the same name that is already on this node, which
// is the same backup. It returns the final paths that did not exist before, which
// a failed transfer must remove again.
//
// Either every backup is moved into place or none is: backups that are being
// replaced are first moved aside and only deleted once all staged backups are in
// place, and restored if a step fails. On error the staged files are left for
// the caller to remove.
func commitReceivedBackups(staged map[string]string) ([]string, error) {
	type commit struct {
		final, tmp string
		existed    bool
		aside      string // where the existing backup was moved to, if it existed
		done       bool   // whether tmp has been moved to final
	}
	commits := make([]*commit, 0, len(staged))
	for final, tmp := range staged {
		cm := &commit{final: final, tmp: tmp}
		st, err := os.Lstat(final)
		switch {
		case err == nil:
			if !st.Mode().IsRegular() {
				return nil, fmt.Errorf("backup %s already exists and is not a regular file", filepath.Base(final))
			}
			cm.existed = true
		case errors.Is(err, os.ErrNotExist):
		default:
			return nil, err
		}
		commits = append(commits, cm)
	}

	rollback := func() {
		for _, cm := range commits {
			if cm.done && !cm.existed {
				_ = os.Remove(cm.final)
			}
			if cm.aside != "" {
				// Replaces the received copy, if it was already moved into place.
				_ = renameFile(cm.aside, cm.final)
			}
		}
	}

	for _, cm := range commits {
		if !cm.existed {
			continue
		}
		f, err := os.CreateTemp(filepath.Dir(cm.final), ".transfer-old-"+filepath.Base(cm.final)+"-*")
		if err != nil {
			rollback()
			return nil, err
		}
		_ = f.Close()
		if err := renameFile(cm.final, f.Name()); err != nil {
			_ = os.Remove(f.Name())
			rollback()
			return nil, err
		}
		cm.aside = f.Name()
	}

	var created []string
	for _, cm := range commits {
		if err := renameFile(cm.tmp, cm.final); err != nil {
			rollback()
			return nil, err
		}
		cm.done = true
		if !cm.existed {
			created = append(created, cm.final)
		}
	}

	for _, cm := range commits {
		if cm.aside != "" {
			_ = os.Remove(cm.aside)
		}
	}
	return created, nil
}

// deleteTransfer cancels an incoming transfer for a server.
// @Summary Cancel incoming transfer
// @Tags Transfers
// @Param server path string true "Server identifier"
// @Success 202 {string} string "Accepted"
// @Failure 409 {object} ErrorResponse
// @Security NodeToken
// @Router /api/transfers/{server} [delete]
func deleteTransfer(c *gin.Context) {
	trnsfr := transfer.Incoming().Get(c.Param("server"))
	if trnsfr == nil {
		c.AbortWithStatusJSON(http.StatusConflict, gin.H{
			"error": "Server is not currently being transferred.",
		})
		return
	}

	trnsfr.Cancel()

	c.Status(http.StatusAccepted)
}
