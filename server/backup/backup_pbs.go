package backup

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"emperror.dev/errors"
	"github.com/apex/log"

	"github.com/mythicalltd/featherwings/config"
	"github.com/mythicalltd/featherwings/remote"
	"github.com/mythicalltd/featherwings/server/filesystem"
)

const (
	// PBSChecksumType is reported to the panel so it can identify PBS snapshots.
	PBSChecksumType = "pbs"

	// pbsBackupType groups Docker server backups as containers on PBS.
	pbsBackupType = "ct"

	// pbsArchiveDefault is used when config does not set archive_name.
	pbsArchiveDefault = "server.pxar"
)

// PBSBackup streams server files to Proxmox Backup Server via proxmox-backup-client.
// It does NOT create local tar.gz archives — PBS handles chunking, deduplication,
// and compression natively.
type PBSBackup struct {
	Backup
	snapshot string
	size     int64
}

var _ BackupInterface = (*PBSBackup)(nil)

// DirectRestorer restores archive contents straight into a destination directory
// without requiring a per-file callback (used by PBS pxar restore).
type DirectRestorer interface {
	RestoreDirect(ctx context.Context, dest string) error
}

var _ DirectRestorer = (*PBSBackup)(nil)

// NewPBS creates a PBS-backed backup adapter instance.
func NewPBS(client remote.Client, uuid string, suuid string, ignore string) *PBSBackup {
	return &PBSBackup{
		Backup: Backup{
			client:     client,
			Uuid:       uuid,
			ServerUuid: suuid,
			Ignore:     ignore,
			adapter:    PBSBackupAdapter,
		},
	}
}

// LocatePBS finds an existing PBS snapshot for this panel backup UUID under the
// server's backup group. Notes on the snapshot store the panel backup UUID.
func LocatePBS(client remote.Client, uuid string, suuid string) (*PBSBackup, error) {
	b := NewPBS(client, uuid, suuid, "")
	snap, size, err := b.findSnapshotByNotes(context.Background(), uuid)
	if err != nil {
		return nil, err
	}
	b.snapshot = snap
	b.size = size
	return b, nil
}

// WithLogContext attaches additional context to the log output for this backup.
func (b *PBSBackup) WithLogContext(c map[string]interface{}) {
	b.logContext = c
}

// Path returns an empty string — PBS backups are not stored as local files.
func (b *PBSBackup) Path() string {
	return ""
}

// Size returns the logical size reported by PBS for the snapshot.
func (b *PBSBackup) Size() (int64, error) {
	if b.size > 0 {
		return b.size, nil
	}
	if b.snapshot == "" {
		return 0, errors.New("backup: pbs snapshot not resolved")
	}
	return b.size, nil
}

// Checksum returns a SHA1 of the snapshot path for a stable panel checksum field
// companion; Details() also returns the snapshot path as Checksum with type "pbs".
func (b *PBSBackup) Checksum() ([]byte, error) {
	if b.snapshot == "" {
		return nil, errors.New("backup: pbs snapshot not resolved")
	}
	sum := sha1.Sum([]byte(b.snapshot))
	return sum[:], nil
}

// Details returns PBS snapshot identity and size for the panel callback.
func (b *PBSBackup) Details(ctx context.Context, parts []remote.BackupPart) (*ArchiveDetails, error) {
	_ = ctx
	if b.snapshot == "" {
		return nil, errors.New("backup: pbs snapshot not resolved")
	}
	return &ArchiveDetails{
		Checksum:     b.snapshot,
		ChecksumType: PBSChecksumType,
		Size:         b.size,
		Parts:        parts,
	}, nil
}

// Remove forgets the PBS snapshot associated with this panel backup UUID.
func (b *PBSBackup) Remove() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	snap := b.snapshot
	if snap == "" {
		var err error
		snap, _, err = b.findSnapshotByNotes(ctx, b.Identifier())
		if err != nil {
			return err
		}
	}
	return b.forgetSnapshot(ctx, snap)
}

// Generate streams the server directory to PBS without creating a local archive.
func (b *PBSBackup) Generate(ctx context.Context, fsys *filesystem.Filesystem, ignore string) (*ArchiveDetails, error) {
	cfg, err := pbsConfig()
	if err != nil {
		return nil, err
	}
	if !cfg.Enabled {
		return nil, errors.New("backup: pbs adapter is not enabled in Wings config (system.backups.pbs.enabled)")
	}
	if _, err := exec.LookPath(cfg.Binary); err != nil {
		return nil, errors.Wrap(err, "backup: proxmox-backup-client not found on PATH (install pbs-client / proxmox-backup-client)")
	}

	source := fsys.Path()
	if st, err := os.Stat(source); err != nil || !st.IsDir() {
		return nil, errors.Wrap(err, "backup: server data directory is not accessible for PBS backup")
	}

	archiveName := cfg.ArchiveName
	if archiveName == "" {
		archiveName = pbsArchiveDefault
	}
	if !strings.HasSuffix(archiveName, ".pxar") {
		archiveName += ".pxar"
	}

	args := []string{
		"backup",
		fmt.Sprintf("%s:%s", archiveName, source),
		"--backup-type", pbsBackupType,
		"--backup-id", b.ServerId(),
		"--backup-time", fmt.Sprintf("%d", time.Now().UTC().Unix()),
	}
	args = append(args, b.repoArgs(cfg)...)
	if ns := strings.TrimSpace(cfg.Namespace); ns != "" {
		args = append(args, "--ns", ns)
	}
	mode := strings.TrimSpace(cfg.ChangeDetectionMode)
	if mode == "" {
		mode = "metadata"
	}
	args = append(args, "--change-detection-mode", mode)
	if kf := strings.TrimSpace(cfg.KeyFile); kf != "" {
		args = append(args, "--keyfile", kf)
	}
	for _, pattern := range parseIgnorePatterns(ignore) {
		args = append(args, "--exclude", pattern)
	}

	b.log().WithFields(log.Fields{
		"source":     source,
		"backup_id":  b.ServerId(),
		"panel_uuid": b.Identifier(),
		"namespace":  cfg.Namespace,
	}).Info("creating PBS backup for server (no local archive)")

	out, err := b.runClient(ctx, cfg, args...)
	if err != nil {
		return nil, errors.Wrap(err, "backup: proxmox-backup-client backup failed: "+string(out))
	}
	b.log().WithField("output", string(out)).Debug("pbs backup command finished")

	snap := parseSnapshotFromBackupOutput(string(out), b.ServerId())
	var size int64
	if snap == "" {
		snap, size, err = b.newestSnapshot(ctx)
		if err != nil {
			return nil, errors.Wrap(err, "backup: failed to resolve created PBS snapshot")
		}
	} else {
		// Refresh size from snapshot list when possible.
		if snaps, lerr := b.listSnapshots(ctx); lerr == nil {
			for _, s := range snaps {
				if s.fullPath(b.ServerId()) == snap {
					size = s.Size
					break
				}
			}
		}
	}
	b.snapshot = snap
	b.size = size

	if err := b.setSnapshotNotes(ctx, snap, b.Identifier()); err != nil {
		// Best-effort cleanup so we do not leave an unmapped snapshot behind.
		_ = b.forgetSnapshot(ctx, snap)
		return nil, errors.Wrap(err, "backup: failed to tag PBS snapshot with panel backup UUID")
	}

	b.log().WithFields(log.Fields{
		"snapshot": snap,
		"size":     size,
	}).Info("created PBS backup successfully")

	return b.Details(ctx, nil)
}

// Restore is unused for PBS when RestoreDirect is available; it restores into a
// temporary directory and invokes the callback for compatibility.
func (b *PBSBackup) Restore(ctx context.Context, _ io.Reader, callback RestoreCallback) error {
	tmp, err := os.MkdirTemp(config.Get().System.TmpDirectory, "pbs-restore-*")
	if err != nil {
		return errors.Wrap(err, "backup: failed to create PBS restore temp directory")
	}
	defer os.RemoveAll(tmp)

	if err := b.RestoreDirect(ctx, tmp); err != nil {
		return err
	}

	return filepath.WalkDir(tmp, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(tmp, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if d.IsDir() {
			// Directory creation is handled by Write when nested files arrive;
			// emit an empty reader so callers can mkdir if needed.
			return callback(rel, info, io.NopCloser(bytes.NewReader(nil)))
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()
		return callback(rel, info, f)
	})
}

// RestoreDirect restores the pxar archive for this backup into dest.
func (b *PBSBackup) RestoreDirect(ctx context.Context, dest string) error {
	cfg, err := pbsConfig()
	if err != nil {
		return err
	}
	snap := b.snapshot
	if snap == "" {
		var size int64
		snap, size, err = b.findSnapshotByNotes(ctx, b.Identifier())
		if err != nil {
			return err
		}
		b.snapshot = snap
		b.size = size
	}
	archiveName := cfg.ArchiveName
	if archiveName == "" {
		archiveName = pbsArchiveDefault
	}
	if !strings.HasSuffix(archiveName, ".pxar") {
		archiveName += ".pxar"
	}

	if err := os.MkdirAll(dest, 0o755); err != nil {
		return errors.Wrap(err, "backup: failed to prepare PBS restore destination")
	}

	args := []string{"restore", snap, archiveName, dest}
	args = append(args, b.repoArgs(cfg)...)
	if ns := strings.TrimSpace(cfg.Namespace); ns != "" {
		args = append(args, "--ns", ns)
	}
	if kf := strings.TrimSpace(cfg.KeyFile); kf != "" {
		args = append(args, "--keyfile", kf)
	}

	b.log().WithFields(log.Fields{
		"snapshot": snap,
		"dest":     dest,
	}).Info("restoring PBS backup to server directory")

	out, err := b.runClient(ctx, cfg, args...)
	if err != nil {
		return errors.Wrap(err, "backup: proxmox-backup-client restore failed: "+string(out))
	}
	return nil
}

// ForgetServerSnapshots removes every PBS snapshot in this server's backup group.
func ForgetServerSnapshots(ctx context.Context, serverUUID string) error {
	cfg, err := pbsConfig()
	if err != nil {
		return err
	}
	if !cfg.Enabled {
		return nil
	}
	b := NewPBS(nil, "", serverUUID, "")
	snaps, err := b.listSnapshots(ctx)
	if err != nil {
		return err
	}
	var first error
	for _, s := range snaps {
		path := s.fullPath(serverUUID)
		if err := b.forgetSnapshot(ctx, path); err != nil && first == nil {
			first = err
		}
	}
	return first
}

type pbsSnapshot struct {
	BackupID string `json:"backup-id"`
	// Some client versions use "snapshot" as the full path.
	Snapshot string `json:"snapshot"`
	Size     int64  `json:"size"`
	Notes    string `json:"notes"`
	Comment  string `json:"comment"`
	Time     int64  `json:"backup-time"`
}

func (b *PBSBackup) newestSnapshot(ctx context.Context) (string, int64, error) {
	snaps, err := b.listSnapshots(ctx)
	if err != nil {
		return "", 0, err
	}
	if len(snaps) == 0 {
		return "", 0, errors.New("backup: no PBS snapshots found after backup")
	}
	best := snaps[0]
	for _, s := range snaps[1:] {
		if s.Time > best.Time {
			best = s
		}
	}
	path := best.fullPath(b.ServerId())
	return path, best.Size, nil
}

func (b *PBSBackup) findSnapshotByNotes(ctx context.Context, panelUUID string) (string, int64, error) {
	snaps, err := b.listSnapshots(ctx)
	if err != nil {
		return "", 0, err
	}
	panelUUID = strings.TrimSpace(panelUUID)
	for _, s := range snaps {
		path := s.fullPath(b.ServerId())
		note := strings.TrimSpace(s.Notes)
		if note == "" {
			note = strings.TrimSpace(s.Comment)
		}
		if note == "" {
			if n, nerr := b.getSnapshotNotes(ctx, path); nerr == nil {
				note = strings.TrimSpace(n)
			}
		}
		if note == panelUUID {
			return path, s.Size, nil
		}
	}
	return "", 0, errors.WithStack(os.ErrNotExist)
}

func (b *PBSBackup) getSnapshotNotes(ctx context.Context, snapshot string) (string, error) {
	cfg, err := pbsConfig()
	if err != nil {
		return "", err
	}
	args := []string{"snapshot", "notes", "show", snapshot, "--output-format", "json"}
	args = append(args, b.repoArgs(cfg)...)
	if ns := strings.TrimSpace(cfg.Namespace); ns != "" {
		args = append(args, "--ns", ns)
	}
	out, err := b.runClient(ctx, cfg, args...)
	if err != nil {
		// Fallback: plain text notes
		argsText := []string{"snapshot", "notes", "show", snapshot}
		argsText = append(argsText, b.repoArgs(cfg)...)
		if ns := strings.TrimSpace(cfg.Namespace); ns != "" {
			argsText = append(argsText, "--ns", ns)
		}
		out, err = b.runClient(ctx, cfg, argsText...)
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(out)), nil
	}
	var payload any
	if err := json.Unmarshal(bytes.TrimSpace(out), &payload); err != nil {
		return strings.TrimSpace(string(out)), nil
	}
	switch v := payload.(type) {
	case string:
		return v, nil
	case map[string]any:
		if n, ok := v["notes"].(string); ok {
			return n, nil
		}
		if n, ok := v["comment"].(string); ok {
			return n, nil
		}
	}
	return strings.TrimSpace(string(out)), nil
}

func (s pbsSnapshot) fullPath(serverUUID string) string {
	if s.Snapshot != "" {
		return s.Snapshot
	}
	if strings.Contains(s.BackupID, "/") {
		return s.BackupID
	}
	// Reconstruct ct/<server>/<rfc3339> when only components are present.
	if s.Time > 0 {
		ts := time.Unix(s.Time, 0).UTC().Format("2006-01-02T15:04:05Z")
		return fmt.Sprintf("%s/%s/%s", pbsBackupType, serverUUID, ts)
	}
	return s.BackupID
}

func (b *PBSBackup) listSnapshots(ctx context.Context) ([]pbsSnapshot, error) {
	cfg, err := pbsConfig()
	if err != nil {
		return nil, err
	}
	args := []string{
		"snapshot", "list",
		"--backup-type", pbsBackupType,
		"--backup-id", b.ServerId(),
		"--output-format", "json",
	}
	args = append(args, b.repoArgs(cfg)...)
	if ns := strings.TrimSpace(cfg.Namespace); ns != "" {
		args = append(args, "--ns", ns)
	}
	out, err := b.runClient(ctx, cfg, args...)
	if err != nil {
		return nil, errors.Wrap(err, "backup: failed to list PBS snapshots: "+string(out))
	}
	out = bytes.TrimSpace(out)
	if len(out) == 0 || string(out) == "null" {
		return nil, nil
	}
	var snaps []pbsSnapshot
	if err := json.Unmarshal(out, &snaps); err != nil {
		// Some versions wrap the array.
		var wrapped struct {
			Data []pbsSnapshot `json:"data"`
		}
		if err2 := json.Unmarshal(out, &wrapped); err2 != nil {
			return nil, errors.Wrap(err, "backup: failed to parse PBS snapshot list")
		}
		snaps = wrapped.Data
	}
	return snaps, nil
}

func (b *PBSBackup) setSnapshotNotes(ctx context.Context, snapshot, notes string) error {
	cfg, err := pbsConfig()
	if err != nil {
		return err
	}
	args := []string{"snapshot", "notes", "update", snapshot, notes}
	args = append(args, b.repoArgs(cfg)...)
	if ns := strings.TrimSpace(cfg.Namespace); ns != "" {
		args = append(args, "--ns", ns)
	}
	out, err := b.runClient(ctx, cfg, args...)
	if err != nil {
		return errors.Wrap(err, "backup: failed to update PBS snapshot notes: "+string(out))
	}
	return nil
}

func (b *PBSBackup) forgetSnapshot(ctx context.Context, snapshot string) error {
	cfg, err := pbsConfig()
	if err != nil {
		return err
	}
	args := []string{"snapshot", "forget", snapshot}
	args = append(args, b.repoArgs(cfg)...)
	if ns := strings.TrimSpace(cfg.Namespace); ns != "" {
		args = append(args, "--ns", ns)
	}
	out, err := b.runClient(ctx, cfg, args...)
	if err != nil {
		return errors.Wrap(err, "backup: failed to forget PBS snapshot: "+string(out))
	}
	b.log().WithField("snapshot", snapshot).Info("forgot PBS snapshot")
	return nil
}

func (b *PBSBackup) repoArgs(cfg config.PBSBackups) []string {
	if repo := strings.TrimSpace(cfg.Repository); repo != "" {
		return []string{"--repository", repo}
	}
	var args []string
	if cfg.Server != "" {
		args = append(args, "--server", cfg.Server)
	}
	if cfg.Port > 0 {
		args = append(args, "--port", fmt.Sprintf("%d", cfg.Port))
	}
	if cfg.Datastore != "" {
		args = append(args, "--datastore", cfg.Datastore)
	}
	if cfg.AuthID != "" {
		args = append(args, "--auth-id", cfg.AuthID)
	}
	return args
}

func (b *PBSBackup) runClient(ctx context.Context, cfg config.PBSBackups, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, cfg.Binary, args...)
	cmd.Env = pbsEnv(cfg)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	combined := append(stdout.Bytes(), stderr.Bytes()...)
	if err != nil {
		return combined, err
	}
	return combined, nil
}

func pbsEnv(cfg config.PBSBackups) []string {
	env := os.Environ()
	set := func(k, v string) {
		if strings.TrimSpace(v) == "" {
			return
		}
		env = append(env, k+"="+v)
	}
	set("PBS_PASSWORD", cfg.Password)
	set("PBS_FINGERPRINT", cfg.Fingerprint)
	set("PBS_ENCRYPTION_PASSWORD", cfg.EncryptionPassword)
	if repo := strings.TrimSpace(cfg.Repository); repo != "" {
		set("PBS_REPOSITORY", repo)
	}
	return env
}

func pbsConfig() (config.PBSBackups, error) {
	cfg := config.Get().System.Backups.PBS
	if strings.TrimSpace(cfg.Binary) == "" {
		cfg.Binary = "proxmox-backup-client"
	}
	if strings.TrimSpace(cfg.Repository) == "" && strings.TrimSpace(cfg.Datastore) == "" {
		return cfg, errors.New("backup: pbs repository/datastore is not configured")
	}
	return cfg, nil
}

// parseIgnorePatterns converts a newline-separated ignore list (gitignore-style
// from the panel) into PBS --exclude patterns.
func parseIgnorePatterns(ignore string) []string {
	if strings.TrimSpace(ignore) == "" {
		return nil
	}
	var out []string
	sc := bufio.NewScanner(strings.NewReader(ignore))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// PBS exclude paths are rooted at the archive source; strip leading ./
		line = strings.TrimPrefix(line, "./")
		if !strings.HasPrefix(line, "/") {
			line = "/" + line
		}
		out = append(out, line)
	}
	return out
}

// parseSnapshotFromBackupOutput extracts "ct/<id>/<timestamp>" from client logs.
func parseSnapshotFromBackupOutput(output, serverUUID string) string {
	prefix := pbsBackupType + "/" + serverUUID + "/"
	sc := bufio.NewScanner(strings.NewReader(output))
	for sc.Scan() {
		line := sc.Text()
		if idx := strings.Index(line, prefix); idx >= 0 {
			rest := line[idx:]
			// snapshot path ends at whitespace or end of line
			end := len(rest)
			for i, r := range rest {
				if r == ' ' || r == '\t' || r == '\r' {
					end = i
					break
				}
			}
			return strings.TrimSpace(rest[:end])
		}
		// Also match "Starting backup: ct/..."
		const marker = "Starting backup: "
		if i := strings.Index(line, marker); i >= 0 {
			return strings.TrimSpace(line[i+len(marker):])
		}
	}
	return ""
}

// SnapshotPath returns the resolved PBS snapshot path if known.
func (b *PBSBackup) SnapshotPath() string {
	return b.snapshot
}

// EncodeChecksum is a helper for tests / logging.
func EncodeChecksum(sum []byte) string {
	return hex.EncodeToString(sum)
}
