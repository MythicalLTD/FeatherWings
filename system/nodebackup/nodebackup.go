package nodebackup

import (
	"archive/tar"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"emperror.dev/errors"
	"github.com/apex/log"
	"github.com/google/uuid"
	"github.com/klauspost/pgzip"

	"github.com/mythicalltd/featherwings/config"
	"github.com/mythicalltd/featherwings/system"
)

// Mode selects what is included in a node-level archive.
type Mode string

const (
	ModeUserBackupsOnly Mode = "user_backups_only"
	ModeFull            Mode = "full"
	ModeVolumes         Mode = "volumes"
)

const (
	StatusPending    = "pending"
	StatusRunning    = "running"
	StatusCompleted  = "completed"
	StatusFailed     = "failed"
	metaFileSuffix   = ".meta.json"
	archiveExt       = ".tar.gz"
	infoFileName     = "backup_info.txt"
	migrationInfo    = "migration_info.txt"
	migrationReadme  = "README_MIGRATION.txt"
)

// Info describes a node backup archive on disk.
type Info struct {
	UUID        string    `json:"uuid"`
	Mode        Mode      `json:"mode"`
	Status      string    `json:"status"`
	Filename    string    `json:"filename"`
	Path        string    `json:"path"`
	Bytes       int64     `json:"bytes"`
	Checksum    string    `json:"checksum,omitempty"`
	Error       string    `json:"error,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	CompletedAt time.Time `json:"completed_at,omitempty"`
	Migration   bool      `json:"migration,omitempty"`
}

// ValidateMode returns a normalized mode or an error.
func ValidateMode(mode string) (Mode, error) {
	switch Mode(strings.TrimSpace(mode)) {
	case ModeUserBackupsOnly:
		return ModeUserBackupsOnly, nil
	case ModeFull, "":
		if mode == "" {
			return ModeFull, nil
		}
		return ModeFull, nil
	case ModeVolumes:
		return ModeVolumes, nil
	default:
		return "", errors.Errorf("invalid node backup mode: %s", mode)
	}
}

func directory() string {
	dir := config.Get().System.NodeBackupDirectory
	if dir == "" {
		dir = filepath.Join(config.Get().System.RootDirectory, "wings_backup")
	}
	return dir
}

// EnsureDirectory creates the node backup directory if missing.
func EnsureDirectory() error {
	return os.MkdirAll(directory(), 0o700)
}

func archivePath(id string) string {
	return filepath.Join(directory(), id+archiveExt)
}

func metaPath(id string) string {
	return filepath.Join(directory(), id+metaFileSuffix)
}

// WriteMeta persists backup metadata next to the archive.
func WriteMeta(info *Info) error {
	if err := EnsureDirectory(); err != nil {
		return err
	}
	b, err := json.MarshalIndent(info, "", "  ")
	if err != nil {
		return errors.Wrap(err, "nodebackup: marshal meta")
	}
	return errors.Wrap(os.WriteFile(metaPath(info.UUID), b, 0o600), "nodebackup: write meta")
}

// ReadMeta loads metadata for a backup UUID.
func ReadMeta(id string) (*Info, error) {
	b, err := os.ReadFile(metaPath(id))
	if err != nil {
		return nil, err
	}
	var info Info
	if err := json.Unmarshal(b, &info); err != nil {
		return nil, errors.Wrap(err, "nodebackup: unmarshal meta")
	}
	return &info, nil
}

// List returns all known node backups (meta files), newest first.
func List() ([]Info, error) {
	if err := EnsureDirectory(); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(directory())
	if err != nil {
		return nil, err
	}
	out := make([]Info, 0, len(entries))
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, metaFileSuffix) {
			continue
		}
		id := strings.TrimSuffix(name, metaFileSuffix)
		info, err := ReadMeta(id)
		if err != nil {
			continue
		}
		if st, err := os.Stat(info.Path); err == nil {
			info.Bytes = st.Size()
		}
		out = append(out, *info)
	}
	// newest first
	for i := 0; i < len(out); i++ {
		for j := i + 1; j < len(out); j++ {
			if out[j].CreatedAt.After(out[i].CreatedAt) {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out, nil
}

// Delete removes archive and metadata for a backup UUID.
func Delete(id string) error {
	_ = os.Remove(archivePath(id))
	_ = os.Remove(metaPath(id))
	return nil
}

// NewPending allocates a pending backup record.
func NewPending(mode Mode, migration bool) (*Info, error) {
	if err := EnsureDirectory(); err != nil {
		return nil, err
	}
	id := uuid.New().String()
	info := &Info{
		UUID:      id,
		Mode:      mode,
		Status:    StatusPending,
		Filename:  id + archiveExt,
		Path:      archivePath(id),
		CreatedAt: time.Now().UTC(),
		Migration: migration,
	}
	if err := WriteMeta(info); err != nil {
		return nil, err
	}
	return info, nil
}

type sourceDir struct {
	HostPath string
	ArcName  string
}

func sourcesForMode(mode Mode) ([]sourceDir, error) {
	cfg := config.Get()
	var sources []sourceDir
	switch mode {
	case ModeVolumes:
		sources = append(sources, sourceDir{HostPath: cfg.System.Data, ArcName: "volumes"})
	case ModeUserBackupsOnly:
		sources = append(sources, sourceDir{HostPath: cfg.System.BackupDirectory, ArcName: "backups"})
	case ModeFull:
		sources = append(sources,
			sourceDir{HostPath: cfg.System.Data, ArcName: "volumes"},
			sourceDir{HostPath: cfg.System.BackupDirectory, ArcName: "backups"},
		)
	default:
		return nil, errors.Errorf("unsupported mode: %s", mode)
	}
	return sources, nil
}

func configPath() string {
	return config.DefaultLocation
}

// Create builds a node backup archive synchronously.
func Create(ctx context.Context, info *Info) error {
	info.Status = StatusRunning
	_ = WriteMeta(info)

	sources, err := sourcesForMode(info.Mode)
	if err != nil {
		return fail(info, err)
	}

	tmp := info.Path + ".partial"
	_ = os.Remove(tmp)

	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return fail(info, errors.Wrap(err, "nodebackup: create archive file"))
	}

	hasher := sha1.New()
	mw := io.MultiWriter(f, hasher)
	gw := pgzip.NewWriter(mw)
	tw := tar.NewWriter(gw)

	writeErr := func() error {
		if err := writeInfoFile(tw, info); err != nil {
			return err
		}
		if info.Migration {
			if err := writeMigrationExtras(tw, info); err != nil {
				return err
			}
		}
		if info.Mode == ModeFull {
			if err := addFile(tw, configPath(), "config/config.yml"); err != nil && !os.IsNotExist(err) {
				return err
			}
		}
		for _, src := range sources {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}
			if _, err := os.Stat(src.HostPath); err != nil {
				if os.IsNotExist(err) {
					log.WithField("path", src.HostPath).Warn("nodebackup: source missing, skipping")
					continue
				}
				return err
			}
			if err := addTree(ctx, tw, src.HostPath, src.ArcName); err != nil {
				return err
			}
		}
		return nil
	}()

	_ = tw.Close()
	_ = gw.Close()
	_ = f.Close()

	if writeErr != nil {
		_ = os.Remove(tmp)
		return fail(info, writeErr)
	}

	if err := os.Rename(tmp, info.Path); err != nil {
		_ = os.Remove(tmp)
		return fail(info, errors.Wrap(err, "nodebackup: finalize archive"))
	}

	st, err := os.Stat(info.Path)
	if err != nil {
		return fail(info, err)
	}
	info.Bytes = st.Size()
	info.Checksum = hex.EncodeToString(hasher.Sum(nil))
	info.Status = StatusCompleted
	info.CompletedAt = time.Now().UTC()
	info.Error = ""
	return WriteMeta(info)
}

func fail(info *Info, err error) error {
	info.Status = StatusFailed
	info.Error = err.Error()
	info.CompletedAt = time.Now().UTC()
	_ = WriteMeta(info)
	return err
}

func writeInfoFile(tw *tar.Writer, info *Info) error {
	cfg := config.Get()
	body := fmt.Sprintf(`FeatherWings Node Backup
UUID: %s
Mode: %s
Migration: %v
Created: %s
Hostname: %s
Wings Version: %s
Data Directory: %s
Backup Directory: %s
Config: %s
`,
		info.UUID,
		info.Mode,
		info.Migration,
		info.CreatedAt.Format(time.RFC3339),
		hostname(),
		system.Version,
		cfg.System.Data,
		cfg.System.BackupDirectory,
		configPath(),
	)
	return writeBytes(tw, infoFileName, []byte(body))
}

func writeMigrationExtras(tw *tar.Writer, info *Info) error {
	mig := fmt.Sprintf(`FeatherWings Migration Package
UUID: %s
Created: %s
Source Host: %s
`, info.UUID, info.CreatedAt.Format(time.RFC3339), hostname())
	if err := writeBytes(tw, migrationInfo, []byte(mig)); err != nil {
		return err
	}
	readme := `FeatherWings Node Migration
===========================

1. Copy this archive to the destination host (scp, rsync, or SFTP).
2. Install FeatherWings on the destination (installer or apt package).
3. Place the archive under /var/lib/featherpanel/wings_migrations/ (or pass the path).
4. Stop featherwings, then restore:
     featherwings node-backup import --file /path/to/archive.tar.gz
   or use the installer: Wings > Backup Manager > Import Migration
5. Start featherwings and update the node FQDN/IP in FeatherPanel if it changed.
`
	return writeBytes(tw, migrationReadme, []byte(readme))
}

func hostname() string {
	h, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return h
}

func writeBytes(tw *tar.Writer, name string, data []byte) error {
	hdr := &tar.Header{
		Name:    name,
		Mode:    0o644,
		Size:    int64(len(data)),
		ModTime: time.Now().UTC(),
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	_, err := tw.Write(data)
	return err
}

func addFile(tw *tar.Writer, hostPath, arcName string) error {
	st, err := os.Stat(hostPath)
	if err != nil {
		return err
	}
	if st.IsDir() {
		return errors.New("expected file: " + hostPath)
	}
	f, err := os.Open(hostPath)
	if err != nil {
		return err
	}
	defer f.Close()
	hdr, err := tar.FileInfoHeader(st, "")
	if err != nil {
		return err
	}
	hdr.Name = arcName
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	_, err = io.Copy(tw, f)
	return err
}

func addTree(ctx context.Context, tw *tar.Writer, root, arcPrefix string) error {
	return filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		name := filepath.ToSlash(filepath.Join(arcPrefix, rel))
		if info.IsDir() {
			if !strings.HasSuffix(name, "/") {
				name += "/"
			}
			hdr, err := tar.FileInfoHeader(info, "")
			if err != nil {
				return err
			}
			hdr.Name = name
			return tw.WriteHeader(hdr)
		}
		if !info.Mode().IsRegular() {
			// skip sockets/devices; include symlinks as links
			if info.Mode()&os.ModeSymlink != 0 {
				target, err := os.Readlink(path)
				if err != nil {
					return err
				}
				hdr, err := tar.FileInfoHeader(info, target)
				if err != nil {
					return err
				}
				hdr.Name = name
				return tw.WriteHeader(hdr)
			}
			return nil
		}
		hdr, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		hdr.Name = name
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(tw, f)
		_ = f.Close()
		return copyErr
	})
}

// Restore extracts a completed node backup archive onto the host paths.
func Restore(ctx context.Context, id string) error {
	info, err := ReadMeta(id)
	if err != nil {
		return errors.Wrap(err, "nodebackup: read meta")
	}
	if info.Status != StatusCompleted {
		return errors.New("nodebackup: backup is not completed")
	}
	return RestoreFile(ctx, info.Path, info.Mode)
}

// RestoreFile extracts an archive path using mode hints from backup_info when possible.
func RestoreFile(ctx context.Context, archive string, mode Mode) error {
	f, err := os.Open(archive)
	if err != nil {
		return errors.Wrap(err, "nodebackup: open archive")
	}
	defer f.Close()

	gr, err := pgzip.NewReader(f)
	if err != nil {
		return errors.Wrap(err, "nodebackup: gzip")
	}
	defer gr.Close()
	tr := tar.NewReader(gr)

	cfg := config.Get()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		name := filepath.Clean(hdr.Name)
		if name == "." || strings.HasPrefix(name, "..") {
			continue
		}
		dest, skip := mapRestorePath(name, cfg, mode)
		if skip {
			continue
		}
		if hdr.Typeflag == tar.TypeDir {
			if err := os.MkdirAll(dest, 0o700); err != nil {
				return err
			}
			continue
		}
		if hdr.Typeflag == tar.TypeSymlink {
			_ = os.Remove(dest)
			if err := os.MkdirAll(filepath.Dir(dest), 0o700); err != nil {
				return err
			}
			if err := os.Symlink(hdr.Linkname, dest); err != nil {
				return err
			}
			continue
		}
		if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeRegA {
			continue
		}
		if err := os.MkdirAll(filepath.Dir(dest), 0o700); err != nil {
			return err
		}
		out, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(hdr.Mode))
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(out, tr)
		_ = out.Close()
		if copyErr != nil {
			return copyErr
		}
	}
	return nil
}

func mapRestorePath(name string, cfg *config.Configuration, mode Mode) (string, bool) {
	switch {
	case name == infoFileName || name == migrationInfo || name == migrationReadme:
		return "", true
	case strings.HasPrefix(name, "config/"):
		if name == "config/config.yml" {
			return configPath(), false
		}
		return "", true
	case strings.HasPrefix(name, "volumes/"):
		rel := strings.TrimPrefix(name, "volumes/")
		return filepath.Join(cfg.System.Data, rel), false
	case strings.HasPrefix(name, "backups/"):
		if mode == ModeVolumes {
			return "", true
		}
		rel := strings.TrimPrefix(name, "backups/")
		return filepath.Join(cfg.System.BackupDirectory, rel), false
	default:
		return "", true
	}
}
