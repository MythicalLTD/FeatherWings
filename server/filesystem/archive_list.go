package filesystem

import (
	"context"
	iofs "io/fs"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"emperror.dev/errors"
	"github.com/mholt/archives"
)

// MaxArchiveListEntries caps how many names are returned from ListArchiveContents to keep responses bounded.
const MaxArchiveListEntries = 2500

// ArchiveListEntry describes one file or directory inside an on-disk archive (zip, tar, etc.).
type ArchiveListEntry struct {
	Name      string `json:"name"`
	Path      string `json:"path"`
	Size      int64  `json:"size"`
	Directory bool   `json:"directory"`
	Modified  string `json:"modified,omitempty"`
}

func sanitizeArchiveListDir(p string) (string, error) {
	p = strings.TrimSpace(filepath.ToSlash(p))
	if p == "" || p == "." {
		return ".", nil
	}
	p = path.Clean(p)
	if p == "." {
		return ".", nil
	}
	var depth int
	for _, part := range strings.Split(p, "/") {
		if part == "" || part == "." {
			continue
		}
		if part == ".." {
			depth--
			if depth < 0 {
				return "", errors.New("invalid archive path")
			}
			continue
		}
		depth++
	}
	if !iofs.ValidPath(p) {
		return "", errors.New("invalid archive path")
	}
	return p, nil
}

func childPathInArchive(listDir, name string) string {
	if listDir == "." {
		return name
	}
	return path.Join(listDir, name)
}

// ListArchiveContents lists one directory level inside an archive at archivePath = join(root, archiveFile)
// without extracting it. innerPath is a path inside the archive ("." for root).
func (fs *Filesystem) ListArchiveContents(ctx context.Context, root, archiveFile, innerPath string) ([]ArchiveListEntry, bool, error) {
	root = strings.TrimSpace(root)
	archiveFile = strings.TrimSpace(archiveFile)
	if archiveFile == "" {
		return nil, false, errors.New("archive file name is required")
	}

	rootSlash := filepath.ToSlash(root)
	rootSlash = strings.Trim(rootSlash, "/")
	archSlash := filepath.ToSlash(archiveFile)
	archSlash = strings.TrimPrefix(archSlash, "/")
	ignoreKey := path.Join(rootSlash, archSlash)
	if err := fs.IsIgnored(ignoreKey); err != nil {
		return nil, false, err
	}

	listDir, err := sanitizeArchiveListDir(innerPath)
	if err != nil {
		return nil, false, err
	}

	archivePath := filepath.Join(root, archiveFile)
	fsys, cleanup, err := fs.openArchiveFS(ctx, archivePath)
	if err != nil {
		if errors.Is(err, archives.NoMatch) {
			return nil, false, newFilesystemError(ErrCodeUnknownArchive, err)
		}
		return nil, false, err
	}
	defer cleanup()

	des, err := iofs.ReadDir(fsys, listDir)
	if err != nil {
		return nil, false, err
	}

	truncated := len(des) > MaxArchiveListEntries
	if truncated {
		des = des[:MaxArchiveListEntries]
	}

	out := make([]ArchiveListEntry, 0, len(des))
	for _, de := range des {
		info, err := de.Info()
		if err != nil {
			continue
		}
		name := de.Name()
		out = append(out, ArchiveListEntry{
			Name:      name,
			Path:      childPathInArchive(listDir, name),
			Size:      info.Size(),
			Directory: info.IsDir(),
			Modified:  formatArchiveModTime(info.ModTime()),
		})
	}

	slices.SortStableFunc(out, func(a, b ArchiveListEntry) int {
		switch {
		case a.Directory && !b.Directory:
			return -1
		case !a.Directory && b.Directory:
			return 1
		case a.Name == b.Name:
			return 0
		case a.Name < b.Name:
			return -1
		default:
			return 1
		}
	})

	return out, truncated, nil
}

func formatArchiveModTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}
