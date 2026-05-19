package filesystem

import (
	"context"
	iofs "io/fs"
	"path"
	"path/filepath"
	"strings"

	"emperror.dev/errors"
	"github.com/mholt/archives"

	"github.com/mythicalltd/featherwings/internal/ufs"
)

// MaxArchiveExtractFiles is the maximum number of files that can be extracted in one request.
const MaxArchiveExtractFiles = 10000

// sanitizeArchiveMemberPath validates a path of a file or directory inside an archive.
func sanitizeArchiveMemberPath(p string) (string, error) {
	p = strings.TrimSpace(filepath.ToSlash(p))
	if p == "" || p == "." {
		return "", errors.New("invalid archive member path")
	}
	p = path.Clean(p)
	if p == "." {
		return "", errors.New("invalid archive member path")
	}
	var depth int
	for _, part := range strings.Split(p, "/") {
		if part == "" || part == "." {
			continue
		}
		if part == ".." {
			depth--
			if depth < 0 {
				return "", errors.New("invalid archive member path")
			}
			continue
		}
		depth++
	}
	if !iofs.ValidPath(p) {
		return "", errors.New("invalid archive member path")
	}
	return p, nil
}

func expandArchiveEntriesToFiles(fsys iofs.FS, rawEntries []string) ([]string, error) {
	seen := make(map[string]struct{})
	var out []string

	for _, raw := range rawEntries {
		p, err := sanitizeArchiveMemberPath(raw)
		if err != nil {
			return nil, err
		}
		st, err := iofs.Stat(fsys, p)
		if err != nil {
			return nil, errors.Wrap(err, "stat archive member")
		}
		if !st.IsDir() {
			if _, ok := seen[p]; !ok {
				seen[p] = struct{}{}
				out = append(out, p)
				if len(out) > MaxArchiveExtractFiles {
					return nil, errors.New("too many files to extract in one request")
				}
			}
			continue
		}
		err = iofs.WalkDir(fsys, p, func(subpath string, d iofs.DirEntry, werr error) error {
			if werr != nil {
				return werr
			}
			if d.IsDir() {
				return nil
			}
			if _, ok := seen[subpath]; ok {
				return nil
			}
			seen[subpath] = struct{}{}
			out = append(out, subpath)
			if len(out) > MaxArchiveExtractFiles {
				return errors.New("too many files to extract in one request")
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}

	if len(out) == 0 {
		return nil, errors.New("no files matched the requested entries")
	}
	return out, nil
}

func destinationRelativePath(destDir, member string) string {
	d := filepath.ToSlash(strings.TrimSpace(destDir))
	d = strings.TrimPrefix(d, "/")
	d = strings.TrimSuffix(d, "/")
	m := filepath.ToSlash(member)
	out := path.Join(d, m)
	if out == "." {
		return ""
	}
	return out
}

// ExtractArchiveMembers writes given files and/or directory trees from an on-disk archive into the server filesystem.
// root and archiveFile identify the archive (same as decompress). destination is the directory on the server to write under.
// entries are paths inside the archive (files or directories).
func (fs *Filesystem) ExtractArchiveMembers(ctx context.Context, root, archiveFile, destination string, entries []string) error {
	root = strings.TrimSpace(root)
	archiveFile = strings.TrimSpace(archiveFile)
	destination = strings.TrimSpace(destination)
	if archiveFile == "" {
		return errors.New("archive file is required")
	}
	if len(entries) == 0 {
		return errors.New("at least one entry is required")
	}

	rootSlash := filepath.ToSlash(root)
	rootSlash = strings.Trim(rootSlash, "/")
	archSlash := filepath.ToSlash(archiveFile)
	archSlash = strings.TrimPrefix(archSlash, "/")
	ignoreKey := path.Join(rootSlash, archSlash)
	if err := fs.IsIgnored(ignoreKey); err != nil {
		return err
	}

	archivePath := filepath.Join(root, archiveFile)
	fsys, cleanup, err := fs.openArchiveFS(ctx, archivePath)
	if err != nil {
		if errors.Is(err, archives.NoMatch) {
			return newFilesystemError(ErrCodeUnknownArchive, err)
		}
		return err
	}
	defer cleanup()

	toWrite, err := expandArchiveEntriesToFiles(fsys, entries)
	if err != nil {
		return err
	}

	for _, member := range toWrite {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		outRel := destinationRelativePath(destination, member)
		if strings.Contains(outRel, "..") {
			return errors.New("invalid extraction path")
		}
		if err := fs.IsIgnored(outRel); err != nil {
			continue
		}

		vf, err := fsys.Open(member)
		if err != nil {
			return errors.Wrap(err, "open archive member")
		}
		st, err := vf.Stat()
		if err != nil {
			_ = vf.Close()
			return err
		}
		if st.IsDir() {
			_ = vf.Close()
			continue
		}

		mode := ufs.FileMode(st.Mode().Perm())
		if mode == 0 {
			mode = 0o644
		}
		sz := st.Size()
		if err := fs.Write(outRel, vf, sz, mode); err != nil {
			_ = vf.Close()
			return errors.Wrap(err, "write extracted file")
		}
		_ = vf.Close()

		if mt := st.ModTime(); !mt.IsZero() {
			_ = fs.Chtimes(outRel, mt, mt)
		}
	}

	return nil
}
