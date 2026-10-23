package filesystem

import (
	"archive/tar"
	"context"
	"fmt"
	"io"
	iofs "io/fs"
	"math"
	"path"
	"path/filepath"
	"strings"
	"time"

	"emperror.dev/errors"
	"github.com/klauspost/compress/zip"
	"github.com/mholt/archives"

	"github.com/mythicalltd/featherwings/internal/ufs"
	"github.com/mythicalltd/featherwings/server/filesystem/archiverext"
)

// CompressFiles compresses all the files matching the given paths in the
// specified directory. This function also supports passing nested paths to only
// compress certain files and folders when working in a larger directory. This
// effectively creates a local backup, but rather than ignoring specific files
// and folders, it takes an allow-list of files and folders.
//
// All paths are relative to the dir that is passed in as the first argument,
// and the compressed file will be placed at that location named
// `archive-{date}.tar.gz`.
func (fs *Filesystem) CompressFiles(ctx context.Context, dir string, name string, paths []string, extension string) (ufs.FileInfo, string, error) {
	var validPaths []string
	for _, file := range paths {
		if err := fs.IsIgnored(path.Join(dir, file)); err == nil {
			validPaths = append(validPaths, file)
		}
	}

	// If there are no valid paths, return an error
	if len(validPaths) == 0 {
		return nil, "", fmt.Errorf("no valid files to compress")
	}

	// Normalize extension & assign MIME type
	extension = strings.ToLower(strings.TrimPrefix(extension, "."))
	var (
		ext      string
		mimetype string
	)
	switch extension {
	case "zip":
		ext = ".zip"
		mimetype = "application/zip"
	case "tar.gz", "tgz":
		ext = ".tar.gz"
		mimetype = "application/gzip"
	case "tar.bz2", "tbz2":
		ext = ".tar.bz2"
		mimetype = "application/x-bzip2"
	case "tar.xz", "txz":
		ext = ".tar.xz"
		mimetype = "application/x-xz"
	default:
		// fallback to tar.gz
		ext = ".tar.gz"
		mimetype = "application/gzip"
	}

	if name == "" {
		name = fmt.Sprintf("archive-%s%s", strings.ReplaceAll(time.Now().Format(time.RFC3339), ":", ""), ext)
	} else {
		dirfd, _, closeFd, err := fs.unixFS.SafePath(path.Join(dir, name) + ext)
		if err != nil {
			if closeFd != nil {
				closeFd()
			}
			return nil, "", err
		}
		if closeFd != nil {
			defer closeFd()
		}

		name, err = fs.findCopySuffix(dirfd, name, ext)
		if err != nil {
			return nil, "", err
		}
	}

	destPath := path.Join(dir, name)

	filesMap := make(map[string]string)
	for _, file := range validPaths {
		_, p, closeFd, err := fs.unixFS.SafePath(path.Join(dir, file))
		if closeFd != nil {
			defer closeFd()
		}
		if err != nil {
			return nil, "", err
		}

		// Construct the absolute path on disk for reading the file
		absolutePath := filepath.Join(fs.Path(), dir, p)
		// Only use the bare filename inside the archive
		filesMap[absolutePath] = file
	}

	files, err := archives.FilesFromDisk(ctx, nil, filesMap)
	if err != nil {
		return nil, "", err
	}

	// Never write into an existing file, such as an archive created by another
	// request within the same second.
	f, err := fs.unixFS.OpenFile(destPath, ufs.O_WRONLY|ufs.O_CREATE|ufs.O_EXCL, 0o644)
	if err != nil {
		return nil, "", err
	}

	// Count every write to the archive against the disk limit as it happens, so
	// that archives being created at the same time cannot each use all the space
	// that is left.
	cw := newQuotaFile(fs, f, 0)
	fail := func(err error) (ufs.FileInfo, string, error) {
		_ = cw.Close()
		_ = fs.unixFS.Remove(destPath)
		return nil, "", err
	}

	// Call the correct archiver
	switch extension {
	case "zip":
		zipper := archives.Zip{}
		if err := zipper.Archive(ctx, cw, files); err != nil {
			return fail(err)
		}
	case "tar.bz2", "tbz2":
		format := archives.CompressedArchive{
			Compression: archives.Bz2{},
			Archival:    archives.Tar{},
		}
		if err := format.Archive(ctx, cw, files); err != nil {
			return fail(err)
		}
	case "tar.xz", "txz":
		format := archives.CompressedArchive{
			Compression: archives.Xz{},
			Archival:    archives.Tar{},
		}
		if err := format.Archive(ctx, cw, files); err != nil {
			return fail(err)
		}
	default: // tar.gz and fallback
		format := archives.CompressedArchive{
			Compression: archives.Gz{},
			Archival:    archives.Tar{},
		}
		if err := format.Archive(ctx, cw, files); err != nil {
			return fail(err)
		}
	}

	info, err := cw.Stat()
	if err != nil {
		return fail(err)
	}
	if err := cw.Close(); err != nil {
		return nil, "", err
	}
	return info, mimetype, nil
}

// openArchiveFS opens an on-disk archive as an io/fs.FS. The caller must invoke cleanup
// when finished to close the backing file descriptor.
func (fs *Filesystem) openArchiveFS(ctx context.Context, archivePath string) (_ iofs.FS, cleanup func(), err error) {
	cleanup = func() {}

	f, err := fs.unixFS.Open(archivePath)
	if err != nil {
		return nil, cleanup, err
	}
	cleanup = func() { _ = f.Close() }

	format, _, err := archives.Identify(ctx, filepath.Base(archivePath), f)
	if err != nil && !errors.Is(err, archives.NoMatch) {
		cleanup()
		return nil, func() {}, err
	}

	if _, err := f.Seek(0, io.SeekStart); err != nil {
		cleanup()
		return nil, func() {}, err
	}

	info, err := f.Stat()
	if err != nil {
		cleanup()
		return nil, func() {}, err
	}

	if format == nil {
		cleanup()
		return nil, func() {}, archives.NoMatch
	}

	switch ff := format.(type) {
	case archives.Zip:
		zr, err := zip.NewReader(f, info.Size())
		if err != nil {
			cleanup()
			return nil, func() {}, err
		}
		// Use a deduplicating FS: stdlib/klauspost zip.Reader rejects archives
		// with duplicate entry names (e.g. shaded jars with multiple LICENSE files).
		return archiverext.NewZipFS(zr), cleanup, nil
	case archives.Extraction:
		afs := &archives.ArchiveFS{
			Stream:  io.NewSectionReader(f, 0, info.Size()),
			Format:  ff,
			Context: ctx,
		}
		return afs, cleanup, nil
	case archives.Compression:
		return archiverext.FileFS{File: f, Compression: ff}, cleanup, nil
	}

	cleanup()
	return nil, func() {}, archives.NoMatch
}

// maxArchiveEntryNameLength is the longest name an entry in an archive can have,
// which matches the longest path that can be created on Linux.
const maxArchiveEntryNameLength = 4096

// SpaceAvailableForDecompression looks through a given archive and determines
// if decompressing it would put the server over its allocated disk space limit.
//
// The entries are read one at a time rather than opening the archive as a file
// system, which is much faster for large archives.
func (fs *Filesystem) SpaceAvailableForDecompression(ctx context.Context, dir string, file string) error {
	// Don't waste time trying to determine this if we know the server will have the space for
	// it since there is no limit.
	if fs.MaxDisk() <= 0 {
		return nil
	}

	f, err := fs.unixFS.Open(filepath.Join(dir, file))
	if err != nil {
		return err
	}
	defer f.Close()

	format, _, err := archives.Identify(ctx, filepath.Base(file), f)
	if err != nil && !errors.Is(err, archives.NoMatch) {
		return err
	}
	// Reset the file reader.
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return err
	}
	info, err := f.Stat()
	if err != nil {
		return err
	}

	var size int64
	add := func(name string, n int64) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if len(name) > maxArchiveEntryNameLength {
			return errors.New("filesystem: archive contains an entry with a name that is too long")
		}
		if n <= 0 {
			return nil
		}
		if n > math.MaxInt64-size {
			return newFilesystemError(ErrCodeDiskSpace, nil)
		}
		size += n
		if !fs.unixFS.CanFit(size) {
			return newFilesystemError(ErrCodeDiskSpace, nil)
		}
		return nil
	}

	switch ff := format.(type) {
	case archives.Zip:
		// The sizes can be read straight from the central directory of a zip.
		reader, err := zip.NewReader(f, info.Size())
		if err != nil {
			return err
		}
		for _, e := range reader.File {
			if e.UncompressedSize64 > math.MaxInt64 {
				return newFilesystemError(ErrCodeDiskSpace, nil)
			}
			if err := add(e.Name, int64(e.UncompressedSize64)); err != nil {
				return err
			}
		}
		return nil
	case archives.Extraction:
		return ff.Extract(ctx, io.NewSectionReader(f, 0, info.Size()), func(ctx context.Context, e archives.FileInfo) error {
			return add(e.NameInArchive, e.Size())
		})
	case archives.Compression:
		// A single compressed file is checked against the disk limit as it is
		// decompressed, since its size is not known until then.
		return add(file, info.Size())
	}
	return newFilesystemError(ErrCodeUnknownArchive, archives.NoMatch)
}

// DecompressFile will decompress a file in a given directory by using the
// archiver tool to infer the file type and go from there. This will walk over
// all the files within the given archive and ensure that there is not a
// zip-slip attack being attempted by validating that the final path is within
// the server data directory.
func (fs *Filesystem) DecompressFile(ctx context.Context, dir string, file string) error {
	f, err := fs.unixFS.Open(filepath.Join(dir, file))
	if err != nil {
		return err
	}
	defer f.Close()

	// Identify the type of archive we are dealing with.
	format, input, err := archives.Identify(ctx, filepath.Base(file), f)
	if err != nil {
		if errors.Is(err, archives.NoMatch) {
			return newFilesystemError(ErrCodeUnknownArchive, err)
		}
		return err
	}

	return fs.extractStream(ctx, extractStreamOptions{
		FileName:  file,
		Directory: dir,
		Format:    format,
		Reader:    input,
	})
}

// ExtractTransfer extracts the archive of a server that is being transferred to
// this node into the server's directory. Every file is kept, including ones the
// denylist would refuse, since they are the server's own files.
func (fs *Filesystem) ExtractTransfer(ctx context.Context, r io.Reader) error {
	format, input, err := archives.Identify(ctx, "archive.tar.gz", r)
	if err != nil {
		if errors.Is(err, archives.NoMatch) {
			return newFilesystemError(ErrCodeUnknownArchive, err)
		}
		return err
	}
	return fs.extractStream(ctx, extractStreamOptions{
		Directory:    "/",
		Format:       format,
		Reader:       input,
		KeepDenylist: true,
	})
}

type extractStreamOptions struct {
	// The directory to extract the archive to.
	Directory string
	// File name of the archive.
	FileName string
	// Format of the archive.
	Format archives.Format
	// Reader for the archive.
	Reader io.Reader
	// KeepDenylist extracts files the denylist would otherwise skip.
	KeepDenylist bool
}

func (fs *Filesystem) extractStream(ctx context.Context, opts extractStreamOptions) error {
	// See if it's a compressed archive, such as TAR or a ZIP
	ex, ok := opts.Format.(archives.Extractor)
	if !ok {
		// If not, check if it's a single-file compression, such as
		// .log.gz, .sql.gz, and so on
		de, ok := opts.Format.(archives.Decompressor)
		if !ok {
			return nil
		}

		// Strip the compression suffix
		p := filepath.Join(opts.Directory, strings.TrimSuffix(opts.FileName, opts.Format.Extension()))

		// Make sure it's not ignored
		if err := fs.IsIgnored(p); err != nil {
			return nil
		}

		reader, err := de.OpenReader(opts.Reader)
		if err != nil {
			return err
		}
		defer reader.Close()

		// Write the file, counting each write against the disk limit. The file is
		// removed if it does not fit.
		if _, err := fs.WriteFrom(p, reader); err != nil {
			return wrapError(err, opts.FileName)
		}
		return nil
	}

	// Decompress and extract archive
	return ex.Extract(ctx, opts.Reader, func(ctx context.Context, f archives.FileInfo) error {
		p := filepath.Join(opts.Directory, f.NameInArchive)
		// If it is ignored, just don't do anything with the entry and skip over it.
		if !opts.KeepDenylist {
			if err := fs.IsIgnored(p); err != nil {
				return nil
			}
		}
		// Create directories explicitly; an empty one has no file to create it
		// implicitly and would otherwise be dropped during extraction.
		if f.IsDir() {
			if err := fs.mkdirAll(p, 0o755); err != nil {
				return wrapError(err, opts.FileName)
			}
			return nil
		}
		if f.Mode()&iofs.ModeSymlink != 0 {
			if f.LinkTarget == "" {
				return nil
			}
			if err := fs.mkdirAll(filepath.Dir(p), 0o755); err != nil {
				return wrapError(err, opts.FileName)
			}
			if err := fs.Symlink(f.LinkTarget, p); err != nil && !errors.Is(err, ufs.ErrExist) {
				return wrapError(err, opts.FileName)
			}
			return nil
		}
		// Hard links, devices and other special files are not extracted.
		if !f.Mode().IsRegular() {
			return nil
		}
		if h, ok := f.Header.(*tar.Header); ok && h.Typeflag == tar.TypeLink {
			return nil
		}
		r, err := f.Open()
		if err != nil {
			return err
		}
		defer r.Close()
		if err := fs.Write(p, r, f.Size(), f.Mode()); err != nil {
			return wrapError(err, opts.FileName)
		}
		// Update the file modification time to the one set in the archive.
		if err := fs.Chtimes(p, f.ModTime(), f.ModTime()); err != nil {
			return wrapError(err, opts.FileName)
		}
		return nil
	})
}
