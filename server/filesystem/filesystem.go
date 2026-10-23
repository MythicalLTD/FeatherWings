package filesystem

import (
	"fmt"
	"io"
	"math/rand/v2"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"emperror.dev/errors"
	"github.com/apex/log"
	"github.com/gabriel-vasile/mimetype"
	ignore "github.com/sabhiram/go-gitignore"

	"github.com/mythicalltd/featherwings/config"
	"github.com/mythicalltd/featherwings/internal/ufs"
	"golang.org/x/sync/semaphore"
	"golang.org/x/sync/singleflight"
	"golang.org/x/sys/unix"
)

type Filesystem struct {
	unixFS *ufs.Quota

	// mu guards changes to the disk usage that must be checked against the
	// limit, along with the fields tracking reservations below.
	mu sync.RWMutex
	// reserved is the space reserved by writes that have not finished yet.
	reserved int64
	// walking is set while the disk usage is being calculated, during which
	// walkReserved is the space reserved by writes in progress at any point.
	walking      bool
	walkReserved int64

	// lookupMu prevents the disk usage from being calculated more than once
	// at the same time.
	lookupMu          sync.Mutex
	lastLookupTime    *usageLookupTime
	lookupInProgress  atomic.Bool
	diskCheckInterval time.Duration
	denylist          *ignore.GitIgnore

	folderSizeMu      sync.Mutex
	folderSizeCache   map[string]folderSizeEntry
	folderSizeGroup   singleflight.Group
	folderSizeWalkSem *semaphore.Weighted

	isTest bool
}

// New creates a new Filesystem instance for a given server.
func New(root string, size int64, denylist []string) (*Filesystem, error) {
	if err := os.MkdirAll(root, 0o755); err != nil { //nolint:gosec // mounted as the container's home directory; the parent data directory is 0700
		return nil, err
	}
	unixFS, err := ufs.NewUnixFS(root, config.UseOpenat2())
	if err != nil {
		return nil, err
	}
	quota := ufs.NewQuota(unixFS, size)

	builtinDeny := []string{TrashDirName, TrashDirName + "/**"}
	combinedDeny := append(builtinDeny, denylist...)

	return &Filesystem{
		unixFS: quota,

		diskCheckInterval: time.Duration(config.Get().System.DiskCheckInterval) * time.Second,
		lastLookupTime:    &usageLookupTime{},
		denylist:          ignore.CompileIgnoreLines(combinedDeny...),
		folderSizeCache:   make(map[string]folderSizeEntry),
		folderSizeWalkSem: semaphore.NewWeighted(maxConcurrentDirectorySizeWalks),
	}, nil
}

// Path returns the root path for the Filesystem instance.
func (fs *Filesystem) Path() string {
	return fs.unixFS.BasePath()
}

// ReadDir reads directory entries.
func (fs *Filesystem) ReadDir(path string) ([]ufs.DirEntry, error) {
	return fs.unixFS.ReadDir(path)
}

// ReadDirStat is like ReadDir except that it returns FileInfo for each entry
// instead of just a DirEntry.
func (fs *Filesystem) ReadDirStat(path string) ([]ufs.FileInfo, error) {
	return ufs.ReadDirMap(fs.unixFS.UnixFS, path, func(e ufs.DirEntry) (ufs.FileInfo, error) {
		return e.Info()
	})
}

// File returns a reader for a file instance as well as the stat information.
func (fs *Filesystem) File(p string) (ufs.File, Stat, error) {
	f, err := fs.unixFS.Open(p)
	if err != nil {
		if errors.Is(err, ufs.ErrNotExist) {
			return nil, Stat{}, newFilesystemError(ErrNotExist, err)
		}
		return nil, Stat{}, err
	}
	st, err := statFromFile(f)
	if err != nil {
		_ = f.Close()
		return nil, Stat{}, err
	}
	if st.IsDir() {
		return f, Stat{}, errors.New("filesystem: is a directory")
	}
	return f, st, nil
}

func (fs *Filesystem) UnixFS() *ufs.UnixFS {
	return fs.unixFS.UnixFS
}

// Touch acts by creating the given file and path on the disk if it is not present
// already. If  it is present, the file is opened using the defaults which will truncate
// the contents. The opened file is then returned to the caller.
func (fs *Filesystem) Touch(p string, flag int) (ufs.File, error) {
	file, currentSize, err := fs.openForWrite(p, flag, 0o644)
	if err != nil {
		return nil, err
	}
	return newQuotaFile(fs, file, currentSize), nil
}

// openForWrite opens p with the given flags, creating it if it does not exist,
// and returns it along with the size it had when it was opened. The size is read
// from the opened file rather than from the path, since the path can be changed,
// for example to a symlink, between being checked and being opened. If flag
// includes O_TRUNC the file is truncated after its size is read.
func (fs *Filesystem) openForWrite(p string, flag int, mode ufs.FileMode) (ufs.File, int64, error) {
	file, err := fs.unixFS.Touch(p, flag&^ufs.O_TRUNC, mode)
	if err != nil {
		return nil, 0, err
	}
	st, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, 0, err
	}
	var size int64
	if st.Mode().IsRegular() {
		size = st.Size()
	}
	if flag&ufs.O_TRUNC != 0 {
		if err := file.Truncate(0); err != nil {
			_ = file.Close()
			return nil, 0, err
		}
	}
	return file, size, nil
}

// checkNotDirectory returns an error if p is a directory.
func (fs *Filesystem) checkNotDirectory(p string) error {
	if st, err := fs.unixFS.Lstat(p); err == nil && st.IsDir() {
		// TODO: resolved
		return errors.WithStack(&Error{code: ErrCodeIsDirectory, resolved: ""})
	}
	return nil
}

func (fs *Filesystem) Write(p string, r io.Reader, newSize int64, mode ufs.FileMode) error {
	if err := fs.checkNotDirectory(p); err != nil {
		return err
	}

	// Ensure the parent directories exist and are owned by the server user
	// before creating the file. Touch would create any missing parents
	// implicitly, but as the user Wings runs as; creating them here lets us
	// chown the ones we add.
	if err := fs.mkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}

	// When the size is not known ahead of time the data is written to a
	// temporary file and only replaces p once all of it fits.
	if newSize < 0 {
		return fs.writeUnknownSize(p, r, mode)
	}

	_, statErr := fs.unixFS.Lstat(p)
	existed := statErr == nil

	// Open the file before reserving space, so that the size being replaced is the
	// size of the file that is written to.
	file, currentSize, err := fs.openForWrite(p, ufs.O_RDWR, mode)
	if err != nil {
		return err
	}
	defer file.Close()

	// Check that the new size we're writing to the disk can fit, and reserve it so that
	// writes happening at the same time cannot each use the space that is left. If there
	// is currently a file we'll subtract that current file size from the size of the buffer
	// to determine the amount of new data we're writing (or amount we're removing if smaller).
	if err := fs.reserveDisk(newSize - currentSize); err != nil {
		if !existed {
			_ = fs.unixFS.Remove(p)
		}
		return err
	}
	reserved := max(newSize-currentSize, 0)
	// Release the reservation even if reading r panics, since the panic is
	// recovered and the reservation would otherwise last until Wings restarts.
	var used int64
	defer func() { fs.releaseDisk(reserved, used) }()

	if err := file.Truncate(0); err != nil {
		return err
	}
	// The file is now empty.
	used = -currentSize

	var n int64
	if newSize > 0 {
		// Do not use CopyBuffer here, it is wasteful as the file implements
		// io.ReaderFrom, which causes it to not use the buffer anyways.
		n, err = io.Copy(file, io.LimitReader(r, newSize))
	}

	// Adjust the disk usage to account for the old size and the new size of the file.
	used = n - currentSize

	if err := fs.chownFile(p); err != nil {
		return err
	}
	// Return any remaining error.
	return err
}

// writeUnknownSize writes r to p when the final size of the data is not known
// up front. The data goes to a hidden temporary file next to p, with every
// write checked against the disk limit, and is only renamed over p once all of
// it has been written. If anything goes wrong, including the data not fitting
// in the disk limit, the temporary file is removed and any existing file at p
// is left untouched.
func (fs *Filesystem) writeUnknownSize(p string, r io.Reader, mode ufs.FileMode) error {
	dirfd, name, closeFd, err := fs.unixFS.SafePath(p)
	defer closeFd()
	if err != nil {
		return err
	}

	tmpName := "." + name + "." + strconv.FormatUint(rand.Uint64(), 36) + ".tmp"
	file, err := fs.unixFS.OpenFileat(dirfd, tmpName, ufs.O_RDWR|ufs.O_CREATE|ufs.O_EXCL, mode)
	if err != nil {
		return err
	}

	dst := newQuotaFile(fs, file, 0)
	_, err = io.Copy(dst, r)
	if closeErr := dst.Close(); err == nil {
		err = closeErr
	}
	if err == nil && !fs.isTest {
		err = fs.unixFS.Lchownat(dirfd, tmpName, config.Get().System.User.Uid, config.Get().System.User.Gid)
	}
	if err == nil {
		err = fs.replaceFile(dirfd, tmpName, name)
	}
	if err != nil {
		fs.removeTempFile(dirfd, tmpName)
		return err
	}
	return nil
}

// replaceFile atomically renames tmpName over name within dirfd, releasing the
// disk space used by the file that gets replaced.
func (fs *Filesystem) replaceFile(dirfd int, tmpName, name string) error {
	var replacedSize int64
	st, err := fs.unixFS.Lstatat(dirfd, name)
	if err != nil && !errors.Is(err, ufs.ErrNotExist) {
		return err
	} else if err == nil && st.Mode().IsRegular() {
		replacedSize = st.Size()
	}

	if err := unix.Renameat(dirfd, tmpName, dirfd, name); err != nil {
		return &ufs.LinkError{Op: "rename", Old: tmpName, New: name, Err: err}
	}
	fs.unixFS.Add(-replacedSize)
	return nil
}

// removeTempFile removes a temporary file created by writeUnknownSize and
// releases the disk space that was reserved while writing it.
func (fs *Filesystem) removeTempFile(dirfd int, tmpName string) {
	st, err := fs.unixFS.Lstatat(dirfd, tmpName)
	if err != nil {
		return
	}
	if err := unix.Unlinkat(dirfd, tmpName, 0); err != nil {
		log.WithField("file", tmpName).WithField("error", err).Warn("failed to remove temporary file")
		return
	}
	fs.unixFS.Add(-st.Size())
}

// WriteFrom writes the contents of r to p, creating the file or truncating it
// if it exists, and returns the number of bytes written. Unlike Write, the size
// of the contents does not need to be known ahead of time: each write is counted
// against the disk limit as it happens. If writing fails the file is removed.
func (fs *Filesystem) WriteFrom(p string, r io.Reader) (int64, error) {
	if err := fs.checkNotDirectory(p); err != nil {
		return 0, err
	}

	if err := fs.mkdirAll(filepath.Dir(p), 0o755); err != nil {
		return 0, err
	}

	file, err := fs.Touch(p, ufs.O_RDWR|ufs.O_TRUNC)
	if err != nil {
		return 0, err
	}
	n, err := io.Copy(file, r)
	if cerr := file.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = fs.chownFile(p)
	}
	if err != nil {
		_ = fs.unixFS.Remove(p)
		return n, err
	}
	return n, nil
}

// CreateDirectory creates a new directory (name) at a specified path (p) for
// the server.
func (fs *Filesystem) CreateDirectory(name string, p string) error {
	return fs.mkdirAll(filepath.Join(p, name), 0o755)
}

func (fs *Filesystem) Rename(oldpath, newpath string) error {
	return fs.unixFS.Rename(oldpath, newpath)
}

func (fs *Filesystem) Symlink(oldpath, newpath string) error {
	return fs.unixFS.Symlink(oldpath, newpath)
}

// needsChown reports whether the file's uid/gid differ from the configured daemon user.
func needsChown(st ufs.FileInfo, uid, gid int) bool {
	sys, ok := st.Sys().(*unix.Stat_t)
	if !ok {
		return true
	}
	return int(sys.Uid) != uid || int(sys.Gid) != gid
}

func (fs *Filesystem) chownFile(name string) error {
	if fs.isTest {
		return nil
	}

	uid := config.Get().System.User.Uid
	gid := config.Get().System.User.Gid
	return fs.unixFS.Lchown(name, uid, gid)
}

// mkdirAll creates the directory p along with any missing parents, chowning
// every directory it creates to the server user so they are not left owned by
// the user Wings runs as.
func (fs *Filesystem) mkdirAll(p string, mode ufs.FileMode) error {
	created, err := fs.unixFS.MkdirAll(p, mode)
	if err != nil {
		return err
	}
	for _, dir := range created {
		if err := fs.chownFile(dir); err != nil {
			return err
		}
	}
	return nil
}

// Chown recursively iterates over a file or directory and sets the permissions on all of the
// underlying files. Iterate over all of the files and directories. If it is a file just
// go ahead and perform the chown operation. Otherwise dig deeper into the directory until
// we've run out of directories to dig into.
func (fs *Filesystem) Chown(p string) error {
	if fs.isTest {
		return nil
	}

	uid := config.Get().System.User.Uid
	gid := config.Get().System.User.Gid

	dirfd, name, closeFd, err := fs.unixFS.SafePath(p)
	defer closeFd()
	if err != nil {
		return err
	}

	st, err := fs.unixFS.Lstatat(dirfd, name)
	if err != nil {
		return errors.Wrap(err, "server/filesystem: chown: failed to stat path")
	}
	if needsChown(st, uid, gid) {
		if err := fs.unixFS.Lchownat(dirfd, name, uid, gid); err != nil {
			return errors.Wrap(err, "server/filesystem: chown: failed to chown path")
		}
	}

	// If this is not a directory we can now return from the function, there is nothing
	// left that we need to do.
	if !st.IsDir() {
		return nil
	}

	// This walker is probably some of the most efficient code in Wings. It has
	// an internally re-used buffer for listing directory entries and doesn't
	// need to check if every individual path it touches is safe as the code
	// doesn't traverse symlinks, is immune to symlink timing attacks, and
	// gives us a dirfd and file name to make a direct syscall with.
	if err := fs.unixFS.WalkDirat(dirfd, name, func(dirfd int, name, _ string, _ ufs.DirEntry, err error) error {
		// Skip files removed while walking (common during installs / server activity).
		if err != nil {
			if errors.Is(err, ufs.ErrNotExist) {
				return nil
			}
			return err
		}
		nst, err := fs.unixFS.Lstatat(dirfd, name)
		if err != nil {
			if errors.Is(err, ufs.ErrNotExist) {
				return nil
			}
			return err
		}
		if !needsChown(nst, uid, gid) {
			return nil
		}
		if err := fs.unixFS.Lchownat(dirfd, name, uid, gid); err != nil {
			if errors.Is(err, ufs.ErrNotExist) {
				return nil
			}
			return err
		}
		return nil
	}); err != nil {
		return fmt.Errorf("server/filesystem: chown: failed to chown during walk function: %w", err)
	}
	return nil
}

func (fs *Filesystem) Chmod(path string, mode ufs.FileMode) error {
	return fs.unixFS.Chmod(path, mode)
}

// Begin looping up to 50 times to try and create a unique copy file or directory name.
// This will take an input of "file.txt" and generate "file - copy.txt". If that name
// already exists, it will then try "file - copy 2.txt" and so on.
func (fs *Filesystem) findCopySuffix(dirfd int, name, extension string) (string, error) {
	var i int
	suffix := ""

	for i = 0; i < 51; i++ {
		if i == 1 {
			suffix = " - copy"
		} else if i == 50 {
			suffix = " - copy." + time.Now().Format(time.RFC3339)
		} else if i > 1 {
			suffix = " - copy " + strconv.Itoa(i)
		}

		n := name + suffix + extension
		// If we stat the file and it does not exist that means we're good to create the copy. If it
		// does exist, we'll just continue to the next loop and try again.
		if _, err := fs.unixFS.Lstatat(dirfd, n); err != nil {
			if !errors.Is(err, ufs.ErrNotExist) {
				return "", err
			}
			break
		}
	}

	return name + suffix + extension, nil
}

func (fs *Filesystem) copyFile(dirfd int, sourceName, destinationName string, mode ufs.FileMode) error {
	source, err := fs.unixFS.OpenFileat(dirfd, sourceName, ufs.O_RDONLY, 0)
	if err != nil {
		return err
	}
	defer source.Close()

	info, err := source.Stat()
	if err != nil {
		return err
	}

	// Reserve the space so that copies happening at the same time cannot each
	// use the space that is left.
	if err := fs.reserveDisk(info.Size()); err != nil {
		return err
	}
	var n int64
	defer func() { fs.releaseDisk(info.Size(), n) }()

	dst, err := fs.unixFS.OpenFileat(dirfd, destinationName, ufs.O_WRONLY|ufs.O_CREATE|ufs.O_EXCL, mode)
	if err != nil {
		return err
	}
	defer dst.Close()

	n, err = io.Copy(dst, io.LimitReader(source, info.Size()))
	if err != nil {
		return err
	}

	if fs.isTest {
		return nil
	}

	return fs.unixFS.Lchownat(dirfd, destinationName, config.Get().System.User.Uid, config.Get().System.User.Gid)
}

func (fs *Filesystem) copyDirectory(sourcePath, destinationPath string) error {
	if err := fs.mkdirAll(destinationPath, 0o755); err != nil {
		return err
	}

	entries, err := fs.unixFS.ReadDir(sourcePath)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		childSource := filepath.Join(sourcePath, entry.Name())
		childDestination := filepath.Join(destinationPath, entry.Name())
		info, err := fs.unixFS.Lstat(childSource)
		if err != nil {
			return err
		}

		if info.IsDir() {
			if err := fs.copyDirectory(childSource, childDestination); err != nil {
				return err
			}
			continue
		}

		if !info.Mode().IsRegular() {
			return ufs.ErrNotExist
		}

		if err := fs.copyFileByPath(childSource, childDestination, info.Mode()); err != nil {
			return err
		}
	}

	return nil
}

func (fs *Filesystem) copyFileByPath(sourcePath, destinationPath string, mode ufs.FileMode) error {
	source, err := fs.unixFS.Open(sourcePath)
	if err != nil {
		return err
	}
	defer source.Close()

	info, err := source.Stat()
	if err != nil {
		return err
	}
	if err := fs.reserveDisk(info.Size()); err != nil {
		return err
	}
	var n int64
	defer func() { fs.releaseDisk(info.Size(), n) }()

	destination, err := fs.unixFS.OpenFile(destinationPath, ufs.O_WRONLY|ufs.O_CREATE|ufs.O_EXCL, mode)
	if err != nil {
		return err
	}
	defer destination.Close()

	n, err = io.Copy(destination, io.LimitReader(source, info.Size()))
	if err != nil {
		return err
	}

	if fs.isTest {
		return nil
	}

	return fs.chownFile(destinationPath)
}

// Copy copies a given file or directory to the same location and appends a suffix.
func (fs *Filesystem) Copy(p string) error {
	dirfd, name, closeFd, err := fs.unixFS.SafePath(p)
	defer closeFd()
	if err != nil {
		return err
	}

	info, err := fs.unixFS.Lstatat(dirfd, name)
	if err != nil {
		return err
	}
	base := info.Name()
	extension := ""
	baseName := base
	if !info.IsDir() {
		if !info.Mode().IsRegular() {
			return ufs.ErrNotExist
		}
		extension = fs.Ext(base)
		baseName = strings.TrimSuffix(base, extension)
	}

	newName, err := fs.findCopySuffix(dirfd, baseName, extension)
	if err != nil {
		return err
	}

	if info.IsDir() {
		sourcePath := filepath.Join(filepath.Dir(p), base)
		destinationPath := filepath.Join(filepath.Dir(p), newName)
		return fs.copyDirectory(sourcePath, destinationPath)
	}

	if err := fs.copyFile(dirfd, name, newName, info.Mode()); err != nil {
		if IsErrorCode(err, ErrCodeDiskSpace) {
			return err
		}
		return ufs.ErrNotExist
	}

	return nil
}

func (fs *Filesystem) Ext(n string) string {

	extension := filepath.Ext(n)
	baseName := strings.TrimSuffix(n, extension)

	// Ensure that ".tar" is also counted as apart of the file extension.
	// There might be a better way to handle this for other double file extensions,
	// but this is a good workaround for now.
	if strings.HasSuffix(baseName, ".tar") {
		extension = ".tar" + extension
		_ = strings.TrimSuffix(baseName, ".tar")
	}
	return extension
}

// TruncateRootDirectory removes _all_ files and directories from a server's
// data directory and resets the used disk space to zero. The directory itself
// is kept, since it is mounted into the server's container.
func (fs *Filesystem) TruncateRootDirectory() error {
	if err := fs.unixFS.RemoveContents("."); err != nil {
		return err
	}
	fs.mu.Lock()
	defer fs.mu.Unlock()
	// Space reserved by writes that are still in progress remains in use.
	fs.unixFS.SetUsage(fs.reserved)
	if fs.isTest {
		fs.unixFS.SetLimit(0)
	}
	return nil
}

// Delete removes a file or folder from the system. Prevents the user from
// accidentally (or maliciously) removing their root server data directory.
func (fs *Filesystem) Delete(p string) error {
	return fs.unixFS.RemoveAll(p)
}

// SafeDeleteRecursively deletes a file or directory while respecting the denylist.
// For files, deletion is skipped if the file matches the denylist. For directories,
// it recursively deletes all non-denylisted files and subdirectories. Empty directories
// are removed automatically, but directories containing denylisted files are preserved.
func (fs *Filesystem) SafeDeleteRecursively(p string) error {
	info, err := fs.unixFS.Lstat(p)
	if err != nil {
		return err
	}

	// Check if this path (file or directory) is denylisted
	if err := fs.IsIgnored(p); err != nil {
		// Skip denylisted file or directory
		return nil
	}
	if !info.IsDir() {
		return fs.Delete(p)
	}

	entries, err := fs.ReadDir(p)
	if err != nil {
		return err
	}

	hasRemainingFiles := false

	for _, e := range entries {
		child := filepath.Join(p, e.Name())

		if e.IsDir() {
			if err := fs.SafeDeleteRecursively(child); err != nil {
				return err
			}
			// Check if the directory still exists after recursive deletion
			if _, statErr := fs.unixFS.Lstat(child); statErr == nil {
				hasRemainingFiles = true
			}
			continue
		}

		// File handling - check if ignored
		if err := fs.IsIgnored(child); err != nil {
			hasRemainingFiles = true
			continue // skip denylisted
		}

		if err := fs.Delete(child); err != nil {
			return err
		}
	}

	// Only remove directory if no files remain
	if !hasRemainingFiles {
		return fs.unixFS.Remove(p)
	}

	return nil
}

// ListDirectory lists the contents of a given directory and returns stat
// information about each file and folder within it.
// When includeDirectorySizes is true, each subdirectory includes directory_size
// (total bytes of regular files under that folder, with hard-link deduplication)
// from a TTL cache; stale or missing entries are refreshed asynchronously so the
// HTTP handler returns promptly.
func (fs *Filesystem) ListDirectory(p string, includeDirectorySizes bool) ([]Stat, error) {
	// Read entries from the path on the filesystem, using the mapped reader, so
	// we can map the DirEntry slice into a Stat slice with mimetype information.
	out, err := ufs.ReadDirMap(fs.unixFS.UnixFS, p, func(e ufs.DirEntry) (Stat, error) {
		info, err := e.Info()
		if err != nil {
			return Stat{}, err
		}

		var d string
		if e.Type().IsDir() {
			d = "inode/directory"
		} else {
			d = "application/octet-stream"
		}
		var m *mimetype.MIME
		if e.Type().IsRegular() {
			// TODO: I should probably find a better way to do this.
			eO := e.(interface {
				Open() (ufs.File, error)
			})
			f, err := eO.Open()
			if err != nil {
				return Stat{}, err
			}
			m, err = mimetype.DetectReader(f)
			if err != nil {
				log.Error(err.Error())
			}
			_ = f.Close()
		}

		st := Stat{FileInfo: info, Mimetype: d}
		if m != nil {
			st.Mimetype = m.String()
		}
		return st, nil
	})
	if err != nil {
		return nil, err
	}

	// Sort entries alphabetically.
	slices.SortStableFunc(out, func(a, b Stat) int {
		switch {
		case a.Name() == b.Name():
			return 0
		case a.Name() > b.Name():
			return 1
		default:
			return -1
		}
	})

	// Sort folders before other file types.
	slices.SortStableFunc(out, func(a, b Stat) int {
		switch {
		case a.IsDir() && b.IsDir():
			return 0
		case a.IsDir():
			return -1
		default:
			return 1
		}
	})

	if includeDirectorySizes {
		fs.attachDirectorySizes(&out, p)
	}

	return out, nil
}

func (fs *Filesystem) Chtimes(path string, atime, mtime time.Time) error {
	if fs.isTest {
		return nil
	}
	return fs.unixFS.Chtimes(path, atime, mtime)
}
