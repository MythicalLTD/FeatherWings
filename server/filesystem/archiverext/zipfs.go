package archiverext

import (
	"io"
	"io/fs"
	"path"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/klauspost/compress/zip"
)

// ZipFS is a read-only fs.FS over a zip archive that tolerates duplicate entry
// names. When the same path appears more than once (common in shaded jars and
// mod packs), the last occurrence wins. The standard zip.Reader fs.FS interface
// rejects duplicates entirely, which breaks archive browsing for those files.
type ZipFS struct {
	r *zip.Reader

	once     sync.Once
	files    map[string]*zip.File // cleaned path -> file (last wins)
	children map[string][]string  // directory path -> sorted child basenames
}

// NewZipFS wraps r as an fs.FS that deduplicates entry names.
func NewZipFS(r *zip.Reader) *ZipFS {
	return &ZipFS{r: r}
}

func (z *ZipFS) build() {
	z.once.Do(func() {
		z.files = make(map[string]*zip.File)
		childSet := make(map[string]map[string]struct{})

		for _, f := range z.r.File {
			name := cleanZipName(f.Name)
			if name == "" {
				continue
			}
			isDir := strings.HasSuffix(f.Name, "/") || f.FileInfo().IsDir()
			if isDir {
				// Ensure empty directory markers are listable.
				if childSet[name] == nil {
					childSet[name] = make(map[string]struct{})
				}
				ensureParents(childSet, name)
				continue
			}
			z.files[name] = f
			ensureParents(childSet, name)
		}

		z.children = make(map[string][]string, len(childSet))
		for dir, set := range childSet {
			names := make([]string, 0, len(set))
			for n := range set {
				names = append(names, n)
			}
			sort.Strings(names)
			z.children[dir] = names
		}
	})
}

func cleanZipName(name string) string {
	name = strings.ReplaceAll(name, `\`, `/`)
	name = path.Clean(name)
	name = strings.TrimPrefix(name, "/")
	for strings.HasPrefix(name, "../") {
		name = name[len("../"):]
	}
	if name == "." || name == ".." {
		return ""
	}
	return name
}

func ensureParents(childSet map[string]map[string]struct{}, name string) {
	for {
		dir := path.Dir(name)
		base := path.Base(name)
		if dir == "." {
			if childSet["."] == nil {
				childSet["."] = make(map[string]struct{})
			}
			childSet["."][base] = struct{}{}
			return
		}
		if childSet[dir] == nil {
			childSet[dir] = make(map[string]struct{})
		}
		childSet[dir][base] = struct{}{}
		name = dir
	}
}

// Open implements fs.FS.
func (z *ZipFS) Open(name string) (fs.File, error) {
	z.build()
	if !fs.ValidPath(name) {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrInvalid}
	}
	if name == "." {
		return &zipDir{z: z, name: ".", children: z.children["."]}, nil
	}
	name = cleanZipName(name)
	if name == "" {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrInvalid}
	}
	if f, ok := z.files[name]; ok {
		rc, err := f.Open()
		if err != nil {
			return nil, &fs.PathError{Op: "open", Path: name, Err: err}
		}
		return &zipFile{ReadCloser: rc, info: f.FileInfo(), name: path.Base(name)}, nil
	}
	if _, ok := z.children[name]; ok {
		return &zipDir{z: z, name: name, children: z.children[name]}, nil
	}
	return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
}

// ReadDir implements fs.ReadDirFS.
func (z *ZipFS) ReadDir(name string) ([]fs.DirEntry, error) {
	z.build()
	if !fs.ValidPath(name) {
		return nil, &fs.PathError{Op: "readdir", Path: name, Err: fs.ErrInvalid}
	}
	dir := name
	if dir != "." {
		dir = cleanZipName(dir)
		if dir == "" {
			return nil, &fs.PathError{Op: "readdir", Path: name, Err: fs.ErrInvalid}
		}
	}
	if dir != "." {
		if _, isFile := z.files[dir]; isFile {
			return nil, &fs.PathError{Op: "readdir", Path: name, Err: fs.ErrNotExist}
		}
		if _, ok := z.children[dir]; !ok {
			return nil, &fs.PathError{Op: "readdir", Path: name, Err: fs.ErrNotExist}
		}
	}
	names := z.children[dir]
	out := make([]fs.DirEntry, 0, len(names))
	for _, base := range names {
		full := base
		if dir != "." {
			full = path.Join(dir, base)
		}
		if f, ok := z.files[full]; ok {
			out = append(out, fs.FileInfoToDirEntry(f.FileInfo()))
			continue
		}
		if _, ok := z.children[full]; ok {
			out = append(out, fs.FileInfoToDirEntry(dirInfo{name: base}))
		}
	}
	return out, nil
}

type zipFile struct {
	io.ReadCloser
	info fs.FileInfo
	name string
}

func (f *zipFile) Stat() (fs.FileInfo, error) { return f.info, nil }

type zipDir struct {
	z        *ZipFS
	name     string
	children []string
	offset   int
}

func (d *zipDir) Stat() (fs.FileInfo, error) {
	return dirInfo{name: path.Base(d.name)}, nil
}

func (d *zipDir) Read([]byte) (int, error) {
	return 0, &fs.PathError{Op: "read", Path: d.name, Err: fs.ErrInvalid}
}

func (d *zipDir) Close() error { return nil }

func (d *zipDir) ReadDir(count int) ([]fs.DirEntry, error) {
	all, err := d.z.ReadDir(d.name)
	if err != nil {
		return nil, err
	}
	n := len(all) - d.offset
	if count > 0 && n > count {
		n = count
	}
	if n == 0 {
		if count <= 0 {
			return nil, nil
		}
		return nil, io.EOF
	}
	list := all[d.offset : d.offset+n]
	d.offset += n
	return list, nil
}

type dirInfo struct{ name string }

func (d dirInfo) Name() string       { return d.name }
func (d dirInfo) Size() int64        { return 0 }
func (d dirInfo) Mode() fs.FileMode  { return fs.ModeDir | 0555 }
func (d dirInfo) ModTime() time.Time { return time.Time{} }
func (d dirInfo) IsDir() bool        { return true }
func (d dirInfo) Sys() any           { return nil }
