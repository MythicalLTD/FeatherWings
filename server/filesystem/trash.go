package filesystem

import (
	"bytes"
	"encoding/json"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"emperror.dev/errors"
	"github.com/google/uuid"
)

var trashIndexMu sync.Mutex

const TrashDirName = ".featherpanel-trash"

type TrashLimits struct {
	MaxSizeBytes  int64 `json:"max_size_bytes"`
	RetentionDays int   `json:"retention_days"`
}

type TrashEntry struct {
	ID           string    `json:"id"`
	OriginalRoot string    `json:"original_root"`
	OriginalName string    `json:"original_name"`
	DeletedAt    time.Time `json:"deleted_at"`
	Size         int64     `json:"size"`
	IsDirectory  bool      `json:"is_directory"`
}

type trashIndex struct {
	Entries []TrashEntry `json:"entries"`
}

func trashIndexPath() string {
	return path.Join(TrashDirName, "index.json")
}

func trashItemPath(id string) string {
	return path.Join(TrashDirName, "items", id)
}

func (fs *Filesystem) ensureTrashLayout() error {
	if err := fs.unixFS.MkdirAll(path.Join(TrashDirName, "items"), 0o755); err != nil {
		return err
	}
	indexPath := trashIndexPath()
	if _, err := fs.unixFS.Lstat(indexPath); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return fs.writeTrashIndexFile(trashIndex{Entries: []TrashEntry{}})
	}
	return nil
}

func (fs *Filesystem) readTrashIndex() (trashIndex, error) {
	trashIndexMu.Lock()
	defer trashIndexMu.Unlock()
	return fs.readTrashIndexLocked()
}

func (fs *Filesystem) readTrashIndexLocked() (trashIndex, error) {
	if err := fs.ensureTrashLayout(); err != nil {
		return trashIndex{}, err
	}
	f, err := fs.unixFS.Open(trashIndexPath())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return trashIndex{Entries: []TrashEntry{}}, nil
		}
		return trashIndex{}, err
	}
	defer f.Close()

	var idx trashIndex
	if err := json.NewDecoder(f).Decode(&idx); err != nil {
		return trashIndex{}, err
	}
	if idx.Entries == nil {
		idx.Entries = []TrashEntry{}
	}
	return idx, nil
}

func (fs *Filesystem) writeTrashIndex(idx trashIndex) error {
	trashIndexMu.Lock()
	defer trashIndexMu.Unlock()
	if err := fs.unixFS.MkdirAll(path.Join(TrashDirName, "items"), 0o755); err != nil {
		return err
	}
	return fs.writeTrashIndexFile(idx)
}

func (fs *Filesystem) writeTrashIndexFile(idx trashIndex) error {
	data, err := json.MarshalIndent(idx, "", "  ")
	if err != nil {
		return err
	}
	tmpPath := trashIndexPath() + ".tmp"
	if err := fs.Write(tmpPath, bytes.NewReader(data), int64(len(data)), 0o644); err != nil {
		return err
	}
	_ = fs.unixFS.Remove(trashIndexPath())
	if err := fs.unixFS.Rename(tmpPath, trashIndexPath()); err != nil {
		return err
	}
	return nil
}

func normalizeTrashRoot(root string) string {
	root = path.Clean("/" + root)
	if root == "." {
		return "/"
	}
	return root
}

func joinTrashSource(root, name string) string {
	root = normalizeTrashRoot(root)
	if root == "/" {
		return path.Join("/", name)
	}
	return path.Join(root, name)
}

func (fs *Filesystem) entrySize(p string) (int64, error) {
	st, err := fs.unixFS.Lstat(p)
	if err != nil {
		return 0, err
	}
	if !st.IsDir() {
		return st.Size(), nil
	}
	// DirectorySize walks with openat while dirfds are still valid. ReadDir-based
	// walks must not call DirEntry.Info() after the listing fd is closed.
	return fs.DirectorySize(p)
}

// MoveFilesToTrash moves files from the server tree into the trash bin.
// DeletePath removes a file or directory, optionally moving it to trash first.
func (fs *Filesystem) DeletePath(p string, limits TrashLimits, useTrash bool) error {
	clean := normalizeTrashPath(p)
	if clean == "/" || clean == "." {
		return errors.New("invalid delete path")
	}
	if useTrash {
		root := path.Dir(clean)
		name := path.Base(clean)
		if name == "" || name == "." {
			return errors.New("invalid delete path")
		}
		return fs.MoveFilesToTrash(root, []string{name}, limits)
	}
	return fs.SafeDeleteRecursively(clean)
}

func normalizeTrashPath(p string) string {
	p = filepath.ToSlash(filepath.Clean(p))
	p = strings.TrimPrefix(p, "/")
	return path.Clean("/" + p)
}

type trashMoveRecord struct {
	source string
	dest   string
}

func (fs *Filesystem) MoveFilesToTrash(root string, files []string, limits TrashLimits) error {
	if err := fs.ensureTrashLayout(); err != nil {
		return err
	}

	trashIndexMu.Lock()
	defer trashIndexMu.Unlock()

	idx, err := fs.readTrashIndexLocked()
	if err != nil {
		return err
	}

	var moved []trashMoveRecord
	rollbackMoves := func() {
		for i := len(moved) - 1; i >= 0; i-- {
			_ = fs.Rename(moved[i].dest, moved[i].source)
		}
	}

	type pendingTrash struct {
		name string
		size int64
		dir  bool
	}
	pending := make([]pendingTrash, 0, len(files))
	var incomingTotal int64

	for _, name := range files {
		source := joinTrashSource(root, name)
		if path.Clean(source) == path.Clean(TrashDirName) || hasPathPrefix(source, TrashDirName) {
			rollbackMoves()
			return errors.New("cannot move the trash folder into itself")
		}

		st, err := fs.unixFS.Lstat(source)
		if err != nil {
			rollbackMoves()
			return err
		}

		size, err := fs.entrySize(source)
		if err != nil {
			rollbackMoves()
			return err
		}

		if limits.MaxSizeBytes > 0 && size > limits.MaxSizeBytes {
			rollbackMoves()
			return NewTrashItemTooLarge(name)
		}

		pending = append(pending, pendingTrash{name: name, size: size, dir: st.IsDir()})
		incomingTotal += size
	}

	if limits.MaxSizeBytes > 0 {
		if incomingTotal > limits.MaxSizeBytes {
			return NewTrashItemTooLarge("")
		}
		var err error
		idx, err = fs.makeRoomInTrashLocked(idx, limits, incomingTotal)
		if err != nil {
			return err
		}
		if err := fs.writeTrashIndexFile(idx); err != nil {
			return err
		}
	}

	for _, item := range pending {
		name := item.name
		size := item.size
		source := joinTrashSource(root, name)

		id := uuid.NewString()
		dest := trashItemPath(id)
		if err := fs.Rename(source, dest); err != nil {
			rollbackMoves()
			return err
		}
		moved = append(moved, trashMoveRecord{source: source, dest: dest})

		idx.Entries = append(idx.Entries, TrashEntry{
			ID:           id,
			OriginalRoot: normalizeTrashRoot(root),
			OriginalName: name,
			DeletedAt:    time.Now().UTC(),
			Size:         size,
			IsDirectory:  item.dir,
		})
	}

	if err := fs.writeTrashIndexFile(idx); err != nil {
		rollbackMoves()
		return err
	}
	return nil
}

// makeRoomInTrashLocked permanently deletes the oldest trashed items until incomingTotal will
// fit within MaxSizeBytes. Must be called before new items are moved into trash.
func (fs *Filesystem) makeRoomInTrashLocked(idx trashIndex, limits TrashLimits, incomingTotal int64) (trashIndex, error) {
	if limits.MaxSizeBytes <= 0 {
		return idx, nil
	}

	now := time.Now().UTC()
	cutoff := now
	if limits.RetentionDays > 0 {
		cutoff = now.Add(-time.Duration(limits.RetentionDays) * 24 * time.Hour)
	}

	kept := make([]TrashEntry, 0, len(idx.Entries))
	for _, e := range idx.Entries {
		if limits.RetentionDays > 0 && e.DeletedAt.Before(cutoff) {
			_ = fs.Delete(trashItemPath(e.ID))
			continue
		}
		kept = append(kept, e)
	}

	sort.Slice(kept, func(i, j int) bool {
		return kept[i].DeletedAt.Before(kept[j].DeletedAt)
	})

	var total int64
	for _, e := range kept {
		total += e.Size
	}

	for total+incomingTotal > limits.MaxSizeBytes && len(kept) > 0 {
		oldest := kept[0]
		kept = kept[1:]
		if err := fs.Delete(trashItemPath(oldest.ID)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return trashIndex{}, err
		}
		total -= oldest.Size
	}

	if total+incomingTotal > limits.MaxSizeBytes {
		return trashIndex{}, NewTrashItemTooLarge("")
	}

	return trashIndex{Entries: kept}, nil
}

func hasPathPrefix(p, prefix string) bool {
	p = path.Clean("/" + p)
	prefix = path.Clean("/" + prefix)
	return p == prefix || len(p) > len(prefix) && p[len(prefix)] == '/' && p[:len(prefix)] == prefix
}

// pruneTrashIndexLocked drops index rows whose on-disk trash item folder is missing.
func (fs *Filesystem) pruneTrashIndexLocked(idx trashIndex) (trashIndex, error) {
	if len(idx.Entries) == 0 {
		return idx, nil
	}
	kept := make([]TrashEntry, 0, len(idx.Entries))
	for _, e := range idx.Entries {
		if _, err := fs.unixFS.Lstat(trashItemPath(e.ID)); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return trashIndex{}, err
		}
		kept = append(kept, e)
	}
	if len(kept) == len(idx.Entries) {
		return idx, nil
	}
	pruned := trashIndex{Entries: kept}
	if err := fs.writeTrashIndexFile(pruned); err != nil {
		return trashIndex{}, err
	}
	return pruned, nil
}

// ListTrash returns trash entries and total bytes used by trashed items.
func (fs *Filesystem) ListTrash(limits TrashLimits) ([]TrashEntry, int64, error) {
	trashIndexMu.Lock()
	defer trashIndexMu.Unlock()
	if err := fs.ensureTrashLayout(); err != nil {
		return nil, 0, err
	}
	if err := fs.enforceTrashLimitsLocked(limits); err != nil {
		return nil, 0, err
	}
	idx, err := fs.readTrashIndexLocked()
	if err != nil {
		return nil, 0, err
	}
	idx, err = fs.pruneTrashIndexLocked(idx)
	if err != nil {
		return nil, 0, err
	}
	var total int64
	for _, e := range idx.Entries {
		total += e.Size
	}
	return idx.Entries, total, nil
}

type trashRestoreRecord struct {
	source string
	dest   string
}

// RestoreTrashEntries moves items from trash back to their original location.
// When overwrite is true, an existing file or folder at the destination is removed first.
func (fs *Filesystem) RestoreTrashEntries(ids []string, overwrite bool) error {
	trashIndexMu.Lock()
	defer trashIndexMu.Unlock()

	idx, err := fs.readTrashIndexLocked()
	if err != nil {
		return err
	}
	idx, err = fs.pruneTrashIndexLocked(idx)
	if err != nil {
		return err
	}

	var moved []trashRestoreRecord
	rollbackMoves := func() {
		for i := len(moved) - 1; i >= 0; i-- {
			_ = fs.Rename(moved[i].dest, moved[i].source)
		}
	}

	restored := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		var entry *TrashEntry
		for i := range idx.Entries {
			if idx.Entries[i].ID == id {
				entry = &idx.Entries[i]
				break
			}
		}
		if entry == nil {
			rollbackMoves()
			return NewTrashEntryNotFound()
		}

		source := trashItemPath(id)
		if _, err := fs.unixFS.Lstat(source); err != nil {
			rollbackMoves()
			if errors.Is(err, os.ErrNotExist) {
				return NewTrashEntryNotFound()
			}
			return err
		}

		dest := joinTrashSource(entry.OriginalRoot, entry.OriginalName)
		if _, err := fs.unixFS.Lstat(dest); err == nil {
			if !overwrite {
				rollbackMoves()
				return NewTrashRestoreConflict(entry.OriginalName)
			}
			if err := fs.Delete(dest); err != nil {
				rollbackMoves()
				return err
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			rollbackMoves()
			return err
		}

		destDir := path.Dir(dest)
		if destDir != "/" && destDir != "." {
			if err := fs.unixFS.MkdirAll(destDir, 0o755); err != nil {
				rollbackMoves()
				return err
			}
		}
		if err := fs.Rename(source, dest); err != nil {
			rollbackMoves()
			return err
		}
		moved = append(moved, trashRestoreRecord{source: source, dest: dest})
		restored[id] = struct{}{}
	}

	remaining := make([]TrashEntry, 0, len(idx.Entries))
	for _, e := range idx.Entries {
		if _, ok := restored[e.ID]; ok {
			continue
		}
		remaining = append(remaining, e)
	}
	if err := fs.writeTrashIndexFile(trashIndex{Entries: remaining}); err != nil {
		rollbackMoves()
		return err
	}
	return nil
}

// DeleteTrashEntries permanently removes selected trash items.
func (fs *Filesystem) DeleteTrashEntries(ids []string) error {
	trashIndexMu.Lock()
	defer trashIndexMu.Unlock()

	idx, err := fs.readTrashIndexLocked()
	if err != nil {
		return err
	}

	remove := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		remove[id] = struct{}{}
	}

	remaining := make([]TrashEntry, 0, len(idx.Entries))
	for _, e := range idx.Entries {
		if _, ok := remove[e.ID]; ok {
			if err := fs.Delete(trashItemPath(e.ID)); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
			continue
		}
		remaining = append(remaining, e)
	}
	return fs.writeTrashIndexFile(trashIndex{Entries: remaining})
}

// EmptyTrash permanently deletes all trashed items.
func (fs *Filesystem) EmptyTrash() error {
	trashIndexMu.Lock()
	defer trashIndexMu.Unlock()
	if err := fs.Delete(TrashDirName); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return fs.ensureTrashLayout()
}

func (fs *Filesystem) enforceTrashLimits(limits TrashLimits) error {
	trashIndexMu.Lock()
	defer trashIndexMu.Unlock()
	return fs.enforceTrashLimitsLocked(limits)
}

func (fs *Filesystem) enforceTrashLimitsLocked(limits TrashLimits) error {
	idx, err := fs.readTrashIndexLocked()
	if err != nil {
		return err
	}
	if len(idx.Entries) == 0 {
		return nil
	}

	now := time.Now().UTC()
	cutoff := now
	if limits.RetentionDays > 0 {
		cutoff = now.Add(-time.Duration(limits.RetentionDays) * 24 * time.Hour)
	}

	kept := make([]TrashEntry, 0, len(idx.Entries))
	for _, e := range idx.Entries {
		if limits.RetentionDays > 0 && e.DeletedAt.Before(cutoff) {
			_ = fs.Delete(trashItemPath(e.ID))
			continue
		}
		kept = append(kept, e)
	}

	sort.Slice(kept, func(i, j int) bool {
		return kept[i].DeletedAt.Before(kept[j].DeletedAt)
	})

	if limits.MaxSizeBytes > 0 {
		var total int64
		for _, e := range kept {
			total += e.Size
		}
		for total > limits.MaxSizeBytes && len(kept) > 0 {
			oldest := kept[0]
			kept = kept[1:]
			_ = fs.Delete(trashItemPath(oldest.ID))
			total -= oldest.Size
		}
	}

	return fs.writeTrashIndexFile(trashIndex{Entries: kept})
}
