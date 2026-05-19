package filesystem

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func trashItemsDir(rfs *rootFs) string {
	return filepath.Join(rfs.root, "server", TrashDirName, "items")
}

func seedTrashIndex(t *testing.T, fs *Filesystem, entries []TrashEntry) {
	t.Helper()
	if err := fs.ensureTrashLayout(); err != nil {
		t.Fatal(err)
	}
	if err := fs.writeTrashIndex(trashIndex{Entries: entries}); err != nil {
		t.Fatal(err)
	}
}

func seedTrashItemOnDisk(t *testing.T, rfs *rootFs, entry TrashEntry, fileContent string) {
	t.Helper()
	base := filepath.Join(trashItemsDir(rfs), entry.ID)
	if entry.IsDirectory {
		if err := os.MkdirAll(filepath.Join(base, "nested"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(base, "nested", "data.txt"), []byte(fileContent), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	if err := os.MkdirAll(filepath.Dir(base), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(base, []byte(fileContent), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestNormalizeTrashRoot(t *testing.T) {
	cases := map[string]string{
		"/":     "/",
		".":     "/",
		"/foo":  "/foo",
		"foo":   "/foo",
		"/foo/": "/foo",
	}
	for in, want := range cases {
		if got := normalizeTrashRoot(in); got != want {
			t.Fatalf("normalizeTrashRoot(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestJoinTrashSource(t *testing.T) {
	if got := joinTrashSource("/", "file.txt"); got != "/file.txt" {
		t.Fatalf("root /: got %q", got)
	}
	if got := joinTrashSource("/plugins", "Essentials"); got != "/plugins/Essentials" {
		t.Fatalf("nested root: got %q", got)
	}
}

func TestHasPathPrefix(t *testing.T) {
	if !hasPathPrefix(".featherpanel-trash", ".featherpanel-trash") {
		t.Fatal("trash dir should match itself")
	}
	if !hasPathPrefix(".featherpanel-trash/items/id", ".featherpanel-trash") {
		t.Fatal("trash subpath should match")
	}
	if hasPathPrefix("/cache", ".featherpanel-trash") {
		t.Fatal("unrelated path should not match")
	}
}

func TestDeletePath_UseTrashAndPermanent(t *testing.T) {
	fs, rfs := NewFs()
	defer os.RemoveAll(rfs.root)

	if err := rfs.CreateServerFileFromString("notes.txt", "keep"); err != nil {
		t.Fatal(err)
	}

	if err := fs.DeletePath("/notes.txt", TrashLimits{}, true); err != nil {
		t.Fatalf("DeletePath trash: %v", err)
	}
	entries, _, err := fs.ListTrash(TrashLimits{})
	if err != nil || len(entries) != 1 || entries[0].OriginalName != "notes.txt" {
		t.Fatalf("ListTrash: %+v err=%v", entries, err)
	}

	if err := rfs.CreateServerFileFromString("gone.txt", "bye"); err != nil {
		t.Fatal(err)
	}
	if err := fs.DeletePath("/gone.txt", TrashLimits{}, false); err != nil {
		t.Fatalf("DeletePath permanent: %v", err)
	}
	if _, err := rfs.StatServerFile("gone.txt"); !os.IsNotExist(err) {
		t.Fatalf("gone.txt should be deleted: %v", err)
	}
}

func TestDeletePath_InvalidPaths(t *testing.T) {
	fs, rfs := NewFs()
	defer os.RemoveAll(rfs.root)

	for _, p := range []string{"/", ".", ""} {
		if err := fs.DeletePath(p, TrashLimits{}, true); err == nil {
			t.Fatalf("expected error for path %q", p)
		}
	}
}

func TestMoveFilesToTrash_NestedDirectory(t *testing.T) {
	fs, rfs := NewFs()
	defer os.RemoveAll(rfs.root)

	if err := os.MkdirAll(filepath.Join(rfs.root, "server", "plugins", "Essentials"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := rfs.CreateServerFileFromString("plugins/Essentials/config.yml", "settings"); err != nil {
		t.Fatal(err)
	}

	if err := fs.MoveFilesToTrash("/plugins", []string{"Essentials"}, TrashLimits{}); err != nil {
		t.Fatalf("MoveFilesToTrash: %v", err)
	}

	entries, _, err := fs.ListTrash(TrashLimits{})
	if err != nil || len(entries) != 1 {
		t.Fatalf("entries: %+v err=%v", entries, err)
	}
	if entries[0].OriginalRoot != "/plugins" || entries[0].OriginalName != "Essentials" {
		t.Fatalf("unexpected entry: %+v", entries[0])
	}

	if err := fs.RestoreTrashEntries([]string{entries[0].ID}, false); err != nil {
		t.Fatalf("restore: %v", err)
	}
	content, err := os.ReadFile(filepath.Join(rfs.root, "server", "plugins", "Essentials", "config.yml"))
	if err != nil || string(content) != "settings" {
		t.Fatalf("restored config: %q err=%v", content, err)
	}
}

func TestMoveFilesToTrash_MultipleFilesOneCall(t *testing.T) {
	fs, rfs := NewFs()
	defer os.RemoveAll(rfs.root)

	for _, name := range []string{"a.txt", "b.txt"} {
		if err := rfs.CreateServerFileFromString(name, name); err != nil {
			t.Fatal(err)
		}
	}

	if err := fs.MoveFilesToTrash("/", []string{"a.txt", "b.txt"}, TrashLimits{}); err != nil {
		t.Fatalf("MoveFilesToTrash: %v", err)
	}

	entries, total, err := fs.ListTrash(TrashLimits{})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("want 2 entries, got %+v", entries)
	}
	if total <= 0 {
		t.Fatalf("expected positive total, got %d", total)
	}
}

func TestMoveFilesToTrash_RejectsTrashFolder(t *testing.T) {
	fs, rfs := NewFs()
	defer os.RemoveAll(rfs.root)

	if err := fs.ensureTrashLayout(); err != nil {
		t.Fatal(err)
	}

	err := fs.MoveFilesToTrash("/", []string{TrashDirName}, TrashLimits{})
	if err == nil || !strings.Contains(err.Error(), "cannot move the trash folder") {
		t.Fatalf("expected trash-self error, got %v", err)
	}
}

func TestMoveFilesToTrash_BatchExceedsTrashLimit(t *testing.T) {
	fs, rfs := NewFs()
	defer os.RemoveAll(rfs.root)

	if err := rfs.CreateServerFileFromString("a.dat", strings.Repeat("a", 1500)); err != nil {
		t.Fatal(err)
	}
	if err := rfs.CreateServerFileFromString("b.dat", strings.Repeat("b", 1500)); err != nil {
		t.Fatal(err)
	}

	err := fs.MoveFilesToTrash("/", []string{"a.dat", "b.dat"}, TrashLimits{MaxSizeBytes: 2048, RetentionDays: 30})
	if err == nil {
		t.Fatal("expected batch size error")
	}
	if !IsErrorCode(err, ErrCodeTrashItemTooLarge) {
		t.Fatalf("expected ErrCodeTrashItemTooLarge, got %v", err)
	}
	for _, name := range []string{"a.dat", "b.dat"} {
		if _, statErr := rfs.StatServerFile(name); statErr != nil {
			t.Fatalf("%s should still exist: %v", name, statErr)
		}
	}
}

func TestMoveFilesToTrash_EvictsOldestForRoom(t *testing.T) {
	fs, rfs := NewFs()
	defer os.RemoveAll(rfs.root)

	limits := TrashLimits{MaxSizeBytes: 3000, RetentionDays: 30}

	if err := rfs.CreateServerFileFromString("old.jar", strings.Repeat("o", 2048)); err != nil {
		t.Fatal(err)
	}
	if err := fs.MoveFilesToTrash("/", []string{"old.jar"}, limits); err != nil {
		t.Fatal(err)
	}

	entries, _, err := fs.ListTrash(TrashLimits{})
	if err != nil || len(entries) != 1 {
		t.Fatalf("after first move: %+v err=%v", entries, err)
	}
	oldID := entries[0].ID
	time.Sleep(10 * time.Millisecond)

	if err := rfs.CreateServerFileFromString("new.jar", strings.Repeat("n", 2048)); err != nil {
		t.Fatal(err)
	}
	if err := fs.MoveFilesToTrash("/", []string{"new.jar"}, limits); err != nil {
		t.Fatalf("second move: %v", err)
	}

	entries, _, err = fs.ListTrash(TrashLimits{})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected only new item in trash, got %+v", entries)
	}
	if entries[0].OriginalName != "new.jar" {
		t.Fatalf("unexpected survivor: %+v", entries[0])
	}
	if _, err := os.Stat(filepath.Join(trashItemsDir(rfs), oldID)); !os.IsNotExist(err) {
		t.Fatalf("old trash item should be purged: %v", err)
	}
}

func TestMoveFilesToTrash_RollbackOnPartialFailure(t *testing.T) {
	fs, rfs := NewFs()
	defer os.RemoveAll(rfs.root)

	if err := rfs.CreateServerFileFromString("kept.txt", "data"); err != nil {
		t.Fatal(err)
	}

	err := fs.MoveFilesToTrash("/", []string{"kept.txt", "missing.txt"}, TrashLimits{})
	if err == nil {
		t.Fatal("expected error for missing file")
	}
	if _, statErr := rfs.StatServerFile("kept.txt"); statErr != nil {
		t.Fatalf("kept.txt should be rolled back to original path: %v", statErr)
	}
	entries, _, listErr := fs.ListTrash(TrashLimits{})
	if listErr != nil {
		t.Fatal(listErr)
	}
	if len(entries) != 0 {
		t.Fatalf("trash should be empty after rollback, got %+v", entries)
	}
}

func TestListTrash_EnforcesRetention(t *testing.T) {
	fs, rfs := NewFs()
	defer os.RemoveAll(rfs.root)

	stale := TrashEntry{
		ID:           "stale-id",
		OriginalRoot: "/",
		OriginalName: "stale.txt",
		DeletedAt:    time.Now().UTC().Add(-72 * time.Hour),
		Size:         4,
		IsDirectory:  false,
	}
	fresh := TrashEntry{
		ID:           "fresh-id",
		OriginalRoot: "/",
		OriginalName: "fresh.txt",
		DeletedAt:    time.Now().UTC(),
		Size:         4,
		IsDirectory:  false,
	}
	seedTrashItemOnDisk(t, rfs, stale, "old")
	seedTrashItemOnDisk(t, rfs, fresh, "new")
	seedTrashIndex(t, fs, []TrashEntry{stale, fresh})

	entries, _, err := fs.ListTrash(TrashLimits{RetentionDays: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].ID != fresh.ID {
		t.Fatalf("expected only fresh entry, got %+v", entries)
	}
	if _, err := os.Stat(filepath.Join(trashItemsDir(rfs), stale.ID)); !os.IsNotExist(err) {
		t.Fatalf("stale item should be deleted from disk")
	}
}

func TestListTrash_EnforcesMaxSize(t *testing.T) {
	fs, rfs := NewFs()
	defer os.RemoveAll(rfs.root)

	old := TrashEntry{
		ID: "old-id", OriginalRoot: "/", OriginalName: "old.txt",
		DeletedAt: time.Now().UTC().Add(-time.Hour), Size: 3000, IsDirectory: false,
	}
	newer := TrashEntry{
		ID: "new-id", OriginalRoot: "/", OriginalName: "new.txt",
		DeletedAt: time.Now().UTC(), Size: 3000, IsDirectory: false,
	}
	seedTrashItemOnDisk(t, rfs, old, strings.Repeat("o", 3000))
	seedTrashItemOnDisk(t, rfs, newer, strings.Repeat("n", 3000))
	seedTrashIndex(t, fs, []TrashEntry{old, newer})

	entries, total, err := fs.ListTrash(TrashLimits{MaxSizeBytes: 4096})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].ID != newer.ID {
		t.Fatalf("expected newest entry only, got %+v", entries)
	}
	if total != newer.Size {
		t.Fatalf("total = %d, want %d", total, newer.Size)
	}
}

func TestDeleteTrashEntries_RemovesSelectedOnly(t *testing.T) {
	fs, rfs := NewFs()
	defer os.RemoveAll(rfs.root)

	if err := rfs.CreateServerFileFromString("a.txt", "a"); err != nil {
		t.Fatal(err)
	}
	if err := rfs.CreateServerFileFromString("b.txt", "b"); err != nil {
		t.Fatal(err)
	}
	if err := fs.MoveFilesToTrash("/", []string{"a.txt", "b.txt"}, TrashLimits{}); err != nil {
		t.Fatal(err)
	}

	entries, _, err := fs.ListTrash(TrashLimits{})
	if err != nil || len(entries) != 2 {
		t.Fatalf("ListTrash: %+v err=%v", entries, err)
	}

	var deleteID string
	for _, e := range entries {
		if e.OriginalName == "a.txt" {
			deleteID = e.ID
		}
	}
	if deleteID == "" {
		t.Fatal("missing a.txt entry")
	}

	if err := fs.DeleteTrashEntries([]string{deleteID}); err != nil {
		t.Fatalf("DeleteTrashEntries: %v", err)
	}

	entries, _, err = fs.ListTrash(TrashLimits{})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].OriginalName != "b.txt" {
		t.Fatalf("expected only b.txt, got %+v", entries)
	}
	if _, err := os.Stat(filepath.Join(trashItemsDir(rfs), deleteID)); !os.IsNotExist(err) {
		t.Fatalf("deleted item folder should be gone")
	}
}

func TestEmptyTrash_RemovesAll(t *testing.T) {
	fs, rfs := NewFs()
	defer os.RemoveAll(rfs.root)

	for _, name := range []string{"x.txt", "y.txt"} {
		if err := rfs.CreateServerFileFromString(name, name); err != nil {
			t.Fatal(err)
		}
	}
	if err := fs.MoveFilesToTrash("/", []string{"x.txt", "y.txt"}, TrashLimits{}); err != nil {
		t.Fatal(err)
	}

	if err := fs.EmptyTrash(); err != nil {
		t.Fatalf("EmptyTrash: %v", err)
	}

	entries, total, err := fs.ListTrash(TrashLimits{})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 || total != 0 {
		t.Fatalf("expected empty trash, got entries=%+v total=%d", entries, total)
	}
	if _, err := os.Stat(filepath.Join(rfs.root, "server", TrashDirName, "index.json")); err != nil {
		t.Fatalf("trash layout should be recreated: %v", err)
	}
}

func TestRestoreTrashEntries_MultipleAndRollbackOnConflict(t *testing.T) {
	fs, rfs := NewFs()
	defer os.RemoveAll(rfs.root)

	for _, pair := range [][2]string{{"one.txt", "1"}, {"two.txt", "2"}} {
		if err := rfs.CreateServerFileFromString(pair[0], pair[1]); err != nil {
			t.Fatal(err)
		}
	}
	if err := fs.MoveFilesToTrash("/", []string{"one.txt", "two.txt"}, TrashLimits{}); err != nil {
		t.Fatal(err)
	}
	if err := rfs.CreateServerFileFromString("two.txt", "blocking"); err != nil {
		t.Fatal(err)
	}

	entries, _, err := fs.ListTrash(TrashLimits{})
	if err != nil || len(entries) != 2 {
		t.Fatalf("ListTrash: %+v err=%v", entries, err)
	}

	ids := []string{entries[0].ID, entries[1].ID}
	err = fs.RestoreTrashEntries(ids, false)
	if err == nil || !IsErrorCode(err, ErrCodeTrashRestoreConflict) {
		t.Fatalf("expected conflict, got %v", err)
	}

	if _, err := rfs.StatServerFile("one.txt"); !os.IsNotExist(err) {
		t.Fatalf("one.txt should not be restored after rollback, err=%v", err)
	}
	if _, err := rfs.StatServerFile("two.txt"); err != nil {
		t.Fatalf("blocking two.txt should remain")
	}

	entries, _, err = fs.ListTrash(TrashLimits{})
	if err != nil || len(entries) != 2 {
		t.Fatalf("both entries should remain in trash: %+v", entries)
	}
}

func TestRestoreTrashEntries_PruneOrphanOnRestore(t *testing.T) {
	fs, rfs := NewFs()
	defer os.RemoveAll(rfs.root)

	good := TrashEntry{
		ID: "good-id", OriginalRoot: "/", OriginalName: "good.txt",
		DeletedAt: time.Now().UTC(), Size: 4, IsDirectory: false,
	}
	bad := TrashEntry{
		ID: "bad-id", OriginalRoot: "/", OriginalName: "bad.txt",
		DeletedAt: time.Now().UTC(), Size: 4, IsDirectory: false,
	}
	seedTrashItemOnDisk(t, rfs, good, "ok")
	seedTrashIndex(t, fs, []TrashEntry{good, bad})

	if err := fs.RestoreTrashEntries([]string{good.ID}, false); err != nil {
		t.Fatalf("restore good: %v", err)
	}
	if _, err := rfs.StatServerFile("good.txt"); err != nil {
		t.Fatalf("good.txt missing: %v", err)
	}

	entries, _, err := fs.ListTrash(TrashLimits{})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("trash should be empty, got %+v", entries)
	}
}

func TestReadWriteTrashIndex_RoundTrip(t *testing.T) {
	fs, rfs := NewFs()
	defer os.RemoveAll(rfs.root)

	when := time.Now().UTC().Truncate(time.Second)
	want := trashIndex{Entries: []TrashEntry{{
		ID: "abc", OriginalRoot: "/data", OriginalName: "file.log",
		DeletedAt: when, Size: 99, IsDirectory: false,
	}}}

	if err := fs.writeTrashIndex(want); err != nil {
		t.Fatal(err)
	}

	got, err := fs.readTrashIndex()
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Entries) != 1 {
		t.Fatalf("entries: %+v", got.Entries)
	}
	e := got.Entries[0]
	if e.ID != want.Entries[0].ID || e.OriginalRoot != "/data" || e.OriginalName != "file.log" || e.Size != 99 {
		t.Fatalf("unexpected entry: %+v", e)
	}
}

func TestTrashErrorCodes(t *testing.T) {
	err := NewTrashItemTooLarge("world")
	if !IsErrorCode(err, ErrCodeTrashItemTooLarge) {
		t.Fatalf("too large: %v", err)
	}
	var fserr *Error
	if !errors.As(err, &fserr) || fserr.ItemName() != "world" {
		t.Fatalf("ItemName: %v", err)
	}

	if err := NewTrashRestoreConflict("dup.txt"); !IsErrorCode(err, ErrCodeTrashRestoreConflict) {
		t.Fatalf("conflict: %v", err)
	}
	if err := NewTrashEntryNotFound(); !IsErrorCode(err, ErrCodeTrashEntryNotFound) {
		t.Fatalf("not found: %v", err)
	}
}

// Keep existing tests below (regression suite).

func TestMoveFilesToTrash_RootFile(t *testing.T) {
	fs, rfs := NewFs()
	defer os.RemoveAll(rfs.root)

	if err := rfs.CreateServerFileFromString("banned-ips.json", "{}"); err != nil {
		t.Fatal(err)
	}

	err := fs.MoveFilesToTrash("/", []string{"banned-ips.json"}, TrashLimits{
		MaxSizeBytes:  512 * 1024 * 1024,
		RetentionDays: 30,
	})
	if err != nil {
		t.Fatalf("MoveFilesToTrash: %v", err)
	}

	if _, err := os.Stat(filepath.Join(rfs.root, "server", "banned-ips.json")); !os.IsNotExist(err) {
		t.Fatalf("source should be gone: %v", err)
	}

	entries, _, err := fs.ListTrash(TrashLimits{})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].OriginalName != "banned-ips.json" {
		t.Fatalf("unexpected entries: %+v", entries)
	}
}

func TestMoveFilesToTrash_Directory(t *testing.T) {
	fs, rfs := NewFs()
	defer os.RemoveAll(rfs.root)

	if err := os.MkdirAll(filepath.Join(rfs.root, "server", "cache", "nested", "com"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := rfs.CreateServerFileFromString("cache/nested/com/file.txt", "data"); err != nil {
		t.Fatal(err)
	}

	err := fs.MoveFilesToTrash("/", []string{"cache"}, TrashLimits{
		MaxSizeBytes:  512 * 1024 * 1024,
		RetentionDays: 30,
	})
	if err != nil {
		t.Fatalf("MoveFilesToTrash: %v", err)
	}

	if _, err := os.Stat(filepath.Join(rfs.root, "server", "cache")); !os.IsNotExist(err) {
		t.Fatalf("source directory should be gone: %v", err)
	}

	entries, total, err := fs.ListTrash(TrashLimits{})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].OriginalName != "cache" || !entries[0].IsDirectory {
		t.Fatalf("unexpected entries: %+v", entries)
	}
	if total <= 0 {
		t.Fatalf("expected positive trash size, got %d", total)
	}
}

func TestRestoreTrashEntries_Directory(t *testing.T) {
	fs, rfs := NewFs()
	defer os.RemoveAll(rfs.root)

	if err := os.MkdirAll(filepath.Join(rfs.root, "server", "cache", "nested"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := rfs.CreateServerFileFromString("cache/nested/note.txt", "restore-me"); err != nil {
		t.Fatal(err)
	}

	if err := fs.MoveFilesToTrash("/", []string{"cache"}, TrashLimits{}); err != nil {
		t.Fatalf("MoveFilesToTrash: %v", err)
	}

	entries, _, err := fs.ListTrash(TrashLimits{})
	if err != nil || len(entries) != 1 {
		t.Fatalf("ListTrash: entries=%+v err=%v", entries, err)
	}

	if err := fs.RestoreTrashEntries([]string{entries[0].ID}, false); err != nil {
		t.Fatalf("RestoreTrashEntries: %v", err)
	}

	restored := filepath.Join(rfs.root, "server", "cache", "nested", "note.txt")
	if _, err := os.Stat(restored); err != nil {
		t.Fatalf("restored file missing: %v", err)
	}
	content, err := os.ReadFile(restored)
	if err != nil || string(content) != "restore-me" {
		t.Fatalf("restored content = %q err=%v", content, err)
	}

	entries, _, err = fs.ListTrash(TrashLimits{})
	if err != nil || len(entries) != 0 {
		t.Fatalf("trash should be empty after restore: %+v err=%v", entries, err)
	}
}

func TestTrashIndex_SerialMoveAndList(t *testing.T) {
	fs, rfs := NewFs()
	defer os.RemoveAll(rfs.root)

	if err := rfs.CreateServerFileFromString("banned-ips.json", "{}"); err != nil {
		t.Fatal(err)
	}

	limits := TrashLimits{MaxSizeBytes: 512 * 1024 * 1024, RetentionDays: 30}
	for i := 0; i < 20; i++ {
		if _, _, err := fs.ListTrash(limits); err != nil {
			t.Fatalf("list before move iteration %d: %v", i, err)
		}
	}
	if err := fs.MoveFilesToTrash("/", []string{"banned-ips.json"}, limits); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		entries, _, err := fs.ListTrash(limits)
		if err != nil {
			t.Fatalf("list after move iteration %d: %v", i, err)
		}
		if len(entries) != 1 {
			t.Fatalf("iteration %d: want 1 entry, got %+v", i, entries)
		}
	}
}

func TestRestoreTrashEntries_ConflictAndOverwrite(t *testing.T) {
	fs, rfs := NewFs()
	defer os.RemoveAll(rfs.root)

	if err := rfs.CreateServerFileFromString("banned-players.json", "trashed"); err != nil {
		t.Fatal(err)
	}
	if err := fs.MoveFilesToTrash("/", []string{"banned-players.json"}, TrashLimits{}); err != nil {
		t.Fatal(err)
	}
	if err := rfs.CreateServerFileFromString("banned-players.json", "recreated"); err != nil {
		t.Fatal(err)
	}

	entries, _, err := fs.ListTrash(TrashLimits{})
	if err != nil || len(entries) != 1 {
		t.Fatalf("ListTrash: %+v err=%v", entries, err)
	}

	if err := fs.RestoreTrashEntries([]string{entries[0].ID}, false); err == nil {
		t.Fatal("expected conflict error")
	} else if !IsErrorCode(err, ErrCodeTrashRestoreConflict) {
		t.Fatalf("expected ErrCodeTrashRestoreConflict, got %v", err)
	}

	if err := fs.RestoreTrashEntries([]string{entries[0].ID}, true); err != nil {
		t.Fatalf("RestoreTrashEntries overwrite: %v", err)
	}

	if err := fs.RestoreTrashEntries([]string{entries[0].ID}, false); !IsErrorCode(err, ErrCodeTrashEntryNotFound) {
		t.Fatalf("expected ErrCodeTrashEntryNotFound after restore, got %v", err)
	}

	content, err := os.ReadFile(filepath.Join(rfs.root, "server", "banned-players.json"))
	if err != nil || string(content) != "trashed" {
		t.Fatalf("restored content = %q err=%v", content, err)
	}
}

func TestMoveFilesToTrash_RejectsOversizedDirectory(t *testing.T) {
	fs, rfs := NewFs()
	defer os.RemoveAll(rfs.root)

	if err := os.MkdirAll(filepath.Join(rfs.root, "server", "cache", "nested"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := rfs.CreateServerFileFromString("cache/nested/big.dat", strings.Repeat("x", 2048)); err != nil {
		t.Fatal(err)
	}

	err := fs.MoveFilesToTrash("/", []string{"cache"}, TrashLimits{MaxSizeBytes: 1024, RetentionDays: 30})
	if err == nil {
		t.Fatal("expected trash size error")
	}
	if !IsErrorCode(err, ErrCodeTrashItemTooLarge) {
		t.Fatalf("expected ErrCodeTrashItemTooLarge, got %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(rfs.root, "server", "cache")); statErr != nil {
		t.Fatalf("cache directory should still exist: %v", statErr)
	}
}

func TestMoveFilesToTrash_DoesNotDeleteNewFolderWhenOverTrashLimit(t *testing.T) {
	fs, rfs := NewFs()
	defer os.RemoveAll(rfs.root)

	if err := os.MkdirAll(filepath.Join(rfs.root, "server", "cache", "nested"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := rfs.CreateServerFileFromString("cache/nested/file.txt", strings.Repeat("x", 2048)); err != nil {
		t.Fatal(err)
	}

	limits := TrashLimits{MaxSizeBytes: 4096, RetentionDays: 30}
	if err := fs.MoveFilesToTrash("/", []string{"cache"}, limits); err != nil {
		t.Fatalf("MoveFilesToTrash: %v", err)
	}

	entries, _, err := fs.ListTrash(TrashLimits{})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].OriginalName != "cache" {
		t.Fatalf("expected cache in trash, got %+v", entries)
	}

	trashPath := filepath.Join(trashItemsDir(rfs), entries[0].ID)
	if _, err := os.Stat(trashPath); err != nil {
		t.Fatalf("trash item folder missing: %v", err)
	}
}

func TestListTrash_PruneOrphanIndexEntry(t *testing.T) {
	fs, rfs := NewFs()
	defer os.RemoveAll(rfs.root)

	if err := fs.ensureTrashLayout(); err != nil {
		t.Fatal(err)
	}
	if err := fs.writeTrashIndex(trashIndex{Entries: []TrashEntry{{
		ID:           "orphan-id",
		OriginalRoot: "/",
		OriginalName: "missing.json",
		DeletedAt:    time.Now().UTC(),
		Size:         1,
	}}}); err != nil {
		t.Fatal(err)
	}

	entries, _, err := fs.ListTrash(TrashLimits{})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("expected orphan to be pruned, got %+v", entries)
	}
}
