package sftp

import (
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/apex/log"
	pkgsftp "github.com/pkg/sftp"

	"github.com/mythicalltd/featherwings/config"
	"github.com/mythicalltd/featherwings/internal/database"
	"github.com/mythicalltd/featherwings/server"
	"github.com/mythicalltd/featherwings/server/filesystem"
)

const (
	sshFxfWrite = 0x02
	sshFxfCreat = 0x08
	sshFxfTrunc = 0x10
	sshFxfExcl  = 0x20

	sshAttrPermissions = 0x04
	sshAttrAcmodtime   = 0x08
)

var (
	testDatabaseOnce sync.Once
	testDatabaseErr  error
)

// newWriteTestHandler returns a handler for a server whose files live in a
// temporary directory, along with that directory.
func newWriteTestHandler(t *testing.T) (*Handler, string) {
	t.Helper()
	testDatabaseOnce.Do(func() {
		dir, err := os.MkdirTemp("", "wings-sftp-test")
		if err != nil {
			testDatabaseErr = err
			return
		}
		config.Set(&config.Configuration{AuthenticationToken: "test-token"})
		cfg := config.Get()
		cfg.System.RootDirectory = dir
		config.Set(cfg)
		testDatabaseErr = database.Initialize()
	})
	if testDatabaseErr != nil {
		t.Fatal(testDatabaseErr)
	}
	srv, err := server.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	fs, err := filesystem.New(root, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fs.UnixFS().Close() })
	return &Handler{
		server:      srv,
		fs:          fs,
		permissions: []string{"*"},
		events:      &eventHandler{server: "test", user: "test", ip: "127.0.0.1"},
		logger:      log.WithField("test", t.Name()),
	}, root
}

func writeAt(t *testing.T, h *Handler, name string, flags uint32, data string, off int64) error {
	t.Helper()
	request := pkgsftp.NewRequest("Put", name)
	request.Flags = flags
	w, err := h.Filewrite(request)
	if err != nil {
		return err
	}
	defer func() {
		if c, ok := w.(io.Closer); ok {
			_ = c.Close()
		}
	}()
	if _, err := w.WriteAt([]byte(data), off); err != nil {
		t.Fatal(err)
	}
	return nil
}

// A client resuming an upload opens the file without SSH_FXF_TRUNC and writes
// from where it stopped; what was already uploaded must be kept.
func TestFilewriteResumeKeepsExistingData(t *testing.T) {
	h, root := newWriteTestHandler(t)
	p := filepath.Join(root, "upload.bin")
	if err := os.WriteFile(p, []byte("hello "), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := writeAt(t, h, "/upload.bin", sshFxfWrite, "world", 6); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "hello world" {
		t.Fatalf("expected the resumed file to be %q, got %q", "hello world", b)
	}
}

func TestFilewriteTruncatesWhenAsked(t *testing.T) {
	h, root := newWriteTestHandler(t)
	p := filepath.Join(root, "upload.bin")
	if err := os.WriteFile(p, []byte("a much longer old content"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := writeAt(t, h, "/upload.bin", sshFxfWrite|sshFxfCreat|sshFxfTrunc, "new", 0); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "new" {
		t.Fatalf("expected the file to be replaced, got %q", b)
	}
}

func TestFilewriteCreatesNewFile(t *testing.T) {
	h, root := newWriteTestHandler(t)
	if err := writeAt(t, h, "/dir/new.txt", sshFxfWrite|sshFxfCreat|sshFxfExcl, "data", 0); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(root, "dir", "new.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "data" {
		t.Fatalf("unexpected content %q", b)
	}
}

func TestFilewriteExclusiveRefusesExistingFile(t *testing.T) {
	h, root := newWriteTestHandler(t)
	p := filepath.Join(root, "exists.txt")
	if err := os.WriteFile(p, []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}

	err := writeAt(t, h, "/exists.txt", sshFxfWrite|sshFxfCreat|sshFxfExcl, "x", 0)
	if !errors.Is(err, pkgsftp.ErrSSHFxFailure) {
		t.Fatalf("expected the exclusive open to fail, got %v", err)
	}
	if b, _ := os.ReadFile(p); string(b) != "keep" {
		t.Fatalf("existing file was changed: %q", b)
	}
	if n := h.open.Load(); n != 0 {
		t.Fatalf("expected the open file slot to be released, %d still open", n)
	}
}

func setstatRequest(name string, flags uint32, mode uint32, atime, mtime int64) *pkgsftp.Request {
	request := pkgsftp.NewRequest("Setstat", name)
	request.Flags = flags
	if flags&sshAttrPermissions != 0 {
		request.Attrs = binary.BigEndian.AppendUint32(request.Attrs, mode)
	}
	if flags&sshAttrAcmodtime != 0 {
		request.Attrs = binary.BigEndian.AppendUint32(request.Attrs, uint32(atime))
		request.Attrs = binary.BigEndian.AppendUint32(request.Attrs, uint32(mtime))
	}
	return request
}

// Clients preserving timestamps send a Setstat with only the times; this must
// set them and must not reset the permissions to 0644.
func TestSetstatTimesOnlyKeepsPermissions(t *testing.T) {
	h, root := newWriteTestHandler(t)
	p := filepath.Join(root, "script.sh")
	if err := os.WriteFile(p, []byte("#!/bin/sh"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0o755); err != nil {
		t.Fatal(err)
	}
	mtime := time.Date(2020, 1, 2, 3, 4, 5, 0, time.UTC)
	atime := mtime.Add(time.Hour)

	if err := h.Filecmd(setstatRequest("/script.sh", sshAttrAcmodtime, 0, atime.Unix(), mtime.Unix())); !errors.Is(err, pkgsftp.ErrSSHFxOk) {
		t.Fatal(err)
	}
	st, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o755 {
		t.Fatalf("expected permissions to stay 0755, got %04o", st.Mode().Perm())
	}
	if !st.ModTime().Equal(mtime) {
		t.Fatalf("expected mtime %s, got %s", mtime, st.ModTime())
	}
}

func TestSetstatPermissionsAndTimes(t *testing.T) {
	h, root := newWriteTestHandler(t)
	p := filepath.Join(root, "file.txt")
	if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	mtime := time.Date(2021, 6, 7, 8, 9, 10, 0, time.UTC)

	if err := h.Filecmd(setstatRequest("/file.txt", sshAttrPermissions|sshAttrAcmodtime, 0o600, mtime.Unix(), mtime.Unix())); !errors.Is(err, pkgsftp.ErrSSHFxOk) {
		t.Fatal(err)
	}
	st, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("expected permissions 0600, got %04o", st.Mode().Perm())
	}
	if !st.ModTime().Equal(mtime) {
		t.Fatalf("expected mtime %s, got %s", mtime, st.ModTime())
	}
}

func TestSetstatMissingFile(t *testing.T) {
	h, _ := newWriteTestHandler(t)
	err := h.Filecmd(setstatRequest("/missing", sshAttrAcmodtime, 0, 1, 1))
	if !errors.Is(err, pkgsftp.ErrSSHFxNoSuchFile) {
		t.Fatalf("expected no such file, got %v", err)
	}
}
