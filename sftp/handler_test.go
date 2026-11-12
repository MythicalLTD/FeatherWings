package sftp

import (
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/apex/log"
	pkgsftp "github.com/pkg/sftp"

	"github.com/mythicalltd/featherwings/config"
	"github.com/mythicalltd/featherwings/server"
	"github.com/mythicalltd/featherwings/server/filesystem"
)

type writeAtFunc func([]byte, int64) (int, error)

func (f writeAtFunc) WriteAt(p []byte, off int64) (int, error) {
	return f(p, off)
}

func TestHandlerDeniesAccessWhenServerIsInProtectedState(t *testing.T) {
	tests := []struct {
		name string
		set  func(*server.Server)
	}{
		{
			name: "installing",
			set: func(s *server.Server) {
				s.SetInstalling(true)
			},
		},
		{
			name: "transferring",
			set: func(s *server.Server) {
				s.SetTransferring(true)
			},
		},
		{
			name: "restoring",
			set: func(s *server.Server) {
				s.SetRestoring(true)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv, err := server.New(nil)
			if err != nil {
				t.Fatal(err)
			}
			tt.set(srv)

			h := Handler{
				server:      srv,
				permissions: []string{"*"},
			}

			if h.can(PermissionFileCreate) {
				t.Fatal("expected SFTP access to be denied")
			}
		})
	}
}

func TestWriterDeniesWritesWhenServerEntersProtectedState(t *testing.T) {
	tests := []struct {
		name string
		set  func(*server.Server)
	}{
		{
			name: "installing",
			set: func(s *server.Server) {
				s.SetInstalling(true)
			},
		},
		{
			name: "transferring",
			set: func(s *server.Server) {
				s.SetTransferring(true)
			},
		},
		{
			name: "restoring",
			set: func(s *server.Server) {
				s.SetRestoring(true)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv, err := server.New(nil)
			if err != nil {
				t.Fatal(err)
			}

			var called bool
			writer := quotaWriterAt{
				server: srv,
				WriterAt: writeAtFunc(func(_ []byte, _ int64) (int, error) {
					called = true
					return 1, nil
				}),
			}
			tt.set(srv)

			n, err := writer.WriteAt([]byte("x"), 0)
			if !errors.Is(err, pkgsftp.ErrSSHFxPermissionDenied) {
				t.Fatalf("expected permission denied, got %v", err)
			}
			if n != 0 {
				t.Fatalf("expected zero bytes written, got %d", n)
			}
			if called {
				t.Fatal("expected underlying writer not to be called")
			}
		})
	}
}

func TestWriterForwardsWritesWhenServerIsAvailable(t *testing.T) {
	srv, err := server.New(nil)
	if err != nil {
		t.Fatal(err)
	}

	writer := quotaWriterAt{
		server: srv,
		WriterAt: writeAtFunc(func(p []byte, _ int64) (int, error) {
			return len(p), io.EOF
		}),
	}

	n, err := writer.WriteAt([]byte("test"), 0)
	if !errors.Is(err, io.EOF) {
		t.Fatalf("expected forwarded error, got %v", err)
	}
	if n != 4 {
		t.Fatalf("expected forwarded byte count, got %d", n)
	}
}
func TestSetstatModeRejectsMalformedAttributes(t *testing.T) {
	request := pkgsftp.NewRequest("Setstat", "/")
	request.Flags = 1 // SSH_FILEXFER_ATTR_SIZE, but no attribute bytes.
	if _, err := setstatMode(request); !errors.Is(err, pkgsftp.ErrSSHFxBadMessage) {
		t.Fatalf("expected bad message, got %v", err)
	}

	request.Flags = sftpAttributeExtended
	request.Attrs = make([]byte, 4)
	binary.BigEndian.PutUint32(request.Attrs, ^uint32(0))
	if _, err := setstatMode(request); !errors.Is(err, pkgsftp.ErrSSHFxBadMessage) {
		t.Fatalf("expected extended attributes to be rejected, got %v", err)
	}
}

func TestSetstatMode(t *testing.T) {
	tests := []struct {
		name     string
		mode     uint32
		expected uint32
	}{
		{name: "file permissions", mode: 0o600, expected: 0o600},
		{name: "default permissions", mode: 0o000, expected: 0o644},
		{name: "directory permissions", mode: 0o040700, expected: 0o755},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := pkgsftp.NewRequest("Setstat", "/test")
			request.Flags = 4 // SSH_FILEXFER_ATTR_PERMISSIONS
			request.Attrs = make([]byte, 4)
			binary.BigEndian.PutUint32(request.Attrs, tt.mode)

			mode, err := setstatMode(request)
			if err != nil {
				t.Fatal(err)
			}
			if uint32(mode) != tt.expected {
				t.Fatalf("expected mode %04o, got %04o", tt.expected, mode)
			}
		})
	}
}

// A rename or symlink onto a path in the egg's file denylist is refused, not only
// one whose source is denylisted.
func TestFilecmdRefusesDenylistedTarget(t *testing.T) {
	config.Set(&config.Configuration{AuthenticationToken: "test-token"})
	srv, err := server.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	fs, err := filesystem.New(root, 0, []string{"server.properties", "locked/**"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fs.UnixFS().Close() })
	if err := os.WriteFile(filepath.Join(root, "evil.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	h := Handler{
		server:      srv,
		fs:          fs,
		permissions: []string{"*"},
		logger:      log.WithField("test", t.Name()),
	}

	tests := []struct {
		method string
		target string
		check  string
	}{
		{method: "Rename", target: "/server.properties", check: "server.properties"},
		{method: "Rename", target: "/locked/file", check: "locked/file"},
		{method: "Symlink", target: "/server.properties", check: "server.properties"},
		{method: "Symlink", target: "/locked/link", check: "locked/link"},
	}
	for _, tt := range tests {
		t.Run(tt.method+tt.target, func(t *testing.T) {
			request := pkgsftp.NewRequest(tt.method, "/evil.txt")
			request.Target = tt.target
			err := h.Filecmd(request)
			if !filesystem.IsErrorCode(err, filesystem.ErrCodeDenylistFile) {
				t.Fatalf("expected a denylist error, got %v", err)
			}
			if _, err := os.Lstat(filepath.Join(root, tt.check)); !os.IsNotExist(err) {
				t.Fatalf("expected %s not to be created, got %v", tt.check, err)
			}
		})
	}
	if _, err := os.Stat(filepath.Join(root, "evil.txt")); err != nil {
		t.Fatalf("source file should be untouched: %v", err)
	}
}
