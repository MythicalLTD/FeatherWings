package server

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/mythicalltd/featherwings/config"
	"github.com/mythicalltd/featherwings/environment"
	"github.com/mythicalltd/featherwings/server/filesystem"
)

func passwdTestConfig(t *testing.T, enabled bool, create bool) (string, string) {
	t.Helper()
	dir := t.TempDir()
	cfg, err := config.NewAtPath(filepath.Join(dir, "config.yml"))
	if err != nil {
		t.Fatal(err)
	}
	cfg.AuthenticationToken = "test-token"
	cfg.System.User.Passwd = enabled
	cfg.System.User.PasswdFile = filepath.Join(dir, "passwd")
	cfg.System.User.GroupFile = filepath.Join(dir, "group")
	cfg.System.MachineID.Enable = true
	cfg.System.MachineID.Directory = filepath.Join(dir, "machine-id")
	config.Set(cfg)
	if create {
		for _, p := range []string{cfg.System.User.PasswdFile, cfg.System.User.GroupFile} {
			if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	return cfg.System.User.PasswdFile, cfg.System.User.GroupFile
}

func newPasswdTestServer(t *testing.T) *Server {
	t.Helper()
	root := filepath.Join(t.TempDir(), "server")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	fs, err := filesystem.New(root, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(nil)
	if err != nil {
		t.Fatal(err)
	}
	s.fs = fs
	return s
}

func findMount(m []environment.Mount, target string) *environment.Mount {
	for i := range m {
		if m[i].Target == target {
			return &m[i]
		}
	}
	return nil
}

func TestMountsIncludePasswdAndGroup(t *testing.T) {
	passwd, group := passwdTestConfig(t, true, true)
	m := newPasswdTestServer(t).Mounts()

	for target, source := range map[string]string{"/etc/passwd": passwd, "/etc/group": group} {
		got := findMount(m, target)
		if got == nil {
			t.Fatalf("expected a mount at %s, got %+v", target, m)
		}
		if got.Source != source || !got.ReadOnly {
			t.Fatalf("mount at %s = %+v, want read-only from %s", target, got, source)
		}
	}
	// The machine-id mount must still be present alongside the user files.
	if findMount(m, "/etc/machine-id") == nil {
		t.Fatalf("expected the machine-id mount to be kept, got %+v", m)
	}
	if findMount(m, "/home/container") == nil {
		t.Fatalf("expected the data directory mount, got %+v", m)
	}
}

func TestMountsSkipPasswdWhenDisabled(t *testing.T) {
	passwdTestConfig(t, false, true)
	m := newPasswdTestServer(t).Mounts()
	if findMount(m, "/etc/passwd") != nil || findMount(m, "/etc/group") != nil {
		t.Fatalf("expected no passwd or group mounts when disabled, got %+v", m)
	}
	if findMount(m, "/etc/machine-id") == nil {
		t.Fatalf("expected the machine-id mount to be kept, got %+v", m)
	}
}

func TestMountsSkipMissingPasswdFiles(t *testing.T) {
	passwdTestConfig(t, true, false)
	m := newPasswdTestServer(t).Mounts()
	if findMount(m, "/etc/passwd") != nil || findMount(m, "/etc/group") != nil {
		t.Fatalf("expected missing files not to be mounted, got %+v", m)
	}
}

// A custom mount targeting /etc/passwd replaces the generated file instead of
// producing two mounts with the same destination, which Docker refuses.
func TestCustomPasswdMountReplacesGeneratedFile(t *testing.T) {
	root := setupMountTest(t, "mnt/")
	mkdirs(t, root, "mnt/users")
	files := t.TempDir()
	config.Update(func(c *config.Configuration) {
		c.System.User.Passwd = true
		c.System.User.PasswdFile = filepath.Join(files, "passwd")
		c.System.User.GroupFile = filepath.Join(files, "group")
	})
	for _, p := range []string{"passwd", "group"} {
		if err := os.WriteFile(filepath.Join(files, p), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	s := newPasswdTestServer(t)
	s.cfg.Mounts = []Mount{{Source: filepath.Join(root, "mnt", "users"), Target: "/etc/passwd/"}}
	m := s.Mounts()

	count := 0
	for _, mount := range m {
		if filepath.Clean(mount.Target) == "/etc/passwd" {
			count++
			if mount.Source != filepath.Join(root, "mnt", "users") {
				t.Fatalf("expected the custom mount to win, got %+v", mount)
			}
		}
	}
	if count != 1 {
		t.Fatalf("expected exactly one /etc/passwd mount, got %d in %+v", count, m)
	}
	if got := findMount(m, "/etc/group"); got == nil || got.Source != filepath.Join(files, "group") {
		t.Fatalf("expected the generated /etc/group mount to be kept, got %+v", m)
	}
}
