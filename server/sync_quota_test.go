package server

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/mythicalltd/featherwings/config"
	"github.com/mythicalltd/featherwings/server/filesystem"
)

// With quotas on, a server whose data directory was removed gets it made
// again and its quota project set on it before the quota is applied, so a
// reinstall can restore it.
func TestSyncDiskLimitRecreatesMissingDirectoryWithQuotas(t *testing.T) {
	s := newLifecycleTestServer(t, nil)
	cfg := config.Get()
	cfg.System.Quotas.Enabled = true
	config.Set(cfg)

	root := filepath.Join(t.TempDir(), "uuid")
	fs, err := filesystem.New(root, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fs.UnixFS().Close() })
	s.fs = fs
	if err := os.RemoveAll(root); err != nil {
		t.Fatal(err)
	}

	prevEnsure, prevSet := ensureQuota, setQuota
	t.Cleanup(func() { ensureQuota, setQuota = prevEnsure, prevSet })
	var calls []string
	ensureQuota = func(int, string) error {
		if _, err := os.Stat(root); err != nil {
			t.Errorf("quota project was set before the data directory was made: %v", err)
		}
		calls = append(calls, "ensure")
		return nil
	}
	setQuota = func(int64, string) error {
		calls = append(calls, "set")
		return nil
	}

	if err := s.syncDiskLimit(); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 2 || calls[0] != "ensure" || calls[1] != "set" {
		t.Fatalf("unexpected quota calls %v", calls)
	}
}

func TestSyncDiskLimitWithoutQuotas(t *testing.T) {
	s := newLifecycleTestServer(t, nil)
	root := filepath.Join(t.TempDir(), "uuid")
	fs, err := filesystem.New(root, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fs.UnixFS().Close() })
	s.fs = fs

	prevEnsure, prevSet := ensureQuota, setQuota
	t.Cleanup(func() { ensureQuota, setQuota = prevEnsure, prevSet })
	ensureQuota = func(int, string) error { t.Error("quotas are off"); return nil }
	setQuota = func(int64, string) error { t.Error("quotas are off"); return nil }

	if err := s.syncDiskLimit(); err != nil {
		t.Fatal(err)
	}
}
