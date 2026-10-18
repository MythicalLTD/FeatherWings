package nodebackup

import (
	"archive/tar"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/klauspost/pgzip"
	"github.com/mythicalltd/featherwings/config"
)

func TestValidateMode(t *testing.T) {
	cases := []struct {
		in   string
		want Mode
		ok   bool
	}{
		{"", ModeFull, true},
		{"full", ModeFull, true},
		{"volumes", ModeVolumes, true},
		{"user_backups_only", ModeUserBackupsOnly, true},
		{"nope", "", false},
	}
	for _, tc := range cases {
		got, err := ValidateMode(tc.in)
		if tc.ok && err != nil {
			t.Fatalf("ValidateMode(%q): %v", tc.in, err)
		}
		if !tc.ok && err == nil {
			t.Fatalf("ValidateMode(%q): expected error", tc.in)
		}
		if tc.ok && got != tc.want {
			t.Fatalf("ValidateMode(%q)=%q want %q", tc.in, got, tc.want)
		}
	}
}

func TestCreateVolumesArchive(t *testing.T) {
	root := t.TempDir()
	data := filepath.Join(root, "volumes")
	backups := filepath.Join(root, "backups")
	nodeBackup := filepath.Join(root, "wings_backup")
	if err := os.MkdirAll(filepath.Join(data, "server-a"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(data, "server-a", "eula.txt"), []byte("eula=true\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_ = os.MkdirAll(backups, 0o700)

	cfg := &config.Configuration{AuthenticationToken: "test-token-for-nodebackup"}
	cfg.System.RootDirectory = root
	cfg.System.Data = data
	cfg.System.BackupDirectory = backups
	cfg.System.NodeBackupDirectory = nodeBackup
	config.Set(cfg)

	info, err := NewPending(ModeVolumes, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := Create(context.Background(), info); err != nil {
		t.Fatal(err)
	}
	if info.Status != StatusCompleted {
		t.Fatalf("status=%s error=%s", info.Status, info.Error)
	}
	if info.Bytes <= 0 {
		t.Fatal("expected non-empty archive")
	}
	if _, err := os.Stat(info.Path); err != nil {
		t.Fatal(err)
	}
}

func TestRestoreFileRejectsOversizedArchive(t *testing.T) {
	root := t.TempDir()
	cfg := &config.Configuration{AuthenticationToken: "test-token-for-nodebackup"}
	cfg.System.RootDirectory = root
	cfg.System.Data = filepath.Join(root, "volumes")
	cfg.System.BackupDirectory = filepath.Join(root, "backups")
	cfg.System.NodeBackupDirectory = filepath.Join(root, "nodebackup")
	config.Set(cfg)

	archive := filepath.Join(root, "oversized.tar.gz")
	f, err := os.Create(archive)
	if err != nil {
		t.Fatal(err)
	}
	gw := pgzip.NewWriter(f)
	tw := tar.NewWriter(gw)
	hdr := &tar.Header{
		Name:     "volumes/huge.bin",
		Typeflag: tar.TypeReg,
		Mode:     0o644,
		Size:     maxRestoreTotalBytes + 1,
	}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatal(err)
	}
	_ = tw.Close()
	_ = gw.Close()
	_ = f.Close()

	err = RestoreFile(context.Background(), archive, ModeVolumes)
	if err == nil {
		t.Fatal("expected oversized archive to be rejected")
	}
	if !strings.Contains(err.Error(), "exceeds maximum uncompressed size") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRestoreFileAcceptsNormalArchive(t *testing.T) {
	root := t.TempDir()
	cfg := &config.Configuration{AuthenticationToken: "test-token-for-nodebackup"}
	cfg.System.RootDirectory = root
	cfg.System.Data = filepath.Join(root, "volumes")
	cfg.System.BackupDirectory = filepath.Join(root, "backups")
	cfg.System.NodeBackupDirectory = filepath.Join(root, "nodebackup")
	config.Set(cfg)

	archive := filepath.Join(root, "normal.tar.gz")
	f, err := os.Create(archive)
	if err != nil {
		t.Fatal(err)
	}
	gw := pgzip.NewWriter(f)
	tw := tar.NewWriter(gw)
	body := []byte("eula=true\n")
	if err := tw.WriteHeader(&tar.Header{
		Name:     "volumes/small.txt",
		Typeflag: tar.TypeReg,
		Mode:     0o644,
		Size:     int64(len(body)),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(body); err != nil {
		t.Fatal(err)
	}
	_ = tw.Close()
	_ = gw.Close()
	_ = f.Close()

	if err := RestoreFile(context.Background(), archive, ModeVolumes); err != nil {
		t.Fatalf("normal archive rejected: %v", err)
	}
	if _, err := os.Stat(filepath.Join(cfg.System.Data, "small.txt")); err != nil {
		t.Fatalf("expected restored file: %v", err)
	}
}
