package filesystem

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestFilesystem_ExtractArchiveMembers_zip_singleFile(t *testing.T) {
	fs, rfs := NewFs()
	t.Cleanup(func() { _ = os.RemoveAll(rfs.root) })

	b, err := os.ReadFile("./testdata/test.zip")
	if err != nil {
		t.Fatal(err)
	}
	if err := rfs.CreateServerFile("test.zip", b); err != nil {
		t.Fatal(err)
	}

	err = fs.ExtractArchiveMembers(context.Background(), "/", "test.zip", "out", []string{"test/outside.txt"})
	if err != nil {
		t.Fatal(err)
	}

	p := filepath.Join(rfs.root, "server", "out", "test", "outside.txt")
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("expected extracted file at %s: %v", p, err)
	}
}

func TestFilesystem_ExtractArchiveMembers_zip_directoryTree(t *testing.T) {
	fs, rfs := NewFs()
	t.Cleanup(func() { _ = os.RemoveAll(rfs.root) })

	b, err := os.ReadFile("./testdata/test.zip")
	if err != nil {
		t.Fatal(err)
	}
	if err := rfs.CreateServerFile("test.zip", b); err != nil {
		t.Fatal(err)
	}

	err = fs.ExtractArchiveMembers(context.Background(), "/", "test.zip", "dest", []string{"test/inside"})
	if err != nil {
		t.Fatal(err)
	}

	p := filepath.Join(rfs.root, "server", "dest", "test", "inside", "finside.txt")
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("expected nested file at %s: %v", p, err)
	}
}
