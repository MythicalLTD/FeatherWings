package filesystem

import (
	"bytes"
	"context"
	"io"
	"os"
	"testing"

	"github.com/klauspost/compress/zip"
)

func TestFilesystem_ListArchiveContents_zip(t *testing.T) {
	fs, rfs := NewFs()
	t.Cleanup(func() { _ = os.RemoveAll(rfs.root) })

	b, err := os.ReadFile("./testdata/test.zip")
	if err != nil {
		t.Fatal(err)
	}
	if err := rfs.CreateServerFile("test.zip", b); err != nil {
		t.Fatal(err)
	}

	entries, truncated, err := fs.ListArchiveContents(context.Background(), "/", "test.zip", ".")
	if err != nil {
		t.Fatal(err)
	}
	if truncated {
		t.Fatal("unexpected truncation")
	}

	names := make(map[string]bool)
	for _, e := range entries {
		names[e.Name] = true
		if e.Path == "" {
			t.Fatal("empty path")
		}
	}
	if !names["test"] {
		t.Fatalf("expected top-level test dir, got %#v", entries)
	}

	inside, truncated, err := fs.ListArchiveContents(context.Background(), "/", "test.zip", "test")
	if err != nil {
		t.Fatal(err)
	}
	if truncated {
		t.Fatal("unexpected truncation")
	}
	var hasInside, hasOutside bool
	for _, e := range inside {
		switch e.Name {
		case "inside":
			hasInside = e.Directory
		case "outside.txt":
			hasOutside = !e.Directory
		}
	}
	if !hasInside || !hasOutside {
		t.Fatalf("expected inside/ and outside.txt in test/, got %#v", inside)
	}
}

func TestFilesystem_ListArchiveContents_zipDuplicateEntries(t *testing.T) {
	fs, rfs := NewFs()
	t.Cleanup(func() { _ = os.RemoveAll(rfs.root) })

	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for _, content := range []string{"a", "b"} {
		fw, err := w.CreateHeader(&zip.FileHeader{Name: "LICENSE", Method: zip.Deflate})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(fw, content); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := rfs.CreateServerFile("dup.zip", buf.Bytes()); err != nil {
		t.Fatal(err)
	}

	entries, truncated, err := fs.ListArchiveContents(context.Background(), "/", "dup.zip", ".")
	if err != nil {
		t.Fatalf("ListArchiveContents should tolerate duplicate zip entries: %v", err)
	}
	if truncated {
		t.Fatal("unexpected truncation")
	}
	var found bool
	for _, e := range entries {
		if e.Name == "LICENSE" && !e.Directory {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected LICENSE entry, got %#v", entries)
	}
}
