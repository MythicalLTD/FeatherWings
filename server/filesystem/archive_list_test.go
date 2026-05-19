package filesystem

import (
	"context"
	"os"
	"testing"
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
