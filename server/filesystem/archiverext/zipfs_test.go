package archiverext

import (
	"bytes"
	"io"
	"io/fs"
	"testing"

	"github.com/klauspost/compress/zip"
)

func makeDupLicenseZip(t *testing.T) *zip.Reader {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for _, content := range []string{"first-license", "second-license"} {
		fw, err := w.CreateHeader(&zip.FileHeader{Name: "LICENSE", Method: zip.Deflate})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(fw, content); err != nil {
			t.Fatal(err)
		}
	}
	fw, err := w.Create("readme.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(fw, "hello"); err != nil {
		t.Fatal(err)
	}
	fw, err = w.Create("nested/a.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(fw, "nested"); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	data := buf.Bytes()
	r, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestZipFS_ReadDirDedupesDuplicateEntries(t *testing.T) {
	r := makeDupLicenseZip(t)

	// Baseline: stdlib-style FS rejects duplicates.
	if _, err := fs.ReadDir(r, "."); err == nil {
		t.Fatal("expected zip.Reader ReadDir to fail on duplicate LICENSE")
	}

	zfs := NewZipFS(r)
	entries, err := fs.ReadDir(zfs, ".")
	if err != nil {
		t.Fatalf("ZipFS ReadDir: %v", err)
	}

	names := map[string]bool{}
	for _, e := range entries {
		if names[e.Name()] {
			t.Fatalf("duplicate dirent %q", e.Name())
		}
		names[e.Name()] = true
	}
	if !names["LICENSE"] || !names["readme.txt"] || !names["nested"] {
		t.Fatalf("unexpected entries: %#v", names)
	}

	// Last occurrence wins.
	b, err := fs.ReadFile(zfs, "LICENSE")
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "second-license" {
		t.Fatalf("expected last LICENSE content, got %q", b)
	}

	nested, err := fs.ReadDir(zfs, "nested")
	if err != nil {
		t.Fatal(err)
	}
	if len(nested) != 1 || nested[0].Name() != "a.txt" {
		t.Fatalf("unexpected nested listing: %#v", nested)
	}
}

func TestZipFS_OpenMissing(t *testing.T) {
	r := makeDupLicenseZip(t)
	zfs := NewZipFS(r)
	if _, err := zfs.Open("nope.txt"); err == nil {
		t.Fatal("expected missing file error")
	}
}
