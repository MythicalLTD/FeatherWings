package diff

import (
	"bytes"
	"path/filepath"
	"testing"
)

func TestSnapshotsCanBeListedAndReconstructed(t *testing.T) {
	store, err := openStorage(filepath.Join(t.TempDir(), "server.db"), 3)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.close() })

	firstID, err := store.insertSnapshot("config/server.properties", []byte("first"), "", 5, 5<<20, 200<<20)
	if err != nil {
		t.Fatal(err)
	}
	secondID, err := store.insertSnapshot("config/server.properties", []byte("second"), "", 5, 5<<20, 200<<20)
	if err != nil {
		t.Fatal(err)
	}

	revisions, err := store.list("config/server.properties")
	if err != nil {
		t.Fatal(err)
	}
	if len(revisions) != 2 || revisions[0].ID != secondID || revisions[1].ID != firstID {
		t.Fatalf("unexpected revision list: %#v", revisions)
	}
	if !revisions[0].IsSnapshot || revisions[0].StoredSize == 0 {
		t.Fatalf("expected compressed snapshot metadata, got %#v", revisions[0])
	}

	content, err := store.reconstruct(firstID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(content, []byte("first")) {
		t.Fatalf("unexpected reconstructed content: %q", content)
	}
}
