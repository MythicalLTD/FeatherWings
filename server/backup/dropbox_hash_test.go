package backup

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestDropboxContentHash(t *testing.T) {
	// Empty file: SHA-256 of nothing (no blocks).
	empty := sha256.Sum256(nil)
	if got, _ := DropboxContentHash(bytes.NewReader(nil)); got != hex.EncodeToString(empty[:]) {
		t.Fatalf("empty: got %s", got)
	}

	// 4 MiB + 3 bytes: two blocks.
	data := bytes.Repeat([]byte{'a'}, dropboxHashBlock+3)
	b1 := sha256.Sum256(data[:dropboxHashBlock])
	b2 := sha256.Sum256(data[dropboxHashBlock:])
	want := sha256.Sum256(append(b1[:], b2[:]...))
	got, err := DropboxContentHash(bytes.NewReader(data))
	if err != nil || got != hex.EncodeToString(want[:]) {
		t.Fatalf("two blocks: got %s err %v", got, err)
	}
}
