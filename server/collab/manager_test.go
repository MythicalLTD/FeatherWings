package collab

import (
	"errors"
	"testing"

	"github.com/mythicalltd/featherwings/config"
	"github.com/mythicalltd/featherwings/server/filesystem"
)

func TestReadContentMissingFile(t *testing.T) {
	config.Set(&config.Configuration{
		AuthenticationToken: "test-token",
		System: config.SystemConfiguration{
			OpenatMode: "openat",
		},
	})

	fs, err := filesystem.New(t.TempDir(), 0, nil)
	if err != nil {
		t.Fatalf("create filesystem: %v", err)
	}

	m := &Manager{fs: fs}
	_, err = m.readContent("missing.txt", 1024)
	if !errors.Is(err, ErrFileNotFound) {
		t.Fatalf("readContent error = %v, want %v", err, ErrFileNotFound)
	}
}
