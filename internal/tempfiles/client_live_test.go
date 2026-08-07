package tempfiles_test

import (
	"bytes"
	"context"
	"os"
	"testing"

	"github.com/mythicalltd/featherwings/internal/tempfiles"
)

func TestUploadAnonymousTinyFile(t *testing.T) {
	if os.Getenv("TEMPFILES_LIVE_TEST") != "1" {
		t.Skip("set TEMPFILES_LIVE_TEST=1 to run live temp uploads test")
	}

	c := tempfiles.New("")
	data := []byte("hello-temp-files-share-test")
	res, err := c.Upload(context.Background(), "hello.txt", int64(len(data)), 1, "", "", bytes.NewReader(data))
	if err != nil {
		t.Fatalf("upload failed: %v", err)
	}
	if res.PublicID == "" || res.URL == "" || res.DeleteKey == "" {
		t.Fatalf("incomplete result: %+v", res)
	}
	t.Logf("shared %s delete_key=%s", res.URL, res.DeleteKey)
}
