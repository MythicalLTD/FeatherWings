package backup

import (
	"context"
	"crypto/rand"
	"crypto/sha1"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mythicalltd/featherwings/config"
	"github.com/mythicalltd/featherwings/remote"
	"github.com/mythicalltd/featherwings/server/filesystem"
)

// e2eClient is the panel side: it hands out the session and checks the size.
type e2eClient struct {
	remote.Client
	info      remote.BackupRemoteUploadResponse
	askedSize int64
}

func (c *e2eClient) GetBackupRemoteUploadURLs(_ context.Context, _ string, size int64) (remote.BackupRemoteUploadResponse, error) {
	c.askedSize = size
	i := c.info
	i.TotalSize = size
	return i, nil
}

// TestResumableEndToEnd archives a real server directory with Generate, uploads
// it to each mock provider with injected faults, checks the checksum and size
// Wings reports against what the provider stored, then restores the stored
// archive through a download that drops twice and is resumed with Range.
func TestResumableEndToEnd(t *testing.T) {
	for _, kind := range []string{"google", "onedrive", "dropbox"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			backupDir := filepath.Join(root, "backups")
			serverDir := filepath.Join(root, "server")
			restoreDir := filepath.Join(root, "restore")
			for _, d := range []string{backupDir, serverDir, restoreDir} {
				if err := os.MkdirAll(d, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			config.Set(&config.Configuration{AuthenticationToken: "t", System: config.SystemConfiguration{BackupDirectory: backupDir}})

			// Incompressible data so the archive spans many chunks.
			big := make([]byte, 6<<20)
			rand.Read(big)
			os.WriteFile(filepath.Join(serverDir, "world.dat"), big, 0o600)
			os.MkdirAll(filepath.Join(serverDir, "plugins"), 0o700)
			os.WriteFile(filepath.Join(serverDir, "plugins", "a.yml"), []byte("hello: world\n"), 0o600)
			fsys, err := filesystem.New(serverDir, 0, nil)
			if err != nil {
				t.Fatal(err)
			}

			stored, _ := os.Create(filepath.Join(root, "stored.tar.gz"))
			defer stored.Close()
			faults := map[int]fault{2: {status: 503}, 4: {drop: true}, 6: {status: 429, retryAfter: "2"}}
			m := &mockProvider{t: t, kind: kind, h: sha1.New(), faults: faults, sink: stored}
			srv := httptest.NewServer(m)
			defer srv.Close()

			client := &e2eClient{info: remote.BackupRemoteUploadResponse{
				Adapter: "resumable", Protocol: ProtocolContentRange, SessionURL: srv.URL, ChunkSize: chunk,
				Headers: map[string]string{"Authorization": "Bearer short-lived"},
			}}
			if kind == "dropbox" {
				client.info.Protocol, client.info.SessionID, client.info.SessionURL = ProtocolDropboxAppend, "sess", srv.URL+"/append"
				client.info.Finish = &remote.BackupResumableFinish{URL: srv.URL + "/finish"}
			}
			b := NewResumable(client, "6a3c2f6e-1b7d-4c8e-9f0a-2d4b6c8e0f12", "srv", "")
			var delays []time.Duration
			b.sleep = func(_ context.Context, d time.Duration) error { delays = append(delays, d); return nil }
			// The mock learns the total from the panel call.
			m.total = -1
			wrapped := &sizeHook{e2eClient: client, m: m}
			b.client = wrapped

			ad, err := b.Generate(context.Background(), fsys, "")
			if err != nil {
				t.Fatal(err)
			}
			if ad.Size != wrapped.askedSize || ad.Size != m.offset {
				t.Fatalf("size: reported %d, asked %d, provider %d", ad.Size, wrapped.askedSize, m.offset)
			}
			if ad.Checksum != m.sum() || ad.ChecksumType != "sha1" {
				t.Fatalf("checksum: reported %s, provider %s", ad.Checksum, m.sum())
			}
			if _, err := os.Stat(b.Path()); !os.IsNotExist(err) {
				t.Fatal("local archive was not removed")
			}
			if !m.authSeen {
				t.Fatal("headers were not sent")
			}
			hasRetryAfter := false
			for _, d := range delays {
				if d == 2*time.Second {
					hasRetryAfter = true
				}
			}
			if !hasRetryAfter {
				t.Fatalf("Retry-After not honoured: %v", delays)
			}

			// Restore: serve the stored archive, dropping the connection twice.
			data, _ := os.ReadFile(stored.Name())
			var gets, ranged atomic.Int32
			dl := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "Bearer dl" {
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				n := gets.Add(1)
				start := 0
				if rg := r.Header.Get("Range"); rg != "" {
					ranged.Add(1)
					start, _ = strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(rg, "bytes="), "-"))
					w.Header().Set("Content-Range", "bytes "+strconv.Itoa(start)+"-"+strconv.Itoa(len(data)-1)+"/"+strconv.Itoa(len(data)))
				}
				w.Header().Set("Accept-Ranges", "bytes")
				w.Header().Set("ETag", `"v1"`)
				w.Header().Set("Content-Type", "application/octet-stream")
				w.Header().Set("Content-Length", strconv.Itoa(len(data)-start))
				if start > 0 {
					w.WriteHeader(http.StatusPartialContent)
				}
				body := data[start:]
				if n <= 2 {
					// Send a third of what is left, then cut the connection.
					w.Write(body[:len(body)/3])
					w.(http.Flusher).Flush()
					c, _, _ := w.(http.Hijacker).Hijack()
					c.Close()
					return
				}
				w.Write(body)
			}))
			defer dl.Close()

			req, _ := http.NewRequest(http.MethodGet, dl.URL, nil)
			req.Header.Set("Authorization", "Bearer dl")
			hc := &http.Client{}
			res, err := hc.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			rr := NewRangeResumeReader(context.Background(), hc, req, res, nil)
			rr.sleep = func(time.Duration) {}
			defer rr.Close()
			restored := map[string]string{}
			err = b.Restore(context.Background(), rr, func(name string, _ os.FileInfo, r io.ReadCloser) error {
				h := sha1.New()
				io.Copy(h, r)
				restored[name] = hex.EncodeToString(h.Sum(nil))
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			want := sha1.Sum(big)
			if restored["world.dat"] != hex.EncodeToString(want[:]) {
				t.Fatalf("restored world.dat mismatch, files: %v", restored)
			}
			small := sha1.Sum([]byte("hello: world\n"))
			if restored["plugins/a.yml"] != hex.EncodeToString(small[:]) {
				t.Fatalf("missing plugins/a.yml: %v", restored)
			}
			if ranged.Load() != 2 {
				t.Fatalf("expected 2 Range resumes, got %d", ranged.Load())
			}
		})
	}
}

type sizeHook struct {
	*e2eClient
	m *mockProvider
}

func (s *sizeHook) GetBackupRemoteUploadURLs(ctx context.Context, u string, size int64) (remote.BackupRemoteUploadResponse, error) {
	s.m.mu.Lock()
	s.m.total = size
	s.m.mu.Unlock()
	return s.e2eClient.GetBackupRemoteUploadURLs(ctx, u, size)
}

func TestRangeResumeReaderRefusesNon206(t *testing.T) {
	n := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n++
		w.Header().Set("Accept-Ranges", "bytes")
		w.Header().Set("Content-Length", "100")
		if n == 1 {
			w.Write(make([]byte, 10))
			w.(http.Flusher).Flush()
			c, _, _ := w.(http.Hijacker).Hijack()
			c.Close()
			return
		}
		w.Write(make([]byte, 100)) // 200: ignores Range, must not be spliced
	}))
	defer srv.Close()
	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	rr := NewRangeResumeReader(context.Background(), http.DefaultClient, req, res, nil)
	rr.sleep = func(time.Duration) {}
	if _, err := io.ReadAll(rr); err == nil || !strings.Contains(err.Error(), "206") {
		t.Fatalf("expected a 206 error, got %v", err)
	}
}
