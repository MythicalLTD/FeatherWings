package backup

import (
	"context"
	"crypto/rand"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mythicalltd/featherwings/remote"
)

// fault is injected on the Nth chunk request (1 based).
type fault struct {
	status     int
	retryAfter string
	drop       bool // read half of the body, then close the connection
	expire     bool // session is gone from now on
}

// mockProvider mimics Google Drive, OneDrive or Dropbox resumable sessions.
// Chunks are committed only when received in full; bytes are hashed, not kept.
type mockProvider struct {
	t         *testing.T
	kind      string // google, onedrive, dropbox
	total     int64
	mu        sync.Mutex
	h         hash.Hash
	offset    int64
	done      bool
	expired   bool
	chunkReq  int
	faults    map[int]fault
	statusQ   int
	finishOK  bool
	finishArg map[string]interface{}
	authSeen  bool
	sink      io.Writer
}

func (m *mockProvider) out() io.Writer {
	if m.sink != nil {
		return io.MultiWriter(m.h, m.sink)
	}
	return m.h
}

func newMock(t *testing.T, kind string, total int64, faults map[int]fault) (*mockProvider, *httptest.Server) {
	m := &mockProvider{t: t, kind: kind, total: total, h: sha1.New(), faults: faults}
	return m, httptest.NewServer(m)
}

func (m *mockProvider) sum() string { return hex.EncodeToString(m.h.Sum(nil)) }

func (m *mockProvider) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if r.Header.Get("Authorization") == "Bearer short-lived" {
		m.authSeen = true
	}
	if m.expired {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if m.kind == "dropbox" {
		m.dropbox(w, r)
		return
	}
	cr := r.Header.Get("Content-Range")
	if r.Method == http.MethodGet || strings.HasPrefix(cr, "bytes */") {
		m.statusQ++
		m.progress(w)
		return
	}
	m.chunkReq++
	if f, ok := m.faults[m.chunkReq]; ok {
		if m.apply(w, r, f) {
			return
		}
	}
	var a, b, tot int64
	if _, err := fmt.Sscanf(cr, "bytes %d-%d/%d", &a, &b, &tot); err != nil || tot != m.total {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if m.kind == "google" && (b-a+1)%262144 != 0 && b != m.total-1 {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if a != m.offset {
		// Google answers out of order chunks with 308 and the right Range.
		io.Copy(io.Discard, r.Body)
		m.progress(w)
		return
	}
	n, err := io.Copy(m.out(), r.Body)
	if err != nil || n != b-a+1 {
		m.t.Fatalf("short chunk: %d %v", n, err)
	}
	m.offset = b + 1
	if m.offset == m.total {
		m.done = true
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"id":"file"}`))
		return
	}
	m.progress(w)
}

func (m *mockProvider) apply(w http.ResponseWriter, r *http.Request, f fault) bool {
	switch {
	case f.expire:
		m.expired = true
		w.WriteHeader(http.StatusGone)
	case f.drop:
		buf := make([]byte, 1024)
		io.ReadFull(r.Body, buf)
		hj, ok := w.(http.Hijacker)
		if !ok {
			m.t.Fatal("no hijacker")
		}
		c, _, _ := hj.Hijack()
		c.Close()
	default:
		if f.retryAfter != "" {
			w.Header().Set("Retry-After", f.retryAfter)
		}
		io.Copy(io.Discard, r.Body)
		w.WriteHeader(f.status)
	}
	return true
}

func (m *mockProvider) progress(w http.ResponseWriter) {
	if m.done {
		w.WriteHeader(http.StatusOK)
		return
	}
	if m.kind == "onedrive" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		fmt.Fprintf(w, `{"nextExpectedRanges":["%d-"]}`, m.offset)
		return
	}
	if m.offset > 0 {
		w.Header().Set("Range", fmt.Sprintf("bytes=0-%d", m.offset-1))
	}
	w.WriteHeader(http.StatusPermanentRedirect)
}

func (m *mockProvider) dropbox(w http.ResponseWriter, r *http.Request) {
	var arg struct {
		Cursor struct {
			SessionID string `json:"session_id"`
			Offset    int64  `json:"offset"`
		} `json:"cursor"`
	}
	raw := r.Header.Get("Dropbox-API-Arg")
	if err := json.Unmarshal([]byte(raw), &arg); err != nil || arg.Cursor.SessionID != "sess" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if r.URL.Path == "/finish" {
		json.Unmarshal([]byte(raw), &m.finishArg)
		if arg.Cursor.Offset != m.total || m.offset != m.total {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		m.finishOK = true
		w.Write([]byte(`{"name":"backup.tar.gz"}`))
		return
	}
	if r.Header.Get("Content-Type") != "application/octet-stream" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	m.chunkReq++
	if f, ok := m.faults[m.chunkReq]; ok {
		m.apply(w, r, f)
		return
	}
	if arg.Cursor.Offset != m.offset {
		io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusConflict)
		fmt.Fprintf(w, `{"error":{".tag":"incorrect_offset","correct_offset":%d}}`, m.offset)
		return
	}
	n, _ := io.Copy(m.out(), r.Body)
	m.offset += n
	w.Write([]byte("null"))
}

func testFile(t *testing.T, size int64) (*os.File, string) {
	t.Helper()
	f, err := os.Create(filepath.Join(t.TempDir(), "archive.tar.gz"))
	if err != nil {
		t.Fatal(err)
	}
	h := sha1.New()
	if _, err := io.CopyN(io.MultiWriter(f, h), rand.Reader, size); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	return f, hex.EncodeToString(h.Sum(nil))
}

func newTestResumable(delays *[]time.Duration) *ResumableBackup {
	r := NewResumable(nil, "00000000-0000-0000-0000-000000000000", "s", "")
	r.sleep = func(_ context.Context, d time.Duration) error {
		if delays != nil {
			*delays = append(*delays, d)
		}
		return nil
	}
	return r
}

const chunk = 262144

func TestResumableGoogleDrive(t *testing.T) {
	cases := map[string]map[int]fault{
		"clean":          nil,
		"503 mid upload": {3: {status: 503}},
		"dropped conn":   {2: {drop: true}},
		"429":            {4: {status: 429, retryAfter: "7"}},
	}
	for name, faults := range cases {
		t.Run(name, func(t *testing.T) {
			size := int64(5*chunk + 1234)
			f, want := testFile(t, size)
			m, srv := newMock(t, "google", size, faults)
			defer srv.Close()
			var delays []time.Duration
			r := newTestResumable(&delays)
			err := r.upload(context.Background(), f, size, remote.BackupRemoteUploadResponse{
				Adapter: "resumable", Protocol: ProtocolContentRange, SessionURL: srv.URL,
				ChunkSize: chunk, TotalSize: size, Headers: map[string]string{"Authorization": "Bearer short-lived"},
			})
			if err != nil {
				t.Fatal(err)
			}
			if !m.done || m.sum() != want || !m.authSeen {
				t.Fatalf("done=%v sum match=%v auth=%v", m.done, m.sum() == want, m.authSeen)
			}
			if len(faults) > 0 && m.statusQ == 0 {
				t.Fatal("expected a status query after the failure")
			}
			if name == "429" && (len(delays) != 1 || delays[0] != 7*time.Second) {
				t.Fatalf("Retry-After not respected: %v", delays)
			}
		})
	}
}

func TestResumableSessionExpiry(t *testing.T) {
	size := int64(4 * chunk)
	f, _ := testFile(t, size)
	_, srv := newMock(t, "google", size, map[int]fault{2: {expire: true}})
	defer srv.Close()
	err := newTestResumable(nil).upload(context.Background(), f, size, remote.BackupRemoteUploadResponse{
		Protocol: ProtocolContentRange, SessionURL: srv.URL, ChunkSize: chunk,
	})
	if err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expected expiry error, got %v", err)
	}
}

func TestResumablePermanent4xx(t *testing.T) {
	size := int64(2 * chunk)
	f, _ := testFile(t, size)
	m, srv := newMock(t, "google", size, map[int]fault{1: {status: 403}})
	defer srv.Close()
	err := newTestResumable(nil).upload(context.Background(), f, size, remote.BackupRemoteUploadResponse{
		Protocol: ProtocolContentRange, SessionURL: srv.URL, ChunkSize: chunk,
	})
	if err == nil || m.chunkReq != 1 {
		t.Fatalf("expected one attempt and an error, got %d %v", m.chunkReq, err)
	}
}

func TestResumableGivesUp(t *testing.T) {
	size := int64(2 * chunk)
	f, _ := testFile(t, size)
	faults := map[int]fault{}
	for i := 1; i < 50; i++ {
		faults[i] = fault{status: 503}
	}
	m, srv := newMock(t, "google", size, faults)
	defer srv.Close()
	err := newTestResumable(nil).upload(context.Background(), f, size, remote.BackupRemoteUploadResponse{
		Protocol: ProtocolContentRange, SessionURL: srv.URL, ChunkSize: chunk,
	})
	if err == nil || m.chunkReq > resumableMaxAttempts {
		t.Fatalf("expected bounded retries, got %d %v", m.chunkReq, err)
	}
}

func TestResumableOneDrive(t *testing.T) {
	size := int64(3*chunk + 99)
	f, want := testFile(t, size)
	m, srv := newMock(t, "onedrive", size, map[int]fault{2: {status: 500}, 3: {drop: true}})
	defer srv.Close()
	err := newTestResumable(nil).upload(context.Background(), f, size, remote.BackupRemoteUploadResponse{
		Protocol: ProtocolContentRange, SessionURL: srv.URL, ChunkSize: chunk, TotalSize: size,
	})
	if err != nil || !m.done || m.sum() != want {
		t.Fatalf("err=%v done=%v", err, m.done)
	}
}

func TestResumableDropbox(t *testing.T) {
	size := int64(3*chunk + 5)
	f, want := testFile(t, size)
	m, srv := newMock(t, "dropbox", size, map[int]fault{2: {drop: true}, 3: {status: 429, retryAfter: "1"}})
	defer srv.Close()
	err := newTestResumable(nil).upload(context.Background(), f, size, remote.BackupRemoteUploadResponse{
		Protocol: ProtocolDropboxAppend, SessionURL: srv.URL + "/append", SessionID: "sess", ChunkSize: chunk,
		Finish: &remote.BackupResumableFinish{URL: srv.URL + "/finish", Arg: map[string]interface{}{"commit": map[string]interface{}{"path": "/b.tar.gz"}}},
	})
	if err != nil || !m.finishOK || m.sum() != want {
		t.Fatalf("err=%v finish=%v", err, m.finishOK)
	}
	if _, ok := m.finishArg["commit"]; !ok {
		t.Fatal("finish arg lost the commit object")
	}
}

func TestResumableValidation(t *testing.T) {
	r := newTestResumable(nil)
	f, _ := testFile(t, 10)
	for _, info := range []remote.BackupRemoteUploadResponse{
		{Protocol: ProtocolContentRange},
		{Protocol: ProtocolContentRange, SessionURL: "http://x", ChunkSize: 1000},
		{Protocol: ProtocolContentRange, SessionURL: "http://x", TotalSize: 11},
		{Protocol: "ftp", SessionURL: "http://x"},
		{Protocol: ProtocolDropboxAppend, SessionURL: "http://x"},
	} {
		if err := r.upload(context.Background(), f, 10, info); err == nil {
			t.Fatalf("expected error for %+v", info)
		}
	}
}

func TestParseRetryAfter(t *testing.T) {
	if parseRetryAfter("3") != 3*time.Second || parseRetryAfter("") != 0 || parseRetryAfter("99999") != resumableMaxRetryAfter {
		t.Fatal("retry-after parse")
	}
}

// TestResumableLargeFile uploads 600MB with faults and checks memory stays
// flat. Run with FW_LARGE_TEST=1.
func TestResumableLargeFile(t *testing.T) {
	if os.Getenv("FW_LARGE_TEST") == "" {
		t.Skip("set FW_LARGE_TEST=1")
	}
	size := int64(600 << 20)
	if v, _ := strconv.ParseInt(os.Getenv("FW_LARGE_MB"), 10, 64); v > 0 {
		size = v << 20
	}
	for _, kind := range []string{"google", "onedrive", "dropbox"} {
		t.Run(kind, func(t *testing.T) {
			f, want := testFile(t, size)
			faults := map[int]fault{3: {status: 503}, 7: {drop: true}, 11: {status: 429, retryAfter: "1"}}
			m, srv := newMock(t, kind, size, faults)
			defer srv.Close()
			info := remote.BackupRemoteUploadResponse{Protocol: ProtocolContentRange, SessionURL: srv.URL, ChunkSize: 32 << 20, TotalSize: size}
			if kind == "dropbox" {
				info.Protocol, info.SessionID, info.SessionURL = ProtocolDropboxAppend, "sess", srv.URL+"/append"
				info.Finish = &remote.BackupResumableFinish{URL: srv.URL + "/finish"}
			}
			runtime.GC()
			var peak atomic.Uint64
			stop := make(chan struct{})
			go func() {
				var ms runtime.MemStats
				for {
					select {
					case <-stop:
						return
					case <-time.After(20 * time.Millisecond):
						runtime.ReadMemStats(&ms)
						if ms.HeapInuse > peak.Load() {
							peak.Store(ms.HeapInuse)
						}
					}
				}
			}()
			start := time.Now()
			err := newTestResumable(nil).upload(context.Background(), f, size, info)
			close(stop)
			if err != nil {
				t.Fatal(err)
			}
			if m.sum() != want {
				t.Fatal("checksum mismatch")
			}
			t.Logf("%s: %d MB in %s, peak heap in use %d MB, chunk requests %d", kind, size>>20, time.Since(start).Round(time.Millisecond), peak.Load()>>20, m.chunkReq)
			if peak.Load() > 64<<20 {
				t.Fatalf("heap grew to %d MB", peak.Load()>>20)
			}
		})
	}
}

// The final chunk lands and closes the session, but the response is lost; the
// retry gets "closed" and the upload must still finish.
func TestResumableDropboxClosedAfterLostResponse(t *testing.T) {
	size := int64(chunk)
	f, _ := testFile(t, size)
	appends, finished := 0, false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		if r.URL.Path == "/finish" {
			finished = true
			w.Write([]byte("{}"))
			return
		}
		appends++
		if appends == 1 {
			c, _, _ := w.(http.Hijacker).Hijack()
			c.Close()
			return
		}
		w.WriteHeader(http.StatusConflict)
		w.Write([]byte(`{"error":{".tag":"closed"}}`))
	}))
	defer srv.Close()
	err := newTestResumable(nil).upload(context.Background(), f, size, remote.BackupRemoteUploadResponse{
		Protocol: ProtocolDropboxAppend, SessionURL: srv.URL + "/append", SessionID: "sess", ChunkSize: chunk,
		Finish: &remote.BackupResumableFinish{URL: srv.URL + "/finish"},
	})
	if err != nil || !finished {
		t.Fatalf("err=%v finished=%v", err, finished)
	}
}

// A session that keeps answering 308 without moving must not loop forever.
func TestResumableNoProgressIsBounded(t *testing.T) {
	size := int64(2 * chunk)
	f, _ := testFile(t, size)
	n := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		n++
		w.WriteHeader(http.StatusPermanentRedirect)
	}))
	defer srv.Close()
	err := newTestResumable(nil).upload(context.Background(), f, size, remote.BackupRemoteUploadResponse{
		Protocol: ProtocolContentRange, SessionURL: srv.URL, ChunkSize: chunk,
	})
	if err == nil || n > resumableMaxAttempts {
		t.Fatalf("err=%v requests=%d", err, n)
	}
}
