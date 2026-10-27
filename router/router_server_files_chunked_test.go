package router

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type chunkResp struct {
	status int
	body   map[string]any
}

func (u *uploadTest) chunkReq(t *testing.T, method, p string, q url.Values, body []byte) chunkResp {
	t.Helper()
	q.Set("token", u.token(t))
	req, err := http.NewRequest(method, u.url+p+"?"+q.Encode(), bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/octet-stream")
	res, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer res.Body.Close()
	out := map[string]any{}
	_ = json.NewDecoder(res.Body).Decode(&out)
	return chunkResp{res.StatusCode, out}
}

func (u *uploadTest) putChunk(t *testing.T, id, name string, total, offset int, data []byte) chunkResp {
	return u.chunkReq(t, http.MethodPost, "/upload/chunk", url.Values{
		"upload_id": {id}, "file_name": {name}, "directory": {"/uploads"},
		"total_size": {strconv.Itoa(total)}, "offset": {strconv.Itoa(offset)},
	}, data)
}

func (u *uploadTest) complete(t *testing.T, id, sum string) chunkResp {
	q := url.Values{"upload_id": {id}}
	if sum != "" {
		q.Set("sha256", sum)
	}
	return u.chunkReq(t, http.MethodPost, "/upload/chunk/complete", q, nil)
}

func TestChunkedUploadResumeAndAssemble(t *testing.T) {
	u := newUploadTest(t, 1, 0)
	content := bytes.Repeat([]byte("0123456789"), 250_000) // 2.5 MB > 1 MiB per-chunk limit
	part := 1 << 20
	id := "resume-test-0001"
	// An existing file is replaced.
	require.NoError(t, os.MkdirAll(filepath.Join(u.root, "uploads"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(u.root, "uploads", "big.bin"), []byte("old"), 0o644))

	// First chunk.
	r := u.putChunk(t, id, "big.bin", len(content), 0, content[:part])
	require.Equal(t, http.StatusOK, r.status)

	// Out of order chunk is refused with the current offset.
	r = u.putChunk(t, id, "big.bin", len(content), 2*part, content[2*part:])
	require.Equal(t, http.StatusConflict, r.status)
	require.EqualValues(t, part, r.body["offset"])

	// Duplicate of the first chunk is acknowledged without changes.
	r = u.putChunk(t, id, "big.bin", len(content), 0, content[:part])
	require.Equal(t, http.StatusOK, r.status)
	require.EqualValues(t, part, r.body["offset"])

	// "Reload": ask for status and continue from there.
	r = u.chunkReq(t, http.MethodGet, "/upload/chunk", url.Values{"upload_id": {id}}, nil)
	require.Equal(t, true, r.body["exists"])
	off := int(r.body["offset"].(float64))
	for off < len(content) {
		end := min(off+part, len(content))
		r = u.putChunk(t, id, "big.bin", len(content), off, content[off:end])
		require.Equal(t, http.StatusOK, r.status)
		off = int(r.body["offset"].(float64))
	}

	// Wrong checksum fails, correct one assembles.
	r = u.complete(t, id, "deadbeef")
	require.Equal(t, http.StatusUnprocessableEntity, r.status)
	sum := sha256.Sum256(content)
	r = u.complete(t, id, hex.EncodeToString(sum[:]))
	require.Equal(t, http.StatusOK, r.status, r.body)

	got, err := os.ReadFile(filepath.Join(u.root, "uploads", "big.bin"))
	require.NoError(t, err)
	require.Equal(t, content, got)
	// Staging is gone.
	r = u.chunkReq(t, http.MethodGet, "/upload/chunk", url.Values{"upload_id": {id}}, nil)
	require.Equal(t, false, r.body["exists"])
}

func TestChunkedUploadRejectsBadInput(t *testing.T) {
	u := newUploadTest(t, 1, 0)

	// Path traversal in the file name.
	r := u.putChunk(t, "traversal-0001", "../../etc/passwd", 4, 0, []byte("evil"))
	require.Equal(t, http.StatusBadRequest, r.status)

	// Traversal through the directory stays inside the server root.
	r = u.chunkReq(t, http.MethodPost, "/upload/chunk", url.Values{
		"upload_id": {"traversal-0002"}, "file_name": {"x.txt"}, "directory": {"../../../../tmp"},
		"total_size": {"4"}, "offset": {"0"},
	}, []byte("evil"))
	require.Equal(t, http.StatusOK, r.status)
	require.Equal(t, http.StatusOK, u.complete(t, "traversal-0002", "").status)
	_, err := os.Stat(filepath.Join(u.root, "tmp", "x.txt"))
	require.NoError(t, err)

	// Bad upload id.
	r = u.putChunk(t, "../x", "a.txt", 1, 0, []byte("a"))
	require.Equal(t, http.StatusBadRequest, r.status)

	// Size mismatch: more data than total_size.
	r = u.putChunk(t, "mismatch-0001", "a.txt", 2, 0, []byte("abcd"))
	require.Equal(t, http.StatusRequestEntityTooLarge, r.status)
	// total_size changed between chunks.
	require.Equal(t, http.StatusOK, u.putChunk(t, "mismatch-0002", "a.txt", 4, 0, []byte("ab")).status)
	require.Equal(t, http.StatusConflict, u.putChunk(t, "mismatch-0002", "a.txt", 5, 2, []byte("cd")).status)
	// Completing an incomplete upload fails.
	require.Equal(t, http.StatusConflict, u.complete(t, "mismatch-0002", "").status)

	// Chunk over the per-request limit.
	r = u.putChunk(t, "toolarge-0001", "a.bin", 3<<20, 0, bytes.Repeat([]byte("a"), 2<<20))
	require.Equal(t, http.StatusRequestEntityTooLarge, r.status)

	// Cancel removes the staged data.
	require.Equal(t, http.StatusNoContent, u.chunkReq(t, http.MethodDelete, "/upload/chunk", url.Values{"upload_id": {"mismatch-0002"}}, nil).status)
	r = u.chunkReq(t, http.MethodGet, "/upload/chunk", url.Values{"upload_id": {"mismatch-0002"}}, nil)
	require.Equal(t, false, r.body["exists"])
}

func TestChunkedUploadRespectsDiskLimit(t *testing.T) {
	u := newUploadTest(t, 10, 1)
	r := u.putChunk(t, "disklimit-0001", "big.bin", 2<<20, 0, bytes.Repeat([]byte("a"), 1<<10))
	require.GreaterOrEqual(t, r.status, http.StatusBadRequest)
}

func TestChunkedUploadStaleCleanup(t *testing.T) {
	u := newUploadTest(t, 1, 0)
	require.Equal(t, http.StatusOK, u.putChunk(t, "stale-000001", "a.txt", 4, 0, []byte("ab")).status)
	cleanStaleChunkedUploads(time.Now().Add(25 * time.Hour))
	r := u.chunkReq(t, http.MethodGet, "/upload/chunk", url.Values{"upload_id": {"stale-000001"}}, nil)
	require.Equal(t, false, r.body["exists"])
}

// Set FW_BIG_UPLOAD_TEST=1 to send a 300 MB file in 50 MB parts.
func TestChunkedUploadBigFile(t *testing.T) {
	if os.Getenv("FW_BIG_UPLOAD_TEST") == "" {
		t.Skip("set FW_BIG_UPLOAD_TEST=1 to run")
	}
	u := newUploadTest(t, 100, 0)
	total, part := 300<<20, 50<<20
	chunk := bytes.Repeat([]byte{0xAB}, part)
	h := sha256.New()
	for off := 0; off < total; off += part {
		r := u.putChunk(t, "bigfile-000001", "big.bin", total, off, chunk)
		require.Equal(t, http.StatusOK, r.status, r.body)
		h.Write(chunk)
	}
	start := time.Now()
	r := u.complete(t, "bigfile-000001", hex.EncodeToString(h.Sum(nil)))
	require.Equal(t, http.StatusOK, r.status, r.body)
	t.Logf("assembled in %s", time.Since(start))
	st, err := os.Stat(filepath.Join(u.root, "uploads", "big.bin"))
	require.NoError(t, err)
	require.EqualValues(t, total, st.Size())
}
