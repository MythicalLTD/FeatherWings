package backup

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"emperror.dev/errors"

	"github.com/mythicalltd/featherwings/remote"
	"github.com/mythicalltd/featherwings/server/filesystem"
)

const (
	ProtocolContentRange  = "content-range"
	ProtocolDropboxAppend = "dropbox-append"

	resumableChunkAlign     = 262144
	resumableDefaultChunk   = 8 * 1024 * 1024
	dropboxMaxChunk         = 150 * 1024 * 1024
	resumableMaxAttempts    = 8
	resumableMaxRetryAfter  = 5 * time.Minute
	resumableInitialBackoff = time.Second
	resumableMaxBackoff     = time.Minute
)

// ResumableBackup uploads the archive to a resumable upload session that the
// panel opened with the user's storage provider. Wings only ever receives the
// session URL and short-lived headers, never the provider's refresh tokens.
type ResumableBackup struct {
	Backup
	// httpClient and sleep can be replaced in tests.
	httpClient *http.Client
	sleep      func(ctx context.Context, d time.Duration) error
}

var _ BackupInterface = (*ResumableBackup)(nil)

func NewResumable(client remote.Client, uuid string, suuid string, ignore string) *ResumableBackup {
	return &ResumableBackup{
		Backup: Backup{
			client:     client,
			Uuid:       uuid,
			ServerUuid: suuid,
			Ignore:     ignore,
			adapter:    ResumableBackupAdapter,
		},
		httpClient: &http.Client{Timeout: 2 * time.Hour},
		sleep:      sleepCtx,
	}
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func (r *ResumableBackup) Remove() error {
	if err := r.validateIdentifier(); err != nil {
		return err
	}
	return os.Remove(r.Path())
}

func (r *ResumableBackup) WithLogContext(c map[string]interface{}) {
	r.logContext = c
}

// Generate creates the archive on disk (the same as the S3 adapter, the total
// size must be known before the session is used), uploads it in chunks and
// removes the local copy.
func (r *ResumableBackup) Generate(ctx context.Context, fsys *filesystem.Filesystem, ignore string) (*ArchiveDetails, error) {
	if err := r.validateIdentifier(); err != nil {
		return nil, err
	}
	defer r.Remove()

	a := &filesystem.Archive{Filesystem: fsys, Ignore: ignore}
	r.log().WithField("path", r.Path()).Info("creating backup for server")
	if _, err := os.Stat(filepath.Dir(r.Path())); os.IsNotExist(err) {
		if err := os.Mkdir(filepath.Dir(r.Path()), 0o700); err != nil {
			return nil, err
		}
	}
	if err := a.Create(ctx, r.Path()); err != nil {
		return nil, err
	}
	r.log().Info("created backup successfully")

	f, err := os.Open(r.Path())
	if err != nil {
		return nil, errors.Wrap(err, "backup: could not read archive from disk")
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}

	info, err := r.client.GetBackupRemoteUploadURLs(ctx, r.Uuid, st.Size())
	if err != nil {
		return nil, err
	}
	if err := r.upload(ctx, f, st.Size(), info); err != nil {
		return nil, err
	}
	ad, err := r.Details(ctx, nil)
	if err != nil {
		return nil, errors.WrapIf(err, "backup: failed to get archive details after upload")
	}
	return ad, nil
}

// Restore reads a gzipped tar archive; the router fetches it from download_url.
func (r *ResumableBackup) Restore(ctx context.Context, rd io.Reader, callback RestoreCallback) error {
	return (&S3Backup{Backup: r.Backup}).Restore(ctx, rd, callback)
}

// upload validates the session description and dispatches on the protocol.
func (r *ResumableBackup) upload(ctx context.Context, src io.ReaderAt, size int64, info remote.BackupRemoteUploadResponse) error {
	if info.SessionURL == "" {
		return errors.New("backup: panel did not return a session_url for the resumable adapter")
	}
	if info.TotalSize != 0 && info.TotalSize != size {
		return fmt.Errorf("backup: panel session total_size %d does not match archive size %d", info.TotalSize, size)
	}
	chunk := info.ChunkSize
	if chunk <= 0 {
		chunk = resumableDefaultChunk
	}
	if r.httpClient == nil {
		r.httpClient = &http.Client{Timeout: 2 * time.Hour}
	}
	if r.sleep == nil {
		r.sleep = sleepCtx
	}
	r.log().WithField("protocol", info.Protocol).WithField("size", size).WithField("chunk_size", chunk).Info("uploading backup to resumable session")
	var err error
	switch info.Protocol {
	case ProtocolContentRange, "":
		if chunk%resumableChunkAlign != 0 {
			return fmt.Errorf("backup: chunk_size %d must be a multiple of %d", chunk, resumableChunkAlign)
		}
		err = r.uploadContentRange(ctx, src, size, chunk, info)
	case ProtocolDropboxAppend:
		if chunk > dropboxMaxChunk {
			chunk = dropboxMaxChunk
		}
		err = r.uploadDropbox(ctx, src, size, chunk, info)
	default:
		return fmt.Errorf("backup: unsupported resumable protocol %q", info.Protocol)
	}
	if err != nil {
		return err
	}
	if info.CompleteURL != "" {
		if err := r.callComplete(ctx, info); err != nil {
			return err
		}
	}
	r.log().Info("backup has been successfully uploaded")
	return nil
}

// retryState tracks consecutive failures; any progress resets it.
type retryState struct {
	attempts int
	backoff  time.Duration
}

func (s *retryState) reset() { s.attempts = 0; s.backoff = 0 }

// wait sleeps before the next attempt or returns lastErr when out of attempts.
func (r *ResumableBackup) wait(ctx context.Context, s *retryState, res *http.Response, lastErr error) error {
	s.attempts++
	if s.attempts >= resumableMaxAttempts {
		return errors.WrapIf(lastErr, "backup: giving up after repeated failures")
	}
	if s.backoff == 0 {
		s.backoff = resumableInitialBackoff
	} else {
		s.backoff *= 2
		if s.backoff > resumableMaxBackoff {
			s.backoff = resumableMaxBackoff
		}
	}
	d := s.backoff
	if res != nil {
		if ra := parseRetryAfter(res.Header.Get("Retry-After")); ra > 0 {
			d = ra
		}
	}
	r.log().WithField("attempt", s.attempts).WithField("delay", d.String()).WithError(lastErr).Warn("resumable upload request failed, retrying")
	return r.sleep(ctx, d)
}

func parseRetryAfter(v string) time.Duration {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0
	}
	var d time.Duration
	if n, err := strconv.Atoi(v); err == nil {
		d = time.Duration(n) * time.Second
	} else if t, err := http.ParseTime(v); err == nil {
		d = time.Until(t)
	}
	if d < 0 {
		return 0
	}
	if d > resumableMaxRetryAfter {
		d = resumableMaxRetryAfter
	}
	return d
}

func retryable(code int) bool {
	return code == http.StatusTooManyRequests || code >= 500
}

func isCtxErr(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

func (r *ResumableBackup) do(req *http.Request, headers map[string]string) (*http.Response, error) {
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return r.httpClient.Do(req)
}

func drain(res *http.Response) []byte {
	b, _ := io.ReadAll(io.LimitReader(res.Body, 64*1024))
	_, _ = io.Copy(io.Discard, res.Body)
	_ = res.Body.Close()
	return b
}

// sessionOutcome is what a content-range response tells us about the session.
type sessionOutcome struct {
	done   bool
	offset int64 // next byte the server expects
	known  bool  // offset is valid
}

// parseProgress interprets 200/201 (done), 308 with Range (Google) and 202 with
// nextExpectedRanges (OneDrive).
func parseProgress(code int, h http.Header, body []byte) (sessionOutcome, bool) {
	switch code {
	case http.StatusOK, http.StatusCreated:
		// OneDrive answers a status query on an unfinished session with 200 and
		// nextExpectedRanges, so check for it before treating 200 as done.
		if off, ok := parseNextExpected(body); ok {
			return sessionOutcome{offset: off, known: true}, true
		}
		return sessionOutcome{done: true}, true
	case http.StatusPermanentRedirect:
		rg := h.Get("Range")
		if rg == "" {
			return sessionOutcome{offset: 0, known: true}, true
		}
		rg = strings.TrimPrefix(strings.TrimSpace(rg), "bytes=")
		if i := strings.LastIndex(rg, "-"); i >= 0 {
			if end, err := strconv.ParseInt(rg[i+1:], 10, 64); err == nil {
				return sessionOutcome{offset: end + 1, known: true}, true
			}
		}
		return sessionOutcome{}, false
	case http.StatusAccepted:
		if off, ok := parseNextExpected(body); ok {
			return sessionOutcome{offset: off, known: true}, true
		}
		return sessionOutcome{}, false
	}
	return sessionOutcome{}, false
}

func parseNextExpected(body []byte) (int64, bool) {
	var v struct {
		NextExpectedRanges []string `json:"nextExpectedRanges"`
	}
	if len(body) == 0 || json.Unmarshal(body, &v) != nil || len(v.NextExpectedRanges) == 0 {
		return 0, false
	}
	first := v.NextExpectedRanges[0]
	if i := strings.Index(first, "-"); i >= 0 {
		first = first[:i]
	}
	n, err := strconv.ParseInt(strings.TrimSpace(first), 10, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}

var errSessionExpired = errors.New("backup: upload session expired or was not found (HTTP 404/410)")

// queryStatus asks the provider how much of the upload it has. Google uses an
// empty PUT with "Content-Range: bytes */total"; OneDrive answers a GET.
func (r *ResumableBackup) queryStatus(ctx context.Context, size int64, info remote.BackupRemoteUploadResponse) (sessionOutcome, *http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, info.SessionURL, http.NoBody)
	if err != nil {
		return sessionOutcome{}, nil, err
	}
	req.ContentLength = 0
	req.Header.Set("Content-Range", fmt.Sprintf("bytes */%d", size))
	res, err := r.do(req, info.Headers)
	if err != nil {
		return sessionOutcome{}, nil, err
	}
	body := drain(res)
	if res.StatusCode == http.StatusNotFound || res.StatusCode == http.StatusGone {
		return sessionOutcome{}, res, backoffPermanent(errSessionExpired)
	}
	if out, ok := parseProgress(res.StatusCode, res.Header, body); ok {
		return out, res, nil
	}
	if !retryable(res.StatusCode) {
		// Fall back to GET (OneDrive status endpoint).
		greq, err := http.NewRequestWithContext(ctx, http.MethodGet, info.SessionURL, nil)
		if err != nil {
			return sessionOutcome{}, nil, err
		}
		gres, err := r.do(greq, info.Headers)
		if err != nil {
			return sessionOutcome{}, nil, err
		}
		gbody := drain(gres)
		if gres.StatusCode == http.StatusNotFound || gres.StatusCode == http.StatusGone {
			return sessionOutcome{}, gres, backoffPermanent(errSessionExpired)
		}
		if off, ok := parseNextExpected(gbody); ok {
			return sessionOutcome{offset: off, known: true}, gres, nil
		}
		return sessionOutcome{}, gres, fmt.Errorf("backup: could not read upload session status: HTTP %d", gres.StatusCode)
	}
	return sessionOutcome{}, res, fmt.Errorf("backup: upload session status query failed: HTTP %d", res.StatusCode)
}

type permanentErr struct{ error }

func (p permanentErr) Unwrap() error   { return p.error }
func backoffPermanent(err error) error { return permanentErr{err} }
func isPermanent(err error) bool {
	var p permanentErr
	return errors.As(err, &p)
}

func (r *ResumableBackup) uploadContentRange(ctx context.Context, src io.ReaderAt, size, chunk int64, info remote.BackupRemoteUploadResponse) error {
	var offset int64
	var rs retryState
	needStatus := false
	for {
		if needStatus {
			out, res, err := r.queryStatus(ctx, size, info)
			if err != nil {
				if isPermanent(err) || isCtxErr(err) {
					return errors.Unwrap(err)
				}
				if werr := r.wait(ctx, &rs, res, err); werr != nil {
					return werr
				}
				continue
			}
			needStatus = false
			if out.done {
				return nil
			}
			if out.offset < 0 || out.offset > size {
				return fmt.Errorf("backup: provider reported invalid offset %d", out.offset)
			}
			offset = out.offset
		}
		if size == 0 || offset >= size {
			// Every byte was accepted but no final 200/201 was seen yet; ask.
			if size == 0 {
				return r.putEmpty(ctx, info)
			}
			needStatus = true
			if werr := r.wait(ctx, &rs, nil, errors.New("backup: provider has all bytes but did not finish the upload")); werr != nil {
				return werr
			}
			continue
		}
		end := offset + chunk
		if end > size {
			end = size
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPut, info.SessionURL, io.NewSectionReader(src, offset, end-offset))
		if err != nil {
			return err
		}
		req.ContentLength = end - offset
		req.Header.Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", offset, end-1, size))
		res, err := r.do(req, info.Headers)
		if err != nil {
			if isCtxErr(err) {
				return err
			}
			needStatus = true
			if werr := r.wait(ctx, &rs, nil, err); werr != nil {
				return werr
			}
			continue
		}
		body := drain(res)
		if res.StatusCode == http.StatusNotFound || res.StatusCode == http.StatusGone {
			return errSessionExpired
		}
		if out, ok := parseProgress(res.StatusCode, res.Header, body); ok {
			if out.done {
				return nil
			}
			if out.offset < 0 || out.offset > size {
				return fmt.Errorf("backup: provider reported invalid offset %d", out.offset)
			}
			if out.offset <= offset {
				// The provider did not take the chunk; count it as a failure so
				// a session that never advances cannot loop forever.
				offset = out.offset
				if werr := r.wait(ctx, &rs, res, fmt.Errorf("backup: provider did not advance past offset %d", offset)); werr != nil {
					return werr
				}
				continue
			}
			rs.reset()
			offset = out.offset
			r.log().WithField("offset", offset).WithField("size", size).Debug("uploaded backup chunk")
			continue
		}
		err = fmt.Errorf("backup: chunk upload failed: HTTP %d: %s", res.StatusCode, strings.TrimSpace(string(body)))
		if !retryable(res.StatusCode) {
			return err
		}
		needStatus = true
		if werr := r.wait(ctx, &rs, res, err); werr != nil {
			return werr
		}
	}
}

// putEmpty finishes a zero byte upload.
func (r *ResumableBackup) putEmpty(ctx context.Context, info remote.BackupRemoteUploadResponse) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, info.SessionURL, http.NoBody)
	if err != nil {
		return err
	}
	req.ContentLength = 0
	req.Header.Set("Content-Range", "bytes */0")
	res, err := r.do(req, info.Headers)
	if err != nil {
		return err
	}
	drain(res)
	if res.StatusCode == http.StatusOK || res.StatusCode == http.StatusCreated {
		return nil
	}
	return fmt.Errorf("backup: empty upload failed: HTTP %d", res.StatusCode)
}

type dropboxCursor struct {
	SessionID string `json:"session_id"`
	Offset    int64  `json:"offset"`
}

// dropboxCorrectOffset reads correct_offset from an incorrect_offset error.
func dropboxCorrectOffset(body []byte) (int64, bool) {
	var v struct {
		Error struct {
			Tag           string `json:".tag"`
			CorrectOffset *int64 `json:"correct_offset"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &v) != nil || v.Error.CorrectOffset == nil {
		return 0, false
	}
	return *v.Error.CorrectOffset, true
}

func dropboxErrorTag(body []byte) string {
	var v struct {
		Error struct {
			Tag string `json:".tag"`
		} `json:"error"`
	}
	_ = json.Unmarshal(body, &v)
	return v.Error.Tag
}

func (r *ResumableBackup) uploadDropbox(ctx context.Context, src io.ReaderAt, size, chunk int64, info remote.BackupRemoteUploadResponse) error {
	if info.SessionID == "" {
		return errors.New("backup: dropbox-append needs session_id")
	}
	if info.Finish == nil || info.Finish.URL == "" {
		return errors.New("backup: dropbox-append needs finish.url")
	}
	var offset int64
	var rs retryState
	for offset < size {
		end := offset + chunk
		if end > size {
			end = size
		}
		arg, _ := json.Marshal(map[string]interface{}{
			"cursor": dropboxCursor{SessionID: info.SessionID, Offset: offset},
			"close":  end == size,
		})
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, info.SessionURL, io.NewSectionReader(src, offset, end-offset))
		if err != nil {
			return err
		}
		req.ContentLength = end - offset
		req.Header.Set("Content-Type", "application/octet-stream")
		req.Header.Set("Dropbox-API-Arg", string(arg))
		res, err := r.do(req, info.Headers)
		if err != nil {
			if isCtxErr(err) {
				return err
			}
			// We cannot know if the chunk landed; the retry will get an
			// incorrect_offset error with the right offset if it did.
			if werr := r.wait(ctx, &rs, nil, err); werr != nil {
				return werr
			}
			continue
		}
		body := drain(res)
		switch {
		case res.StatusCode == http.StatusOK:
			offset = end
			rs.reset()
		case res.StatusCode == http.StatusConflict:
			if off, ok := dropboxCorrectOffset(body); ok && off >= 0 && off <= size {
				if off == offset {
					return fmt.Errorf("backup: dropbox rejected offset %d it reported as correct", off)
				}
				offset = off
				continue
			}
			// A retried final chunk that already landed (and closed the
			// session) is answered with a "closed" error.
			if end == size && dropboxErrorTag(body) == "closed" {
				offset = size
				continue
			}
			return fmt.Errorf("backup: dropbox append failed: %s", strings.TrimSpace(string(body)))
		case res.StatusCode == http.StatusNotFound || res.StatusCode == http.StatusGone:
			return errSessionExpired
		case retryable(res.StatusCode):
			if werr := r.wait(ctx, &rs, res, fmt.Errorf("backup: dropbox append HTTP %d", res.StatusCode)); werr != nil {
				return werr
			}
		default:
			return fmt.Errorf("backup: dropbox append failed: HTTP %d: %s", res.StatusCode, strings.TrimSpace(string(body)))
		}
	}

	argObj := map[string]interface{}{}
	for k, v := range info.Finish.Arg {
		argObj[k] = v
	}
	argObj["cursor"] = dropboxCursor{SessionID: info.SessionID, Offset: size}
	arg, _ := json.Marshal(argObj)
	headers := map[string]string{}
	for k, v := range info.Headers {
		headers[k] = v
	}
	for k, v := range info.Finish.Headers {
		headers[k] = v
	}
	rs.reset()
	for {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, info.Finish.URL, http.NoBody)
		if err != nil {
			return err
		}
		req.ContentLength = 0
		req.Header.Set("Content-Type", "application/octet-stream")
		req.Header.Set("Dropbox-API-Arg", string(arg))
		res, err := r.do(req, headers)
		if err != nil {
			if isCtxErr(err) {
				return err
			}
			if werr := r.wait(ctx, &rs, nil, err); werr != nil {
				return werr
			}
			continue
		}
		body := drain(res)
		if res.StatusCode == http.StatusOK {
			return nil
		}
		err = fmt.Errorf("backup: dropbox finish failed: HTTP %d: %s", res.StatusCode, strings.TrimSpace(string(body)))
		if !retryable(res.StatusCode) {
			return err
		}
		if werr := r.wait(ctx, &rs, res, err); werr != nil {
			return werr
		}
	}
}

// callComplete sends an empty POST to complete_url when the panel asks for one.
func (r *ResumableBackup) callComplete(ctx context.Context, info remote.BackupRemoteUploadResponse) error {
	var rs retryState
	for {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, info.CompleteURL, bytes.NewReader(nil))
		if err != nil {
			return err
		}
		res, err := r.do(req, info.Headers)
		if err != nil {
			if isCtxErr(err) {
				return err
			}
			if werr := r.wait(ctx, &rs, nil, err); werr != nil {
				return werr
			}
			continue
		}
		drain(res)
		if res.StatusCode >= 200 && res.StatusCode < 300 {
			return nil
		}
		err = fmt.Errorf("backup: complete_url returned HTTP %d", res.StatusCode)
		if !retryable(res.StatusCode) {
			return err
		}
		if werr := r.wait(ctx, &rs, res, err); werr != nil {
			return werr
		}
	}
}
