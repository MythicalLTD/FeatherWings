package backup

import (
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"

	"github.com/apex/log"
)

const rangeResumeMaxAttempts = 5

// RangeResumeReader wraps a backup download body. When the body fails before
// the full content was read and the server advertised byte ranges, it asks
// for the remainder with "Range: bytes=N-" and continues where it stopped.
type RangeResumeReader struct {
	ctx      context.Context
	client   *http.Client
	req      *http.Request
	body     io.ReadCloser
	read     int64
	total    int64 // -1 when unknown
	ranges   bool
	etag     string
	attempts int
	logger   *log.Entry
	sleep    func(time.Duration)
}

func NewRangeResumeReader(ctx context.Context, client *http.Client, req *http.Request, res *http.Response, logger *log.Entry) *RangeResumeReader {
	return &RangeResumeReader{
		ctx:    ctx,
		client: client,
		req:    req,
		body:   res.Body,
		total:  res.ContentLength,
		ranges: strings.EqualFold(strings.TrimSpace(res.Header.Get("Accept-Ranges")), "bytes"),
		etag:   res.Header.Get("ETag"),
		logger: logger,
		sleep:  time.Sleep,
	}
}

func (r *RangeResumeReader) Read(p []byte) (int, error) {
	for {
		n, err := r.body.Read(p)
		r.read += int64(n)
		if err == nil {
			return n, nil
		}
		if err == io.EOF {
			if r.total >= 0 && r.read < r.total {
				err = io.ErrUnexpectedEOF
			} else {
				return n, io.EOF
			}
		}
		if !r.ranges || r.ctx.Err() != nil || r.attempts >= rangeResumeMaxAttempts {
			return n, err
		}
		if rerr := r.resume(err); rerr != nil {
			return n, rerr
		}
		if n > 0 {
			return n, nil
		}
	}
}

func (r *RangeResumeReader) resume(cause error) error {
	_ = r.body.Close()
	for r.attempts < rangeResumeMaxAttempts {
		r.attempts++
		r.sleep(time.Duration(r.attempts) * time.Second)
		if r.ctx.Err() != nil {
			return r.ctx.Err()
		}
		if r.logger != nil {
			r.logger.WithField("offset", r.read).WithField("attempt", r.attempts).WithField("error", cause).Warn("backup download interrupted, resuming with a Range request")
		}
		req := r.req.Clone(r.ctx)
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-", r.read))
		if r.etag != "" {
			req.Header.Set("If-Range", r.etag)
		}
		res, err := r.client.Do(req)
		if err != nil {
			cause = err
			continue
		}
		if res.StatusCode != http.StatusPartialContent {
			_ = res.Body.Close()
			return fmt.Errorf("backup: resuming download failed: server answered %s instead of 206", res.Status)
		}
		// Make sure the server continues the same object at our offset.
		cr := strings.TrimSpace(res.Header.Get("Content-Range"))
		var start int64
		if _, err := fmt.Sscanf(cr, "bytes %d-", &start); err != nil || start != r.read {
			_ = res.Body.Close()
			return fmt.Errorf("backup: resumed download started at %q instead of byte %d", cr, r.read)
		}
		if r.etag != "" && res.Header.Get("ETag") != "" && res.Header.Get("ETag") != r.etag {
			_ = res.Body.Close()
			return errors.New("backup: backup file changed while it was being downloaded")
		}
		r.body = res.Body
		return nil
	}
	return fmt.Errorf("backup: backup download failed after %d resume attempts: %w", r.attempts, cause)
}

func (r *RangeResumeReader) Close() error {
	return r.body.Close()
}

func IsOctetStream(value string) bool {
	mediaType, _, err := mime.ParseMediaType(value)
	if err != nil {
		mediaType = strings.TrimSpace(value)
	}
	return strings.EqualFold(mediaType, "application/octet-stream")
}
