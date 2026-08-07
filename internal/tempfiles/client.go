package tempfiles

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"emperror.dev/errors"
	"github.com/cenkalti/backoff/v4"
	"github.com/goccy/go-json"
)

const (
	DefaultBaseURL = "https://www.mythicalsystems.org"

	PartSizeBytes      = 67108864
	AnonymousMaxBytes  = 16106127360
	APIKeyMaxBytes     = 32212254720
	BackgroundMinBytes = 256 << 20 // 256 MiB
)

// InitRequest is the JSON body for POST /api/temp-files.
type InitRequest struct {
	Filename  string `json:"filename"`
	Size      int64  `json:"size"`
	TTLDays   int    `json:"ttl_days"`
	Password  string `json:"password,omitempty"`
	DeleteKey string `json:"delete_key,omitempty"`
}

// Part describes a single multipart upload URL from init.
type Part struct {
	PartNumber int    `json:"part_number"`
	URL        string `json:"url"`
}

// InitResponse is returned by POST /api/temp-files.
type InitResponse struct {
	Success           bool   `json:"success"`
	PublicID          string `json:"public_id"`
	PartSize          int64  `json:"part_size"`
	PartCount         int    `json:"part_count"`
	Parts             []Part `json:"parts"`
	DeleteKey         string `json:"delete_key"`
	DeleteToken       string `json:"delete_token"`
	PasswordProtected bool   `json:"password_protected"`
	ExpiresAt         string `json:"expires_at"`
	CompleteURL       string `json:"complete_url"`
	PageURL           string `json:"page_url"`
	DownloadPath      string `json:"download_path"`
	Error             string `json:"error"`
	Message           string `json:"message"`
}

// CompletedPart is sent to complete.
type CompletedPart struct {
	PartNumber int    `json:"part_number"`
	ETag       string `json:"etag"`
}

// CompleteRequest is the JSON body for POST /api/temp-files/{id}/complete.
type CompleteRequest struct {
	Parts []CompletedPart `json:"parts"`
}

// CompleteResponse is returned by complete.
type CompleteResponse struct {
	Success           bool   `json:"success"`
	PublicID          string `json:"public_id"`
	PageURL           string `json:"page_url"`
	DownloadPath      string `json:"download_path"`
	ExpiresAt         string `json:"expires_at"`
	Size              int64  `json:"size"`
	OriginalName      string `json:"original_name"`
	PasswordProtected bool   `json:"password_protected"`
	DownloadURL       string `json:"download_url"`
	Error             string `json:"error"`
	Message           string `json:"message"`
}

// Result is the final share result returned to callers.
type Result struct {
	PublicID          string `json:"public_id"`
	URL               string `json:"url"`
	DeleteKey         string `json:"delete_key"`
	ExpiresAt         string `json:"expires_at"`
	PasswordProtected bool   `json:"password_protected"`
	Size              int64  `json:"size"`
	Filename          string `json:"filename"`
}

// Client talks to the temp uploads API and the multipart upload endpoint.
type Client struct {
	BaseURL string
	Token   string
	HTTP    *http.Client
}

// New returns a Client with sensible timeouts for large multipart uploads.
func New(token string) *Client {
	return &Client{
		BaseURL: DefaultBaseURL,
		Token:   token,
		HTTP:    &http.Client{Timeout: time.Hour * 2},
	}
}

// MaxBytes returns the size limit for the current auth mode.
func (c *Client) MaxBytes() int64 {
	if strings.TrimSpace(c.Token) != "" {
		return APIKeyMaxBytes
	}
	return AnonymousMaxBytes
}

// Upload streams reader to temp uploads and returns the share result.
func (c *Client) Upload(ctx context.Context, filename string, size int64, ttlDays int, password, deleteKey string, reader io.Reader) (*Result, error) {
	if filename == "" {
		return nil, errors.New("tempfiles: filename is required")
	}
	filename = filepath.Base(filename)
	if size <= 0 {
		return nil, errors.New("tempfiles: size must be greater than zero")
	}
	if ttlDays != 1 && ttlDays != 5 {
		return nil, errors.New("tempfiles: ttl_days must be 1 or 5")
	}
	if size > c.MaxBytes() {
		return nil, errors.Errorf("tempfiles: file exceeds maximum size of %d bytes for this auth mode", c.MaxBytes())
	}
	if password != "" && len(password) < 4 {
		return nil, errors.New("tempfiles: password must be at least 4 characters")
	}
	if deleteKey != "" && len(deleteKey) < 8 {
		return nil, errors.New("tempfiles: delete_key must be at least 8 characters")
	}

	initRes, err := c.Init(ctx, InitRequest{
		Filename:  filename,
		Size:      size,
		TTLDays:   ttlDays,
		Password:  password,
		DeleteKey: deleteKey,
	})
	if err != nil {
		return nil, err
	}

	completed, err := c.uploadParts(ctx, reader, size, initRes)
	if err != nil {
		return nil, err
	}

	completeRes, err := c.Complete(ctx, initRes.PublicID, CompleteRequest{Parts: completed})
	if err != nil {
		return nil, err
	}

	url := completeRes.PageURL
	if url == "" {
		url = initRes.PageURL
	}
	if url == "" {
		url = strings.TrimRight(c.BaseURL, "/") + "/f/" + initRes.PublicID
	}

	deleteKeyOut := initRes.DeleteKey
	if deleteKeyOut == "" {
		deleteKeyOut = initRes.DeleteToken
	}

	return &Result{
		PublicID:          initRes.PublicID,
		URL:               url,
		DeleteKey:         deleteKeyOut,
		ExpiresAt:         firstNonEmpty(completeRes.ExpiresAt, initRes.ExpiresAt),
		PasswordProtected: initRes.PasswordProtected || password != "",
		Size:              size,
		Filename:          filename,
	}, nil
}

// Init creates a multipart upload session.
func (c *Client) Init(ctx context.Context, req InitRequest) (*InitResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, errors.Wrap(err, "tempfiles: encode init request")
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(c.BaseURL, "/")+"/api/temp-files", bytes.NewReader(body))
	if err != nil {
		return nil, errors.Wrap(err, "tempfiles: create init request")
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")
	c.applyAuth(httpReq)

	res, err := c.HTTP.Do(httpReq)
	if err != nil {
		return nil, errors.Wrap(err, "tempfiles: init request failed")
	}
	defer res.Body.Close()

	raw, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, errors.Wrap(err, "tempfiles: read init response")
	}

	var out InitResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, errors.Wrapf(err, "tempfiles: decode init response (HTTP/%d): %s", res.StatusCode, truncate(string(raw), 256))
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 || !out.Success || out.PublicID == "" {
		msg := firstNonEmpty(out.Error, out.Message, string(raw))
		return nil, errors.Errorf("tempfiles: init failed (HTTP/%d): %s", res.StatusCode, truncate(msg, 512))
	}
	if len(out.Parts) == 0 {
		return nil, errors.New("tempfiles: init returned no upload parts")
	}
	return &out, nil
}

// Complete finalizes the multipart upload.
func (c *Client) Complete(ctx context.Context, publicID string, req CompleteRequest) (*CompleteResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, errors.Wrap(err, "tempfiles: encode complete request")
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(c.BaseURL, "/")+"/api/temp-files/"+publicID+"/complete", bytes.NewReader(body))
	if err != nil {
		return nil, errors.Wrap(err, "tempfiles: create complete request")
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")
	c.applyAuth(httpReq)

	res, err := c.HTTP.Do(httpReq)
	if err != nil {
		return nil, errors.Wrap(err, "tempfiles: complete request failed")
	}
	defer res.Body.Close()

	raw, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, errors.Wrap(err, "tempfiles: read complete response")
	}

	var out CompleteResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, errors.Wrapf(err, "tempfiles: decode complete response (HTTP/%d): %s", res.StatusCode, truncate(string(raw), 256))
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 || !out.Success {
		msg := firstNonEmpty(out.Error, out.Message, string(raw))
		return nil, errors.Errorf("tempfiles: complete failed (HTTP/%d): %s", res.StatusCode, truncate(msg, 512))
	}
	return &out, nil
}

func (c *Client) uploadParts(ctx context.Context, reader io.Reader, totalSize int64, init *InitResponse) ([]CompletedPart, error) {
	partSize := init.PartSize
	if partSize <= 0 {
		partSize = PartSizeBytes
	}

	uploader := &partUploader{
		reader: reader,
		client: c.HTTP,
	}

	completed := make([]CompletedPart, 0, len(init.Parts))
	for i, part := range init.Parts {
		var size int64
		if i+1 < len(init.Parts) {
			size = partSize
		} else {
			size = totalSize - (int64(i) * partSize)
			if size < 0 {
				size = 0
			}
		}

		etag, n, err := uploader.uploadPart(ctx, part.URL, size)
		if err != nil {
			return nil, errors.Wrapf(err, "tempfiles: upload part %d", part.PartNumber)
		}
		if n != size {
			return nil, errors.Errorf("tempfiles: part %d expected %d bytes, got %d", part.PartNumber, size, n)
		}
		completed = append(completed, CompletedPart{
			PartNumber: part.PartNumber,
			ETag:       etag,
		})
	}
	return completed, nil
}

func (c *Client) applyAuth(req *http.Request) {
	token := strings.TrimSpace(c.Token)
	if token == "" {
		return
	}
	if !strings.HasPrefix(token, "Bearer ") {
		token = "Bearer " + token
	}
	req.Header.Set("Authorization", token)
}

type partUploader struct {
	reader io.Reader
	client *http.Client
}

func (u *partUploader) uploadPart(ctx context.Context, partURL string, size int64) (string, int64, error) {
	limited := io.LimitReader(u.reader, size)
	// Buffer the part so we can retry on 5xx without needing a Seekable source.
	buf, err := io.ReadAll(limited)
	if err != nil {
		return "", 0, errors.Wrap(err, "tempfiles: read part bytes")
	}
	n := int64(len(buf))

	var etag string
	err = backoff.Retry(func() error {
		req, err := http.NewRequestWithContext(ctx, http.MethodPut, partURL, bytes.NewReader(buf))
		if err != nil {
			return backoff.Permanent(errors.Wrap(err, "tempfiles: create part PUT"))
		}
		req.ContentLength = n
		req.Header.Set("Content-Length", fmt.Sprintf("%d", n))
		req.Header.Set("Content-Type", "application/octet-stream")

		res, err := u.client.Do(req)
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
				return backoff.Permanent(err)
			}
			return errors.Wrap(err, "tempfiles: part PUT failed")
		}
		defer res.Body.Close()
		_, _ = io.Copy(io.Discard, res.Body)

		if res.StatusCode < 200 || res.StatusCode >= 300 {
			err := errors.New(fmt.Sprintf("tempfiles: part PUT failed: [HTTP/%d] %s", res.StatusCode, res.Status))
			if res.StatusCode >= http.StatusInternalServerError {
				return err
			}
			return backoff.Permanent(err)
		}

		etag = res.Header.Get("ETag")
		if etag == "" {
			return backoff.Permanent(errors.New("tempfiles: part PUT missing ETag header"))
		}
		return nil
	}, u.backoff(ctx))

	if err != nil {
		if v, ok := err.(*backoff.PermanentError); ok {
			return "", n, v.Unwrap()
		}
		return "", n, err
	}
	return etag, n, nil
}

func (u *partUploader) backoff(ctx context.Context) backoff.BackOffContext {
	b := backoff.NewExponentialBackOff()
	b.Multiplier = 2
	b.MaxElapsedTime = time.Minute
	return backoff.WithContext(b, ctx)
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
