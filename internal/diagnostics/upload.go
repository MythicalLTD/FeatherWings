package diagnostics

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/goccy/go-json"
)

// DefaultPasteAPIURL is the MythicalSystems pastes API (mclo.gs-compatible) endpoint used for diagnostics uploads.
const DefaultPasteAPIURL = "https://pastes.mythicalsystems.org/log"

// DefaultMclogsAPIURL is kept as an alias for backwards compatibility with existing callers and CLI flags.
const DefaultMclogsAPIURL = DefaultPasteAPIURL

const defaultPasteSource = "featherwings"

var (
	ErrMissingUploadAPIURL = errors.New("diagnostics: upload api url is required")
	ErrInvalidUploadAPIURL = errors.New("diagnostics: upload api url is invalid")
)

type pasteUploadRequest struct {
	Content  string `json:"content"`
	Source   string `json:"source,omitempty"`
	Metadata []any  `json:"metadata,omitempty"`
}

type pasteUploadResponse struct {
	Success bool   `json:"success"`
	ID      string `json:"id"`
	URL     string `json:"url"`
	Raw     string `json:"raw"`
	Error   string `json:"error"`
}

// maxUploadResponseSize is the largest response read from the paste service.
const maxUploadResponseSize = 64 * 1024

// uploadTimeout bounds how long an upload may take when the caller did not set
// a shorter deadline.
const uploadTimeout = 30 * time.Second

// UploadReport posts diagnostics content to the given mclo.gs-compatible paste API endpoint and returns the resulting URL.
func UploadReport(ctx context.Context, apiURL string, content string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, uploadTimeout)
	defer cancel()

	if apiURL == "" {
		return "", ErrMissingUploadAPIURL
	}

	u, err := url.Parse(apiURL)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrInvalidUploadAPIURL, err)
	}

	payload, err := json.Marshal(pasteUploadRequest{
		Content: content,
		Source:  defaultPasteSource,
	})
	if err != nil {
		return "", fmt.Errorf("failed to encode upload payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(payload))
	if err != nil {
		return "", fmt.Errorf("failed to create upload request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to upload report: %w", err)
	}
	defer res.Body.Close()

	// The paste service only answers with a short JSON document, so do not read
	// more than that from it.
	body, err := io.ReadAll(io.LimitReader(res.Body, maxUploadResponseSize+1))
	if err != nil {
		return "", fmt.Errorf("failed to read upload response: %w", err)
	}
	if len(body) > maxUploadResponseSize {
		return "", errors.New("upload response is too large")
	}

	if res.StatusCode != http.StatusOK {
		return "", fmt.Errorf("upload failed with status %s: %s", res.Status, string(body))
	}

	var uploadResponse pasteUploadResponse
	if err := json.Unmarshal(body, &uploadResponse); err != nil {
		return "", fmt.Errorf("failed to decode upload response: %w", err)
	}

	if !uploadResponse.Success {
		if uploadResponse.Error != "" {
			return "", errors.New(uploadResponse.Error)
		}
		return "", errors.New("upload failed")
	}

	if uploadResponse.URL == "" {
		return "", errors.New("upload response missing URL")
	}

	return uploadResponse.URL, nil
}
