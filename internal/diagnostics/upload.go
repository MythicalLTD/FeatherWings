package diagnostics

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"

	"github.com/goccy/go-json"
)

const DefaultMclogsAPIURL = "https://api.mclo.gs/1/log"

var (
	ErrMissingUploadAPIURL = errors.New("diagnostics: upload api url is required")
	ErrInvalidUploadAPIURL = errors.New("diagnostics: upload api url is invalid")
)

type mclogsUploadResponse struct {
	Success bool   `json:"success"`
	ID      string `json:"id"`
	URL     string `json:"url"`
	Raw     string `json:"raw"`
	Error   string `json:"error"`
}

// UploadReport posts diagnostics content to the given mclogs-compatible API endpoint and returns the resulting URL.
func UploadReport(ctx context.Context, apiURL string, content string) (string, error) {
	if apiURL == "" {
		return "", ErrMissingUploadAPIURL
	}

	u, err := url.Parse(apiURL)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrInvalidUploadAPIURL, err)
	}

	formData := new(bytes.Buffer)
	formWriter := multipart.NewWriter(formData)
	if err := formWriter.WriteField("content", content); err != nil {
		return "", fmt.Errorf("failed to write form field: %w", err)
	}
	if err := formWriter.Close(); err != nil {
		return "", fmt.Errorf("failed to finalize form data: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), formData)
	if err != nil {
		return "", fmt.Errorf("failed to create upload request: %w", err)
	}
	req.Header.Set("Content-Type", formWriter.FormDataContentType())

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to upload report: %w", err)
	}
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read upload response: %w", err)
	}

	if res.StatusCode != http.StatusOK {
		return "", fmt.Errorf("upload failed with status %s: %s", res.Status, string(body))
	}

	var uploadResponse mclogsUploadResponse
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
