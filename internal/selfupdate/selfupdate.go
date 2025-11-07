package selfupdate

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"
)

var checksumPattern = regexp.MustCompile(`^[a-fA-F0-9]{64}$`)

var (
	// ErrUnsupportedArch indicates that the current runtime architecture is not supported.
	ErrUnsupportedArch = errors.New("selfupdate: unsupported architecture")

	// ErrChecksumNotFound indicates that the requested checksum could not be found in the checksum file.
	ErrChecksumNotFound = errors.New("selfupdate: checksum not found for binary")

	// ErrChecksumRequired indicates that a checksum must be supplied for direct downloads.
	ErrChecksumRequired = errors.New("selfupdate: checksum required for direct download")
)

// HTTPError represents a non-successful HTTP response from an upstream service.
type HTTPError struct {
	StatusCode int
	URL        string
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("selfupdate: unexpected HTTP status %d (%s) for %s", e.StatusCode, http.StatusText(e.StatusCode), e.URL)
}

// DetermineBinaryName resolves the correct binary asset name for the current architecture.
func DetermineBinaryName() (string, error) {
	switch runtime.GOARCH {
	case "amd64":
		return "wings_linux_amd64", nil
	case "arm64":
		return "wings_linux_arm64", nil
	default:
		return "", ErrUnsupportedArch
	}
}

// FetchLatestRelease retrieves the latest release tag for the provided repository.
func FetchLatestRelease(ctx context.Context, owner string, repo string) (string, error) {
	apiURL := fmt.Sprintf("https://api.github.com/repos/%s/%s/releases/latest", owner, repo)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return "", err
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return "", &HTTPError{StatusCode: res.StatusCode, URL: req.URL.String()}
	}

	var releaseData struct {
		TagName string `json:"tag_name"`
	}
	if err := json.NewDecoder(res.Body).Decode(&releaseData); err != nil {
		return "", err
	}

	return releaseData.TagName, nil
}

// UpdateFromGitHub downloads the requested version from GitHub and replaces the current binary.
// When skipChecksum is true the checksum verification step is skipped entirely.
func UpdateFromGitHub(ctx context.Context, owner string, repo string, version string, binaryName string, skipChecksum bool) error {
	downloadURL := fmt.Sprintf("https://github.com/%s/%s/releases/download/%s/%s", owner, repo, version, binaryName)
	checksumURL := fmt.Sprintf("https://github.com/%s/%s/releases/download/%s/checksums.txt", owner, repo, version)

	tmpDir, err := os.MkdirTemp("", "wings-update-*")
	if err != nil {
		return fmt.Errorf("failed to create temp directory: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	var expectedChecksum string
	if !skipChecksum {
		checksumPath := filepath.Join(tmpDir, "checksums.txt")
		if err := downloadWithProgress(ctx, checksumURL, checksumPath); err != nil {
			return fmt.Errorf("failed to download checksums: %w", err)
		}

		expectedChecksum, err = findChecksum(checksumPath, binaryName)
		if err != nil {
			return fmt.Errorf("failed to locate checksum: %w", err)
		}
	} else {
		fmt.Println("Warning: checksum verification disabled; proceeding without verification.")
	}

	binaryPath := filepath.Join(tmpDir, binaryName)
	if err := downloadWithProgress(ctx, downloadURL, binaryPath); err != nil {
		return fmt.Errorf("failed to download binary: %w", err)
	}

	if !skipChecksum {
		if err := verifyChecksumMatch(binaryPath, expectedChecksum); err != nil {
			return err
		}
	}

	return replaceCurrentBinary(binaryPath)
}

// UpdateFromURL downloads a binary from the specified URL and replaces the current binary.
// If expectedChecksum is provided it will be validated prior to replacing the binary unless skipChecksum is true.
func UpdateFromURL(ctx context.Context, downloadURL string, binaryName string, expectedChecksum string, skipChecksum bool) error {
	tmpDir, err := os.MkdirTemp("", "wings-update-url-*")
	if err != nil {
		return fmt.Errorf("failed to create temp directory: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	binaryPath := filepath.Join(tmpDir, binaryName)
	if err := downloadWithProgress(ctx, downloadURL, binaryPath); err != nil {
		return fmt.Errorf("failed to download binary: %w", err)
	}

	if skipChecksum {
		fmt.Println("Warning: checksum verification disabled; proceeding without verification.")
	} else {
		if expectedChecksum == "" {
			return ErrChecksumRequired
		}
		if !checksumPattern.MatchString(expectedChecksum) {
			return fmt.Errorf("invalid checksum format: %s", expectedChecksum)
		}
		if err := verifyChecksumMatch(binaryPath, strings.ToLower(expectedChecksum)); err != nil {
			return err
		}
	}
	return replaceCurrentBinary(binaryPath)
}

func downloadWithProgress(ctx context.Context, downloadURL string, dest string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, downloadURL, nil)
	if err != nil {
		return err
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return &HTTPError{StatusCode: res.StatusCode, URL: downloadURL}
	}

	out, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer out.Close()

	filename := filepath.Base(dest)
	fmt.Printf("Downloading %s (%.2f MB)...\n", filename, float64(res.ContentLength)/1024/1024)

	pw := &progressWriter{
		Writer:    out,
		Total:     res.ContentLength,
		StartTime: time.Now(),
	}

	if _, err := io.Copy(pw, res.Body); err != nil {
		return err
	}

	fmt.Println()
	return nil
}

func findChecksum(checksumPath string, binaryName string) (string, error) {
	data, err := os.ReadFile(checksumPath)
	if err != nil {
		return "", err
	}

	for _, line := range strings.Split(string(data), "\n") {
		if !strings.Contains(line, binaryName) {
			continue
		}
		matches := checksumPattern.FindStringSubmatch(line)
		if len(matches) == 0 {
			continue
		}
		return strings.ToLower(matches[0]), nil
	}

	return "", ErrChecksumNotFound
}

func verifyChecksumMatch(binaryPath string, expectedChecksum string) error {
	file, err := os.Open(binaryPath)
	if err != nil {
		return err
	}
	defer file.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return err
	}
	actualChecksum := fmt.Sprintf("%x", hasher.Sum(nil))

	if actualChecksum == expectedChecksum {
		fmt.Printf("Checksum verification successful!\n")
		return nil
	}

	return fmt.Errorf("checksum mismatch: expected %s, got %s", expectedChecksum, actualChecksum)
}

func replaceCurrentBinary(binaryPath string) error {
	if err := os.Chmod(binaryPath, 0o755); err != nil {
		return fmt.Errorf("failed to set executable permissions: %w", err)
	}

	currentExecutable, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to locate current executable: %w", err)
	}

	if err := os.Rename(binaryPath, currentExecutable); err == nil {
		return nil
	}

	fmt.Println("Direct replacement failed, using copy method...")

	src, err := os.Open(binaryPath)
	if err != nil {
		return fmt.Errorf("failed to open source file: %w", err)
	}
	defer src.Close()

	execDir := filepath.Dir(currentExecutable)
	tempExec := filepath.Join(execDir, fmt.Sprintf(".%s.new", filepath.Base(currentExecutable)))

	dst, err := os.OpenFile(tempExec, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o755)
	if err != nil {
		return fmt.Errorf("failed to create new executable: %w", err)
	}

	if _, err := io.Copy(dst, src); err != nil {
		dst.Close()
		os.Remove(tempExec)
		return fmt.Errorf("failed to copy new binary: %w", err)
	}
	dst.Close()

	if err := os.Rename(tempExec, currentExecutable); err != nil {
		os.Remove(tempExec)
		return fmt.Errorf("failed to replace executable: %w", err)
	}

	return nil
}

type progressWriter struct {
	io.Writer
	Total     int64
	Written   int64
	StartTime time.Time
}

func (pw *progressWriter) Write(p []byte) (int, error) {
	n, err := pw.Writer.Write(p)
	pw.Written += int64(n)

	if pw.Total > 0 {
		percent := float64(pw.Written) / float64(pw.Total) * 100
		fmt.Printf("\rProgress: %.2f%%", percent)
	}

	return n, err
}
