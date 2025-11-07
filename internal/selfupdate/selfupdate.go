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

const DefaultBinaryTemplate = "wings_linux_{arch}"

var (
	// ErrUnsupportedArch indicates that the current runtime architecture is not supported.
	ErrUnsupportedArch = errors.New("selfupdate: unsupported architecture")

	// ErrChecksumNotFound indicates that the requested checksum could not be found in the checksum file.
	ErrChecksumNotFound = errors.New("selfupdate: checksum not found for binary")

	// ErrChecksumRequired indicates that a checksum must be supplied for direct downloads.
	ErrChecksumRequired = errors.New("selfupdate: checksum required for direct download")
)

type ReleaseInfo struct {
	TagName string         `json:"tag_name"`
	Assets  []ReleaseAsset `json:"assets"`
}

type ReleaseAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

type assetSelection struct {
	Binary   ReleaseAsset
	Checksum *ReleaseAsset
}

// HTTPError represents a non-successful HTTP response from an upstream service.
type HTTPError struct {
	StatusCode int
	URL        string
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("selfupdate: unexpected HTTP status %d (%s) for %s", e.StatusCode, http.StatusText(e.StatusCode), e.URL)
}

// DetermineBinaryName resolves the binary asset name using the provided template.
// The template may include the placeholder "{arch}", which will be replaced with
// the runtime architecture (amd64 or arm64). When template is empty, a default
// value is used.
func DetermineBinaryName(template string) (string, error) {
	if template == "" {
		template = DefaultBinaryTemplate
	}

	var archToken string
	switch runtime.GOARCH {
	case "amd64":
		archToken = "amd64"
	case "arm64":
		archToken = "arm64"
	default:
		return "", ErrUnsupportedArch
	}

	return strings.ReplaceAll(template, "{arch}", archToken), nil
}

func FetchLatestReleaseInfo(ctx context.Context, owner string, repo string) (ReleaseInfo, error) {
	return fetchRelease(ctx, fmt.Sprintf("https://api.github.com/repos/%s/%s/releases/latest", owner, repo))
}

func FetchReleaseByTag(ctx context.Context, owner string, repo string, tag string) (ReleaseInfo, error) {
	tag = strings.TrimSpace(tag)
	if tag == "" {
		return ReleaseInfo{}, errors.New("selfupdate: release tag is required")
	}
	apiURL := fmt.Sprintf("https://api.github.com/repos/%s/%s/releases/tags/%s", owner, repo, tag)
	return fetchRelease(ctx, apiURL)
}

func fetchRelease(ctx context.Context, apiURL string) (ReleaseInfo, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return ReleaseInfo{}, err
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return ReleaseInfo{}, err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return ReleaseInfo{}, &HTTPError{StatusCode: res.StatusCode, URL: req.URL.String()}
	}

	var release ReleaseInfo
	if err := json.NewDecoder(res.Body).Decode(&release); err != nil {
		return ReleaseInfo{}, err
	}

	return release, nil
}

func UpdateFromGitHub(ctx context.Context, owner string, repo string, release ReleaseInfo, binaryTemplate string, skipChecksum bool) (string, error) {
	tmpDir, err := os.MkdirTemp("", "wings-update-*")
	if err != nil {
		return "", fmt.Errorf("failed to create temp directory: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	selection, err := selectAssets(release.Assets, binaryTemplate)
	if err != nil {
		return "", err
	}

	assetName := selection.Binary.Name

	var checksumPath string
	if !skipChecksum {
		checksumURL := fmt.Sprintf("https://github.com/%s/%s/releases/download/%s/checksums.txt", owner, repo, release.TagName)
		if selection.Checksum != nil && selection.Checksum.BrowserDownloadURL != "" {
			checksumURL = selection.Checksum.BrowserDownloadURL
		}

		checksumPath = filepath.Join(tmpDir, "checksums.txt")
		if err := downloadWithProgress(ctx, checksumURL, checksumPath); err != nil {
			return "", fmt.Errorf("failed to download checksums: %w", err)
		}
	} else {
		fmt.Println("Warning: checksum verification disabled; proceeding without verification.")
	}

	binaryFilename := filepath.Base(assetName)
	binaryPath := filepath.Join(tmpDir, binaryFilename)
	if err := downloadWithProgress(ctx, selection.Binary.BrowserDownloadURL, binaryPath); err != nil {
		return "", fmt.Errorf("failed to download binary: %w", err)
	}

	if !skipChecksum {
		expectedChecksum, err := findChecksum(checksumPath, assetName)
		if err != nil {
			return "", fmt.Errorf("failed to locate checksum: %w", err)
		}
		if err := verifyChecksumMatch(binaryPath, expectedChecksum); err != nil {
			return "", err
		}
	}

	if err := replaceCurrentBinary(binaryPath); err != nil {
		return "", err
	}

	return assetName, nil
}

func selectAssets(assets []ReleaseAsset, template string) (assetSelection, error) {
	preferred, err := DetermineBinaryName(template)
	if err != nil {
		return assetSelection{}, err
	}

	archToken := runtime.GOARCH
	binaryAsset, err := selectBinaryAsset(assets, preferred, archToken)
	if err != nil {
		return assetSelection{}, err
	}

	checksumAsset := selectChecksumsAsset(assets)
	return assetSelection{Binary: binaryAsset, Checksum: checksumAsset}, nil
}

func selectBinaryAsset(assets []ReleaseAsset, preferred string, arch string) (ReleaseAsset, error) {
	lowerPreferred := strings.ToLower(preferred)
	for _, asset := range assets {
		if asset.Name == preferred {
			return asset, nil
		}
	}
	for _, asset := range assets {
		if lowerPreferred != "" && strings.Contains(strings.ToLower(asset.Name), lowerPreferred) {
			return asset, nil
		}
	}

	var candidates []ReleaseAsset
	for _, asset := range assets {
		nameLower := strings.ToLower(asset.Name)
		if !strings.Contains(nameLower, arch) {
			continue
		}
		if !strings.Contains(nameLower, "linux") {
			continue
		}
		if strings.Contains(nameLower, "checksum") || strings.Contains(nameLower, "sha") || strings.Contains(nameLower, ".sig") {
			continue
		}
		candidates = append(candidates, asset)
	}

	if len(candidates) == 0 {
		return ReleaseAsset{}, fmt.Errorf("selfupdate: could not locate release asset for architecture %s", arch)
	}

	best := candidates[0]
	bestScore := assetScore(best.Name)
	for _, candidate := range candidates[1:] {
		score := assetScore(candidate.Name)
		if score < bestScore {
			best = candidate
			bestScore = score
		}
	}

	return best, nil
}

func selectChecksumsAsset(assets []ReleaseAsset) *ReleaseAsset {
	for _, asset := range assets {
		nameLower := strings.ToLower(asset.Name)
		if strings.Contains(nameLower, "checksums") || strings.Contains(nameLower, "sha256sum") {
			a := asset
			return &a
		}
	}
	for _, asset := range assets {
		nameLower := strings.ToLower(asset.Name)
		if strings.Contains(nameLower, "checksum") || strings.Contains(nameLower, "sha256") {
			a := asset
			return &a
		}
	}
	return nil
}

func assetScore(name string) int {
	lower := strings.ToLower(name)
	switch {
	case strings.Contains(lower, ".tar.gz") || strings.Contains(lower, ".tar.xz"):
		return 3
	case strings.HasSuffix(lower, ".gz") || strings.HasSuffix(lower, ".xz") || strings.HasSuffix(lower, ".zip"):
		return 2
	case strings.Contains(lower, "/"):
		return 1
	default:
		return 0
	}
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

func findChecksum(checksumPath string, assetName string) (string, error) {
	data, err := os.ReadFile(checksumPath)
	if err != nil {
		return "", err
	}

	baseName := filepath.Base(assetName)
	for _, line := range strings.Split(string(data), "\n") {
		if !(strings.Contains(line, assetName) || strings.Contains(line, baseName)) {
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
