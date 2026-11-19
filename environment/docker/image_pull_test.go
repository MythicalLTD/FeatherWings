package docker

import (
	"errors"
	"strings"
	"testing"
)

func TestReadImagePullPublishesProgress(t *testing.T) {
	stream := strings.Join([]string{
		`{"status":"Pulling from library/alpine","id":"latest"}`,
		`{"status":"Downloading","progressDetail":{"current":1048576,"total":4194304},"progress":"[=>  ] 1MB/4MB","id":"abc123"}`,
		`{"status":"Pull complete","progressDetail":{},"id":"abc123"}`,
		`{"status":"Status: Downloaded newer image for alpine:latest"}`,
	}, "\n")

	var got []string
	if err := ReadImagePull(strings.NewReader(stream), func(s string) { got = append(got, s) }); err != nil {
		t.Fatalf("ReadImagePull() error = %v", err)
	}
	want := []string{
		"latest Pulling from library/alpine",
		"abc123 Downloading [=====>              ] 25% (1.0 MiB/4.0 MiB)",
		"abc123 Pull complete",
		"Status: Downloaded newer image for alpine:latest",
	}
	if len(got) != len(want) {
		t.Fatalf("got %d messages %q, want %q", len(got), got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("message %d = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestReadImagePullReturnsStreamErrors(t *testing.T) {
	tests := map[string]string{
		"errorDetail":       `{"errorDetail":{"message":"manifest unknown"},"error":"manifest unknown"}`,
		"error only":        `{"error":"toomanyrequests: rate limit"}`,
		"empty errorDetail": `{"errorDetail":{}}`,
	}
	for name, line := range tests {
		t.Run(name, func(t *testing.T) {
			stream := `{"status":"Pulling fs layer","id":"a"}` + "\n" + line + "\n" + `{"status":"never read"}`
			var published []string
			err := ReadImagePull(strings.NewReader(stream), func(s string) { published = append(published, s) })
			if err == nil {
				t.Fatal("expected an error from the pull stream")
			}
			if !IsImagePullStreamError(err) {
				t.Fatalf("expected a stream error, got %T %v", err, err)
			}
			if len(published) != 1 {
				t.Fatalf("expected reading to stop at the error, published %q", published)
			}
		})
	}
}

func TestReadImagePullInvalidJSONIsNotAStreamError(t *testing.T) {
	err := ReadImagePull(strings.NewReader(`{"status":`), func(string) {})
	if err == nil || IsImagePullStreamError(err) {
		t.Fatalf("expected a decode error, got %v", err)
	}
	if IsImagePullStreamError(errors.New("other")) {
		t.Fatal("plain errors are not stream errors")
	}
}

func TestFormatPullProgress(t *testing.T) {
	tests := []struct {
		current, total int64
		units, want    string
	}{
		{0, 100, "", "[>                   ] 0% (0 B/100 B)"},
		{2048, 2048, "", "[====================] 100% (2.0 KiB/2.0 KiB)"},
		{4096, 1024, "", "[====================] 100% (1.0 KiB/1.0 KiB)"},
		{3 * 1024 * 1024, 0, "", "3.0 MiB"},
		{0, 0, "", ""},
		{12, 0, "s", "12s elapsed"},
		{7, 0, "layers", "7 layers"},
	}
	for _, tt := range tests {
		if got := formatPullProgress(tt.current, tt.total, tt.units); got != tt.want {
			t.Errorf("formatPullProgress(%d, %d, %q) = %q, want %q", tt.current, tt.total, tt.units, got, tt.want)
		}
	}
}
