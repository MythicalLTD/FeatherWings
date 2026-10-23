package server

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/docker/docker/api/types/container"

	"github.com/mythicalltd/featherwings/config"
	"github.com/mythicalltd/featherwings/events"
)

func TestInstallationWaitError(t *testing.T) {
	tests := []struct {
		name      string
		response  container.WaitResponse
		wantError string
	}{
		{
			name:     "successful installation",
			response: container.WaitResponse{StatusCode: 0},
		},
		{
			name:      "installation script failure",
			response:  container.WaitResponse{StatusCode: 1},
			wantError: "install: installation script exited with code 1",
		},
		{
			name:      "command not found",
			response:  container.WaitResponse{StatusCode: 127},
			wantError: "install: installation script exited with code 127",
		},
		{
			name: "container wait failure",
			response: container.WaitResponse{
				Error: &container.WaitExitError{Message: "daemon disconnected"},
			},
			wantError: "install: installation container wait failed: daemon disconnected",
		},
		{
			name: "container wait failure without message",
			response: container.WaitResponse{
				Error: &container.WaitExitError{},
			},
			wantError: "install: installation container wait failed: unknown container wait error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := installationWaitError(tt.response)
			if tt.wantError == "" {
				if err != nil {
					t.Fatalf("installationWaitError() returned unexpected error: %v", err)
				}
				return
			}

			if err == nil {
				t.Fatalf("installationWaitError() returned nil, expected %q", tt.wantError)
			}
			if err.Error() != tt.wantError {
				t.Fatalf("installationWaitError() error = %q, expected %q", err.Error(), tt.wantError)
			}
		})
	}
}

func TestWaitForInstallationContainerPublishesWaitFailure(t *testing.T) {
	s, err := New(nil)
	if err != nil {
		t.Fatalf("New() returned unexpected error: %v", err)
	}

	listener := make(chan []byte, 1)
	s.Events().On(listener)
	defer s.Events().Off(listener)

	waitErr := errors.New("daemon disconnected")
	sChan := make(chan container.WaitResponse)
	eChan := make(chan error, 1)
	eChan <- waitErr

	ip := &InstallationProcess{Server: s}
	if err := ip.waitForInstallationContainer(sChan, eChan); !errors.Is(err, waitErr) {
		t.Fatalf("waitForInstallationContainer() error = %v, expected %v", err, waitErr)
	}

	select {
	case raw := <-listener:
		event := events.MustDecode(raw)
		if event.Topic != DaemonMessageEvent {
			t.Fatalf("event topic = %q, expected %q", event.Topic, DaemonMessageEvent)
		}
		if event.Data != "Installation process failed: daemon disconnected" {
			t.Fatalf("event data = %q, expected failure message", event.Data)
		}
	default:
		t.Fatal("waitForInstallationContainer() did not publish a failure event")
	}
}

func TestWaitForInstallationContainerExitCodeIsConfigurable(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		cfg, err := config.NewAtPath(filepath.Join(t.TempDir(), "config.yml"))
		if err != nil {
			t.Fatal(err)
		}
		cfg.AuthenticationToken = "test-token"
		cfg.System.CheckInstallExitCode = enabled
		config.Set(cfg)

		s, err := New(nil)
		if err != nil {
			t.Fatalf("New() returned unexpected error: %v", err)
		}
		sChan := make(chan container.WaitResponse, 1)
		sChan <- container.WaitResponse{StatusCode: 3}

		ip := &InstallationProcess{Server: s}
		err = ip.waitForInstallationContainer(sChan, make(chan error))
		if enabled && err == nil {
			t.Fatal("expected a non-zero exit code to fail the installation when enabled")
		}
		if !enabled && err != nil {
			t.Fatalf("expected a non-zero exit code to be ignored by default, got %v", err)
		}
	}
}
