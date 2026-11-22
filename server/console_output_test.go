package server

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/mythicalltd/featherwings/config"
	"github.com/mythicalltd/featherwings/environment"
	"github.com/mythicalltd/featherwings/remote"
)

// blockingStateEnvironment holds every call to State until it is released.
type blockingStateEnvironment struct {
	environment.ProcessEnvironment
	release chan struct{}
}

func (e *blockingStateEnvironment) State() string {
	<-e.release
	return environment.ProcessRunningState
}

// Each line of console output is checked before the next one is read.
func TestConsoleOutputIsCheckedAsItIsRead(t *testing.T) {
	cfg, err := config.NewAtPath(filepath.Join(t.TempDir(), "config.yml"))
	require.NoError(t, err)
	cfg.AuthenticationToken = "test-token"
	config.Set(cfg)

	s, err := New(nil)
	require.NoError(t, err)
	env := &blockingStateEnvironment{release: make(chan struct{})}
	s.Environment = env
	s.procConfig = &remote.ProcessConfiguration{}

	done := make(chan struct{})
	go func() {
		s.processConsoleOutputEvent([]byte("line"))
		close(done)
	}()

	select {
	case <-done:
		t.Fatal("expected the line to be checked before the next one is read")
	case <-time.After(100 * time.Millisecond):
	}

	close(env.release)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("expected the line to be processed once it could be checked")
	}
}

// recordingStateEnvironment reports a fixed state and records every state change.
type recordingStateEnvironment struct {
	environment.ProcessEnvironment
	state string
	set   []string
}

func (e *recordingStateEnvironment) State() string { return e.state }

func (e *recordingStateEnvironment) SetState(st string) { e.set = append(e.set, st) }

// A console line that equals the stop command does not change the server state;
// only sending the stop command does.
func TestConsoleOutputMatchingTheStopCommandKeepsTheState(t *testing.T) {
	cfg, err := config.NewAtPath(filepath.Join(t.TempDir(), "config.yml"))
	require.NoError(t, err)
	cfg.AuthenticationToken = "test-token"
	config.Set(cfg)

	s, err := New(nil)
	require.NoError(t, err)
	env := &recordingStateEnvironment{state: environment.ProcessRunningState}
	s.Environment = env
	s.procConfig = &remote.ProcessConfiguration{}
	s.procConfig.Stop.Type = remote.ProcessStopCommand
	s.procConfig.Stop.Value = "stop"

	s.onConsoleOutput([]byte("stop"))

	require.Empty(t, env.set)
}
