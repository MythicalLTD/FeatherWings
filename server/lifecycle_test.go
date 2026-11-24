package server

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/mythicalltd/featherwings/config"
	"github.com/mythicalltd/featherwings/remote"
)

// lifecycleTestClient records the install status reported to the Panel.
type lifecycleTestClient struct {
	remote.Client
	statuses chan remote.InstallStatusRequest
}

func (c lifecycleTestClient) SetInstallationStatus(_ context.Context, _ string, r remote.InstallStatusRequest) error {
	c.statuses <- r
	return nil
}

func newLifecycleTestServer(t *testing.T, client remote.Client) *Server {
	t.Helper()
	cfg, err := config.NewAtPath(filepath.Join(t.TempDir(), "config.yml"))
	if err != nil {
		t.Fatal(err)
	}
	cfg.AuthenticationToken = "test-token"
	config.Set(cfg)
	s, err := New(client)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// Installing, transferring and restoring exclude each other.
func TestLifecycleStatesExcludeEachOther(t *testing.T) {
	s := newLifecycleTestServer(t, nil)

	starts := map[string]func() bool{
		"install":  s.StartInstalling,
		"transfer": s.StartTransferring,
		"restore":  s.StartRestoring,
	}
	finish := map[string]func(){
		"install":  func() { s.SetInstalling(false) },
		"transfer": func() { s.SetTransferring(false) },
		"restore":  func() { s.SetRestoring(false) },
	}
	for held, start := range starts {
		if !start() {
			t.Fatalf("could not start %s on an idle server", held)
		}
		for other, try := range starts {
			if try() {
				t.Fatalf("%s started while %s was in progress", other, held)
			}
		}
		if !s.IsInProtectedState() {
			t.Fatalf("server is not in a protected state while %s is in progress", held)
		}
		finish[held]()
		if s.IsInProtectedState() {
			t.Fatalf("server is still in a protected state after %s finished", held)
		}
	}
}

// When many operations start at once, exactly one of them is allowed to run.
func TestLifecycleStartIsAtomic(t *testing.T) {
	s := newLifecycleTestServer(t, nil)
	fns := []func() bool{s.StartInstalling, s.StartTransferring, s.StartRestoring}

	for round := 0; round < 50; round++ {
		var started atomic.Int32
		var wg sync.WaitGroup
		for i := 0; i < 30; i++ {
			wg.Add(1)
			go func(fn func() bool) {
				defer wg.Done()
				if fn() {
					started.Add(1)
				}
			}(fns[i%len(fns)])
		}
		wg.Wait()
		if n := started.Load(); n != 1 {
			t.Fatalf("round %d: %d operations started at once, expected exactly 1", round, n)
		}
		s.SetInstalling(false)
		s.SetTransferring(false)
		s.SetRestoring(false)
	}
}

// An install requested while a restore is running is refused, reported to the
// Panel as unsuccessful, and does not touch the restore's state.
func TestInstallIsRefusedWhileRestoring(t *testing.T) {
	client := lifecycleTestClient{statuses: make(chan remote.InstallStatusRequest, 1)}
	s := newLifecycleTestServer(t, client)
	if !s.StartRestoring() {
		t.Fatal("could not start a restore")
	}

	err := s.Install()
	if !errors.Is(err, ErrLifecycleBusy) {
		t.Fatalf("Install() error = %v, expected ErrLifecycleBusy", err)
	}
	select {
	case r := <-client.statuses:
		if r.Successful {
			t.Fatal("refused install was reported to the Panel as successful")
		}
	default:
		t.Fatal("refused install was not reported to the Panel")
	}
	if !s.IsRestoring() {
		t.Fatal("refusing the install cleared the restore state")
	}
	if s.IsInstalling() {
		t.Fatal("refused install left the server marked as installing")
	}
}
