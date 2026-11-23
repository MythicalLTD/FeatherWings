package docker

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mythicalltd/featherwings/environment"
	"github.com/mythicalltd/featherwings/events"
	"github.com/mythicalltd/featherwings/system"
)

func newPollTestEnv() *Environment {
	return &Environment{Id: "test-server", st: system.NewAtomicString(environment.ProcessRunningState), emitter: events.NewBus()}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// A replacement attach session asks for polling while the old session's loop
// still runs; once the old session is canceled the new one must be polled.
func TestEnsurePollingHandsOverToReplacementSession(t *testing.T) {
	e := newPollTestEnv()

	var running atomic.Int32
	started := make(chan context.Context, 4)
	run := func(ctx context.Context) error {
		running.Add(1)
		defer running.Add(-1)
		started <- ctx
		<-ctx.Done()
		return ctx.Err()
	}

	oldCtx, oldCancel := context.WithCancel(context.Background())
	e.ensurePolling(oldCtx, run)
	if got := <-started; got != oldCtx {
		t.Fatal("first loop did not use the first session context")
	}

	// Replacement session attaches before the old session's cancel() runs.
	newCtx, newCancel := context.WithCancel(context.Background())
	defer newCancel()
	e.ensurePolling(newCtx, run)
	if running.Load() != 1 {
		t.Fatal("a second polling loop was started while one was running")
	}

	oldCancel()
	select {
	case got := <-started:
		if got != newCtx {
			t.Fatal("hand-over loop did not use the replacement session context")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("polling was not restarted for the replacement session")
	}

	newCancel()
	waitFor(t, "polling to stop", func() bool {
		e.pollMu.Lock()
		defer e.pollMu.Unlock()
		return !e.pollActive
	})

	// After everything stopped a new request starts a fresh loop.
	ctx3, cancel3 := context.WithCancel(context.Background())
	defer cancel3()
	e.ensurePolling(ctx3, run)
	if got := <-started; got != ctx3 {
		t.Fatal("polling did not start again after the loop stopped")
	}
}

// A request that is canceled before the running loop exits is dropped, and a
// repeat request for the running context does not cause a restart.
func TestEnsurePollingDropsStaleRequests(t *testing.T) {
	e := newPollTestEnv()

	var runs atomic.Int32
	run := func(ctx context.Context) error {
		runs.Add(1)
		<-ctx.Done()
		return ctx.Err()
	}

	ctx1, cancel1 := context.WithCancel(context.Background())
	e.ensurePolling(ctx1, run)
	e.ensurePolling(ctx1, run)

	ctx2, cancel2 := context.WithCancel(context.Background())
	e.ensurePolling(ctx2, run)
	cancel2()
	cancel1()

	waitFor(t, "polling to stop", func() bool {
		e.pollMu.Lock()
		defer e.pollMu.Unlock()
		return !e.pollActive
	})
	if n := runs.Load(); n != 1 {
		t.Fatalf("expected 1 polling run, got %d", n)
	}
}

// A request that is already canceled must not replace a live pending request.
func TestEnsurePollingCanceledRequestKeepsLivePending(t *testing.T) {
	e := newPollTestEnv()

	started := make(chan context.Context, 4)
	run := func(ctx context.Context) error {
		started <- ctx
		<-ctx.Done()
		return ctx.Err()
	}

	ctxA, cancelA := context.WithCancel(context.Background())
	e.ensurePolling(ctxA, run)
	<-started

	ctxB, cancelB := context.WithCancel(context.Background())
	defer cancelB()
	e.ensurePolling(ctxB, run)

	ctxC, cancelC := context.WithCancel(context.Background())
	cancelC()
	e.ensurePolling(ctxC, run)

	cancelA()
	select {
	case got := <-started:
		if got != ctxB {
			t.Fatal("hand-over did not use the live pending request")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("live pending request was lost")
	}
}
