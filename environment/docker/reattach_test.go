package docker

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/docker/docker/client"

	"github.com/mythicalltd/featherwings/config"
	"github.com/mythicalltd/featherwings/environment"
	"github.com/mythicalltd/featherwings/events"
	"github.com/mythicalltd/featherwings/system"
)

// reattachDaemon is a fake Docker daemon. inspect decides the answer to each
// container inspect, by call number; attach answers attach requests.
type reattachDaemon struct {
	mu       sync.Mutex
	inspects int
	killed   bool
	attaches int
	inspect  func(n int, killed bool) (int, string)
	attach   int
	conns    []net.Conn
}

func (d *reattachDaemon) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	d.mu.Lock()
	defer d.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/containers/test-server/json"):
		d.inspects++
		status, body := d.inspect(d.inspects, d.killed)
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/containers/test-server/kill"):
		d.killed = true
		w.WriteHeader(http.StatusNoContent)
	case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/containers/test-server/attach"):
		d.attaches++
		if d.attach == http.StatusSwitchingProtocols {
			conn, buf, err := w.(http.Hijacker).Hijack()
			if err != nil {
				return
			}
			_, _ = buf.WriteString("HTTP/1.1 101 UPGRADED\r\nContent-Type: application/vnd.docker.raw-stream\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n\r\n")
			_ = buf.Flush()
			d.conns = append(d.conns, conn)
			return
		}
		w.WriteHeader(d.attach)
		_, _ = w.Write([]byte(`{"message":"attach failed"}`))
	default:
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"message":"not found"}`))
	}
}

const (
	inspectRunning = `{"Id":"test-server","State":{"Running":true,"Status":"running"}}`
	inspectStopped = `{"Id":"test-server","State":{"Running":false,"Status":"exited"}}`
	inspectMissing = `{"message":"No such container: test-server"}`
	inspectBroken  = `{"message":"daemon is not responding"}`
)

func newReattachEnvironment(t *testing.T, d *reattachDaemon) *Environment {
	t.Helper()
	config.Set(&config.Configuration{AuthenticationToken: "test-token"})
	previousDelay, previousMax, previousLimit := reattachInspectDelay, reattachMaxDelay, reattachWaitLimit
	reattachInspectDelay = 2 * time.Millisecond
	reattachMaxDelay = 10 * time.Millisecond
	reattachWaitLimit = 5 * time.Second
	t.Cleanup(func() {
		reattachInspectDelay, reattachMaxDelay, reattachWaitLimit = previousDelay, previousMax, previousLimit
	})

	srv := httptest.NewServer(d)
	t.Cleanup(srv.Close)
	cli, err := client.NewClientWithOpts(client.WithHost("tcp://"+strings.TrimPrefix(srv.URL, "http://")), client.WithHTTPClient(srv.Client()), client.WithVersion("1.47"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cli.Close() })
	return &Environment{
		Id:            "test-server",
		Configuration: environment.NewConfiguration(environment.Settings{}, nil),
		client:        cli,
		st:            system.NewAtomicString(environment.ProcessRunningState),
		emitter:       events.NewBus(),
	}
}

// A container that is gone is not attached to or killed: the server is offline.
func TestReattachMissingContainerIsOffline(t *testing.T) {
	d := &reattachDaemon{inspect: func(int, bool) (int, string) { return http.StatusNotFound, inspectMissing }}
	e := newReattachEnvironment(t, d)

	if e.reattach() {
		t.Fatal("reattach() = true for a container that no longer exists")
	}
	if d.killed || d.attaches != 0 {
		t.Fatalf("missing container was killed=%v or attached %d times", d.killed, d.attaches)
	}
}

// A container that stopped is not attached to or killed.
func TestReattachStoppedContainerIsOffline(t *testing.T) {
	d := &reattachDaemon{inspect: func(int, bool) (int, string) { return http.StatusOK, inspectStopped }}
	e := newReattachEnvironment(t, d)

	if e.reattach() {
		t.Fatal("reattach() = true for a stopped container")
	}
	if d.killed || d.attaches != 0 {
		t.Fatalf("stopped container was killed=%v or attached %d times", d.killed, d.attaches)
	}
}

// While Docker does not answer, for example while dockerd restarts with
// live-restore, Wings waits for it and attaches again once it answers; the
// running container is never killed for it.
func TestReattachWaitsForDockerAndAttachesAgain(t *testing.T) {
	d := &reattachDaemon{
		attach: http.StatusSwitchingProtocols,
		inspect: func(n int, _ bool) (int, string) {
			if n <= 6 {
				return http.StatusInternalServerError, inspectBroken
			}
			return http.StatusOK, inspectRunning
		},
	}
	e := newReattachEnvironment(t, d)
	t.Cleanup(func() { closeAttached(d) })

	if !e.reattach() {
		t.Fatal("reattach() = false for a running container")
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.killed {
		t.Fatal("running container was killed while Docker was not answering")
	}
	if d.attaches != 1 {
		t.Fatalf("attach was tried %d times, expected 1", d.attaches)
	}
	if d.inspects != 7 {
		t.Fatalf("inspect was called %d times, expected 7", d.inspects)
	}
}

// A container that stopped while Docker was not answering is reported as
// stopped once Docker answers.
func TestReattachWaitsForDockerThenOffline(t *testing.T) {
	d := &reattachDaemon{inspect: func(n int, _ bool) (int, string) {
		if n <= 3 {
			return http.StatusInternalServerError, inspectBroken
		}
		return http.StatusOK, inspectStopped
	}}
	e := newReattachEnvironment(t, d)

	if e.reattach() {
		t.Fatal("reattach() = true for a stopped container")
	}
	if d.killed {
		t.Fatal("stopped container was killed")
	}
}

// When Docker never answers within the wait limit the server is marked
// offline without a crash and the container is not killed.
func TestReattachGivesUpWithoutKillingWhenDockerNeverAnswers(t *testing.T) {
	d := &reattachDaemon{inspect: func(int, bool) (int, string) { return http.StatusInternalServerError, inspectBroken }}
	e := newReattachEnvironment(t, d)
	reattachWaitLimit = 100 * time.Millisecond

	if !e.reattach() {
		t.Fatal("reattach() = false; the state must be set here, through stopping")
	}
	if d.killed {
		t.Fatal("container was killed although Docker never answered")
	}
	if st := e.State(); st != environment.ProcessOfflineState {
		t.Fatalf("state = %q, expected offline", st)
	}
}

// Waiting stops without touching the state when something else changes it,
// for example a power action or the server being deleted.
func TestReattachStopsWaitingWhenStateChanges(t *testing.T) {
	var e *Environment
	d := &reattachDaemon{inspect: func(n int, _ bool) (int, string) {
		if n == 2 {
			e.st.Store(environment.ProcessStoppingState)
		}
		return http.StatusInternalServerError, inspectBroken
	}}
	e = newReattachEnvironment(t, d)

	if !e.reattach() {
		t.Fatal("reattach() = false after another action took over")
	}
	if d.killed {
		t.Fatal("container was killed")
	}
	if st := e.State(); st != environment.ProcessStoppingState {
		t.Fatalf("state = %q, expected it to be left as stopping", st)
	}
}

// A running container that Docker confirms can't be attached to is attached
// to again a few times and only then terminated.
func TestReattachTerminatesWhenAttachKeepsFailing(t *testing.T) {
	d := &reattachDaemon{
		attach: http.StatusInternalServerError,
		inspect: func(_ int, killed bool) (int, string) {
			if killed {
				return http.StatusOK, inspectStopped
			}
			return http.StatusOK, inspectRunning
		},
	}
	e := newReattachEnvironment(t, d)

	if e.reattach() {
		t.Fatal("reattach() = true although attaching failed")
	}
	if d.attaches != maxAttachFailuresPerWindow {
		t.Fatalf("attach was tried %d times, expected %d", d.attaches, maxAttachFailuresPerWindow)
	}
	if !d.killed {
		t.Fatal("running container that could not be attached to was not terminated")
	}
}

// An attach failure is not counted when Docker can't confirm afterwards that
// the container is running, so a Docker outage never leads to a kill.
func TestReattachDoesNotCountAttachFailureWhileDockerIsDown(t *testing.T) {
	d := &reattachDaemon{
		attach: http.StatusInternalServerError,
		inspect: func(n int, _ bool) (int, string) {
			if n%2 == 1 {
				return http.StatusOK, inspectRunning
			}
			return http.StatusInternalServerError, inspectBroken
		},
	}
	e := newReattachEnvironment(t, d)
	reattachWaitLimit = 200 * time.Millisecond

	e.reattach()
	if d.killed {
		t.Fatal("container was killed although Docker never confirmed the failed attach")
	}
	if d.attaches < maxAttachFailuresPerWindow {
		t.Fatalf("attach was tried only %d times", d.attaches)
	}
}

// A container that keeps losing its stream but can be attached to again is not
// killed for it.
func TestReattachRepeatedLossIsNotTerminated(t *testing.T) {
	d := &reattachDaemon{
		attach:  http.StatusSwitchingProtocols,
		inspect: func(int, bool) (int, string) { return http.StatusOK, inspectRunning },
	}
	e := newReattachEnvironment(t, d)
	t.Cleanup(func() { closeAttached(d) })
	e.droppedAt = time.Now()
	e.droppedCount = 10

	if !e.reattach() {
		t.Fatal("reattach() = false for a running container")
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.killed {
		t.Fatal("container that could be attached to again was killed")
	}
}

// closeAttached ends the fake attach streams; the container is reported gone
// from then on so the attach session ends quietly.
func closeAttached(d *reattachDaemon) {
	d.mu.Lock()
	d.inspect = func(int, bool) (int, string) { return http.StatusNotFound, inspectMissing }
	conns := d.conns
	d.conns = nil
	d.mu.Unlock()
	for _, c := range conns {
		_ = c.Close()
	}
	time.Sleep(50 * time.Millisecond)
}
