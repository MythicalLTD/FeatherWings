package docker

import (
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
	previousDelay := reattachInspectDelay
	reattachInspectDelay = 10 * time.Millisecond
	t.Cleanup(func() { reattachInspectDelay = previousDelay })

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

// When Docker cannot say whether the container is running, it is not simply
// marked offline: the inspect is retried, and the container is terminated
// before reattach reports it as stopped.
func TestReattachTerminatesWhenStateIsUnknown(t *testing.T) {
	d := &reattachDaemon{inspect: func(n int, killed bool) (int, string) {
		switch {
		case n <= reattachInspectAttempts:
			return http.StatusInternalServerError, inspectBroken
		case killed:
			return http.StatusOK, inspectStopped
		default:
			return http.StatusOK, inspectRunning
		}
	}}
	e := newReattachEnvironment(t, d)

	if e.reattach() {
		t.Fatal("reattach() = true although the container could not be inspected")
	}
	if !d.killed {
		t.Fatal("container whose state is unknown was not terminated before being reported as stopped")
	}
	if d.inspects < reattachInspectAttempts {
		t.Fatalf("inspect was tried %d times, expected at least %d", d.inspects, reattachInspectAttempts)
	}
	if st := e.State(); st != environment.ProcessOfflineState {
		t.Fatalf("state after termination = %q, expected offline", st)
	}
}

// One failed inspect is retried instead of deciding the container stopped.
func TestReattachRetriesTransientInspectError(t *testing.T) {
	d := &reattachDaemon{inspect: func(n int, _ bool) (int, string) {
		if n == 1 {
			return http.StatusInternalServerError, inspectBroken
		}
		return http.StatusOK, inspectStopped
	}}
	e := newReattachEnvironment(t, d)

	if e.reattach() {
		t.Fatal("reattach() = true for a stopped container")
	}
	if d.killed {
		t.Fatal("container was killed after a single transient inspect error")
	}
	if d.inspects != 2 {
		t.Fatalf("inspect was called %d times, expected 2", d.inspects)
	}
}

// A running container that cannot be attached to again is terminated instead
// of being left running unmanaged.
func TestReattachTerminatesWhenAttachFails(t *testing.T) {
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
	if d.attaches != 1 {
		t.Fatalf("attach was tried %d times, expected 1", d.attaches)
	}
	if !d.killed {
		t.Fatal("running container that could not be attached to was not terminated")
	}
}

// A container that keeps losing its stream is terminated instead of being
// attached to again forever.
func TestReattachTerminatesAfterRepeatedLoss(t *testing.T) {
	d := &reattachDaemon{inspect: func(_ int, killed bool) (int, string) {
		if killed {
			return http.StatusOK, inspectStopped
		}
		return http.StatusOK, inspectRunning
	}}
	e := newReattachEnvironment(t, d)
	e.reattachedAt = time.Now()
	e.reattachedCount = maxReattachesPerWindow

	if e.reattach() {
		t.Fatal("reattach() = true after too many lost streams")
	}
	if d.attaches != 0 {
		t.Fatalf("attach was tried %d times after the limit was reached", d.attaches)
	}
	if !d.killed {
		t.Fatal("container that kept losing its stream was not terminated")
	}
}
