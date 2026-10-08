package docker

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"

	"github.com/mythicalltd/featherwings/config"
	"github.com/mythicalltd/featherwings/environment"
	"github.com/mythicalltd/featherwings/events"
	"github.com/mythicalltd/featherwings/system"
)

func TestDestroyClearsAttachment(t *testing.T) {
	for _, status := range []int{http.StatusNoContent, http.StatusNotFound, http.StatusInternalServerError} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			daemon := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodDelete || r.URL.Path != "/v1.47/containers/test-server" || r.URL.Query().Get("force") != "1" {
					t.Errorf("unexpected removal request: %s %s", r.Method, r.URL)
				}
				w.WriteHeader(status)
			}))
			defer daemon.Close()
			cli, err := client.NewClientWithOpts(client.WithHost(daemon.URL), client.WithVersion("1.47"))
			if err != nil {
				t.Fatal(err)
			}
			defer cli.Close()
			conn, peer := net.Pipe()
			defer conn.Close()
			defer peer.Close()
			stream := &types.HijackedResponse{Conn: conn}
			e := &Environment{Id: "test-server", client: cli, stream: stream,
				st: system.NewAtomicString(environment.ProcessRunningState), emitter: events.NewBus()}

			err = e.Destroy()
			if status == http.StatusInternalServerError {
				if err == nil || !e.IsAttached() {
					t.Fatal("failed removal must return an error and retain the attachment")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if e.IsAttached() {
				t.Fatal("removed container still has an attachment")
			}
			if _, err := conn.Write([]byte("test")); err == nil {
				t.Fatal("old connection was not closed")
			}
		})
	}
}

func TestPreBootRecreatesContainerWithUpdatedStartup(t *testing.T) {
	config.Set(&config.Configuration{AuthenticationToken: "test-token"})
	var requests []string
	var created container.Config
	daemon := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.Method+" "+r.URL.Path)
		switch r.Method + " " + r.URL.Path {
		case "DELETE /v1.47/containers/test-server":
			if r.URL.Query().Get("force") != "1" {
				t.Error("removal must force-stop a lingering running container")
			}
			w.WriteHeader(http.StatusNoContent)
		case "GET /v1.47/containers/test-server/json":
			w.WriteHeader(http.StatusNotFound)
		case "POST /v1.47/containers/create":
			if err := json.NewDecoder(r.Body).Decode(&created); err != nil {
				t.Error(err)
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"Id":"replacement"}`))
		default:
			t.Errorf("unexpected Docker request: %s %s", r.Method, r.URL)
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer daemon.Close()
	cli, err := client.NewClientWithOpts(client.WithHost(daemon.URL), client.WithVersion("1.47"))
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	cfg := environment.NewConfiguration(environment.Settings{
		Allocations: environment.Allocations{DefaultMapping: &environment.DefaultAllocationMapping{}},
	}, []string{"STARTUP=game --old-flag"})
	cfg.SetEnvironmentVariables([]string{"STARTUP=game --new-flag"})
	e := &Environment{Id: "test-server", client: cli, Configuration: cfg,
		meta: &Metadata{Image: "~local-image"}, emitter: events.NewBus()}
	if err := e.OnBeforeStart(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(created.Env, []string{"STARTUP=game --new-flag"}) {
		t.Fatalf("replacement startup: %v", created.Env)
	}
	want := []string{"DELETE /v1.47/containers/test-server", "GET /v1.47/containers/test-server/json", "POST /v1.47/containers/create"}
	if !reflect.DeepEqual(requests, want) {
		t.Fatalf("Docker requests: %v", requests)
	}
}
