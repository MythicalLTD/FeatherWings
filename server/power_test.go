package server

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	. "github.com/franela/goblin"

	"github.com/mythicalltd/featherwings/environment"
	"github.com/mythicalltd/featherwings/remote"
	"github.com/mythicalltd/featherwings/system"
)

func TestPower(t *testing.T) {
	g := Goblin(t)

	g.Describe("Server#ExecutingPowerAction", func() {
		g.It("should return based on locker status", func() {
			s := &Server{powerLock: system.NewLocker()}

			g.Assert(s.ExecutingPowerAction()).IsFalse()
			s.powerLock.Acquire()
			g.Assert(s.ExecutingPowerAction()).IsTrue()
		})
	})
}

type restartEnvironment struct {
	environment.ProcessEnvironment
	calls      *[]string
	stopErr    error
	destroyErr error
}

func (e *restartEnvironment) WaitForStop(context.Context, time.Duration, bool) error {
	*e.calls = append(*e.calls, "stop")
	return e.stopErr
}

func (e *restartEnvironment) Destroy() error {
	*e.calls = append(*e.calls, "destroy")
	return e.destroyErr
}

type restartPanel struct {
	remote.Client
	calls *[]string
	err   error
}

func (p *restartPanel) GetServerConfiguration(context.Context, string) (remote.ServerConfigurationResponse, error) {
	*p.calls = append(*p.calls, "sync")
	return remote.ServerConfigurationResponse{}, p.err
}

func TestRestartDestroysBeforePanelSync(t *testing.T) {
	stopErr := errors.New("container still running")
	destroyErr := errors.New("Docker removal failed")
	syncErr := errors.New("panel unavailable")
	for _, tt := range []struct {
		name       string
		stopErr    error
		destroyErr error
		wantErr    error
		wantCalls  []string
	}{
		{"graceful stop", nil, nil, syncErr, []string{"stop", "destroy", "sync"}},
		{"failed stop", stopErr, nil, syncErr, []string{"stop", "destroy", "sync"}},
		{"failed removal", nil, destroyErr, destroyErr, []string{"stop", "destroy"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var calls []string
			s, err := New(&restartPanel{calls: &calls, err: syncErr})
			if err != nil {
				t.Fatal(err)
			}
			s.Environment = &restartEnvironment{calls: &calls, stopErr: tt.stopErr, destroyErr: tt.destroyErr}
			if err := s.HandlePowerAction(PowerActionRestart); !errors.Is(err, tt.wantErr) {
				t.Fatalf("restart error: %v, want %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(calls, tt.wantCalls) {
				t.Fatalf("restart calls: %v, want %v", calls, tt.wantCalls)
			}
			if s.ExecutingPowerAction() {
				t.Fatal("restart did not release the power lock")
			}
		})
	}
}
