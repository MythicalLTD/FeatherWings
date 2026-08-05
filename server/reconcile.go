package server

import (
	"context"
	"sync"
	"time"

	"emperror.dev/errors"
	"github.com/apex/log"
	"github.com/docker/docker/client"

	"github.com/mythicalltd/featherwings/config"
	"github.com/mythicalltd/featherwings/environment"
	"github.com/mythicalltd/featherwings/environment/docker"
)

// Runtime health statuses exposed via the server API.
const (
	RuntimeStatusOK            = "ok"
	RuntimeStatusUnresponsive  = "unresponsive"
	RuntimeStatusDesynced      = "desynced"
	RuntimeStatusRecovered     = "recovered"
)

// RuntimeInfo is included in server API responses so the Panel can surface
// Docker/containerd desynchronization instead of leaving admins guessing.
type RuntimeInfo struct {
	Healthy   bool   `json:"healthy"`
	Status    string `json:"status"`
	Message   string `json:"message,omitempty"`
	CheckedAt int64  `json:"checked_at,omitempty"`
}

type runtimeTracker struct {
	mu               sync.RWMutex
	status           string
	message          string
	checkedAt        time.Time
	stateEnteredAt   time.Time
	failCount        int
	lastRecoveredAt  time.Time
}

func (s *Server) initRuntimeTracker() {
	s.runtimeOnce.Do(func() {
		s.runtime = &runtimeTracker{
			status:         RuntimeStatusOK,
			stateEnteredAt: time.Now(),
		}
	})
}

// Runtime returns the latest runtime health snapshot for this server.
func (s *Server) Runtime() RuntimeInfo {
	s.initRuntimeTracker()
	s.runtime.mu.RLock()
	defer s.runtime.mu.RUnlock()
	info := RuntimeInfo{
		Healthy: s.runtime.status == RuntimeStatusOK || s.runtime.status == RuntimeStatusRecovered,
		Status:  s.runtime.status,
		Message: s.runtime.message,
	}
	if !s.runtime.checkedAt.IsZero() {
		info.CheckedAt = s.runtime.checkedAt.Unix()
	}
	return info
}

func (s *Server) noteStateEntered() {
	s.initRuntimeTracker()
	s.runtime.mu.Lock()
	s.runtime.stateEnteredAt = time.Now()
	s.runtime.mu.Unlock()
}

func (s *Server) stateEnteredAt() time.Time {
	s.initRuntimeTracker()
	s.runtime.mu.RLock()
	defer s.runtime.mu.RUnlock()
	return s.runtime.stateEnteredAt
}

func (s *Server) setRuntimeStatus(status, message string) {
	s.initRuntimeTracker()
	s.runtime.mu.Lock()
	s.runtime.status = status
	s.runtime.message = message
	s.runtime.checkedAt = time.Now()
	if status == RuntimeStatusOK || status == RuntimeStatusRecovered {
		s.runtime.failCount = 0
	}
	s.runtime.mu.Unlock()
}

func (s *Server) bumpRuntimeFailure() int {
	s.initRuntimeTracker()
	s.runtime.mu.Lock()
	defer s.runtime.mu.Unlock()
	s.runtime.failCount++
	s.runtime.checkedAt = time.Now()
	return s.runtime.failCount
}

func (s *Server) resetRuntimeFailures() {
	s.initRuntimeTracker()
	s.runtime.mu.Lock()
	s.runtime.failCount = 0
	s.runtime.mu.Unlock()
}

// ReconcileResult describes what a reconciliation pass decided for a server.
type ReconcileResult struct {
	Action  string `json:"action"`
	Status  string `json:"status"`
	Message string `json:"message,omitempty"`
}

// ReconcileRuntime compares Wings' tracked process state against Docker and
// recovers servers stuck due to hung or desynchronized runtimes.
func (s *Server) ReconcileRuntime(ctx context.Context) (ReconcileResult, error) {
	s.initRuntimeTracker()

	if s.IsInstalling() || s.IsTransferring() || s.IsRestoring() {
		return ReconcileResult{Action: "skipped", Status: RuntimeStatusOK, Message: "server is busy with install/transfer/restore"}, nil
	}

	cfg := config.Get().Docker.RuntimeReconciliation
	timeout := time.Duration(cfg.InspectTimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	threshold := cfg.UnresponsiveThreshold
	if threshold <= 0 {
		threshold = 2
	}
	stuckStopping := time.Duration(cfg.StuckStoppingSeconds) * time.Second
	if stuckStopping <= 0 {
		stuckStopping = 12 * time.Minute
	}
	stuckStarting := time.Duration(cfg.StuckStartingSeconds) * time.Second
	if stuckStarting <= 0 {
		stuckStarting = 5 * time.Minute
	}

	state := s.Environment.State()
	inspectCtx, cancel := context.WithTimeout(ctx, timeout)
	running, err := s.Environment.IsRunning(inspectCtx)
	cancel()

	if err != nil && !client.IsErrNotFound(err) {
		fails := s.bumpRuntimeFailure()
		s.Log().WithField("error", err).WithField("failures", fails).
			Warn("runtime reconcile: docker inspect failed or timed out")

		if fails < threshold {
			s.setRuntimeStatus(RuntimeStatusUnresponsive, err.Error())
			return ReconcileResult{Action: "watch", Status: RuntimeStatusUnresponsive, Message: err.Error()}, nil
		}

		msg := "docker runtime unresponsive; forcing recovery"
		s.setRuntimeStatus(RuntimeStatusUnresponsive, msg)
		if rerr := s.recoverRuntime(ctx, environment.ProcessErrorState, msg); rerr != nil {
			return ReconcileResult{Action: "recover_failed", Status: RuntimeStatusUnresponsive, Message: rerr.Error()}, rerr
		}
		return ReconcileResult{Action: "recovered", Status: RuntimeStatusUnresponsive, Message: msg}, nil
	}

	s.resetRuntimeFailures()

	// Container missing while Wings thinks it is online.
	if client.IsErrNotFound(err) || (err == nil && !running) {
		if state == environment.ProcessRunningState || state == environment.ProcessStartingState {
			msg := "tracked as online but container is not running"
			s.setRuntimeStatus(RuntimeStatusDesynced, msg)
			// Transition via stopping so crash detection does not auto-restart into a broken runtime.
			s.Environment.SetState(environment.ProcessStoppingState)
			s.Environment.SetState(environment.ProcessOfflineState)
			s.setRuntimeStatus(RuntimeStatusRecovered, msg)
			return ReconcileResult{Action: "forced_offline", Status: RuntimeStatusDesynced, Message: msg}, nil
		}
		if state == environment.ProcessStoppingState && time.Since(s.stateEnteredAt()) >= stuckStopping {
			msg := "stuck in stopping with no running container"
			s.Environment.SetState(environment.ProcessOfflineState)
			s.setRuntimeStatus(RuntimeStatusRecovered, msg)
			s.powerLock.Release()
			return ReconcileResult{Action: "forced_offline", Status: RuntimeStatusRecovered, Message: msg}, nil
		}
		if state == environment.ProcessErrorState {
			return ReconcileResult{Action: "noop", Status: RuntimeStatusOK}, nil
		}
		s.setRuntimeStatus(RuntimeStatusOK, "")
		return ReconcileResult{Action: "noop", Status: RuntimeStatusOK}, nil
	}

	// Docker reports running — check for containerd desync markers when possible.
	if desynced, dmsg := s.detectContainerDesync(ctx, timeout); desynced {
		s.setRuntimeStatus(RuntimeStatusDesynced, dmsg)
		if rerr := s.recoverRuntime(ctx, environment.ProcessErrorState, dmsg); rerr != nil {
			return ReconcileResult{Action: "recover_failed", Status: RuntimeStatusDesynced, Message: rerr.Error()}, rerr
		}
		return ReconcileResult{Action: "recovered", Status: RuntimeStatusDesynced, Message: dmsg}, nil
	}

	entered := s.stateEnteredAt()
	switch state {
	case environment.ProcessStoppingState:
		if time.Since(entered) >= stuckStopping {
			msg := "stuck in stopping longer than threshold; terminating"
			s.setRuntimeStatus(RuntimeStatusUnresponsive, msg)
			if rerr := s.recoverRuntime(ctx, environment.ProcessErrorState, msg); rerr != nil {
				return ReconcileResult{Action: "recover_failed", Status: RuntimeStatusUnresponsive, Message: rerr.Error()}, rerr
			}
			return ReconcileResult{Action: "recovered", Status: RuntimeStatusUnresponsive, Message: msg}, nil
		}
	case environment.ProcessStartingState:
		// Only escalate long starts when a power action is also wedged (lock held past threshold).
		if s.ExecutingPowerAction() && time.Since(entered) >= stuckStarting {
			msg := "stuck in starting with held power lock; docker still reports running"
			s.setRuntimeStatus(RuntimeStatusUnresponsive, msg)
			if rerr := s.recoverRuntime(ctx, environment.ProcessErrorState, msg); rerr != nil {
				return ReconcileResult{Action: "recover_failed", Status: RuntimeStatusUnresponsive, Message: rerr.Error()}, rerr
			}
			return ReconcileResult{Action: "recovered", Status: RuntimeStatusUnresponsive, Message: msg}, nil
		}
	case environment.ProcessOfflineState, environment.ProcessErrorState:
		// Orphan container while Wings says offline — re-attach only when not in error.
		if state == environment.ProcessOfflineState && !s.ExecutingPowerAction() {
			s.Log().Warn("runtime reconcile: docker reports running while wings state is offline; re-attaching")
			actx, acancel := context.WithTimeout(ctx, 15*time.Second)
			aerr := s.Environment.Attach(actx)
			acancel()
			if aerr != nil {
				s.Log().WithField("error", aerr).Warn("runtime reconcile: failed to re-attach orphan container; leaving offline")
			} else {
				s.Environment.SetState(environment.ProcessRunningState)
				s.setRuntimeStatus(RuntimeStatusOK, "re-attached orphan container")
				return ReconcileResult{Action: "reattached", Status: RuntimeStatusOK, Message: "re-attached orphan container"}, nil
			}
		}
	}

	s.setRuntimeStatus(RuntimeStatusOK, "")
	return ReconcileResult{Action: "noop", Status: RuntimeStatusOK}, nil
}

// ForceReconcile attempts an immediate recovery of stale Docker runtime state
// for administrators (POST /api/servers/:server/reconcile).
func (s *Server) ForceReconcile(ctx context.Context) (ReconcileResult, error) {
	if s.IsInstalling() || s.IsTransferring() || s.IsRestoring() {
		if s.IsRestoring() {
			return ReconcileResult{}, ErrServerIsRestoring
		} else if s.IsTransferring() {
			return ReconcileResult{}, ErrServerIsTransferring
		}
		return ReconcileResult{}, ErrServerIsInstalling
	}

	s.PublishConsoleOutputFromDaemon("Force runtime reconcile requested — probing Docker and recovering stale state...")
	s.resetRuntimeFailures()

	// Always attempt a hard recovery path: terminate/remove with timeouts, clear lock, offline.
	msg := "administrator force-reconcile"
	if err := s.recoverRuntime(ctx, environment.ProcessOfflineState, msg); err != nil {
		s.PublishConsoleOutputFromDaemon("Force reconcile completed with errors; server marked offline. Check Wings logs.")
		s.setRuntimeStatus(RuntimeStatusRecovered, err.Error())
		return ReconcileResult{Action: "force_recovered", Status: RuntimeStatusRecovered, Message: err.Error()}, nil
	}
	s.PublishConsoleOutputFromDaemon("Force reconcile complete — server is offline and ready to start.")
	s.setRuntimeStatus(RuntimeStatusRecovered, msg)
	return ReconcileResult{Action: "force_recovered", Status: RuntimeStatusRecovered, Message: msg}, nil
}

func (s *Server) recoverRuntime(ctx context.Context, finalState, reason string) error {
	s.Log().WithFields(log.Fields{
		"reason":      reason,
		"final_state": finalState,
	}).Warn("recovering server from docker runtime failure")
	s.PublishConsoleOutputFromDaemon("Runtime error detected: " + reason)

	// Avoid crash auto-restart: enter stopping first when coming from an online state.
	cur := s.Environment.State()
	if cur == environment.ProcessRunningState || cur == environment.ProcessStartingState || cur == environment.ProcessStoppingState {
		s.Environment.SetState(environment.ProcessStoppingState)
	}

	termCtx, cancel := context.WithTimeout(ctx, docker.DefaultDockerOpTimeout*2)
	terr := s.Environment.Terminate(termCtx, "SIGKILL")
	cancel()
	if terr != nil {
		s.Log().WithField("error", terr).Warn("terminate during runtime recovery failed; attempting destroy")
	}

	// Best-effort container removal when terminate cannot clear a ghost container.
	if derr := s.Environment.Destroy(); derr != nil {
		s.Log().WithField("error", derr).Warn("destroy during runtime recovery failed")
	}

	// Clear any hijacked stream and release a wedged power lock so admins can act again.
	if de, ok := s.Environment.(*docker.Environment); ok {
		de.SetStream(nil)
	}
	s.powerLock.Release()

	if finalState == environment.ProcessErrorState {
		s.Environment.SetState(environment.ProcessErrorState)
	} else {
		s.Environment.SetState(environment.ProcessOfflineState)
	}

	s.initRuntimeTracker()
	s.runtime.mu.Lock()
	s.runtime.lastRecoveredAt = time.Now()
	s.runtime.failCount = 0
	s.runtime.mu.Unlock()

	return errors.WithStackIf(terr)
}

// detectContainerDesync looks for inspect results that indicate Docker still
// thinks a container is Running while the runtime task is gone (Pid 0).
func (s *Server) detectContainerDesync(ctx context.Context, timeout time.Duration) (bool, string) {
	de, ok := s.Environment.(*docker.Environment)
	if !ok {
		return false, ""
	}
	inspectCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	c, err := de.ContainerInspect(inspectCtx)
	if err != nil {
		return false, ""
	}
	if c.State != nil && c.State.Running && c.State.Pid == 0 {
		return true, "docker reports container running but process pid is 0 (containerd desync)"
	}
	if c.State != nil && c.State.Dead {
		return true, "docker reports container in dead state while tracked as active"
	}
	return false, ""
}
