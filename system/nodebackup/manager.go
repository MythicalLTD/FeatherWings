package nodebackup

import (
	"context"
	"sync"
	"time"

	"emperror.dev/errors"
	"github.com/apex/log"

	"github.com/mythicalltd/featherwings/server"
)

// ServerStopper stops servers before a full/volumes node backup.
type ServerStopper interface {
	All() []*server.Server
}

// JobManager tracks in-flight and recent node backup jobs.
type JobManager struct {
	mu       sync.Mutex
	active   string
	stopper  ServerStopper
	cancelFn context.CancelFunc
}

var defaultManager = &JobManager{}

// Default returns the process-wide job manager.
func Default() *JobManager {
	return defaultManager
}

// SetStopper attaches the server manager used to quiesce instances.
func (m *JobManager) SetStopper(s ServerStopper) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stopper = s
}

// ActiveUUID returns the currently running backup UUID, if any.
func (m *JobManager) ActiveUUID() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.active
}

// StartCreate begins an async node backup. Returns the pending Info.
func (m *JobManager) StartCreate(ctx context.Context, mode Mode, migration bool, quiesce bool) (*Info, error) {
	m.mu.Lock()
	if m.active != "" {
		m.mu.Unlock()
		return nil, errors.New("a node backup is already in progress")
	}
	info, err := NewPending(mode, migration)
	if err != nil {
		m.mu.Unlock()
		return nil, err
	}
	jobCtx, cancel := context.WithCancel(context.Background())
	m.active = info.UUID
	m.cancelFn = cancel
	stopper := m.stopper
	m.mu.Unlock()

	go func() {
		defer func() {
			m.mu.Lock()
			if m.active == info.UUID {
				m.active = ""
				m.cancelFn = nil
			}
			m.mu.Unlock()
		}()

		if quiesce && (mode == ModeFull || mode == ModeVolumes) && stopper != nil {
			if err := stopAllServers(jobCtx, stopper); err != nil {
				log.WithError(err).Warn("nodebackup: failed to stop all servers before backup")
			}
		}

		if err := Create(jobCtx, info); err != nil {
			log.WithField("backup", info.UUID).WithError(err).Error("node backup failed")
			return
		}
		log.WithField("backup", info.UUID).WithField("bytes", info.Bytes).Info("node backup completed")
	}()

	return info, nil
}

// Cancel aborts the active job if any.
func (m *JobManager) Cancel() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cancelFn != nil {
		m.cancelFn()
	}
}

func stopAllServers(ctx context.Context, stopper ServerStopper) error {
	var first error
	for _, s := range stopper.All() {
		if s == nil {
			continue
		}
		if err := s.Environment.WaitForStop(ctx, 2*time.Minute, true); err != nil {
			log.WithField("server", s.ID()).WithError(err).Warn("nodebackup: stop server")
			if first == nil {
				first = err
			}
		}
	}
	return first
}
