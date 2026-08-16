package operations

import (
	"context"
	"encoding/json"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
)

const (
	ProgressEvent  = "operation progress"
	CompletedEvent = "operation completed"
	ErrorEvent     = "operation error"

	progressInterval = time.Second
	removalDelay     = 5 * time.Second
)

// Broadcast publishes a websocket-compatible event and its string arguments.
type Broadcast func(event string, args ...string)

// Operation describes a long-running filesystem operation.
type Operation struct {
	Type            string         `json:"type"`
	Path            string         `json:"path,omitempty"`
	DestinationPath string         `json:"destination_path,omitempty"`
	StartTime       time.Time      `json:"start_time"`
	BytesProcessed  *atomic.Uint64 `json:"-"`
	BytesTotal      *atomic.Uint64 `json:"-"`
	FilesProcessed  *atomic.Uint64 `json:"-"`
}

// MarshalJSON snapshots atomic counters as ordinary JSON numbers.
func (o Operation) MarshalJSON() ([]byte, error) {
	type payload struct {
		Type            string    `json:"type"`
		Path            string    `json:"path,omitempty"`
		DestinationPath string    `json:"destination_path,omitempty"`
		StartTime       time.Time `json:"start_time"`
		BytesProcessed  uint64    `json:"bytes_processed"`
		BytesTotal      uint64    `json:"bytes_total"`
		FilesProcessed  uint64    `json:"files_processed"`
	}

	return json.Marshal(payload{
		Type:            o.Type,
		Path:            o.Path,
		DestinationPath: o.DestinationPath,
		StartTime:       o.StartTime,
		BytesProcessed:  load(o.BytesProcessed),
		BytesTotal:      load(o.BytesTotal),
		FilesProcessed:  load(o.FilesProcessed),
	})
}

type entry struct {
	operation Operation
	ctx       context.Context
	cancel    context.CancelFunc
	finish    sync.Once
}

// Manager tracks asynchronous operations for one server.
type Manager struct {
	ctx       context.Context
	broadcast Broadcast

	mu         sync.RWMutex
	operations map[uuid.UUID]*entry
}

func NewManager(ctx context.Context, broadcast Broadcast) *Manager {
	if ctx == nil {
		ctx = context.Background()
	}
	if broadcast == nil {
		broadcast = func(string, ...string) {}
	}
	return &Manager{
		ctx:        ctx,
		broadcast:  broadcast,
		operations: make(map[uuid.UUID]*entry),
	}
}

// Add registers an operation and starts its heartbeat progress publisher.
func (m *Manager) Add(op Operation) (uuid.UUID, context.CancelFunc) {
	initialize(&op)
	ctx, cancel := context.WithCancel(m.ctx)
	id := uuid.New()
	e := &entry{operation: op, ctx: ctx, cancel: cancel}

	m.mu.Lock()
	m.operations[id] = e
	m.mu.Unlock()

	m.publishProgress(id, op)
	go m.tick(ctx, id, op)
	return id, cancel
}

// Context returns the cancelable context associated with an operation.
func (m *Manager) Context(id uuid.UUID) (context.Context, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	e, ok := m.operations[id]
	if !ok {
		return nil, false
	}
	return e.ctx, true
}

// Abort cancels an active operation.
func (m *Manager) Abort(id uuid.UUID) bool {
	m.mu.RLock()
	e, ok := m.operations[id]
	m.mu.RUnlock()
	if ok {
		e.cancel()
	}
	return ok
}

func (m *Manager) Get(id uuid.UUID) (Operation, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	e, ok := m.operations[id]
	if !ok {
		return Operation{}, false
	}
	return e.operation, true
}

func (m *Manager) List() map[uuid.UUID]Operation {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make(map[uuid.UUID]Operation, len(m.operations))
	for id, e := range m.operations {
		out[id] = e.operation
	}
	return out
}

// Complete emits final progress and completion, then removes the operation.
func (m *Manager) Complete(id uuid.UUID) bool {
	return m.finish(id, "")
}

// Fail emits an operation error, then removes the operation.
func (m *Manager) Fail(id uuid.UUID, message string) bool {
	return m.finish(id, message)
}

func (m *Manager) finish(id uuid.UUID, message string) bool {
	m.mu.RLock()
	e, ok := m.operations[id]
	m.mu.RUnlock()
	if !ok {
		return false
	}

	finished := false
	e.finish.Do(func() {
		finished = true
		e.cancel()
		if message == "" {
			m.publishProgress(id, e.operation)
			m.broadcast(CompletedEvent, id.String())
		} else {
			m.broadcast(ErrorEvent, id.String(), message)
		}
		time.AfterFunc(removalDelay, func() {
			m.mu.Lock()
			delete(m.operations, id)
			m.mu.Unlock()
		})
	})
	return finished
}

func (m *Manager) tick(ctx context.Context, id uuid.UUID, op Operation) {
	ticker := time.NewTicker(progressInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.publishProgress(id, op)
		}
	}
}

func (m *Manager) publishProgress(id uuid.UUID, op Operation) {
	data, err := json.Marshal(op)
	if err == nil {
		m.broadcast(ProgressEvent, id.String(), string(data))
	}
}

func initialize(op *Operation) {
	if op.StartTime.IsZero() {
		op.StartTime = time.Now().UTC()
	}
	if op.BytesProcessed == nil {
		op.BytesProcessed = &atomic.Uint64{}
	}
	if op.BytesTotal == nil {
		op.BytesTotal = &atomic.Uint64{}
	}
	if op.FilesProcessed == nil {
		op.FilesProcessed = &atomic.Uint64{}
	}
}

func load(counter *atomic.Uint64) uint64 {
	if counter == nil {
		return 0
	}
	return counter.Load()
}
