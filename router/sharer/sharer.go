package sharer

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"time"

	"emperror.dev/errors"
	"github.com/goccy/go-json"
	"github.com/google/uuid"

	"github.com/mythicalltd/featherwings/internal/tempfiles"
	"github.com/mythicalltd/featherwings/server"
)

var instance = &tracker{
	jobs:        make(map[string]*Job),
	serverCache: make(map[string][]string),
}

type tracker struct {
	mu          sync.Mutex
	jobs        map[string]*Job
	serverCache map[string][]string
}

// Request describes a file share upload.
type Request struct {
	File      string
	TTLDays   int
	Password  string
	DeleteKey string
	Token     string
}

// Job tracks a temp-files share upload.
type Job struct {
	Identifier string
	File       string
	Status     string
	Progress   float64
	Error      string
	Result     *tempfiles.Result

	mu         sync.RWMutex
	server     *server.Server
	req        Request
	cancelFunc context.CancelFunc
}

const (
	StatusQueued    = "queued"
	StatusUploading = "uploading"
	StatusCompleted = "completed"
	StatusFailed    = "failed"
	StatusCancelled = "cancelled"
)

// New creates and tracks a share job for the server.
func New(s *server.Server, r Request) *Job {
	j := &Job{
		Identifier: uuid.Must(uuid.NewRandom()).String(),
		File:       r.File,
		Status:     StatusQueued,
		server:     s,
		req:        r,
	}
	instance.track(j)
	return j
}

// ByServer returns active share jobs for a server.
func ByServer(sid string) []*Job {
	instance.mu.Lock()
	defer instance.mu.Unlock()
	var out []*Job
	if ids, ok := instance.serverCache[sid]; ok {
		for _, id := range ids {
			if j, ok := instance.jobs[id]; ok {
				out = append(out, j)
			}
		}
	}
	return out
}

// ByID returns a job by identifier.
func ByID(id string) *Job {
	instance.mu.Lock()
	defer instance.mu.Unlock()
	return instance.jobs[id]
}

func (t *tracker) track(j *Job) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.jobs[j.Identifier] = j
	sid := j.server.ID()
	t.serverCache[sid] = append(t.serverCache[sid], j.Identifier)
}

func (t *tracker) untrack(j *Job) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.jobs, j.Identifier)
	sid := j.server.ID()
	ids := t.serverCache[sid]
	filtered := ids[:0]
	for _, id := range ids {
		if id != j.Identifier {
			filtered = append(filtered, id)
		}
	}
	if len(filtered) == 0 {
		delete(t.serverCache, sid)
	} else {
		t.serverCache[sid] = filtered
	}
}

// BelongsTo reports whether the job belongs to the given server.
func (j *Job) BelongsTo(s *server.Server) bool {
	return j.server != nil && s != nil && j.server.ID() == s.ID()
}

// Cancel cancels an in-progress share.
func (j *Job) Cancel() {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.cancelFunc != nil {
		j.cancelFunc()
	}
	if j.Status == StatusQueued || j.Status == StatusUploading {
		j.Status = StatusCancelled
	}
}

// MarshalJSON exposes a stable job snapshot.
func (j *Job) MarshalJSON() ([]byte, error) {
	j.mu.RLock()
	defer j.mu.RUnlock()
	return json.Marshal(struct {
		Identifier string            `json:"identifier"`
		File       string            `json:"file"`
		Status     string            `json:"status"`
		Progress   float64           `json:"progress"`
		Error      string            `json:"error,omitempty"`
		Result     *tempfiles.Result `json:"result,omitempty"`
	}{
		Identifier: j.Identifier,
		File:       j.File,
		Status:     j.Status,
		Progress:   j.Progress,
		Error:      j.Error,
		Result:     j.Result,
	})
}

// Execute uploads the server file as a temp upload.
func (j *Job) Execute() error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Hour*12)
	j.mu.Lock()
	j.cancelFunc = cancel
	j.Status = StatusUploading
	j.Progress = 0
	j.mu.Unlock()
	defer func() {
		cancel()
		j.mu.RLock()
		status := j.Status
		j.mu.RUnlock()
		if status == StatusCancelled {
			instance.untrack(j)
			return
		}
		time.AfterFunc(time.Minute*10, func() {
			instance.untrack(j)
		})
	}()

	path := j.req.File
	if err := j.server.Filesystem().IsIgnored(path); err != nil {
		return j.fail(err)
	}

	f, st, err := j.server.Filesystem().File(path)
	if err != nil {
		return j.fail(err)
	}
	defer f.Close()

	if st.IsDir() {
		return j.fail(errors.New("cannot share a directory"))
	}
	if st.Mode()&os.ModeNamedPipe != 0 {
		return j.fail(errors.New("cannot share files of this type"))
	}

	client := tempfiles.New(j.req.Token)
	filename := filepath.Base(path)
	result, err := client.Upload(ctx, filename, st.Size(), j.req.TTLDays, j.req.Password, j.req.DeleteKey, f)
	if err != nil {
		if ctx.Err() != nil {
			j.mu.Lock()
			if j.Status != StatusCancelled {
				j.Status = StatusCancelled
				j.Error = "share cancelled"
			}
			j.mu.Unlock()
			return ctx.Err()
		}
		return j.fail(err)
	}

	j.mu.Lock()
	j.Status = StatusCompleted
	j.Progress = 100
	j.Result = result
	j.mu.Unlock()
	return nil
}

// Snapshot returns a copy of the current job state for API responses.
func (j *Job) Snapshot() (status string, progress float64, errMsg string, result *tempfiles.Result) {
	j.mu.RLock()
	defer j.mu.RUnlock()
	return j.Status, j.Progress, j.Error, j.Result
}

func (j *Job) fail(err error) error {
	j.mu.Lock()
	j.Status = StatusFailed
	j.Error = err.Error()
	j.mu.Unlock()
	return err
}
