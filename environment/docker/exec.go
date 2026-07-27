package docker

import (
	"bytes"
	"context"
	"io"
	"strings"
	"time"

	"emperror.dev/errors"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/pkg/stdcopy"
)

const (
	defaultExecTimeout = 30 * time.Second
	maxExecTimeout     = 120 * time.Second
	maxExecOutputBytes = 64 * 1024
)

// ExecResult is the outcome of a one-shot docker exec inside a running container.
type ExecResult struct {
	ExitCode   int    `json:"exit_code"`
	Stdout     string `json:"stdout"`
	Stderr     string `json:"stderr"`
	DurationMs int64  `json:"duration_ms"`
	TimedOut   bool   `json:"timed_out"`
}

// Exec runs a shell command inside the container via Docker exec (not console stdin).
// The command is executed as ["/bin/sh", "-c", command].
func (e *Environment) Exec(ctx context.Context, command string, timeout time.Duration) (*ExecResult, error) {
	command = strings.TrimSpace(command)
	if command == "" {
		return nil, errors.New("environment/docker: exec command cannot be blank")
	}

	if timeout <= 0 {
		timeout = defaultExecTimeout
	}
	if timeout > maxExecTimeout {
		timeout = maxExecTimeout
	}

	running, err := e.IsRunning(ctx)
	if err != nil {
		return nil, errors.WrapIf(err, "environment/docker: failed to determine container state for exec")
	}
	if !running {
		return nil, errors.New("environment/docker: cannot exec into a stopped container")
	}

	execCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	created, err := e.client.ContainerExecCreate(execCtx, e.Id, container.ExecOptions{
		AttachStdout: true,
		AttachStderr: true,
		Cmd:          []string{"/bin/sh", "-c", command},
	})
	if err != nil {
		return nil, errors.WrapIf(err, "environment/docker: failed to create exec instance")
	}

	start := time.Now()
	hijacked, err := e.client.ContainerExecAttach(execCtx, created.ID, container.ExecAttachOptions{})
	if err != nil {
		return nil, errors.WrapIf(err, "environment/docker: failed to attach to exec instance")
	}
	defer hijacked.Close()

	var stdoutBuf, stderrBuf bytes.Buffer
	limitedStdout := &limitedWriter{buf: &stdoutBuf, limit: maxExecOutputBytes}
	limitedStderr := &limitedWriter{buf: &stderrBuf, limit: maxExecOutputBytes}

	copyErr := make(chan error, 1)
	go func() {
		_, err := stdcopy.StdCopy(limitedStdout, limitedStderr, hijacked.Reader)
		copyErr <- err
	}()

	select {
	case <-execCtx.Done():
		hijacked.Close()
		<-copyErr
		return &ExecResult{
			ExitCode:   -1,
			Stdout:     stdoutBuf.String(),
			Stderr:     stderrBuf.String(),
			DurationMs: time.Since(start).Milliseconds(),
			TimedOut:   true,
		}, nil
	case err := <-copyErr:
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, errors.WrapIf(err, "environment/docker: failed to read exec output")
		}
	}

	inspect, err := e.client.ContainerExecInspect(context.Background(), created.ID)
	if err != nil {
		return nil, errors.WrapIf(err, "environment/docker: failed to inspect exec instance")
	}

	return &ExecResult{
		ExitCode:   inspect.ExitCode,
		Stdout:     stdoutBuf.String(),
		Stderr:     stderrBuf.String(),
		DurationMs: time.Since(start).Milliseconds(),
		TimedOut:   false,
	}, nil
}

type limitedWriter struct {
	buf   *bytes.Buffer
	limit int
	n     int
}

func (w *limitedWriter) Write(p []byte) (int, error) {
	if w.n >= w.limit {
		return len(p), nil
	}
	remaining := w.limit - w.n
	if len(p) > remaining {
		_, _ = w.buf.Write(p[:remaining])
		w.n = w.limit
		return len(p), nil
	}
	n, err := w.buf.Write(p)
	w.n += n
	return n, err
}
