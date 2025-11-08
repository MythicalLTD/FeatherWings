package router

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/mythicalltd/featherwings/config"
	"github.com/mythicalltd/featherwings/router/middleware"
)

const (
	defaultShellExecutable   = "/bin/bash"
	defaultCommandTimeoutSec = 60
)

type hostCommandRequest struct {
	Command          string            `json:"command" binding:"required"`
	TimeoutSeconds   int               `json:"timeout_seconds"`
	Shell            string            `json:"shell"`
	WorkingDirectory string            `json:"working_directory"`
	Environment      map[string]string `json:"environment"`
}

type hostCommandResponse struct {
	ExitCode   int    `json:"exit_code"`
	Stdout     string `json:"stdout"`
	Stderr     string `json:"stderr"`
	TimedOut   bool   `json:"timed_out"`
	DurationMs int64  `json:"duration_ms"`
}

func resolveShellExecutable(cfg config.HostTerminalConfiguration, override string) ([]string, error) {
	spec := strings.TrimSpace(override)
	if spec == "" {
		spec = strings.TrimSpace(cfg.Shell)
	}
	if spec == "" {
		spec = defaultShellExecutable
	}

	parts := strings.Fields(spec)
	if len(parts) == 0 {
		return nil, errors.New("invalid shell specification")
	}

	execPath, err := exec.LookPath(parts[0])
	if err != nil {
		fallback, fbErr := exec.LookPath("/bin/sh")
		if fbErr != nil {
			return nil, fmt.Errorf("unable to resolve shell executable %q or fallback /bin/sh", parts[0])
		}
		parts[0] = fallback
	} else {
		parts[0] = execPath
	}

	return parts, nil
}

func buildEnvironment(overrides map[string]string) []string {
	env := os.Environ()
	if len(overrides) == 0 {
		return env
	}
	for key, value := range overrides {
		if key == "" {
			continue
		}
		entry := fmt.Sprintf("%s=%s", key, value)
		replaced := false
		for i, existing := range env {
			if strings.HasPrefix(existing, key+"=") {
				env[i] = entry
				replaced = true
				break
			}
		}
		if !replaced {
			env = append(env, entry)
		}
	}
	return env
}

func isCommandDisabled(command string, disabled []string) bool {
	if len(disabled) == 0 {
		return false
	}

	trimmed := strings.TrimSpace(command)
	if trimmed == "" {
		return false
	}

	lowerCommand := strings.ToLower(trimmed)
	fields := strings.Fields(trimmed)
	var executable string
	if len(fields) > 0 {
		executable = strings.ToLower(fields[0])
	}

	for _, entry := range disabled {
		match := strings.ToLower(strings.TrimSpace(entry))
		if match == "" {
			continue
		}
		if match == lowerCommand || (executable != "" && match == executable) {
			return true
		}
	}

	return false
}

// postSystemHostCommand executes a command on the host system synchronously and returns the output.
// @Summary Execute host command
// @Description Runs a command on the host operating system using the configured shell and returns stdout/stderr.
// @Tags System
// @Accept json
// @Produce json
// @Param request body hostCommandRequest true "Host command request"
// @Success 200 {object} hostCommandResponse
// @Success 504 {object} hostCommandResponse "Command timed out"
// @Failure 400 {object} ErrorResponse
// @Failure 403 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Security NodeToken
// @Router /api/system/terminal/exec [post]
func postSystemHostCommand(c *gin.Context) {
	cfg := config.Get()
	if !cfg.System.HostTerminal.Enabled {
		c.AbortWithStatusJSON(http.StatusForbidden, ErrorResponse{Error: "host command execution is disabled"})
		return
	}

	var req hostCommandRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, ErrorResponse{Error: "invalid request payload"})
		return
	}

	req.Command = strings.TrimSpace(req.Command)
	if req.Command == "" {
		c.AbortWithStatusJSON(http.StatusBadRequest, ErrorResponse{Error: "command cannot be blank"})
		return
	}

	if isCommandDisabled(req.Command, cfg.System.HostTerminal.DisabledCommands) {
		c.AbortWithStatusJSON(http.StatusForbidden, ErrorResponse{Error: "command execution is disabled"})
		return
	}

	shell, err := resolveShellExecutable(cfg.System.HostTerminal, req.Shell)
	if err != nil {
		middleware.CaptureAndAbort(c, err)
		return
	}

	timeout := time.Duration(req.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = time.Duration(defaultCommandTimeoutSec) * time.Second
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), timeout)
	defer cancel()

	arguments := append(shell[1:], "-c", req.Command)
	cmd := exec.CommandContext(ctx, shell[0], arguments...)
	cmd.Env = buildEnvironment(req.Environment)
	if req.WorkingDirectory != "" {
		cmd.Dir = req.WorkingDirectory
	}

	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	logger := middleware.ExtractLogger(c).
		WithField("subsystem", "host_terminal_http").
		WithField("command", req.Command).
		WithField("shell", shell[0]).
		WithField("timeout", timeout.String())

	start := time.Now()
	err = cmd.Run()
	duration := time.Since(start)

	response := hostCommandResponse{
		Stdout:     stdoutBuf.String(),
		Stderr:     stderrBuf.String(),
		DurationMs: duration.Milliseconds(),
		ExitCode:   0,
		TimedOut:   false,
	}

	if ctxErr := ctx.Err(); errors.Is(ctxErr, context.DeadlineExceeded) {
		response.TimedOut = true
		response.ExitCode = -1
		logger.WithField("duration", duration.String()).Warn("host command timed out")
		c.AbortWithStatusJSON(http.StatusGatewayTimeout, response)
		return
	}

	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			response.ExitCode = exitErr.ExitCode()
		} else {
			response.ExitCode = -1
		}
		logger.WithField("exit_code", response.ExitCode).WithError(err).Warn("host command finished with error")
	} else {
		logger.WithField("duration", duration.String()).Info("host command executed successfully")
	}

	c.JSON(http.StatusOK, response)
}
