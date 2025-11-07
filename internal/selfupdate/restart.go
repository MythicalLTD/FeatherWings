package selfupdate

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// RunRestartCommand executes the provided restart command using /bin/sh -c and returns combined output.
func RunRestartCommand(ctx context.Context, command string) (string, error) {
	if strings.TrimSpace(command) == "" {
		return "", nil
	}

	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", command)
	output, err := cmd.CombinedOutput()
	out := strings.TrimSpace(string(output))
	if err != nil {
		if out != "" {
			return out, fmt.Errorf("restart command failed: %w: %s", err, out)
		}
		return out, fmt.Errorf("restart command failed: %w", err)
	}
	return out, nil
}
