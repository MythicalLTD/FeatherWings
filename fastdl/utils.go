package fastdl

import (
	"os"
	"os/exec"

	"github.com/mythicalltd/featherwings/server"
)

// IsNginxInstalled checks if nginx is installed and available on the system.
func IsNginxInstalled() bool {
	// Check if nginx binary exists
	if _, err := exec.LookPath("nginx"); err != nil {
		return false
	}

	// Check if nginx configuration directory exists
	if _, err := os.Stat("/etc/nginx"); err != nil {
		if os.IsNotExist(err) {
			return false
		}
	}

	return true
}

// HasFastDLEnabledServers checks if any servers have FastDL enabled.
func HasFastDLEnabledServers(manager *server.Manager) bool {
	for _, srv := range manager.All() {
		if srv.Config().FastDL.Enabled {
			return true
		}
	}
	return false
}
