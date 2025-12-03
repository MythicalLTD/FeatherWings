package firewall

import (
	"github.com/mythicalltd/featherwings/environment"
)

// ValidatePortForServer validates that a port is allocated to a server
func ValidatePortForServer(allocations *environment.Allocations, port int) bool {
	// Check default mapping
	if allocations.DefaultMapping != nil && allocations.DefaultMapping.Port == port {
		return true
	}

	// Check all mappings
	for _, ports := range allocations.Mappings {
		for _, p := range ports {
			if p == port {
				return true
			}
		}
	}

	return false
}
