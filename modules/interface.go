package modules

import (
	"context"
)

// Module represents a pluggable module that can be enabled/disabled
type Module interface {
	// Name returns the unique identifier for this module
	Name() string

	// Description returns a human-readable description of what this module does
	Description() string

	// Enabled returns whether the module is currently enabled
	Enabled() bool

	// Enable starts the module and makes it active
	// Dependencies can be passed via context values if needed
	Enable(ctx context.Context) error

	// Disable stops the module and makes it inactive
	Disable(ctx context.Context) error

	// GetConfig returns the current configuration for the module
	GetConfig() interface{}

	// SetConfig updates the module's configuration
	SetConfig(config interface{}) error

	// ValidateConfig validates the provided configuration
	ValidateConfig(config interface{}) error
}
