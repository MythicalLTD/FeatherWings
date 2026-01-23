package fastdl

import (
	"context"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"emperror.dev/errors"
	"github.com/apex/log"

	"github.com/mythicalltd/featherwings/config"
	"github.com/mythicalltd/featherwings/server"
)

// FastDLServer represents the FastDL HTTP server instance.
type FastDLServer struct {
	manager  *server.Manager
	BasePath string
	ReadOnly bool
	Listen   string
	Handler  *FastDLHandler
	server   *http.Server
}

// New creates a new FastDL server instance.
// NOTE: This is not used when FastDL uses nginx (which is the default).
// Kept for potential future use or if built-in server is re-enabled.
func New(m *server.Manager) *FastDLServer {
	cfg := config.Get().System
	fastdlCfg := cfg.FastDL

	handler := NewHandler(m, cfg.Data, fastdlCfg)

	return &FastDLServer{
		manager:  m,
		BasePath: cfg.Data,
		ReadOnly: false, // Default
		Listen:   "0.0.0.0:" + strconv.Itoa(fastdlCfg.Port),
		Handler:  handler,
	}
}

// checkPortAvailable checks if a port is available for binding.
func checkPortAvailable(address string) error {
	conn, err := net.DialTimeout("tcp", address, 2*time.Second)
	if err == nil {
		conn.Close()
		return errors.Errorf("port is already in use: %s", address)
	}
	return nil
}

// Run starts the FastDL HTTP server and begins listening for connections.
func (s *FastDLServer) Run() error {
	// Check if port is available before trying to bind
	if err := checkPortAvailable(s.Listen); err != nil {
		log.WithError(err).WithField("listen", s.Listen).Warn("fastdl: port is already in use, FastDL server will not start")
		return nil // Don't crash, just warn and skip
	}

	mux := http.NewServeMux()

	// Main FastDL handler - serves files from server directories
	// Path format: /{server-uuid}/path/to/file
	mux.HandleFunc("/", s.Handler.ServeHTTP)

	// Health check endpoint
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	// Create HTTP server
	s.server = &http.Server{
		Addr:    s.Listen,
		Handler: mux,
	}

	// FastDL uses HTTP only (no SSL) - nginx handles SSL if needed
	log.WithField("listen", s.Listen).Info("fastdl server listening for HTTP connections")

	// Start HTTP server
	if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		// Check if it's a port binding error
		if strings.Contains(err.Error(), "bind: address already in use") || strings.Contains(err.Error(), "bind: port already in use") {
			log.WithError(err).WithField("listen", s.Listen).Warn("fastdl: port is already in use, FastDL server disabled")
			return nil // Don't crash, just warn
		}
		return errors.Wrap(err, "fastdl: failed to start HTTP server")
	}

	return nil
}

// Shutdown gracefully shuts down the FastDL server.
func (s *FastDLServer) Shutdown(ctx context.Context) error {
	if s.server == nil {
		return nil
	}
	return s.server.Shutdown(ctx)
}

// GetListenAddress returns the address the server is listening on.
func (s *FastDLServer) GetListenAddress() string {
	return s.Listen
}

// GetPort returns the port the server is listening on.
func (s *FastDLServer) GetPort() int {
	fastdlCfg := config.Get().System.FastDL
	return fastdlCfg.Port
}
