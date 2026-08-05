package cron

import (
	"context"
	"time"

	"emperror.dev/errors"
	"github.com/apex/log"

	"github.com/mythicalltd/featherwings/config"
	"github.com/mythicalltd/featherwings/server"
	"github.com/mythicalltd/featherwings/system"
)

type runtimeCron struct {
	mu      *system.AtomicBool
	manager *server.Manager
}

// Run probes each server's Docker runtime and recovers stuck starting/stopping
// states when Docker API calls hang or containerd is desynchronized.
func (rc *runtimeCron) Run(ctx context.Context) error {
	if !rc.mu.SwapIf(true) {
		return errors.WithStack(ErrCronRunning)
	}
	defer rc.mu.Store(false)

	cfg := config.Get().Docker.RuntimeReconciliation
	if !cfg.Enabled {
		return nil
	}

	timeout := time.Duration(cfg.InspectTimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	for _, s := range rc.manager.All() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Per-server budget so one hung node cannot block the whole cron tick.
		sctx, cancel := context.WithTimeout(ctx, timeout*3+15*time.Second)
		result, err := s.ReconcileRuntime(sctx)
		cancel()
		if err != nil {
			log.WithField("server", s.ID()).WithField("error", err).
				Warn("cron: runtime reconciliation failed for server")
			continue
		}
		if result.Action != "noop" && result.Action != "skipped" && result.Action != "watch" {
			log.WithFields(log.Fields{
				"server":  s.ID(),
				"action":  result.Action,
				"status":  result.Status,
				"message": result.Message,
			}).Info("cron: runtime reconciliation acted on server")
		}
	}

	return nil
}
