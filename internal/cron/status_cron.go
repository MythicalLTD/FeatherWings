package cron

import (
	"context"
	"time"

	"emperror.dev/errors"
	"github.com/apex/log"

	"github.com/mythicalltd/featherwings/server"
	"github.com/mythicalltd/featherwings/system"
)

type statusCron struct {
	mu      *system.AtomicBool
	manager *server.Manager
}

// Run re-reports each server's current power state to the Panel so the Panel
// database stays in sync if a transition notification was missed.
func (sc *statusCron) Run(ctx context.Context) error {
	if !sc.mu.SwapIf(true) {
		return errors.WithStack(ErrCronRunning)
	}
	defer sc.mu.Store(false)

	for _, s := range sc.manager.All() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		sctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		err := s.ReportPowerState(sctx)
		cancel()
		if err != nil {
			log.WithField("server", s.ID()).WithField("error", err).
				Warn("cron: failed to sync server power state to Panel")
		}
	}

	return nil
}
