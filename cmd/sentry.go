package cmd

import (
	"strings"
	"time"

	"github.com/apex/log"
	"github.com/getsentry/sentry-go"

	"github.com/mythicalltd/featherwings/config"
	"github.com/mythicalltd/featherwings/system"
)

// initSentry configures the Sentry SDK for GlitchTip (or any Sentry-compatible
// backend) using values from config.yml. Safe to call when reporting is disabled.
func initSentry() {
	cfg := config.Get().Sentry
	if !cfg.Enabled || strings.TrimSpace(cfg.Dsn) == "" {
		log.Debug("error reporting disabled (sentry.enabled=false or empty dsn)")
		return
	}

	sampleRate := cfg.TracesSampleRate
	if sampleRate < 0 {
		sampleRate = 0
	} else if sampleRate > 1 {
		sampleRate = 1
	}

	err := sentry.Init(sentry.ClientOptions{
		Dsn:              cfg.Dsn,
		Environment:      cfg.Environment,
		Release:          "featherwings@" + system.Version,
		ServerName:       config.Get().Uuid,
		TracesSampleRate: sampleRate,
	})
	if err != nil {
		log.WithField("error", err).Error("failed to initialize sentry error reporting")
		return
	}

	log.WithFields(log.Fields{
		"environment":        cfg.Environment,
		"traces_sample_rate": sampleRate,
	}).Info("sentry error reporting enabled")
}

// flushSentry drains buffered events before process exit.
func flushSentry() {
	sentry.Flush(2 * time.Second)
}
