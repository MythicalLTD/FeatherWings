package config

import (
	"testing"
)

func TestSentryDefaults(t *testing.T) {
	c, err := NewAtPath("/tmp/featherwings-sentry-test.yml")
	if err != nil {
		t.Fatalf("NewAtPath: %v", err)
	}

	if !c.Sentry.Enabled {
		t.Fatal("expected sentry.enabled default true")
	}
	wantDSN := "https://293bbc3bca1d4f7b92d27e04fdda3fa8@error.mythical.systems/4"
	if c.Sentry.Dsn != wantDSN {
		t.Fatalf("dsn = %q, want %q", c.Sentry.Dsn, wantDSN)
	}
	if c.Sentry.Environment != "production" {
		t.Fatalf("environment = %q, want production", c.Sentry.Environment)
	}
	if c.Sentry.TracesSampleRate != 0.01 {
		t.Fatalf("traces_sample_rate = %v, want 0.01", c.Sentry.TracesSampleRate)
	}
}
