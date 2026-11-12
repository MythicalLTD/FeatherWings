package environment

import (
	"testing"

	"github.com/mythicalltd/featherwings/config"
)

func TestVariablesGet(t *testing.T) {
	tests := []struct {
		name      string
		variables Variables
		key       string
		want      string
	}{
		{
			name:      "missing key returns an empty string",
			variables: Variables{},
			key:       "SERVER_VAR",
			want:      "",
		},
		{
			name:      "nil value returns an empty string",
			variables: Variables{"SERVER_VAR": nil},
			key:       "SERVER_VAR",
			want:      "",
		},
		{
			name:      "string value is returned verbatim",
			variables: Variables{"SERVER_VAR": "hello"},
			key:       "SERVER_VAR",
			want:      "hello",
		},
		{
			name:      "int value is formatted in base 10",
			variables: Variables{"SERVER_VAR": 42},
			key:       "SERVER_VAR",
			want:      "42",
		},
		{
			name:      "int32 value is formatted in base 10",
			variables: Variables{"SERVER_VAR": int32(42)},
			key:       "SERVER_VAR",
			want:      "42",
		},
		{
			name:      "int64 value is formatted in base 10",
			variables: Variables{"SERVER_VAR": int64(42)},
			key:       "SERVER_VAR",
			want:      "42",
		},
		{
			name:      "float32 value uses percent-f formatting",
			variables: Variables{"SERVER_VAR": float32(1.5)},
			key:       "SERVER_VAR",
			want:      "1.500000",
		},
		{
			name:      "float64 value uses percent-f formatting",
			variables: Variables{"SERVER_VAR": float64(1.5)},
			key:       "SERVER_VAR",
			want:      "1.500000",
		},
		{
			name:      "bool value is formatted as true or false",
			variables: Variables{"SERVER_VAR": true},
			key:       "SERVER_VAR",
			want:      "true",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.variables.Get(tt.key); got != tt.want {
				t.Fatalf("Variables.Get(%q) = %q, want %q", tt.key, got, tt.want)
			}
		})
	}
}

// The CFS quota is never below the kernel's 1ms minimum, even for a tiny CPU
// limit combined with a short custom cpu_period, and the CPU limit is kept.
func TestAsContainerResourcesClampsCpuQuota(t *testing.T) {
	prev := config.Get()
	t.Cleanup(func() { config.Set(prev) })

	tests := []struct {
		name      string
		period    int64
		limit     int64
		quota     int64
		cfsPeriod int64
	}{
		{name: "default period", period: 0, limit: 150, quota: 150_000, cfsPeriod: 100_000},
		{name: "default period, 1%", period: 0, limit: 1, quota: 1_000, cfsPeriod: 100_000},
		{name: "short period, 1%", period: 10_000, limit: 1, quota: 1_000, cfsPeriod: 100_000},
		{name: "minimum period, 1%", period: 1_000, limit: 1, quota: 1_000, cfsPeriod: 100_000},
		{name: "minimum period, 50%", period: 1_000, limit: 50, quota: 1_000, cfsPeriod: 2_000},
		{name: "minimum period, 3%", period: 1_000, limit: 3, quota: 1_000, cfsPeriod: 33_333},
		{name: "short period, 200%", period: 10_000, limit: 200, quota: 20_000, cfsPeriod: 10_000},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.Configuration{AuthenticationToken: "test-token"}
			cfg.Docker.CpuPeriod = tt.period
			config.Set(cfg)

			r := Limits{CpuLimit: tt.limit}.AsContainerResources()
			if r.CPUQuota != tt.quota || r.CPUPeriod != tt.cfsPeriod {
				t.Errorf("expected quota %d / period %d, got %d / %d", tt.quota, tt.cfsPeriod, r.CPUQuota, r.CPUPeriod)
			}
			// The limit itself is kept: quota/period stays at CpuLimit percent.
			if got := float64(r.CPUQuota) * 100 / float64(r.CPUPeriod); got < float64(tt.limit)-0.01 || got > float64(tt.limit)+0.01 {
				t.Errorf("expected a %d%% CPU limit, got %.3f%%", tt.limit, got)
			}
		})
	}
}
