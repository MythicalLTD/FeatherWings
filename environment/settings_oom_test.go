package environment

import (
	"testing"

	"github.com/mythicalltd/featherwings/config"
)

func TestOomKillDisableOnlyOnCgroupV1(t *testing.T) {
	config.Set(&config.Configuration{AuthenticationToken: "test-token"})
	prev := cgroupV2
	t.Cleanup(func() { cgroupV2 = prev })

	tests := []struct {
		name      string
		v2        bool
		oomKiller bool
		expected  *bool
	}{
		{name: "v2 killer off", v2: true, oomKiller: false, expected: nil},
		{name: "v2 killer on", v2: true, oomKiller: true, expected: nil},
		{name: "v1 killer off", v2: false, oomKiller: false, expected: boolPtr(true)},
		{name: "v1 killer on", v2: false, oomKiller: true, expected: boolPtr(false)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cgroupV2 = func() bool { return tt.v2 }
			got := Limits{MemoryLimit: 1024, OOMKiller: tt.oomKiller}.AsContainerResources().OomKillDisable
			switch {
			case tt.expected == nil && got != nil:
				t.Fatalf("expected OomKillDisable to be unset, got %v", *got)
			case tt.expected != nil && (got == nil || *got != *tt.expected):
				t.Fatalf("expected OomKillDisable %v, got %v", *tt.expected, got)
			}
		})
	}
}
