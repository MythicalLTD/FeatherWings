package cmd

import "testing"

func TestConfigureModeFromChoice(t *testing.T) {
	t.Parallel()

	tests := []struct {
		choice string
		want   configureMode
	}{
		{choice: "oauth", want: configureModeOAuth},
		{choice: "manual", want: configureModeJoin},
		{choice: "unexpected", want: configureModeJoin},
	}

	for _, tc := range tests {
		got := configureModeFromChoice(tc.choice)
		if got != tc.want {
			t.Fatalf("configureModeFromChoice(%q) = %v, want %v", tc.choice, got, tc.want)
		}
	}
}
