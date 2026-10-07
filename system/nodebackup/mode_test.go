package nodebackup

import "testing"

func TestValidateModeAliases(t *testing.T) {
	full, err := ValidateMode("full")
	if err != nil || full != ModeFull {
		t.Fatalf("full: got %q err=%v", full, err)
	}
	volumes, err := ValidateMode("volumes")
	if err != nil || volumes != ModeVolumes {
		t.Fatalf("volumes: got %q err=%v", volumes, err)
	}
	userOnly, err := ValidateMode("user_backups_only")
	if err != nil || userOnly != ModeUserBackupsOnly {
		t.Fatalf("user_backups_only: got %q err=%v", userOnly, err)
	}
}
