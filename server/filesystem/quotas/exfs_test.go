//go:build linux

package quotas

import (
	"os"
	"syscall"
	"testing"

	"emperror.dev/errors"
	"github.com/parkervcp/fsquota"
)

func stubQuota(t *testing.T, setErr error, readBack uint64, readErr error) *int {
	t.Helper()
	prevLookup, prevSet, prevGet := lookupProject, setProjectHardLimit, projectHardLimit
	t.Cleanup(func() { lookupProject, setProjectHardLimit, projectHardLimit = prevLookup, prevSet, prevGet })
	reads := 0
	lookupProject = func(name string) (*fsquota.Project, error) {
		return &fsquota.Project{Name: name, ID: "7"}, nil
	}
	setProjectHardLimit = func(string, *fsquota.Project, uint64) error { return setErr }
	projectHardLimit = func(string, *fsquota.Project) (uint64, error) {
		reads++
		return readBack, readErr
	}
	return &reads
}

func quotactlErr(errno syscall.Errno) error {
	return os.NewSyscallError("quotactl", errno)
}

// fsquota reads a project quota back as a user quota, which fails with ESRCH
// or ENOENT although the project quota was set; that must not fail the sync.
func TestSetQuotaAcceptsFailedUserQuotaReadBack(t *testing.T) {
	for _, errno := range []syscall.Errno{syscall.ESRCH, syscall.ENOENT} {
		t.Run(errno.Error(), func(t *testing.T) {
			reads := stubQuota(t, quotactlErr(errno), 200*1024*1024, nil)
			if err := (exfsProject{Name: "uuid", BasePath: "/data"}).setQuota(200 * 1024 * 1024); err != nil {
				t.Fatalf("setQuota() = %v, expected the project quota to be accepted", err)
			}
			if *reads != 1 {
				t.Fatalf("expected the quota to be read back once as a project quota, got %d", *reads)
			}
		})
	}
}

func TestSetQuotaRoundsLimitToBlocks(t *testing.T) {
	stubQuota(t, quotactlErr(syscall.ESRCH), 2048, nil)
	if err := (exfsProject{Name: "uuid"}).setQuota(2048 + 100); err != nil {
		t.Fatal(err)
	}
}

func TestSetQuotaRejectsMismatchedReadBack(t *testing.T) {
	stubQuota(t, quotactlErr(syscall.ESRCH), 1024, nil)
	if err := (exfsProject{Name: "uuid"}).setQuota(200 * 1024 * 1024); err == nil {
		t.Fatal("expected an error when the project quota does not match")
	}
}

func TestSetQuotaReturnsReadBackError(t *testing.T) {
	stubQuota(t, quotactlErr(syscall.ESRCH), 0, errors.New("read failed"))
	if err := (exfsProject{Name: "uuid"}).setQuota(1024); err == nil {
		t.Fatal("expected an error when the project quota can't be read")
	}
}

func TestSetQuotaReturnsOtherErrors(t *testing.T) {
	for name, setErr := range map[string]error{
		"permission":  quotactlErr(syscall.EPERM),
		"missing dir": &os.PathError{Op: "lstat", Path: "/data/uuid", Err: syscall.ENOENT},
	} {
		t.Run(name, func(t *testing.T) {
			reads := stubQuota(t, setErr, 1024, nil)
			if err := (exfsProject{Name: "uuid"}).setQuota(1024); err == nil {
				t.Fatal("expected the error to be returned")
			}
			if *reads != 0 {
				t.Fatal("the quota should not be read back for other errors")
			}
		})
	}
}
