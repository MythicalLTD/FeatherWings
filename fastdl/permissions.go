package fastdl

import (
	"os"
	"os/exec"
	"os/user"
	"strings"

	"emperror.dev/errors"
	"github.com/apex/log"

	"github.com/mythicalltd/featherwings/config"
)

// nginxUsers are common Linux users nginx workers run as.
var nginxUsers = []string{"www-data", "nginx"}

// EnsureNginxAccess adds the nginx worker user to the FeatherPanel system group
// and opens the root/data directories so nginx can traverse into server volumes.
//
// Without this, FastDL returns 403/404 because volumes are created as 0700
// owned by the featherpanel user while nginx runs as www-data (or nginx).
//
// Returns true when a user was newly added to the group — the nginx process
// must be restarted (not only reloaded) for the new membership to apply.
func EnsureNginxAccess() (membershipChanged bool, err error) {
	cfg := config.Get()
	groupName := strings.TrimSpace(cfg.System.Username)
	if groupName == "" {
		groupName = "featherpanel"
	}

	root := cfg.System.RootDirectory
	data := cfg.System.Data

	for _, nginxUser := range nginxUsers {
		if _, lookupErr := user.Lookup(nginxUser); lookupErr != nil {
			continue
		}
		added, addErr := ensureUserInGroup(nginxUser, groupName)
		if addErr != nil {
			log.WithError(addErr).WithFields(log.Fields{
				"user":  nginxUser,
				"group": groupName,
			}).Warn("fastdl: failed to add nginx user to featherpanel group")
			continue
		}
		if added {
			membershipChanged = true
			log.WithFields(log.Fields{
				"user":  nginxUser,
				"group": groupName,
			}).Info("fastdl: added nginx user to featherpanel group")
		} else {
			log.WithFields(log.Fields{
				"user":  nginxUser,
				"group": groupName,
			}).Debug("fastdl: nginx user already in featherpanel group")
		}
	}

	for _, path := range []string{root, data} {
		if path == "" {
			continue
		}
		if chmodErr := os.Chmod(path, 0o755); chmodErr != nil {
			if os.IsNotExist(chmodErr) {
				continue
			}
			return membershipChanged, errors.Wrapf(chmodErr, "fastdl: failed to chmod 755 %s", path)
		}
		log.WithField("path", path).Debug("fastdl: set directory mode 0755 for nginx access")
	}

	return membershipChanged, nil
}

// ensureUserInGroup adds userName to groupName when not already a member.
// Returns true if the user was newly added.
func ensureUserInGroup(userName, groupName string) (bool, error) {
	u, err := user.Lookup(userName)
	if err != nil {
		return false, err
	}
	g, err := user.LookupGroup(groupName)
	if err != nil {
		return false, err
	}

	groups, err := u.GroupIds()
	if err != nil {
		return false, err
	}
	for _, gid := range groups {
		if gid == g.Gid {
			return false, nil
		}
	}

	// gpasswd -a www-data featherpanel
	cmd := exec.Command("gpasswd", "-a", userName, groupName)
	if out, err := cmd.CombinedOutput(); err != nil {
		// Fallback for Alpine / systems without gpasswd
		cmd2 := exec.Command("addgroup", userName, groupName)
		if out2, err2 := cmd2.CombinedOutput(); err2 != nil {
			return false, errors.Errorf("gpasswd: %s (%v); addgroup: %s (%v)",
				strings.TrimSpace(string(out)), err,
				strings.TrimSpace(string(out2)), err2)
		}
	}
	return true, nil
}
