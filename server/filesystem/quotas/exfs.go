//go:build linux

package quotas

import (
	"html/template"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"

	"emperror.dev/errors"
	"github.com/apex/log"
	"github.com/mythicalltd/featherwings/config"
	"github.com/parkervcp/fsquota"
)

var exfs struct {
	projects []exfsProject
	sync.Mutex
}

type exfsProject struct {
	ID       int
	Name     string
	BasePath string
}

const (
	projidTemplateSrc = `{{ range . }}{{ .Name }}:{{ .ID }}
{{ end }}`
	projectsTemplateSrc = `{{ range . }}{{ .ID }}:{{ .BasePath }}/{{ .Name }}
{{ end }}`

	projidFile  = `/etc/projid`
	projectFile = `/etc/projects`
)

var (
	projidTemplate   = template.Must(template.New("projid").Parse(projidTemplateSrc))
	projectsTemplate = template.Must(template.New("projects").Parse(projectsTemplateSrc))
)

var (
	lookupProject = fsquota.LookupProject
	// setProjectHardLimit and projectHardLimit wrap fsquota so tests can
	// replace them; quotactl needs root and a filesystem with project quotas.
	setProjectHardLimit = func(path string, project *fsquota.Project, byteLimit uint64) error {
		limits := fsquota.Limits{}
		limits.Bytes.SetHard(byteLimit)
		_, err := fsquota.SetProjectQuota(path, project, limits)
		return err
	}
	projectHardLimit = func(path string, project *fsquota.Project) (uint64, error) {
		info, err := fsquota.GetProjectInfo(path, project)
		if err != nil {
			return 0, err
		}
		return info.Bytes.GetHard(), nil
	}
)

func isQuotaReadBackError(err error) bool {
	var serr *os.SyscallError
	if !errors.As(err, &serr) || serr.Syscall != "quotactl" {
		return false
	}
	return errors.Is(serr.Err, syscall.ESRCH) || errors.Is(serr.Err, syscall.ENOENT)
}

// quotaBlockSize is the unit quotactl stores limits in; a limit read back is
// rounded down to it.
const quotaBlockSize = 1024

// setQuota sets the quota in bytes for the specified server uuid
// A limit of 0 is treated as unlimited by xfs and ext4
func (q exfsProject) setQuota(byteLimit uint64) (err error) {
	serverDirPath := filepath.Join(q.BasePath, q.Name)
	log.WithFields(log.Fields{"server_path": serverDirPath, "limit_bytes": byteLimit}).Debug("setting quota")
	serverProject, err := lookupProject(q.Name)
	if err != nil {
		return
	}

	if err = setProjectHardLimit(serverDirPath, serverProject, byteLimit); err != nil {
		// fsquota reads the quota back as a user quota after setting the
		// project quota, which fails with ESRCH when no user with the
		// project's ID has a quota (ESRCH), or with ENOENT when user quotas
		// are on as well, even though the project quota was set. Read it back
		// as a project quota and accept it when it matches.
		if !isQuotaReadBackError(err) {
			return
		}
		hard, readErr := projectHardLimit(serverDirPath, serverProject)
		if readErr != nil {
			return errors.Wrap(err, "quota could not be read back: "+readErr.Error())
		}
		if hard != byteLimit/quotaBlockSize*quotaBlockSize {
			return errors.Wrapf(err, "quota read back as %d bytes instead of %d", hard, byteLimit)
		}
		err = nil
	}

	log.WithField("server_path", serverDirPath).Debug("quota set")
	return
}

// getQuota gets the specified quotas and usage of a specified server uuid
func (q exfsProject) getQuota() (bytesUsed int64, err error) {
	serverProject, err := fsquota.LookupProject(q.Name)
	if err != nil {
		return -1, err
	}

	projInfo, err := fsquota.GetProjectInfo(q.BasePath, serverProject)
	if err != nil {
		return -1, err
	}

	// converts the uint64 to int64.
	// This should only be an issue in the terms of exabytes...
	return int64(projInfo.BytesUsed), nil
}

// enableEXFSQuota enables quotas on a specified directory
func (q exfsProject) enableEXFSQuota() (err error) {
	serverDir, err := os.Open(filepath.Join(q.BasePath, q.Name))
	if err != nil {
		return err
	}

	defer serverDir.Close()

	// enable project quota inheritance and set project id
	if err = setXAttr(serverDir, q.ID, FS_XFLAG_PROJINHERIT); err != nil {
		log.WithFields(log.Fields{"server_uuid": q.Name, "server_path": serverDir.Name()}).Error("failed to update XATTRs for server")
		return
	}

	return
}

func (q exfsProject) addProject() (err error) {
	q.BasePath = strings.TrimSuffix(config.Get().System.Data, "/")
	exfs.Lock()
	defer exfs.Unlock()

	projects := make([]exfsProject, len(exfs.projects), len(exfs.projects)+1)
	copy(projects, exfs.projects)
	projects = append(projects, q)

	if err = writeEXFSProjects(projects); err != nil {
		log.WithError(err).Error("failed to write exfs projects")
		return
	}

	if err = q.enableEXFSQuota(); err != nil {
		log.WithError(err).Error("failed to enable quota")
		// Roll back the disk write so /etc/projects and exfs.projects stay in sync.
		if err := writeEXFSProjects(exfs.projects); err != nil {
			log.WithError(err).Error("failed to roll back exfs projects after enableEXFSQuota failure")
		}
		return
	}

	exfs.projects = projects
	return
}

// removeProject drops a specified project from the
// if the project is already missing will return with no error
func (q exfsProject) removeProject() (err error) {
	exfs.Lock()
	defer exfs.Unlock()

	projects := make([]exfsProject, 0, len(exfs.projects))
	for _, project := range exfs.projects {
		if project.Name != q.Name {
			projects = append(projects, project)
		}
	}

	if err = writeEXFSProjects(projects); err != nil {
		return err
	}

	exfs.projects = projects

	return
}

func getProject(serverUUID string) (serverProject exfsProject, err error) {
	exfs.Lock()
	defer exfs.Unlock()
	for _, project := range exfs.projects {
		if project.Name == serverUUID {
			return project, nil
		}
	}

	return serverProject, errors.New("quota for server doesn't exist")
}

// writeEXFSProjects
func writeEXFSProjects(projects []exfsProject) (err error) {
	if err = writeTemplate(projidTemplate, projidFile, projects); err != nil {
		return err
	}
	if err = writeTemplate(projectsTemplate, projectFile, projects); err != nil {
		return err
	}
	return
}

// writeTemplate renders t into file atomically: it writes to a temp file in
// the same directory, fsyncs, and renames over the target. On any failure the
// temp file is removed and the original file is left untouched.
func writeTemplate(t *template.Template, file string, data interface{}) (err error) {
	dir := filepath.Dir(file)
	tmp, err := os.CreateTemp(dir, filepath.Base(file)+".tmp.*")
	if err != nil {
		return err
	}

	tmpName := tmp.Name()

	defer func() {
		if err != nil {
			os.Remove(tmpName)
		}
	}()

	if err = t.Execute(tmp, data); err != nil {
		tmp.Close()
		return err
	}

	if err = tmp.Chmod(0o644); err != nil {
		tmp.Close()
		return err
	}

	if err = tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}

	if err = tmp.Close(); err != nil {
		return err
	}

	return os.Rename(tmpName, file)
}
