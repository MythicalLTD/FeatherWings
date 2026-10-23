package server

import (
	"os"
	"runtime"

	"fmt"
	"strings"

	"emperror.dev/errors"
	"github.com/gammazero/workerpool"
	"github.com/mythicalltd/featherwings/internal/ufs"
	"github.com/mythicalltd/featherwings/parser"
)

// Helper function to replace variables in the file path of the configuration parser
func replaceParserConfigPathVariables(filename string, envvars map[string]interface{}) string {
	// Check if filename contains at least one '{' and one '}'
	// This is here for performance as 99% of the eggs configuration parsers do not have variables in its path
	if !strings.Contains(filename, "{") || !strings.Contains(filename, "}") {
		return filename
	}

	// Replace "{{" with "${" and "}}" with "}"
	filename = strings.ReplaceAll(filename, "{{", "${")
	filename = strings.ReplaceAll(filename, "}}", "}")

	// replaces ${varname} with varval
	for varname, varval := range envvars {
		filename = strings.ReplaceAll(filename, fmt.Sprintf("${%s}", varname), fmt.Sprint(varval))
	}

	return filename
}

// UpdateConfigurationFiles updates all the defined configuration files for
// a server automatically to ensure that they always use the specified values.
func (s *Server) UpdateConfigurationFiles() {
	pool := workerpool.New(runtime.NumCPU())

	s.Log().Debug("acquiring process configuration files...")
	files := s.ProcessConfiguration().ConfigurationFiles
	s.Log().Debug("acquired process configuration files")
	for _, cf := range files {
		f := cf

		pool.Submit(func() {
			// Carry on with the other files if updating this one panics.
			defer func() {
				if r := recover(); r != nil {
					s.Log().WithField("file_name", f.FileName).WithField("panic", r).Error("recovered from panic while updating configuration file")
				}
			}()

			filename := replaceParserConfigPathVariables(f.FileName, s.Config().EnvVars)
			if f.Parser == parser.File && !f.AllowCreateFile {
				if _, err := s.Filesystem().UnixFS().Stat(filename); errors.Is(err, ufs.ErrNotExist) {
					s.Log().WithField("file_name", f.FileName).Debug("skipping text configuration file that does not exist yet")
					return
				}
			}

			// Writes to the file count against the server's disk limit.
			flag := ufs.O_RDWR
			if f.AllowCreateFile {
				flag |= ufs.O_CREATE
			} else if _, err := s.Filesystem().UnixFS().Stat(filename); errors.Is(err, ufs.ErrNotExist) {
				s.Log().WithField("file_name", filename).Debug("file not created")
				return
			}
			file, err := s.Filesystem().Touch(filename, flag)
			if err != nil {
				log := s.Log().WithField("file_name", filename)
				if os.IsNotExist(err) && !f.AllowCreateFile {
					log.Debug("file not created")
				} else {
					log.WithField("error", err).Error("failed to open file for configuration")
				}
				return
			}

			if err := f.Parse(file); err != nil {
				s.Log().WithField("error", err).Error("failed to parse and update server configuration file")
			}
			if err := file.Close(); err != nil {
				s.Log().WithField("file_name", f.FileName).WithField("error", err).Error("failed to close configuration file")
			}
			if err := s.Filesystem().Chown(filename); err != nil {
				s.Log().WithField("file_name", f.FileName).WithField("error", err).Warn("failed to set the owner of configuration file")
			}

			s.Log().WithField("file_name", f.FileName).Debug("finished processing server configuration file")
		})
	}

	pool.StopWait()
}
