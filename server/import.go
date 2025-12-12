package server

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"emperror.dev/errors"
	"github.com/apex/log"
	"github.com/mythicalltd/featherwings/environment"
	"github.com/mythicalltd/featherwings/remote"
	"github.com/pkg/sftp"
	"github.com/secsy/goftp"
	"golang.org/x/crypto/ssh"
)

// Import imports server files from a remote SFTP or FTP server.
func (s *Server) Import(sync bool, user string, password string, hote string, port int, srclocation string, dstlocation string, Type string) error {
	if sync {
		s.Log().Info("syncing server state with remote source before executing import process")
		if err := s.Sync(); err != nil {
			return err
		}
	}

	var err error
	s.Events().Publish(ImportStartedEvent, "")
	if Type == "ftp" || port == 21 {
		err = s.internalImportFtp(user, password, hote, port, srclocation, dstlocation)

	} else {
		err = s.internalImport(user, password, hote, port, srclocation, dstlocation)

	}

	// Ensure that the server is marked as offline at this point, otherwise you end up
	// with a blank value which is a bit confusing.
	s.Environment.SetState(environment.ProcessOfflineState)

	// Prepare error message for panel notification
	var errorMessage string
	if err != nil {
		errorMessage = err.Error()
	}

	// Notify panel of import status with detailed error information
	s.Log().WithField("was_successful", err == nil).Debug("notifying panel of server import state")
	if serr := s.SyncImportState(err == nil, errorMessage); serr != nil {
		if !remote.IsRequestError(serr) {
			s.Log().WithFields(log.Fields{
				"server": s.ID(),
				"error":  serr,
			}).Error("failed to notify panel of import status due to wings error")
		} else {
			s.Log().WithField("error", serr).Warn("failed to notify panel of server import state")
		}
	} else {
		s.Log().WithField("was_successful", err == nil).Info("notified panel of server import state")
	}

	// Push an event to the websocket so we can auto-refresh the information in the panel once
	// the import is completed.
	s.Events().Publish(ImportCompletedEvent, "")

	return err
}

// ImportNew imports server files from a remote SFTP or FTP server.
// If Wipe is true, the destination directory will be cleared before importing.
func (s *Server) ImportNew(user string, password string, hote string, port int, srclocation string, dstlocation string, Type string, Wipe bool) error {
	if s.Environment.State() != environment.ProcessOfflineState {
		s.Log().Debug("waiting for server instance to enter a stopped state")
		if err := s.Environment.WaitForStop(s.Context(), time.Second*10, true); err != nil {
			return err
		}
	}

	// Validate destination path
	if err := s.Filesystem().IsIgnored(dstlocation); err != nil {
		return errors.Wrap(err, "server/import: destination path is not allowed")
	}

	// Get the full destination path
	cleaned := filepath.Join(s.Filesystem().Path(), dstlocation)

	if Wipe {
		s.Log().Info("wiping destination directory before import")
		if err := os.RemoveAll(cleaned); err != nil {
			s.Log().WithField("error", err).Warn("failed to remove existing files during wipe")
		}
		if err := os.MkdirAll(cleaned, 0o755); err != nil {
			return errors.Wrap(err, "server/import: failed to create destination directory")
		}
	}

	// Normalize destination location
	if !strings.HasSuffix(dstlocation, "/") {
		dstlocation = dstlocation + "/"
	}

	// Normalize source location based on type
	if Type == "sftp" {
		if !strings.HasPrefix(srclocation, "/") {
			srclocation = "/" + srclocation
		}
		if !strings.HasSuffix(srclocation, "/") {
			srclocation = srclocation + "/"
		}
	} else {
		if !strings.HasPrefix(srclocation, "/") {
			srclocation = "/" + srclocation
		}
	}

	return s.Import(true, user, password, hote, port, srclocation, dstlocation, Type)
}

/*
*
*
*	ONLY FOR SFTP
*
*
 */
// Internal import function used to simplify reporting back to the Panel.
func (s *Server) internalImport(user string, password string, hote string, port int, srclocation string, dstlocation string) error {

	s.Log().Info("beginning import process for server")
	if err := s.ServerImporter(user, password, hote, port, srclocation, dstlocation); err != nil {
		return err
	}
	s.Log().Info("completed import process for server")
	return nil
}

func (s *Server) ServerImporter(user string, password string, hote string, port int, srclocation string, dstlocation string) error {
	config := ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	// Get the full destination path
	cleaned := filepath.Join(s.Filesystem().Path(), dstlocation)
	if err := os.MkdirAll(cleaned, 0o755); err != nil {
		return errors.Wrap(err, "server/import: failed to create destination directory")
	}

	addr := fmt.Sprintf("%s:%d", hote, port)
	s.Log().WithField("address", addr).Info("connecting to SFTP server")

	// Connect to server
	conn, err := ssh.Dial("tcp", addr, &config)
	if err != nil {
		return errors.Wrapf(err, "server/import: failed to connect to [%s]", addr)
	}
	defer conn.Close()

	sc, err := sftp.NewClient(conn)
	if err != nil {
		return errors.Wrap(err, "server/import: unable to start SFTP subsystem")
	}
	defer sc.Close()

	files, err := sc.ReadDir(srclocation)
	if err != nil {
		return errors.Wrapf(err, "server/import: unable to list remote directory: %s", srclocation)
	}

	for _, f := range files {
		name := f.Name()

		if f.IsDir() {
			// Create directory and recursively import its contents
			dirPath := filepath.Join(cleaned, srclocation, name)
			if err := os.MkdirAll(dirPath, 0o755); err != nil {
				return errors.Wrapf(err, "server/import: failed to create directory: %s", dirPath)
			}
			if err := isdir(srclocation+name+"/", sc, cleaned, srclocation, dstlocation); err != nil {
				return err
			}
		} else {
			if err := downloadfilesfromsftpserver(name, sc, cleaned, srclocation); err != nil {
				return err
			}
		}
	}
	return nil
}

func isdir(dir string, sc *sftp.Client, cleaned string, srclocation string, dstlocation string) error {
	files, err := sc.ReadDir(dir)
	if err != nil {
		return errors.Wrapf(err, "server/import: unable to list remote directory: %s", dir)
	}

	for _, f := range files {
		name := f.Name()

		if f.IsDir() {
			// Create directory and recursively process its contents
			dirPath := filepath.Join(cleaned, dir, name)
			if err := os.MkdirAll(dirPath, 0o755); err != nil {
				return errors.Wrapf(err, "server/import: failed to create directory: %s", dirPath)
			}
			if err := isdir(dir+name+"/", sc, cleaned, srclocation, dstlocation); err != nil {
				return err
			}
		} else {
			// Ensure parent directory exists
			parentDir := filepath.Join(cleaned, dir)
			if err := os.MkdirAll(parentDir, 0o755); err != nil {
				return errors.Wrapf(err, "server/import: failed to create parent directory: %s", parentDir)
			}
			if err := downloadfilesfromsftpserver(name, sc, cleaned, dir); err != nil {
				return err
			}
		}
	}
	return nil
}
func downloadfilesfromsftpserver(name string, sc *sftp.Client, folder string, srcfolder string) error {
	remotePath := srcfolder + name
	srcFile, err := sc.OpenFile(remotePath, os.O_RDONLY)
	if err != nil {
		return errors.Wrapf(err, "server/import: unable to open remote file: %s", remotePath)
	}
	defer srcFile.Close()

	// Clean up the local file path
	localPath := filepath.Join(folder, srcfolder, name)
	localPath = filepath.Clean(localPath)

	// Ensure parent directory exists
	if err := os.MkdirAll(filepath.Dir(localPath), 0o755); err != nil {
		return errors.Wrapf(err, "server/import: failed to create parent directory for: %s", localPath)
	}

	dstFile, err := os.Create(localPath)
	if err != nil {
		return errors.Wrapf(err, "server/import: unable to create local file: %s", localPath)
	}
	defer dstFile.Close()

	_, err = io.Copy(dstFile, srcFile)
	if err != nil {
		return errors.Wrapf(err, "server/import: unable to download remote file: %s", remotePath)
	}
	return nil
}
func (s *Server) SyncImportState(successful bool, errorMessage string) error {
	status := remote.ImportStatusRequest{
		Successful: successful,
	}
	if !successful && errorMessage != "" {
		status.Error = errorMessage
	}
	return s.client.SetImportStatus(s.Context(), s.ID(), status)
}

/*
*
*
*
*
*
*	ONLY FOR FTP
*
*
*
*
*
*
*

 */
// Internal import function used to simplify reporting back to the Panel.
func (s *Server) internalImportFtp(user string, password string, hote string, port int, srclocation string, dstlocation string) error {

	s.Log().Info("beginning import process for server")
	if err := s.ServerImporterFtp(user, password, hote, port, srclocation, dstlocation); err != nil {
		return err
	}
	s.Log().Info("completed import process for server")
	return nil
}

func (s *Server) ServerImporterFtp(user string, password string, hote string, port int, srclocation string, dstlocation string) error {
	config := goftp.Config{
		User:               user,
		Password:           password,
		ConnectionsPerHost: 10,
		Timeout:            10 * time.Second,
	}

	// Get the full destination path
	cleaned := filepath.Join(s.Filesystem().Path(), dstlocation)
	if err := os.MkdirAll(cleaned, 0o755); err != nil {
		return errors.Wrap(err, "server/import: failed to create destination directory")
	}

	addr := fmt.Sprintf("%s:%d", hote, port)
	s.Log().WithField("address", addr).Info("connecting to FTP server")

	// Connect to server
	sc, err := goftp.DialConfig(config, addr)
	if err != nil {
		return errors.Wrapf(err, "server/import: failed to connect to [%s]", addr)
	}
	defer sc.Close()

	files, err := sc.ReadDir("." + srclocation)
	if err != nil {
		return errors.Wrapf(err, "server/import: unable to list remote FTP directory: %s", srclocation)
	}

	for _, f := range files {
		name := f.Name()

		if f.IsDir() {
			// Create directory and recursively import its contents
			dirPath := filepath.Join(cleaned, name)
			if err := os.MkdirAll(dirPath, 0o755); err != nil {
				return errors.Wrapf(err, "server/import: failed to create directory: %s", dirPath)
			}
			if err := isdirFtp(name+"/", sc, cleaned, srclocation, dstlocation); err != nil {
				return err
			}
		} else {
			if err := downloadfilesfromftpserver(name, sc, cleaned, "", srclocation, dstlocation); err != nil {
				return err
			}
		}
	}
	return nil
}

func isdirFtp(dir string, sc *goftp.Client, cleaned string, srclocation string, dstlocation string) error {
	remoteDir := "./" + srclocation + "/" + dir
	files, err := sc.ReadDir(remoteDir)
	if err != nil {
		return errors.Wrapf(err, "server/import: unable to list remote FTP directory: %s", remoteDir)
	}

	for _, f := range files {
		name := f.Name()

		if f.IsDir() {
			// Create directory and recursively process its contents
			dirPath := filepath.Join(cleaned, dir, name)
			if err := os.MkdirAll(dirPath, 0o755); err != nil {
				return errors.Wrapf(err, "server/import: failed to create directory: %s", dirPath)
			}
			if err := isdirFtp(dir+name+"/", sc, cleaned, srclocation, dstlocation); err != nil {
				return err
			}
		} else {
			// Ensure parent directory exists
			parentDir := filepath.Join(cleaned, dir)
			if err := os.MkdirAll(parentDir, 0o755); err != nil {
				return errors.Wrapf(err, "server/import: failed to create parent directory: %s", parentDir)
			}
			if err := downloadfilesfromftpserver(name, sc, cleaned, dir, srclocation, dstlocation); err != nil {
				return err
			}
		}
	}
	return nil
}
func downloadfilesfromftpserver(name string, sc *goftp.Client, folder string, srcfolder string, srclocation string, dstlocation string) error {
	// Construct local file path
	localPath := filepath.Join(folder, srcfolder, name)
	localPath = filepath.Clean(localPath)

	// Ensure parent directory exists
	if err := os.MkdirAll(filepath.Dir(localPath), 0o755); err != nil {
		return errors.Wrapf(err, "server/import: failed to create parent directory for: %s", localPath)
	}

	dstFile, err := os.Create(localPath)
	if err != nil {
		return errors.Wrapf(err, "server/import: unable to create local file: %s", localPath)
	}
	defer dstFile.Close()

	// Construct remote file path
	remotePath := "." + srclocation + "/" + srcfolder + name
	if err := sc.Retrieve(remotePath, dstFile); err != nil {
		return errors.Wrapf(err, "server/import: unable to download remote file: %s", remotePath)
	}
	return nil
}
