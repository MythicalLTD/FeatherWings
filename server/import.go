package server

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/mythicalltd/featherwings/environment"
	"github.com/pkg/sftp"
	"github.com/secsy/goftp"
	"golang.org/x/crypto/ssh"
)

type Runes []rune

// Import imports server files from a remote SFTP or FTP server.
// It handles the complete import workflow including state synchronization,
// file transfer, and event notifications.
//
// Parameters:
//   - sync: If true, syncs server state with remote source before import
//   - user: Remote server username for authentication
//   - password: Remote server password for authentication
//   - hote: Remote server hostname or IP address
//   - port: Remote server port (22 for SFTP, 21 for FTP)
//   - srclocation: Source location on remote server (absolute path)
//   - dstlocation: Destination location on local server (relative to server root)
//   - Type: Connection type, either "sftp" or "ftp" (or "ftp" if port is 21)
//
// Returns an error if the import process fails at any stage.
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

	s.Log().WithField("was_successful", err == nil).Debug("notifying panel of server import state")
	if serr := s.SyncImportState(err == nil); serr != nil {
		l := s.Log().WithField("was_successful", err == nil)

		// If the request was successful but there was an error with this request, attach the
		// error to this log entry. Otherwise ignore it in this log since whatever is calling
		// this function should handle the error and will end up logging the same one.
		if err == nil {
			l.WithField("error", serr)
		}

		l.Warn("failed to notify panel of server import state")
	}

	// Ensure that the server is marked as offline at this point, otherwise you end up
	// with a blank value which is a bit confusing.
	s.Environment.SetState(environment.ProcessOfflineState)

	// Push an event to the websocket so we can auto-refresh the information in the panel once
	// the install is completed.
	s.Events().Publish(ImportCompletedEvent, "")
	s.SyncImportState(err != nil)

	return err
}

// ImportNew performs a new server import with optional file wiping.
// This function ensures the server is stopped before importing and optionally
// wipes existing files before starting the import process.
//
// Parameters:
//   - user: Remote server username for authentication
//   - password: Remote server password for authentication
//   - hote: Remote server hostname or IP address
//   - port: Remote server port (22 for SFTP, 21 for FTP)
//   - srclocation: Source location on remote server (absolute path)
//   - dstlocation: Destination location on local server (relative to server root)
//   - Type: Connection type, either "sftp" or "ftp"
//   - Wipe: If true, removes all existing files in the server directory before import
//
// Returns an error if the import process fails at any stage.
func (s *Server) ImportNew(user string, password string, hote string, port int, srclocation string, dstlocation string, Type string, Wipe bool) error {
	if s.Environment.State() != environment.ProcessOfflineState {
		s.Log().Debug("waiting for server instance to enter a stopped state")
		if err := s.Environment.WaitForStop(s.Context(), time.Second*10, true); err != nil {
			return err
		}
	}
	if Wipe {
		cleaned := s.fs.Path()
		os.RemoveAll(cleaned)
		os.MkdirAll(cleaned, 0777)
	}
	if !strings.HasSuffix(dstlocation, "/") {
		dstlocation = dstlocation + "/"
	}

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

// internalImport handles the SFTP import process.
// This is an internal function that wraps the actual SFTP import logic
// and provides consistent logging and error handling.
func (s *Server) internalImport(user string, password string, hote string, port int, srclocation string, dstlocation string) error {

	s.Log().Info("beginning import process for server")
	if err := s.ServerImporter(user, password, hote, port, srclocation, dstlocation); err != nil {
		return err
	}
	s.Log().Info("completed import process for server")
	return nil
}

// ServerImporter performs the actual SFTP file import operation.
// It establishes an SSH/SFTP connection to the remote server and recursively
// downloads all files and directories from the source location to the destination.
//
// Parameters:
//   - user: Remote server username for SSH authentication
//   - password: Remote server password for SSH authentication
//   - hote: Remote server hostname or IP address
//   - port: Remote server SSH port (typically 22)
//   - srclocation: Source location on remote server (absolute path)
//   - dstlocation: Destination location on local server (relative to server root)
//
// Returns an error if the connection, file listing, or file transfer fails.
func (s *Server) ServerImporter(user string, password string, hote string, port int, srclocation string, dstlocation string) error {
	config := ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
		},

		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	cleaned := filepath.Clean(filepath.Join(s.fs.Path(), dstlocation))
	os.MkdirAll(cleaned, 0777)

	addr := fmt.Sprintf("%s:%d", hote, port)
	// Connect to server
	conn, err := ssh.Dial("tcp", addr, &config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to connecto to [%s]: %v\n", addr, err)
		return err
	}
	sc, err := sftp.NewClient(conn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to start SFTP subsystem: %v\n", err)
		return err
	}
	files, err := sc.ReadDir(srclocation)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to list remote dir: %v\n", err)
		return err
	}

	for _, f := range files {
		var name string

		name = f.Name()

		if f.IsDir() {
			strRune := Runes(name)
			reversed := strRune.ReverseString()
			slashnumber := strings.Index(string(name), "/")
			if string(reversed[slashnumber+1]) != "" {

				os.MkdirAll(cleaned+"/"+srclocation+name, 0777)
			}
			if err := isdir("."+srclocation+name+"/", sc, cleaned, srclocation, dstlocation); err != nil {
				return err
			}

		}
		if !f.IsDir() {

			if err := downloadfilesfromsftpserver(name, sc, cleaned, srclocation); err != nil {
				return err
			}
		}
	}
	return nil

}

// isdir recursively processes directories during SFTP import.
// It creates local directories and processes nested files and subdirectories.
func isdir(dir string, sc *sftp.Client, cleaned string, srclocation string, dstlocation string) error {
	files, err := sc.ReadDir(dir)

	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to list remote dir: %v\n", err)
		return err
	}
	for _, f := range files {
		var name string

		name = f.Name()

		if f.IsDir() {
			strRune := Runes(name)
			reversed := strRune.ReverseString()
			slashnumber := strings.Index(string(name), "/")
			if string(reversed[slashnumber+1]) != "" {
				os.MkdirAll(cleaned+dir+name, 0777)

			}
			isdir(dir+name+"/", sc, cleaned, srclocation, dstlocation)
		}
		if !f.IsDir() {
			afterlastslash := strings.Split(name, "/")
			test := strings.Join(afterlastslash[len(afterlastslash)-1:], "")
			slashnumber := strings.ReplaceAll(dir+name, test, "")
			os.MkdirAll(cleaned+"/"+slashnumber, 0777)
			// Output each file name and size in bytes
			// Note: SFTP To Go doesn't support O_RDWR mode

			if err := downloadfilesfromsftpserver(name, sc, cleaned, dir); err != nil {
				return err
			}
		}

	}
	return nil
}

// ReverseString reverses a Runes slice.
// This is a helper function used during directory processing.
func (str Runes) ReverseString() (revStr Runes) {
	l := len(str)
	revStr = make(Runes, l)
	for i := 0; i <= l/2; i++ {
		revStr[i], revStr[l-1-i] = str[l-1-i], str[i]
	}
	return revStr
}

// downloadfilesfromsftpserver downloads a single file from the SFTP server.
// It opens the remote file, creates a local file, and copies the contents.
func downloadfilesfromsftpserver(name string, sc *sftp.Client, folder string, srcfolder string) error {
	// Note: SFTP To Go doesn't support O_RDWR mode
	srcFile, err := sc.OpenFile(srcfolder+name, (os.O_RDONLY))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to open remote file: %v\n", err)
		return err
	}
	defer srcFile.Close()

	dstFile, err := os.Create(strings.ReplaceAll(strings.ReplaceAll(folder+"/"+srcfolder+name, "//", "/"), "./", ""))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to open local file: %v\n", err)
		return err
	}
	defer dstFile.Close()
	bytes, err := io.Copy(dstFile, srcFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to download remote file: %v\n and %v", err, bytes)
		return err
	}
	return nil
}

// SyncImportState notifies the panel of the import operation status.
// This is used to update the panel's knowledge of whether the import succeeded or failed.
func (s *Server) SyncImportState(successful bool) error {
	return s.client.SetImportStatus(s.Context(), s.ID(), successful)
}

// internalImportFtp handles the FTP import process.
// This is an internal function that wraps the actual FTP import logic
// and provides consistent logging and error handling.
func (s *Server) internalImportFtp(user string, password string, hote string, port int, srclocation string, dstlocation string) error {

	s.Log().Info("beginning import process for server")
	if err := s.ServerImporterFtp(user, password, hote, port, srclocation, dstlocation); err != nil {
		return err
	}
	s.Log().Info("completed import process for server")
	return nil
}

// ServerImporterFtp performs the actual FTP file import operation.
// It establishes an FTP connection to the remote server and recursively
// downloads all files and directories from the source location to the destination.
//
// Parameters:
//   - user: Remote server username for FTP authentication
//   - password: Remote server password for FTP authentication
//   - hote: Remote server hostname or IP address
//   - port: Remote server FTP port (typically 21)
//   - srclocation: Source location on remote server (absolute path)
//   - dstlocation: Destination location on local server (relative to server root)
//
// Returns an error if the connection, file listing, or file transfer fails.
func (s *Server) ServerImporterFtp(user string, password string, hote string, port int, srclocation string, dstlocation string) error {
	config := goftp.Config{
		User:               user,
		Password:           password,
		ConnectionsPerHost: 10,
		Timeout:            10 * time.Second,
	}

	cleaned := filepath.Clean(filepath.Join(s.fs.Path(), dstlocation))
	os.MkdirAll(cleaned, 0777)

	addr := fmt.Sprintf("%s:%d", hote, port)
	// Connect to server
	sc, err := goftp.DialConfig(config, addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to connecto to [%s]: %v\n", addr, err)
		return err
	}
	files, err := sc.ReadDir("." + srclocation)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to list remote ftp dir: %v\n", err)
		return err
	}

	for _, f := range files {

		var name string

		name = f.Name()
		if f.IsDir() {
			strRune := Runes(name)
			reversed := strRune.ReverseString()
			slashnumber := strings.Index(string(name), "/")
			if string(reversed[slashnumber+1]) != "" {
				os.MkdirAll(cleaned+"/"+name, 0777)
			}
			if err := isdirFtp(name+"/", sc, cleaned, srclocation, dstlocation); err != nil {
				return err
			}

		}
		if !f.IsDir() {

			if err := downloadfilesfromftpserver(name, sc, cleaned, "", srclocation, dstlocation); err != nil {
				return err
			}
		}
	}
	return nil
}

// isdirFtp recursively processes directories during FTP import.
// It creates local directories and processes nested files and subdirectories.
func isdirFtp(dir string, sc *goftp.Client, cleaned string, srclocation string, dstlocation string) error {
	files, err := sc.ReadDir("./" + srclocation + "/" + dir)

	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to list remote ftp isdir: %v\n", err)
		return err
	}
	for _, f := range files {
		var name string

		name = f.Name()

		if f.IsDir() {
			strRune := Runes(name)
			reversed := strRune.ReverseString()
			slashnumber := strings.Index(string(name), "/")
			if string(reversed[slashnumber+1]) != "" {

				os.MkdirAll(cleaned+"/"+dir+name, 0777)
			}
			isdirFtp(dir+name+"/", sc, cleaned, srclocation, dstlocation)
		}
		if !f.IsDir() {
			afterlastslash := strings.Split(name, "/")
			test := strings.Join(afterlastslash[len(afterlastslash)-1:], "")
			slashnumber := strings.ReplaceAll(dir+"/"+name, test, "")

			os.MkdirAll(cleaned+"/"+slashnumber, 0777)
			// Output each file name and size in bytes
			// Note: SFTP To Go doesn't support O_RDWR mode

			if err := downloadfilesfromftpserver(name, sc, cleaned, dir, srclocation, dstlocation); err != nil {
				return err
			}
		}

	}
	return nil
}

// downloadfilesfromftpserver downloads a single file from the FTP server.
// It creates a local file and retrieves the remote file contents.
func downloadfilesfromftpserver(name string, sc *goftp.Client, folder string, srcfolder string, srclocation string, dstlocation string) error {

	// Note: SFTP To Go doesn't support O_RDWR mode
	dstFile, err := os.Create(strings.Replace(folder+"/"+srcfolder+"/"+name, "//", "/", -1))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to open local file: %v\n", err)
		return err
	}
	defer dstFile.Close()
	errr := sc.Retrieve("."+srclocation+"/"+srcfolder+name, dstFile)
	if errr != nil {
		fmt.Fprintf(os.Stderr, "Unable to download remote file: %v\n", errr)
		return errr
	}
	return nil
}
