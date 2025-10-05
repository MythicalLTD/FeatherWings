// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2024 Matthew Penner

//go:build unix

package ufs_test

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/mythicalltd/featherwings/internal/ufs"
)

type testUnixFS struct {
	*ufs.UnixFS

	TmpDir string
	Root   string
}

func (fs *testUnixFS) Cleanup() {
	_ = fs.Close()
	_ = os.RemoveAll(fs.TmpDir)
}

func newTestUnixFS() (*testUnixFS, error) {
	tmpDir, err := os.MkdirTemp(os.TempDir(), "ufs")
	if err != nil {
		return nil, err
	}
	root := filepath.Join(tmpDir, "root")
	if err := os.Mkdir(root, 0o755); err != nil {
		return nil, err
	}
	// fmt.Println(tmpDir)
	fs, err := ufs.NewUnixFS(root, true)
	if err != nil {
		return nil, err
	}
	tfs := &testUnixFS{
		UnixFS: fs,
		TmpDir: tmpDir,
		Root:   root,
	}
	return tfs, nil
}

func TestUnixFS(t *testing.T) {
	t.Parallel()

	fs, err := newTestUnixFS()
	if err != nil {
		t.Fatal(err)
		return
	}
	defer fs.Cleanup()

	// Test creating a file within the root.
	_, _, closeFd, err := fs.SafePath("/")
	closeFd()
	if err != nil {
		t.Error(err)
		return
	}

	f, err := fs.Touch("directory/file", ufs.O_RDWR, 0o644)
	if err != nil {
		t.Error(err)
		return
	}
	_ = f.Close()

	// Test creating a file within the root.
	f, err = fs.Create("test")
	if err != nil {
		t.Error(err)
		return
	}
	_ = f.Close()

	// Test stating a file within the root.
	if _, err := fs.Stat("test"); err != nil {
		t.Error(err)
		return
	}

	// Test creating a directory within the root.
	if err := fs.Mkdir("ima_directory", 0o755); err != nil {
		t.Error(err)
		return
	}

	// Test creating a nested directory within the root.
	if err := fs.Mkdir("ima_directory/ima_nother_directory", 0o755); err != nil {
		t.Error(err)
		return
	}

	// Test creating a file inside a directory within the root.
	f, err = fs.Create("ima_directory/ima_file")
	if err != nil {
		t.Error(err)
		return
	}
	_ = f.Close()

	// Test listing directory entries.
	if _, err := fs.ReadDir("ima_directory"); err != nil {
		t.Error(err)
		return
	}

	// Test symlink pointing outside the root.
	if err := os.Symlink(fs.TmpDir, filepath.Join(fs.Root, "ima_bad_link")); err != nil {
		t.Error(err)
		return
	}
	f, err = fs.Create("ima_bad_link/ima_bad_file")
	if err == nil {
		_ = f.Close()
		t.Error("expected an error")
		return
	}
	if err := fs.Mkdir("ima_bad_link/ima_bad_directory", 0o755); err == nil {
		t.Error("expected an error")
		return
	}

	// Test symlink pointing outside the root inside a parent directory.
	if err := fs.Symlink(fs.TmpDir, filepath.Join(fs.Root, "ima_directory/ima_bad_link")); err != nil {
		t.Error(err)
		return
	}
	if err := fs.Mkdir("ima_directory/ima_bad_link/ima_bad_directory", 0o755); err == nil {
		t.Error("expected an error")
		return
	}

	// Test symlink pointing outside the root with a child directory.
	if err := os.Mkdir(filepath.Join(fs.TmpDir, "ima_directory"), 0o755); err != nil {
		t.Error(err)
		return
	}
	f, err = fs.Create("ima_bad_link/ima_directory/ima_bad_file")
	if err == nil {
		_ = f.Close()
		t.Error("expected an error")
		return
	}
	if err := fs.Mkdir("ima_bad_link/ima_directory/ima_bad_directory", 0o755); err == nil {
		t.Error("expected an error")
		return
	}

	if _, err := fs.ReadDir("ima_bad_link/ima_directory"); err == nil {
		t.Error("expected an error")
		return
	}

	// Create multiple nested directories.
	if err := fs.MkdirAll("ima_directory/ima_directory/ima_directory/ima_directory", 0o755); err != nil {
		t.Error(err)
		return
	}
	if _, err := fs.ReadDir("ima_directory/ima_directory"); err != nil {
		t.Error(err)
		return
	}

	// Test creating a directory under a symlink with a pre-existing directory.
	if err := fs.MkdirAll("ima_bad_link/ima_directory/ima_bad_directory/ima_bad_directory", 0o755); err == nil {
		t.Error("expected an error")
		return
	}

	// Test deletion
	if err := fs.Remove("test"); err != nil {
		t.Error(err)
		return
	}
	if err := fs.Remove("ima_bad_link"); err != nil {
		t.Error(err)
		return
	}

	// Test recursive deletion
	if err := fs.RemoveAll("ima_directory"); err != nil {
		t.Error(err)
		return
	}

	// Test recursive deletion underneath a bad symlink
	if err := fs.Mkdir("ima_directory", 0o755); err != nil {
		t.Error(err)
		return
	}
	if err := fs.Symlink(fs.TmpDir, filepath.Join(fs.Root, "ima_directory/ima_bad_link")); err != nil {
		t.Error(err)
		return
	}
	if err := fs.RemoveAll("ima_directory/ima_bad_link/ima_bad_file"); err == nil {
		t.Error("expected an error")
		return
	}

	// This should delete the symlink itself.
	if err := fs.RemoveAll("ima_directory/ima_bad_link"); err != nil {
		t.Error(err)
		return
	}

	//for i := 0; i < 5; i++ {
	//	dirName := "dir" + strconv.Itoa(i)
	//	if err := fs.Mkdir(dirName, 0o755); err != nil {
	//		t.Error(err)
	//		return
	//	}
	//	for j := 0; j < 5; j++ {
	//		f, err := fs.Create(filepath.Join(dirName, "file"+strconv.Itoa(j)))
	//		if err != nil {
	//			t.Error(err)
	//			return
	//		}
	//		_ = f.Close()
	//	}
	//}
	//
	//if err := fs.WalkDir2("", func(fd int, path string, info filesystem.DirEntry, err error) error {
	//	if err != nil {
	//		return err
	//	}
	//	fmt.Println(path)
	//	return nil
	//}); err != nil {
	//	t.Error(err)
	//	return
	//}
}

func TestUnixFS_Chmod(t *testing.T) {
	t.Parallel()
	fs, err := newTestUnixFS()
	if err != nil {
		t.Fatal(err)
		return
	}
	defer fs.Cleanup()

	// Create a test file
	f, err := fs.Create("test_file")
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Close()

	// Test changing permissions to 0755
	if err := fs.Chmod("test_file", 0o755); err != nil {
		t.Errorf("Chmod failed: %v", err)
	}

	// Verify the permissions were changed
	info, err := fs.Stat("test_file")
	if err != nil {
		t.Errorf("Stat failed: %v", err)
	}
	if info.Mode()&0o777 != 0o755 {
		t.Errorf("Expected mode 0755, got %o", info.Mode()&0o777)
	}

	// Test changing permissions to 0644
	if err := fs.Chmod("test_file", 0o644); err != nil {
		t.Errorf("Chmod failed: %v", err)
	}

	// Verify the permissions were changed again
	info, err = fs.Stat("test_file")
	if err != nil {
		t.Errorf("Stat failed: %v", err)
	}
	if info.Mode()&0o777 != 0o644 {
		t.Errorf("Expected mode 0644, got %o", info.Mode()&0o777)
	}
}

func TestUnixFS_Chown(t *testing.T) {
	t.Parallel()
	fs, err := newTestUnixFS()
	if err != nil {
		t.Fatal(err)
		return
	}
	defer fs.Cleanup()

	// Create a test file
	f, err := fs.Create("test_file")
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Close()

	// Get current user info
	currentUser := os.Getuid()
	currentGroup := os.Getgid()

	// Test changing ownership (should work if running as root, may fail otherwise)
	err = fs.Chown("test_file", currentUser, currentGroup)
	if err != nil {
		// This is expected to fail on most systems unless running as root
		t.Logf("Chown failed (expected on non-root systems): %v", err)
		return
	}

	// Verify the ownership was changed
	info, err := fs.Stat("test_file")
	if err != nil {
		t.Errorf("Stat failed: %v", err)
	}

	// Note: FileInfo.Sys() returns the underlying stat structure
	// The exact type depends on the platform, so we just verify it's not nil
	if info.Sys() == nil {
		t.Error("FileInfo.Sys() returned nil")
	}
}

func TestUnixFS_Lchown(t *testing.T) {
	t.Parallel()
	fs, err := newTestUnixFS()
	if err != nil {
		t.Fatal(err)
		return
	}
	defer fs.Cleanup()

	// Create a test file
	f, err := fs.Create("test_file")
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Close()

	// Create a symlink to the test file
	if err := fs.Symlink("test_file", "test_link"); err != nil {
		t.Fatal(err)
	}

	// Get current user info
	currentUser := os.Getuid()
	currentGroup := os.Getgid()

	// Test changing ownership of the symlink itself (not the target)
	err = fs.Lchown("test_link", currentUser, currentGroup)
	if err != nil {
		// This is expected to fail on most systems unless running as root
		t.Logf("Lchown failed (expected on non-root systems): %v", err)
		return
	}

	// Verify the symlink still exists and points to the right target
	info, err := fs.Lstat("test_link")
	if err != nil {
		t.Errorf("Lstat failed: %v", err)
	}
	if !info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 {
		t.Error("Expected symlink, but Lstat didn't return symlink mode")
	}
}

func TestUnixFS_Chtimes(t *testing.T) {
	t.Parallel()
	fs, err := newTestUnixFS()
	if err != nil {
		t.Fatal(err)
		return
	}
	defer fs.Cleanup()

	// Create a test file
	f, err := fs.Create("test_file")
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Close()

	// Get the current time
	now := time.Now()

	// Set specific access and modification times
	accessTime := now.Add(-2 * time.Hour)
	modTime := now.Add(-1 * time.Hour)

	// Test changing the times
	if err := fs.Chtimes("test_file", accessTime, modTime); err != nil {
		t.Errorf("Chtimes failed: %v", err)
	}

	// Verify the times were changed
	info, err := fs.Stat("test_file")
	if err != nil {
		t.Errorf("Stat failed: %v", err)
	}

	// Check modification time (access time is harder to verify on some systems)
	if !info.ModTime().Equal(modTime) {
		// Allow for some precision loss
		diff := info.ModTime().Sub(modTime)
		if diff < -time.Second || diff > time.Second {
			t.Errorf("Expected mod time %v, got %v (diff: %v)", modTime, info.ModTime(), diff)
		}
	}
}

func TestUnixFS_Create(t *testing.T) {
	t.Parallel()
	fs, err := newTestUnixFS()
	if err != nil {
		t.Fatal(err)
		return
	}
	defer fs.Cleanup()

	// Test creating a new file
	f, err := fs.Create("test_file")
	if err != nil {
		t.Errorf("Create failed: %v", err)
		return
	}
	defer f.Close()

	// Verify the file was created
	info, err := fs.Stat("test_file")
	if err != nil {
		t.Errorf("Stat failed: %v", err)
		return
	}

	if !info.Mode().IsRegular() {
		t.Error("Created file is not a regular file")
	}

	if info.Size() != 0 {
		t.Errorf("Expected file size 0, got %d", info.Size())
	}

	// Test creating a file that already exists (should truncate)
	_, err = f.Write([]byte("test content"))
	if err != nil {
		t.Errorf("Write failed: %v", err)
	}
	f.Close()

	// Create again - should truncate
	f2, err := fs.Create("test_file")
	if err != nil {
		t.Errorf("Create failed: %v", err)
		return
	}
	defer f2.Close()

	// Verify the file was truncated
	info, err = fs.Stat("test_file")
	if err != nil {
		t.Errorf("Stat failed: %v", err)
		return
	}

	if info.Size() != 0 {
		t.Errorf("Expected file size 0 after truncate, got %d", info.Size())
	}
}

func TestUnixFS_Mkdir(t *testing.T) {
	t.Parallel()
	fs, err := newTestUnixFS()
	if err != nil {
		t.Fatal(err)
		return
	}
	defer fs.Cleanup()

	// Test creating a directory
	if err := fs.Mkdir("test_dir", 0o755); err != nil {
		t.Errorf("Mkdir failed: %v", err)
		return
	}

	// Verify the directory was created
	info, err := fs.Stat("test_dir")
	if err != nil {
		t.Errorf("Stat failed: %v", err)
		return
	}

	if !info.IsDir() {
		t.Error("Created directory is not a directory")
	}

	// Test creating a directory that already exists (should fail)
	if err := fs.Mkdir("test_dir", 0o755); err == nil {
		t.Error("Expected error when creating existing directory")
	}

	// Test creating a nested directory
	if err := fs.Mkdir("test_dir/nested", 0o755); err != nil {
		t.Errorf("Mkdir failed for nested directory: %v", err)
		return
	}

	// Verify the nested directory was created
	info, err = fs.Stat("test_dir/nested")
	if err != nil {
		t.Errorf("Stat failed for nested directory: %v", err)
		return
	}

	if !info.IsDir() {
		t.Error("Created nested directory is not a directory")
	}
}

func TestUnixFS_MkdirAll(t *testing.T) {
	t.Parallel()
	fs, err := newTestUnixFS()
	if err != nil {
		t.Fatal(err)
		return
	}
	defer fs.Cleanup()

	if err := fs.MkdirAll("/a/bunch/of/directories", 0o755); err != nil {
		t.Error(err)
		return
	}

	// TODO: stat sanity check
}

func TestUnixFS_Open(t *testing.T) {
	t.Parallel()
	fs, err := newTestUnixFS()
	if err != nil {
		t.Fatal(err)
		return
	}
	defer fs.Cleanup()

	// Create a test file with some content
	f, err := fs.Create("test_file")
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.Write([]byte("test content"))
	if err != nil {
		t.Fatal(err)
	}
	f.Close()

	// Test opening the file for reading
	f, err = fs.Open("test_file")
	if err != nil {
		t.Errorf("Open failed: %v", err)
		return
	}
	defer f.Close()

	// Read the content
	buf := make([]byte, 20)
	n, err := f.Read(buf)
	if err != nil && err.Error() != "EOF" {
		t.Errorf("Read failed: %v", err)
		return
	}

	content := string(buf[:n])
	if content != "test content" {
		t.Errorf("Expected 'test content', got '%s'", content)
	}

	// Test opening a non-existent file
	_, err = fs.Open("non_existent_file")
	if err == nil {
		t.Error("Expected error when opening non-existent file")
	}
}

func TestUnixFS_OpenFile(t *testing.T) {
	t.Parallel()
	fs, err := newTestUnixFS()
	if err != nil {
		t.Fatal(err)
		return
	}
	defer fs.Cleanup()

	// Test opening a file for reading (O_RDONLY)
	f, err := fs.OpenFile("test_file", ufs.O_RDONLY, 0)
	if err == nil {
		f.Close()
		t.Error("Expected error when opening non-existent file")
	}

	// Create a test file
	f, err = fs.Create("test_file")
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.Write([]byte("test content"))
	if err != nil {
		t.Fatal(err)
	}
	f.Close()

	// Test opening for reading
	f, err = fs.OpenFile("test_file", ufs.O_RDONLY, 0)
	if err != nil {
		t.Errorf("OpenFile failed for reading: %v", err)
		return
	}
	defer f.Close()

	// Test opening for writing (O_WRONLY)
	f2, err := fs.OpenFile("test_file", ufs.O_WRONLY, 0)
	if err != nil {
		t.Errorf("OpenFile failed for writing: %v", err)
		return
	}
	defer f2.Close()

	// Test opening for read-write (O_RDWR)
	f3, err := fs.OpenFile("test_file", ufs.O_RDWR, 0)
	if err != nil {
		t.Errorf("OpenFile failed for read-write: %v", err)
		return
	}
	defer f3.Close()

	// Test creating a new file (O_CREATE)
	f4, err := fs.OpenFile("new_file", ufs.O_CREATE|ufs.O_WRONLY, 0o644)
	if err != nil {
		t.Errorf("OpenFile failed for create: %v", err)
		return
	}
	defer f4.Close()

	// Verify the new file was created
	info, err := fs.Stat("new_file")
	if err != nil {
		t.Errorf("Stat failed: %v", err)
		return
	}

	if !info.Mode().IsRegular() {
		t.Error("Created file is not a regular file")
	}
}

func TestUnixFS_ReadDir(t *testing.T) {
	t.Parallel()
	fs, err := newTestUnixFS()
	if err != nil {
		t.Fatal(err)
		return
	}
	defer fs.Cleanup()

	// Create some test files and directories
	if err := fs.Mkdir("test_dir", 0o755); err != nil {
		t.Fatal(err)
	}

	f1, err := fs.Create("file1")
	if err != nil {
		t.Fatal(err)
	}
	f1.Close()

	f2, err := fs.Create("file2")
	if err != nil {
		t.Fatal(err)
	}
	f2.Close()

	f3, err := fs.Create("test_dir/file3")
	if err != nil {
		t.Fatal(err)
	}
	f3.Close()

	// Test reading the root directory
	entries, err := fs.ReadDir("")
	if err != nil {
		t.Errorf("ReadDir failed: %v", err)
		return
	}

	// Should have at least 3 entries: test_dir, file1, file2
	if len(entries) < 3 {
		t.Errorf("Expected at least 3 entries, got %d", len(entries))
	}

	// Check that we have the expected entries
	names := make(map[string]bool)
	for _, entry := range entries {
		names[entry.Name()] = true
	}

	if !names["test_dir"] {
		t.Error("Expected 'test_dir' in directory listing")
	}
	if !names["file1"] {
		t.Error("Expected 'file1' in directory listing")
	}
	if !names["file2"] {
		t.Error("Expected 'file2' in directory listing")
	}

	// Test reading a subdirectory
	entries, err = fs.ReadDir("test_dir")
	if err != nil {
		t.Errorf("ReadDir failed for subdirectory: %v", err)
		return
	}

	if len(entries) != 1 {
		t.Errorf("Expected 1 entry in test_dir, got %d", len(entries))
	}

	if len(entries) > 0 && entries[0].Name() != "file3" {
		t.Errorf("Expected 'file3' in test_dir, got '%s'", entries[0].Name())
	}

	// Test reading a non-existent directory
	_, err = fs.ReadDir("non_existent_dir")
	if err == nil {
		t.Error("Expected error when reading non-existent directory")
	}
}

func TestUnixFS_Remove(t *testing.T) {
	t.Parallel()
	fs, err := newTestUnixFS()
	if err != nil {
		t.Fatal(err)
		return
	}
	defer fs.Cleanup()

	t.Run("base directory", func(t *testing.T) {
		// Try to remove the base directory.
		if err := fs.Remove(""); !errors.Is(err, ufs.ErrBadPathResolution) {
			t.Errorf("expected an a bad path resolution error, but got: %v", err)
			return
		}
	})

	t.Run("path traversal", func(t *testing.T) {
		// Try to remove the base directory.
		if err := fs.RemoveAll("../root"); !errors.Is(err, ufs.ErrBadPathResolution) {
			t.Errorf("expected an a bad path resolution error, but got: %v", err)
			return
		}
	})
}

func TestUnixFS_RemoveAll(t *testing.T) {
	t.Parallel()
	fs, err := newTestUnixFS()
	if err != nil {
		t.Fatal(err)
		return
	}
	defer fs.Cleanup()

	t.Run("base directory", func(t *testing.T) {
		// Try to remove the base directory.
		if err := fs.RemoveAll(""); !errors.Is(err, ufs.ErrBadPathResolution) {
			t.Errorf("expected an a bad path resolution error, but got: %v", err)
			return
		}
	})

	t.Run("path traversal", func(t *testing.T) {
		// Try to remove the base directory.
		if err := fs.RemoveAll("../root"); !errors.Is(err, ufs.ErrBadPathResolution) {
			t.Errorf("expected an a bad path resolution error, but got: %v", err)
			return
		}
	})
}

func TestUnixFS_Rename(t *testing.T) {
	t.Parallel()
	fs, err := newTestUnixFS()
	if err != nil {
		t.Fatal(err)
		return
	}
	defer fs.Cleanup()

	t.Run("rename base directory", func(t *testing.T) {
		// Try to rename the base directory.
		if err := fs.Rename("", "yeet"); !errors.Is(err, ufs.ErrBadPathResolution) {
			t.Errorf("expected an a bad path resolution error, but got: %v", err)
			return
		}
	})

	t.Run("rename over base directory", func(t *testing.T) {
		// Create a directory that we are going to try and move over top of the
		// existing base directory.
		if err := fs.Mkdir("overwrite_dir", 0o755); err != nil {
			t.Error(err)
			return
		}

		// Try to rename over the base directory.
		if err := fs.Rename("overwrite_dir", ""); !errors.Is(err, ufs.ErrBadPathResolution) {
			t.Errorf("expected an a bad path resolution error, but got: %v", err)
			return
		}
	})

	t.Run("directory rename", func(t *testing.T) {
		// Create a directory to rename to something else.
		if err := fs.Mkdir("test_directory", 0o755); err != nil {
			t.Error(err)
			return
		}

		// Try to rename "test_directory" to "directory".
		if err := fs.Rename("test_directory", "directory"); err != nil {
			t.Errorf("expected no error, but got: %v", err)
			return
		}

		// Sanity check
		if _, err := os.Lstat(filepath.Join(fs.Root, "directory")); err != nil {
			t.Errorf("Lstat errored when performing sanity check: %v", err)
			return
		}
	})

	t.Run("file rename", func(t *testing.T) {
		// Create a directory to rename to something else.
		f, err := fs.Create("test_file")
		if err != nil {
			t.Error(err)
			return
		}
		_ = f.Close()

		// Try to rename "test_file" to "file".
		if err := fs.Rename("test_file", "file"); err != nil {
			t.Errorf("expected no error, but got: %v", err)
			return
		}

		// Sanity check
		if _, err := os.Lstat(filepath.Join(fs.Root, "file")); err != nil {
			t.Errorf("Lstat errored when performing sanity check: %v", err)
			return
		}
	})
}

func TestUnixFS_Stat(t *testing.T) {
	t.Parallel()
	fs, err := newTestUnixFS()
	if err != nil {
		t.Fatal(err)
		return
	}
	defer fs.Cleanup()

	// Create a test file
	f, err := fs.Create("test_file")
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.Write([]byte("test content"))
	if err != nil {
		t.Fatal(err)
	}
	f.Close()

	// Create a test directory
	if err := fs.Mkdir("test_dir", 0o755); err != nil {
		t.Fatal(err)
	}

	// Test statting a file
	info, err := fs.Stat("test_file")
	if err != nil {
		t.Errorf("Stat failed for file: %v", err)
		return
	}

	if !info.Mode().IsRegular() {
		t.Error("Expected regular file")
	}
	if info.Size() != 12 { // "test content" is 12 bytes
		t.Errorf("Expected size 12, got %d", info.Size())
	}
	if info.Name() != "test_file" {
		t.Errorf("Expected name 'test_file', got '%s'", info.Name())
	}

	// Test statting a directory
	info, err = fs.Stat("test_dir")
	if err != nil {
		t.Errorf("Stat failed for directory: %v", err)
		return
	}

	if !info.IsDir() {
		t.Error("Expected directory")
	}
	if info.Name() != "test_dir" {
		t.Errorf("Expected name 'test_dir', got '%s'", info.Name())
	}

	// Test statting a non-existent file
	_, err = fs.Stat("non_existent_file")
	if err == nil {
		t.Error("Expected error when statting non-existent file")
	}
}

func TestUnixFS_Lstat(t *testing.T) {
	t.Parallel()
	fs, err := newTestUnixFS()
	if err != nil {
		t.Fatal(err)
		return
	}
	defer fs.Cleanup()

	// Create a test file
	f, err := fs.Create("test_file")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()

	// Create a symlink to the test file
	if err := fs.Symlink("test_file", "test_link"); err != nil {
		t.Fatal(err)
	}

	// Test lstatting a regular file (should be the same as stat)
	info, err := fs.Lstat("test_file")
	if err != nil {
		t.Errorf("Lstat failed for file: %v", err)
		return
	}

	if !info.Mode().IsRegular() {
		t.Error("Expected regular file")
	}

	// Test lstatting a symlink (should return info about the symlink, not the target)
	info, err = fs.Lstat("test_link")
	if err != nil {
		t.Errorf("Lstat failed for symlink: %v", err)
		return
	}

	// Check if it's a symlink
	if info.Mode()&os.ModeSymlink == 0 {
		t.Error("Expected symlink")
	}

	// Compare with Stat (which follows symlinks)
	statInfo, err := fs.Stat("test_link")
	if err != nil {
		t.Errorf("Stat failed for symlink: %v", err)
		return
	}

	// Lstat should return different info than Stat for symlinks
	if info.Mode() == statInfo.Mode() {
		t.Error("Lstat and Stat returned the same mode for symlink")
	}

	// Test lstatting a non-existent file
	_, err = fs.Lstat("non_existent_file")
	if err == nil {
		t.Error("Expected error when lstatting non-existent file")
	}
}

func TestUnixFS_Symlink(t *testing.T) {
	t.Parallel()
	fs, err := newTestUnixFS()
	if err != nil {
		t.Fatal(err)
		return
	}
	defer fs.Cleanup()

	// Create a test file
	f, err := fs.Create("test_file")
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.Write([]byte("test content"))
	if err != nil {
		t.Fatal(err)
	}
	f.Close()

	// Test creating a symlink to a file
	if err := fs.Symlink("test_file", "file_link"); err != nil {
		t.Errorf("Symlink failed: %v", err)
		return
	}

	// Verify the symlink was created
	info, err := fs.Lstat("file_link")
	if err != nil {
		t.Errorf("Lstat failed: %v", err)
		return
	}

	if info.Mode()&os.ModeSymlink == 0 {
		t.Error("Expected symlink")
	}

	// Test that the symlink points to the correct target
	linkInfo, err := fs.Stat("file_link")
	if err != nil {
		t.Errorf("Stat failed on symlink: %v", err)
		return
	}

	if !linkInfo.Mode().IsRegular() {
		t.Error("Symlink should point to a regular file")
	}

	// Test creating a symlink to a directory
	if err := fs.Mkdir("test_dir", 0o755); err != nil {
		t.Fatal(err)
	}

	if err := fs.Symlink("test_dir", "dir_link"); err != nil {
		t.Errorf("Symlink to directory failed: %v", err)
		return
	}

	// Verify the directory symlink
	info, err = fs.Lstat("dir_link")
	if err != nil {
		t.Errorf("Lstat failed on directory symlink: %v", err)
		return
	}

	if info.Mode()&os.ModeSymlink == 0 {
		t.Error("Expected directory symlink")
	}

	// Test that the directory symlink works
	linkInfo, err = fs.Stat("dir_link")
	if err != nil {
		t.Errorf("Stat failed on directory symlink: %v", err)
		return
	}

	if !linkInfo.IsDir() {
		t.Error("Directory symlink should point to a directory")
	}

	// Test creating a symlink that already exists (should fail)
	if err := fs.Symlink("test_file", "file_link"); err == nil {
		t.Error("Expected error when creating existing symlink")
	}

	// Test creating a symlink to a non-existent target (should still work)
	if err := fs.Symlink("non_existent", "broken_link"); err != nil {
		t.Errorf("Symlink to non-existent target failed: %v", err)
		return
	}

	// Verify the broken symlink exists
	info, err = fs.Lstat("broken_link")
	if err != nil {
		t.Errorf("Lstat failed on broken symlink: %v", err)
		return
	}

	if info.Mode()&os.ModeSymlink == 0 {
		t.Error("Expected broken symlink")
	}

	// Test that accessing the broken symlink fails
	_, err = fs.Stat("broken_link")
	if err == nil {
		t.Error("Expected error when accessing broken symlink")
	}
}

func TestUnixFS_Touch(t *testing.T) {
	t.Parallel()
	fs, err := newTestUnixFS()
	if err != nil {
		t.Fatal(err)
		return
	}
	defer fs.Cleanup()

	t.Run("base directory", func(t *testing.T) {
		path := "i_touched_a_file"
		f, err := fs.Touch(path, ufs.O_RDWR, 0o644)
		if err != nil {
			t.Error(err)
			return
		}
		_ = f.Close()

		// Sanity check
		if _, err := os.Lstat(filepath.Join(fs.Root, path)); err != nil {
			t.Errorf("Lstat errored when performing sanity check: %v", err)
			return
		}
	})

	t.Run("existing parent directory", func(t *testing.T) {
		dir := "some_parent_directory"
		if err := fs.Mkdir(dir, 0o755); err != nil {
			t.Errorf("error creating parent directory: %v", err)
			return
		}
		path := filepath.Join(dir, "i_touched_a_file")
		f, err := fs.Touch(path, ufs.O_RDWR, 0o644)
		if err != nil {
			t.Errorf("error touching file: %v", err)
			return
		}
		_ = f.Close()

		// Sanity check
		if _, err := os.Lstat(filepath.Join(fs.Root, path)); err != nil {
			t.Errorf("Lstat errored when performing sanity check: %v", err)
			return
		}
	})

	t.Run("non-existent parent directory", func(t *testing.T) {
		path := "some_other_directory/i_touched_a_file"
		f, err := fs.Touch(path, ufs.O_RDWR, 0o644)
		if err != nil {
			t.Errorf("error touching file: %v", err)
			return
		}
		_ = f.Close()

		// Sanity check
		if _, err := os.Lstat(filepath.Join(fs.Root, path)); err != nil {
			t.Errorf("Lstat errored when performing sanity check: %v", err)
			return
		}
	})

	t.Run("non-existent parent directories", func(t *testing.T) {
		path := "some_other_directory/some_directory/i_touched_a_file"
		f, err := fs.Touch(path, ufs.O_RDWR, 0o644)
		if err != nil {
			t.Errorf("error touching file: %v", err)
			return
		}
		_ = f.Close()

		// Sanity check
		if _, err := os.Lstat(filepath.Join(fs.Root, path)); err != nil {
			t.Errorf("Lstat errored when performing sanity check: %v", err)
			return
		}
	})
}

func TestUnixFS_WalkDir(t *testing.T) {
	t.Parallel()
	fs, err := newTestUnixFS()
	if err != nil {
		t.Fatal(err)
		return
	}
	defer fs.Cleanup()

	//for i := 0; i < 5; i++ {
	//	dirName := "dir" + strconv.Itoa(i)
	//	if err := fs.Mkdir(dirName, 0o755); err != nil {
	//		t.Error(err)
	//		return
	//	}
	//	for j := 0; j < 5; j++ {
	//		f, err := fs.Create(filepath.Join(dirName, "file"+strconv.Itoa(j)))
	//		if err != nil {
	//			t.Error(err)
	//			return
	//		}
	//		_ = f.Close()
	//	}
	//}
	//
	//if err := fs.WalkDir(".", func(path string, info ufs.DirEntry, err error) error {
	//	if err != nil {
	//		return err
	//	}
	//	t.Log(path)
	//	return nil
	//}); err != nil {
	//	t.Error(err)
	//	return
	//}
}

func TestUnixFS_WalkDirat(t *testing.T) {
	t.Parallel()
	fs, err := newTestUnixFS()
	if err != nil {
		t.Fatal(err)
		return
	}
	defer fs.Cleanup()

	for i := 0; i < 2; i++ {
		dirName := "base" + strconv.Itoa(i)
		if err := fs.Mkdir(dirName, 0o755); err != nil {
			t.Error(err)
			return
		}
		for j := 0; j < 1; j++ {
			f, err := fs.Create(filepath.Join(dirName, "file"+strconv.Itoa(j)))
			if err != nil {
				t.Error(err)
				return
			}
			_ = f.Close()
			if err := fs.Mkdir(filepath.Join(dirName, "dir"+strconv.Itoa(j)), 0o755); err != nil {
				t.Error(err)
				return
			}
			f, err = fs.Create(filepath.Join(dirName, "dir"+strconv.Itoa(j), "file"+strconv.Itoa(j)))
			if err != nil {
				t.Error(err)
				return
			}
			_ = f.Close()
		}
	}

	t.Run("walk starting at the filesystem root", func(t *testing.T) {
		pathsTraversed, err := fs.testWalkDirAt("")
		if err != nil {
			t.Error(err)
			return
		}
		expect := []Path{
			{Name: ".", Relative: "."},
			{Name: "base0", Relative: "base0"},
			{Name: "dir0", Relative: "base0/dir0"},
			{Name: "file0", Relative: "base0/dir0/file0"},
			{Name: "file0", Relative: "base0/file0"},
			{Name: "base1", Relative: "base1"},
			{Name: "dir0", Relative: "base1/dir0"},
			{Name: "file0", Relative: "base1/dir0/file0"},
			{Name: "file0", Relative: "base1/file0"},
		}
		if !reflect.DeepEqual(pathsTraversed, expect) {
			t.Log(pathsTraversed)
			t.Log(expect)
			t.Error("walk doesn't match")
			return
		}
	})

	t.Run("walk starting in a directory", func(t *testing.T) {
		pathsTraversed, err := fs.testWalkDirAt("base0")
		if err != nil {
			t.Error(err)
			return
		}
		expect := []Path{
			// TODO: what should relative actually be here?
			// The behaviour differs from walking the directory root vs a sub
			// directory. When walking from the root, dirfd is the directory we
			// are walking from and both name and relative are `.`. However,
			// when walking from a subdirectory, fd is the parent of the
			// subdirectory, and name is the subdirectory.
			{Name: "base0", Relative: "."},
			{Name: "dir0", Relative: "dir0"},
			{Name: "file0", Relative: "dir0/file0"},
			{Name: "file0", Relative: "file0"},
		}
		if !reflect.DeepEqual(pathsTraversed, expect) {
			t.Log(pathsTraversed)
			t.Log(expect)
			t.Error("walk doesn't match")
			return
		}
	})
}

type Path struct {
	Name     string
	Relative string
}

func (fs *testUnixFS) testWalkDirAt(path string) ([]Path, error) {
	dirfd, name, closeFd, err := fs.SafePath(path)
	defer closeFd()
	if err != nil {
		return nil, err
	}
	var pathsTraversed []Path
	if err := fs.WalkDirat(dirfd, name, func(_ int, name, relative string, _ ufs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		pathsTraversed = append(pathsTraversed, Path{Name: name, Relative: relative})
		return nil
	}); err != nil {
		return nil, err
	}
	slices.SortStableFunc(pathsTraversed, func(a, b Path) int {
		if a.Relative > b.Relative {
			return 1
		}
		if a.Relative < b.Relative {
			return -1
		}
		return 0
	})
	return pathsTraversed, nil
}
