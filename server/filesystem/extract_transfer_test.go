package filesystem

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// A server being transferred keeps all of its files, including ones the
// denylist would refuse to write.
func TestExtractTransferKeepsDenylistedFiles(t *testing.T) {
	// NewFs sets up the configuration the filesystem reads.
	_, rfs := NewFs()
	t.Cleanup(func() { _ = os.RemoveAll(rfs.root) })
	root := filepath.Join(rfs.root, "server")
	fs, err := New(root, 0, []string{"denied.txt"})
	require.NoError(t, err)
	fs.isTest = true

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, body := range map[string]string{"allowed.txt": "allowed", "denied.txt": "denied"} {
		require.NoError(t, tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg}))
		_, err := tw.Write([]byte(body))
		require.NoError(t, err)
	}
	require.NoError(t, tw.Close())
	require.NoError(t, gz.Close())

	require.NoError(t, fs.ExtractTransfer(context.Background(), &buf))

	for _, name := range []string{"allowed.txt", "denied.txt"} {
		_, err := os.Stat(filepath.Join(root, name))
		require.NoError(t, err, name)
	}
}

// Directories of a transferred server keep the mode they had on the source
// node, also read-only ones, and their files are still written into them.
func TestExtractTransferKeepsDirectoryModes(t *testing.T) {
	_, rfs := NewFs()
	root := filepath.Join(rfs.root, "server")
	t.Cleanup(func() {
		_ = filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
			if err == nil && info.IsDir() {
				_ = os.Chmod(p, 0o755)
			}
			return nil
		})
		_ = os.RemoveAll(rfs.root)
	})
	fs, err := New(root, 0, nil)
	require.NoError(t, err)
	fs.isTest = true

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	require.NoError(t, tw.WriteHeader(&tar.Header{Name: "./", Mode: 0o711, Typeflag: tar.TypeDir}))
	for name, mode := range map[string]int64{"ro/": 0o555, "ro/nested/": 0o500, "private/": 0o700, "open/": 0o755} {
		require.NoError(t, tw.WriteHeader(&tar.Header{Name: name, Mode: mode, Typeflag: tar.TypeDir}))
	}
	for _, name := range []string{"ro/inside.txt", "ro/nested/deep.txt"} {
		require.NoError(t, tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: 6, Typeflag: tar.TypeReg}))
		_, err := tw.Write([]byte("inside"))
		require.NoError(t, err)
	}
	require.NoError(t, tw.Close())
	require.NoError(t, gz.Close())

	before, err := os.Stat(root)
	require.NoError(t, err)

	require.NoError(t, fs.ExtractTransfer(context.Background(), &buf))

	for name, mode := range map[string]os.FileMode{"ro": 0o555, "ro/nested": 0o500, "private": 0o700, "open": 0o755} {
		st, err := os.Stat(filepath.Join(root, name))
		require.NoError(t, err, name)
		require.Equal(t, mode, st.Mode().Perm(), name)
	}
	for _, name := range []string{"ro/inside.txt", "ro/nested/deep.txt"} {
		b, err := os.ReadFile(filepath.Join(root, name))
		require.NoError(t, err, name)
		require.Equal(t, "inside", string(b), name)
	}
	after, err := os.Stat(root)
	require.NoError(t, err)
	require.Equal(t, before.Mode().Perm(), after.Mode().Perm(), "root directory mode")
}
