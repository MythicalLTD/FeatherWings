package parser

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// sizeLimitedFile refuses to grow past limit bytes, like a file that counts
// against a server's disk limit.
type sizeLimitedFile struct {
	*os.File
	limit int64
}

func (f sizeLimitedFile) CheckSize(size int64) error {
	if size > f.limit {
		return errors.New("not enough disk space")
	}
	return nil
}

func tomlTestFile(t *testing.T, content string) (ConfigurationFile, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.toml")
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))

	var cf ConfigurationFile
	require.NoError(t, json.Unmarshal([]byte(`{"file":"config.toml","parser":"toml","replace":[{"match":"server.name","replace_with":"a much longer server name than before"}]}`), &cf))
	cf.configuration = []byte(`{}`)
	return cf, path
}

// A TOML file whose new content doesn't fit in the disk space it may use is
// left as it was instead of being truncated.
func TestTomlRewriteThatDoesNotFitLeavesFile(t *testing.T) {
	const content = "[server]\nname = \"short\"\n"
	cf, path := tomlTestFile(t, content)

	f, err := os.OpenFile(path, os.O_RDWR, 0)
	require.NoError(t, err)
	defer f.Close()

	require.Error(t, cf.parseTomlFile(sizeLimitedFile{File: f, limit: int64(len(content))}))

	b, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, content, string(b))
}

func TestTomlRewriteWritesNewContent(t *testing.T) {
	cf, path := tomlTestFile(t, "[server]\nname = \"short\"\n")

	f, err := os.OpenFile(path, os.O_RDWR, 0)
	require.NoError(t, err)
	defer f.Close()

	require.NoError(t, cf.parseTomlFile(sizeLimitedFile{File: f, limit: 1 << 20}))

	b, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Contains(t, string(b), "a much longer server name than before")
}
