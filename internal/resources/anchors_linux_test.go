//go:build linux

package resources

import (
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEnumerateAnchorDir(t *testing.T) {
	t.Run("empty dir argument returns nil", func(t *testing.T) {
		out, err := EnumerateAnchorDir("")
		require.NoError(t, err)
		assert.Nil(t, out)
	})

	t.Run("missing dir is not an error", func(t *testing.T) {
		out, err := EnumerateAnchorDir(filepath.Join(t.TempDir(), "no-such-dir"))
		require.NoError(t, err)
		assert.Nil(t, out)
	})

	t.Run("empty existing dir returns no entries", func(t *testing.T) {
		out, err := EnumerateAnchorDir(t.TempDir())
		require.NoError(t, err)
		assert.Empty(t, out)
	})

	t.Run("mixed extensions and junk files", func(t *testing.T) {
		dir := t.TempDir()
		// Two valid certs with different extensions.
		require.NoError(t, os.WriteFile(filepath.Join(dir, "a.crt"), makeTestPEM(t, "anchor-a"), 0o644))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "b.pem"), makeTestPEM(t, "anchor-b"), 0o644))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "c.cer"), makeTestPEM(t, "anchor-c"), 0o644))
		// Junk that should be ignored.
		require.NoError(t, os.WriteFile(filepath.Join(dir, "README"), []byte("docs"), 0o644))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("notes"), 0o644))
		// An unparseable cert file (correct extension, bad content).
		require.NoError(t, os.WriteFile(filepath.Join(dir, "broken.pem"), []byte("not a certificate"), 0o644))
		// A subdirectory with a cert that should NOT be picked up (non-recursive).
		require.NoError(t, os.MkdirAll(filepath.Join(dir, "subdir"), 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "subdir", "nested.pem"), makeTestPEM(t, "anchor-nested"), 0o644))

		entries, err := EnumerateAnchorDir(dir)
		require.NoError(t, err)
		require.Len(t, entries, 3)

		var names []string
		for _, e := range entries {
			assert.Equal(t, OriginDistroAnchorDir, e.OriginType)
			assert.True(t, filepath.IsAbs(e.OriginPath), "OriginPath should be absolute")
			names = append(names, e.Cert.Subject.CommonName)
		}
		sort.Strings(names)
		assert.Equal(t, []string{"anchor-a", "anchor-b", "anchor-c"}, names)
	})

	t.Run("multi-cert PEM file yields multiple entries with same OriginPath", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "bundle.pem")
		// Concatenate two certs into one file.
		bundle := append(makeTestPEM(t, "first"), makeTestPEM(t, "second")...)
		require.NoError(t, os.WriteFile(path, bundle, 0o644))

		entries, err := EnumerateAnchorDir(dir)
		require.NoError(t, err)
		require.Len(t, entries, 2)
		for _, e := range entries {
			assert.Equal(t, OriginDistroAnchorDir, e.OriginType)
			assert.Equal(t, path, e.OriginPath)
		}
	})
}
