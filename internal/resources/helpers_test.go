package resources

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"cert_viewer/internal/prefs"
)

// withTempCache redirects prefs.CacheDir() to a temp directory for the
// duration of the test by overriding $XDG_CACHE_HOME. Returns the path to
// the cert_viewer subdirectory that CacheDir() will create and return.
func withTempCache(t *testing.T) string {
	t.Helper()
	tmp := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", tmp)
	return filepath.Join(tmp, "cert_viewer")
}

// writeTempCSV writes content to the CCADB CSV path for p within cacheDir.
func writeTempCSV(t *testing.T, cacheDir, content string, p prefs.Preferences) {
	t.Helper()
	require.NoError(t, os.MkdirAll(cacheDir, 0o755))
	name := p.Resources.CachedFilename
	if name == "" {
		name = prefs.CacheFilenameFromURL(p.Resources.CCADBURL)
	}
	require.NoError(t, os.WriteFile(filepath.Join(cacheDir, name), []byte(content), 0o644))
}
