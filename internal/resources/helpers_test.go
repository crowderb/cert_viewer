package resources

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
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

// writeTempCSV writes content to the CCADB CSV path within cacheDir.
func writeTempCSV(t *testing.T, cacheDir, content string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(cacheDir, 0o755))
	path := filepath.Join(cacheDir, ccadbCachedName)
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
}
