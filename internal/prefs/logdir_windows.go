//go:build windows

package prefs

import (
	"os"
	"path/filepath"
)

// LogDir returns the directory where the application's log file should
// be written. On Windows this is %LOCALAPPDATA%\cert_viewer\Logs\,
// matching the convention used by other Windows desktop apps. We resolve
// LOCALAPPDATA explicitly via the environment because os.UserCacheDir()
// (which also returns LOCALAPPDATA on Windows) would land logs in the
// "cache" subtree alongside non-essential data — logs deserve their own
// "Logs" subdirectory for users browsing %LOCALAPPDATA% in Explorer.
//
// The directory is created with mode 0o755 if it does not yet exist.
// Mode bits are advisory on NTFS but Go applies them as best-effort.
// The log file inside it should be opened with mode 0o600 by the
// caller — paths in log records may be user-private.
func LogDir() (string, error) {
	base := os.Getenv("LOCALAPPDATA")
	if base == "" {
		// Fallback: use the user cache dir (Roaming AppData) when
		// LOCALAPPDATA is somehow unset. Better than failing outright.
		var err error
		base, err = os.UserCacheDir()
		if err != nil {
			return "", err
		}
	}
	dir := filepath.Join(base, "cert_viewer", "Logs")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	return dir, nil
}
