//go:build !linux

package prefs

import (
	"os"
	"path/filepath"
)

// LogDir returns a fallback log directory on non-Linux platforms. Tasks
// 4.I (macOS) and 4.J (Windows) replace this with the OS-conventional
// location (~/Library/Logs/cert_viewer/ on macOS,
// %LOCALAPPDATA%\cert_viewer\Logs\ on Windows). Until then the cache
// directory is good enough — it's user-writable and per-user.
func LogDir() (string, error) {
	base, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(base, "cert_viewer", "logs")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	return dir, nil
}
