//go:build !linux && !darwin && !windows

package prefs

import (
	"os"
	"path/filepath"
)

// LogDir returns a fallback log directory for platforms without a
// first-class implementation (anything that isn't Linux, macOS, or
// Windows). Uses os.UserCacheDir() so the path is at least user-writable
// and per-user. New target platforms should add their own logdir_<os>.go
// file rather than rely on this fallback.
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
