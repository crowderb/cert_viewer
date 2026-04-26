//go:build linux

package prefs

import (
	"os"
	"path/filepath"
)

// LogDir returns the directory where the application's log file should be
// written. On Linux, this resolves XDG_STATE_HOME (default ~/.local/state)
// per the XDG Base Directory Specification, then appends /cert_viewer/.
//
// The directory is created with mode 0o755 if it does not yet exist. The
// log file inside it should be opened with mode 0o600 by the caller — log
// records may include file paths users consider private.
func LogDir() (string, error) {
	base := os.Getenv("XDG_STATE_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		base = filepath.Join(home, ".local", "state")
	}
	dir := filepath.Join(base, "cert_viewer")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	return dir, nil
}
