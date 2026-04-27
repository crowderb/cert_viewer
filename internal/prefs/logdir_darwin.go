//go:build darwin

package prefs

import (
	"os"
	"path/filepath"
)

// LogDir returns the directory where the application's log file should
// be written. On macOS this is ~/Library/Logs/cert_viewer/, the
// Apple-conventional location. Console.app reads ~/Library/Logs by
// default, so users on a bug report can be told "open Console.app and
// look under cert_viewer".
//
// The directory is created with mode 0o755 if it does not yet exist.
// The log file inside it should be opened with mode 0o600 by the
// caller — log records may include file paths users consider private.
func LogDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(home, "Library", "Logs", "cert_viewer")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	return dir, nil
}
