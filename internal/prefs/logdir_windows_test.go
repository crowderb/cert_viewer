//go:build windows

package prefs

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLogDir_HonorsLocalAppData(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("LOCALAPPDATA", tmp)

	dir, err := LogDir()
	if err != nil {
		t.Fatalf("LogDir() error: %v", err)
	}
	want := filepath.Join(tmp, "cert_viewer", "Logs")
	if dir != want {
		t.Fatalf("LogDir() = %q, want %q", dir, want)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("LogDir did not create %s: %v", dir, err)
	}
	if !info.IsDir() {
		t.Fatalf("LogDir created %s but it is not a directory", dir)
	}
}

func TestLogDir_FallsBackWhenLocalAppDataUnset(t *testing.T) {
	// LOCALAPPDATA is essentially always set on Windows, but guard the
	// fallback path anyway. UserCacheDir on Windows reads APPDATA, so
	// we point that at a temp dir to keep the test hermetic.
	t.Setenv("LOCALAPPDATA", "")
	tmp := t.TempDir()
	t.Setenv("APPDATA", tmp)

	dir, err := LogDir()
	if err != nil {
		t.Fatalf("LogDir() error: %v", err)
	}
	want := filepath.Join(tmp, "cert_viewer", "Logs")
	if dir != want {
		t.Fatalf("LogDir() = %q, want %q", dir, want)
	}
}
