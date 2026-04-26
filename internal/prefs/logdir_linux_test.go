//go:build linux

package prefs

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLogDir_HonorsXDGStateHome(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("XDG_STATE_HOME", tmp)

	dir, err := LogDir()
	if err != nil {
		t.Fatalf("LogDir() error: %v", err)
	}
	want := filepath.Join(tmp, "cert_viewer")
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

func TestLogDir_DefaultsToHomeLocalState(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("XDG_STATE_HOME", "")
	t.Setenv("HOME", tmp)

	dir, err := LogDir()
	if err != nil {
		t.Fatalf("LogDir() error: %v", err)
	}
	want := filepath.Join(tmp, ".local", "state", "cert_viewer")
	if dir != want {
		t.Fatalf("LogDir() = %q, want %q", dir, want)
	}
}
