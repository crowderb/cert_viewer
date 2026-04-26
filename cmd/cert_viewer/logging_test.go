package main

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRotateLogIfLarge_Rotates(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cert_viewer.log")

	// Write a 100-byte file and rotate when threshold = 50 — must rotate.
	if err := os.WriteFile(path, bytes.Repeat([]byte("x"), 100), 0o600); err != nil {
		t.Fatalf("seed log: %v", err)
	}
	if err := rotateLogIfLarge(path, 50); err != nil {
		t.Fatalf("rotateLogIfLarge: %v", err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("active log still exists after rotation: %v", err)
	}
	rotated, err := os.ReadFile(path + ".1")
	if err != nil {
		t.Fatalf("rotated file missing: %v", err)
	}
	if len(rotated) != 100 {
		t.Fatalf("rotated file size = %d, want 100", len(rotated))
	}
}

func TestRotateLogIfLarge_BelowThreshold(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cert_viewer.log")

	if err := os.WriteFile(path, bytes.Repeat([]byte("x"), 10), 0o600); err != nil {
		t.Fatalf("seed log: %v", err)
	}
	if err := rotateLogIfLarge(path, 100); err != nil {
		t.Fatalf("rotateLogIfLarge: %v", err)
	}
	// Active file must remain; .1 must not exist.
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("active log unexpectedly removed: %v", err)
	}
	if _, err := os.Stat(path + ".1"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("rotated file unexpectedly created: %v", err)
	}
}

func TestRotateLogIfLarge_OverwritesPriorRotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cert_viewer.log")

	// Existing rotation slot from a prior run.
	if err := os.WriteFile(path+".1", []byte("OLD"), 0o600); err != nil {
		t.Fatalf("seed prior rotation: %v", err)
	}
	// Active log over threshold.
	if err := os.WriteFile(path, bytes.Repeat([]byte("y"), 200), 0o600); err != nil {
		t.Fatalf("seed log: %v", err)
	}
	if err := rotateLogIfLarge(path, 100); err != nil {
		t.Fatalf("rotateLogIfLarge: %v", err)
	}
	rotated, err := os.ReadFile(path + ".1")
	if err != nil {
		t.Fatalf("rotated file missing: %v", err)
	}
	// Must contain the new content (200 'y'), not the old "OLD".
	if string(rotated[:1]) == "O" {
		t.Fatal("prior rotation slot was not overwritten")
	}
	if len(rotated) != 200 {
		t.Fatalf("rotated file size = %d, want 200", len(rotated))
	}
}

func TestRotateLogIfLarge_NoFileIsOK(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cert_viewer.log")

	// No log file exists yet — rotation should be a no-op, not an error.
	if err := rotateLogIfLarge(path, 100); err != nil {
		t.Fatalf("rotateLogIfLarge on nonexistent file: %v", err)
	}
}

func TestTeeHandler_FansOutToAllChildren(t *testing.T) {
	var bufA, bufB bytes.Buffer
	h := newTeeHandler(
		slog.NewTextHandler(&bufA, &slog.HandlerOptions{Level: slog.LevelDebug}),
		slog.NewTextHandler(&bufB, &slog.HandlerOptions{Level: slog.LevelDebug}),
	)
	logger := slog.New(h)
	logger.Info("hello", "k", "v")

	if !bytes.Contains(bufA.Bytes(), []byte("hello")) {
		t.Fatalf("buf A missing record: %q", bufA.String())
	}
	if !bytes.Contains(bufB.Bytes(), []byte("hello")) {
		t.Fatalf("buf B missing record: %q", bufB.String())
	}
}

func TestTeeHandler_LevelFilteringPerChild(t *testing.T) {
	// Verify that a child handler with a higher level threshold drops
	// records the other child accepts.
	var bufLow, bufHigh bytes.Buffer
	h := newTeeHandler(
		slog.NewTextHandler(&bufLow, &slog.HandlerOptions{Level: slog.LevelDebug}),
		slog.NewTextHandler(&bufHigh, &slog.HandlerOptions{Level: slog.LevelError}),
	)
	logger := slog.New(h)
	logger.Info("info-only")

	if !bytes.Contains(bufLow.Bytes(), []byte("info-only")) {
		t.Fatalf("debug-level buf missing record: %q", bufLow.String())
	}
	if bufHigh.Len() != 0 {
		t.Fatalf("error-level buf got record it should have filtered: %q", bufHigh.String())
	}
}

// errHandler is a slog.Handler that returns a fixed error from Handle and
// is otherwise enabled at all levels. Used to verify teeHandler.Handle
// joins errors from multiple children.
type errHandler struct{ err error }

func (e *errHandler) Enabled(context.Context, slog.Level) bool { return true }
func (e *errHandler) Handle(context.Context, slog.Record) error {
	return e.err
}
func (e *errHandler) WithAttrs(_ []slog.Attr) slog.Handler { return e }
func (e *errHandler) WithGroup(_ string) slog.Handler      { return e }

func TestTeeHandler_JoinsChildErrors(t *testing.T) {
	errA := errors.New("childA failed")
	errB := errors.New("childB failed")
	h := newTeeHandler(&errHandler{err: errA}, &errHandler{err: errB})

	r := slog.NewRecord(time.Time{}, slog.LevelInfo, "hello", 0)
	err := h.Handle(context.Background(), r)
	if err == nil {
		t.Fatal("expected joined error, got nil")
	}
	if !errors.Is(err, errA) || !errors.Is(err, errB) {
		t.Fatalf("joined error missing components: %v", err)
	}
}
