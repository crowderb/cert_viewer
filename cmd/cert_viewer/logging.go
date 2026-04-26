package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"

	"cert_viewer/internal/prefs"
)

// logFileName is the basename of the active log file inside prefs.LogDir().
const logFileName = "cert_viewer.log"

// logRotateThreshold is the size at which the active log file is rotated
// to <name>.1 on startup. 5 MiB is generous for a desktop GUI's typical
// log volume but small enough that a single rotation slot stays bounded.
const logRotateThreshold = 5 * 1024 * 1024

// teeHandler fans every slog.Record out to a list of child handlers. slog
// itself does not provide a multi-handler; this is the smallest workable
// implementation.
type teeHandler struct {
	handlers []slog.Handler
}

func newTeeHandler(handlers ...slog.Handler) *teeHandler {
	return &teeHandler{handlers: handlers}
}

func (t *teeHandler) Enabled(ctx context.Context, level slog.Level) bool {
	for _, h := range t.handlers {
		if h.Enabled(ctx, level) {
			return true
		}
	}
	return false
}

func (t *teeHandler) Handle(ctx context.Context, r slog.Record) error {
	var errs []error
	for _, h := range t.handlers {
		if !h.Enabled(ctx, r.Level) {
			continue
		}
		if err := h.Handle(ctx, r.Clone()); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (t *teeHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	out := make([]slog.Handler, len(t.handlers))
	for i, h := range t.handlers {
		out[i] = h.WithAttrs(attrs)
	}
	return &teeHandler{handlers: out}
}

func (t *teeHandler) WithGroup(name string) slog.Handler {
	out := make([]slog.Handler, len(t.handlers))
	for i, h := range t.handlers {
		out[i] = h.WithGroup(name)
	}
	return &teeHandler{handlers: out}
}

// rotateLogIfLarge renames path → path+".1" (overwriting any existing .1)
// when the file exceeds threshold bytes. Single-slot rotation is enough
// for a desktop app: once the active file fills again, the prior .1 is
// overwritten. Errors are returned so the caller can downgrade to a
// stderr-only handler — never panic the app over a logging setup failure.
func rotateLogIfLarge(path string, threshold int64) error {
	info, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if info.Size() < threshold {
		return nil
	}
	rotated := path + ".1"
	if rmErr := os.Remove(rotated); rmErr != nil && !errors.Is(rmErr, os.ErrNotExist) {
		return rmErr
	}
	return os.Rename(path, rotated)
}

// openLogFile resolves prefs.LogDir(), rotates an oversize active log,
// and opens the file with O_APPEND|O_CREATE at mode 0o600. Returns the
// open file plus its full path so callers can log the destination once.
func openLogFile() (*os.File, string, error) {
	dir, err := prefs.LogDir()
	if err != nil {
		return nil, "", err
	}
	path := filepath.Join(dir, logFileName)
	if rotErr := rotateLogIfLarge(path, logRotateThreshold); rotErr != nil {
		// Rotation failure is non-fatal; the open below will simply
		// continue appending to the existing file.
		slog.Warn("log rotation failed", "path", path, "err", rotErr)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, path, err
	}
	return f, path, nil
}

// configureLogger installs a slog default handler before any other code
// can emit a record. CERT_VIEWER_LOG=debug raises the level; the default
// is INFO. Records fan out to both stderr and a per-OS log file (Linux:
// $XDG_STATE_HOME/cert_viewer/cert_viewer.log; non-Linux: a fallback
// path until tasks 4.I/4.J ship the OS-native locations).
//
// On any failure setting up the file sink, the function falls back to a
// stderr-only handler — a logging-setup failure must never block the app.
func configureLogger() {
	level := slog.LevelInfo
	if v := os.Getenv("CERT_VIEWER_LOG"); v == "debug" || v == "DEBUG" {
		level = slog.LevelDebug
	}
	opts := &slog.HandlerOptions{Level: level}
	stderrHandler := slog.NewTextHandler(os.Stderr, opts)

	logFile, logPath, err := openLogFile()
	if err != nil {
		// Stderr-only fallback. Use the partial handler so the user
		// still gets diagnostics; log the failure once it's installed.
		slog.SetDefault(slog.New(stderrHandler))
		slog.Warn("log file unavailable; stderr-only logging", "err", err)
		return
	}

	fileHandler := slog.NewTextHandler(logFile, opts)
	slog.SetDefault(slog.New(newTeeHandler(stderrHandler, fileHandler)))
	slog.Info("logger ready", "path", logPath, "level", level.String())
	// logFile is intentionally not closed — it lives for the process
	// lifetime, and the OS reclaims it on exit. A defer in main() would
	// fire before goroutines that may still be logging.
}
