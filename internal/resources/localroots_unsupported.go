//go:build !linux && !windows && !darwin

package resources

import (
	"context"
	"crypto/x509"
	"time"
)

func enumerateSystemRootCertificates(_ context.Context) ([]*x509.Certificate, string, error) {
	return nil, "unsupported platform", nil
}

func resolveTrustSource() string                { return "unsupported platform" }
func trustSourceMTime(string) (time.Time, bool) { return time.Time{}, false }

// collectRoots returns an empty result on unsupported platforms.
// macOS support is tracked in ROADMAP.md (Phase 2 — macOS Trust Store).
func collectRoots(ctx context.Context) ([]LocalRootSummary, string, error) {
	_, source, err := enumerateSystemRootCertificates(ctx)
	if err != nil {
		return nil, source, err
	}
	return nil, source, nil
}
