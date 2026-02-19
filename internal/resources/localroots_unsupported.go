//go:build !linux && !windows

package resources

import "context"

// collectRoots returns an empty result on unsupported platforms.
// macOS support is tracked in ROADMAP.md (Phase 2 — macOS Trust Store).
func collectRoots(_ context.Context) ([]LocalRootSummary, string, error) {
	return nil, "unsupported platform", nil
}
