//go:build linux

package resources

import (
	"path/filepath"
	"testing"
)

// withIsolatedTrustEnvironment isolates a test from the host's distro
// anchor directory and per-user NSS databases by:
//
//   - pointing os-release at a non-existent path (DetectDistroFamily
//     returns DistroUnknown, anchor enumeration becomes a no-op)
//   - overriding $HOME to a fresh tempdir (no ~/.pki/nssdb, no Firefox
//     profiles found by EnumerateAllNSSDBs)
//
// Use this in any test of the system-bundle / env-override path that
// asserts an exact set of certs in the merged cache; without it, real
// host state (homelab CA, mkcert dev CA, Firefox profile) bleeds in.
func withIsolatedTrustEnvironment(t *testing.T) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	prev := osReleasePath
	osReleasePath = filepath.Join(t.TempDir(), "no-such-os-release")
	t.Cleanup(func() { osReleasePath = prev })
}
