package version

import "testing"

// TestDefaults verifies the dev-sentinel defaults that every test build
// inherits when no -ldflags injection happens. If a future change drops
// one of these vars, this test fails before downstream packages do.
func TestDefaults(t *testing.T) {
	if Version != "dev" {
		t.Errorf("Version = %q, want %q", Version, "dev")
	}
	if Commit != "unknown" {
		t.Errorf("Commit = %q, want %q", Commit, "unknown")
	}
	if BuildDate != "<unset>" {
		t.Errorf("BuildDate = %q, want %q", BuildDate, "<unset>")
	}
}

func TestIsDev(t *testing.T) {
	// Defaults are the dev sentinel, so IsDev should be true.
	if !IsDev() {
		t.Error("IsDev() = false on a default-built binary; want true")
	}

	// Save and restore so this test does not pollute package state for
	// other tests in the same binary.
	saved := Version
	t.Cleanup(func() { Version = saved })

	Version = "2026.04.26.1"
	if IsDev() {
		t.Error("IsDev() = true after setting Version to a CalVer string; want false")
	}
}
