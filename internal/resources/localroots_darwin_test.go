//go:build darwin

package resources

import (
	"context"
	"os"
	"os/exec"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestEnsureLocalRootsJSON_Integration exercises the full macOS security CLI path.
func TestEnsureLocalRootsJSON_Integration(t *testing.T) {
	if _, err := exec.LookPath("security"); err != nil {
		t.Skip("security CLI not found in PATH")
	}
	withTempCache(t)

	// First call should generate the cache file.
	err := EnsureLocalRootsJSON(context.Background())
	require.NoError(t, err)

	path, err := LocalRootsPath()
	require.NoError(t, err)
	_, statErr := os.Stat(path)
	assert.NoError(t, statErr, "local_roots.json should have been created")

	// Second call should be a no-op (returns nil without rebuilding).
	err = EnsureLocalRootsJSON(context.Background())
	assert.NoError(t, err)
}
