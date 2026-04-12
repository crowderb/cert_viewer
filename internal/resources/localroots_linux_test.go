//go:build linux

package resources

import (
	"context"
	"os"
	"testing"

	"cert_viewer/internal/certs"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestEnsureLocalRootsJSON_Integration exercises the full Linux PEM-bundle path.
func TestEnsureLocalRootsJSON_Integration(t *testing.T) {
	if _, err := os.Stat(defaultLinuxBundle); os.IsNotExist(err) {
		t.Skip("Linux certificate bundle not found at " + defaultLinuxBundle)
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

// TestFindTrustedRootCertBySubjectKeyID_Integration checks SKI lookup against the live bundle.
func TestFindTrustedRootCertBySubjectKeyID_Integration(t *testing.T) {
	if _, err := os.Stat(defaultLinuxBundle); os.IsNotExist(err) {
		t.Skip("Linux certificate bundle not found at " + defaultLinuxBundle)
	}
	withTempCache(t)
	require.NoError(t, EnsureLocalRootsJSON(context.Background()))

	m, err := LoadLocalRootsSKISet()
	require.NoError(t, err)
	require.NotEmpty(t, m)

	var skiKey string
	for k := range m {
		skiKey = k
		break
	}

	cert, err := FindTrustedRootCertBySubjectKeyID(context.Background(), skiKey)
	require.NoError(t, err)
	require.NotNil(t, cert)
	assert.Equal(t, skiKey, certs.NormalizeHexBytesNoSepUpper(cert.SubjectKeyId))
}
