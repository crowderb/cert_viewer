//go:build linux

package resources

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

// --- Helpers for synthetic-bundle tests ---

// makeTestPEM generates a fresh self-signed ECDSA root certificate and returns
// its PEM encoding. CommonName uniquifies the cert so tests can assert the
// expected subject made it through enumeration.
func makeTestPEM(t *testing.T, cn string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	var buf bytes.Buffer
	require.NoError(t, pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: der}))
	return buf.Bytes()
}

// readCachedRoots reads and decodes local_roots.json for inspection.
func readCachedRoots(t *testing.T) localRootsFile {
	t.Helper()
	path, err := LocalRootsPath()
	require.NoError(t, err)
	b, err := os.ReadFile(path)
	require.NoError(t, err)
	var f localRootsFile
	require.NoError(t, json.Unmarshal(b, &f))
	return f
}

// rootSubjects extracts the Subject string from each cached root for assertions.
func rootSubjects(roots []LocalRootSummary) []string {
	out := make([]string, len(roots))
	for i, r := range roots {
		out[i] = r.Subject
	}
	return out
}

// --- resolveTrustSource ---

func TestResolveTrustSource(t *testing.T) {
	t.Run("default when no env vars", func(t *testing.T) {
		t.Setenv("SSL_CERT_FILE", "")
		t.Setenv("SSL_CERT_DIR", "")
		assert.Equal(t, defaultLinuxBundle, resolveTrustSource())
	})

	t.Run("SSL_CERT_FILE wins when readable", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "custom.pem")
		require.NoError(t, os.WriteFile(path, makeTestPEM(t, "env-file"), 0o644))
		t.Setenv("SSL_CERT_FILE", path)
		t.Setenv("SSL_CERT_DIR", "/some/other/dir")
		assert.Equal(t, path, resolveTrustSource())
	})

	t.Run("SSL_CERT_FILE missing falls through to SSL_CERT_DIR", func(t *testing.T) {
		t.Setenv("SSL_CERT_FILE", "/nonexistent/bundle.pem")
		t.Setenv("SSL_CERT_DIR", "/etc/anchors")
		assert.Equal(t, dirSourcePrefix+"/etc/anchors", resolveTrustSource())
	})

	t.Run("SSL_CERT_DIR alone is returned with prefix", func(t *testing.T) {
		t.Setenv("SSL_CERT_FILE", "")
		t.Setenv("SSL_CERT_DIR", "/a:/b:/c")
		assert.Equal(t, dirSourcePrefix+"/a:/b:/c", resolveTrustSource())
	})
}

// --- trustSourceMTime ---

func TestTrustSourceMTime(t *testing.T) {
	t.Run("file source returns file mtime", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "bundle.pem")
		require.NoError(t, os.WriteFile(path, []byte("data"), 0o644))
		want := time.Now().Add(-2 * time.Hour).Truncate(time.Second)
		require.NoError(t, os.Chtimes(path, want, want))

		got, ok := trustSourceMTime(path)
		require.True(t, ok)
		assert.WithinDuration(t, want, got, time.Second)
	})

	t.Run("missing file returns ok=false", func(t *testing.T) {
		_, ok := trustSourceMTime("/nonexistent/bundle.pem")
		assert.False(t, ok)
	})

	t.Run("DIR source returns max mtime across PEM files", func(t *testing.T) {
		dir := t.TempDir()
		older := filepath.Join(dir, "older.pem")
		newer := filepath.Join(dir, "newer.crt")
		ignored := filepath.Join(dir, "README.md") // wrong extension
		require.NoError(t, os.WriteFile(older, []byte("a"), 0o644))
		require.NoError(t, os.WriteFile(newer, []byte("b"), 0o644))
		require.NoError(t, os.WriteFile(ignored, []byte("c"), 0o644))

		oldT := time.Now().Add(-3 * time.Hour).Truncate(time.Second)
		newT := time.Now().Add(-1 * time.Hour).Truncate(time.Second)
		future := time.Now().Add(time.Hour).Truncate(time.Second) // shouldn't influence — wrong ext
		require.NoError(t, os.Chtimes(older, oldT, oldT))
		require.NoError(t, os.Chtimes(newer, newT, newT))
		require.NoError(t, os.Chtimes(ignored, future, future))

		got, ok := trustSourceMTime(dirSourcePrefix + dir)
		require.True(t, ok)
		assert.WithinDuration(t, newT, got, time.Second)
	})

	t.Run("DIR source with no readable dirs returns ok=false", func(t *testing.T) {
		_, ok := trustSourceMTime(dirSourcePrefix + "/no/such/dir1:/no/such/dir2")
		assert.False(t, ok)
	})
}

// --- enumerateSystemRootCertificates with overrides ---

func TestEnumerateSystemRootCertificates_Overrides(t *testing.T) {
	t.Run("SSL_CERT_FILE bundle is read", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "custom.pem")
		require.NoError(t, os.WriteFile(path, makeTestPEM(t, "from-env-file"), 0o644))
		t.Setenv("SSL_CERT_FILE", path)
		t.Setenv("SSL_CERT_DIR", "")

		certs, source, err := enumerateSystemRootCertificates(context.Background())
		require.NoError(t, err)
		assert.Equal(t, path, source)
		require.Len(t, certs, 1)
		assert.Equal(t, "from-env-file", certs[0].Subject.CommonName)
	})

	t.Run("SSL_CERT_DIR enumerates and merges across dirs", func(t *testing.T) {
		d1 := t.TempDir()
		d2 := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(d1, "a.pem"), makeTestPEM(t, "dir1-a"), 0o644))
		require.NoError(t, os.WriteFile(filepath.Join(d1, "b.crt"), makeTestPEM(t, "dir1-b"), 0o644))
		require.NoError(t, os.WriteFile(filepath.Join(d2, "c.pem"), makeTestPEM(t, "dir2-c"), 0o644))
		require.NoError(t, os.WriteFile(filepath.Join(d1, "skip.txt"), []byte("ignored"), 0o644))

		t.Setenv("SSL_CERT_FILE", "")
		t.Setenv("SSL_CERT_DIR", d1+string(os.PathListSeparator)+d2)

		got, source, err := enumerateSystemRootCertificates(context.Background())
		require.NoError(t, err)
		assert.True(t, strings.HasPrefix(source, dirSourcePrefix), "source should be DIR-prefixed")
		require.Len(t, got, 3)
		var names []string
		for _, c := range got {
			names = append(names, c.Subject.CommonName)
		}
		assert.ElementsMatch(t, []string{"dir1-a", "dir1-b", "dir2-c"}, names)
	})
}

// --- EnsureLocalRootsJSON regen behavior ---

func TestEnsureLocalRootsJSON_RegensWhenBundleNewer(t *testing.T) {
	withTempCache(t)
	dir := t.TempDir()
	bundle := filepath.Join(dir, "bundle.pem")
	require.NoError(t, os.WriteFile(bundle, makeTestPEM(t, "v1"), 0o644))
	t.Setenv("SSL_CERT_FILE", bundle)
	t.Setenv("SSL_CERT_DIR", "")

	require.NoError(t, EnsureLocalRootsJSON(context.Background()))
	first := readCachedRoots(t)
	require.Equal(t, []string{"CN=v1"}, rootSubjects(first.Roots))

	// Backdate the cache so the bundle write below is unambiguously newer.
	cachePath, err := LocalRootsPath()
	require.NoError(t, err)
	old := time.Now().Add(-time.Hour).Truncate(time.Second)
	require.NoError(t, os.Chtimes(cachePath, old, old))

	// Replace the bundle content and bump its mtime.
	require.NoError(t, os.WriteFile(bundle, makeTestPEM(t, "v2"), 0o644))
	now := time.Now().Truncate(time.Second)
	require.NoError(t, os.Chtimes(bundle, now, now))

	require.NoError(t, EnsureLocalRootsJSON(context.Background()))
	second := readCachedRoots(t)
	assert.Equal(t, []string{"CN=v2"}, rootSubjects(second.Roots),
		"cache should have been regenerated to reflect the newer bundle")
}

func TestEnsureLocalRootsJSON_RegensWhenSourceChanges(t *testing.T) {
	withTempCache(t)
	dir := t.TempDir()
	bundleA := filepath.Join(dir, "a.pem")
	bundleB := filepath.Join(dir, "b.pem")
	require.NoError(t, os.WriteFile(bundleA, makeTestPEM(t, "from-A"), 0o644))
	require.NoError(t, os.WriteFile(bundleB, makeTestPEM(t, "from-B"), 0o644))

	t.Setenv("SSL_CERT_FILE", bundleA)
	t.Setenv("SSL_CERT_DIR", "")
	require.NoError(t, EnsureLocalRootsJSON(context.Background()))
	assert.Equal(t, bundleA, readCachedRoots(t).SourcePath)

	// Point the env var at a different bundle — the recorded source no longer
	// matches the resolved source, so the cache must be regenerated.
	t.Setenv("SSL_CERT_FILE", bundleB)
	require.NoError(t, EnsureLocalRootsJSON(context.Background()))
	final := readCachedRoots(t)
	assert.Equal(t, bundleB, final.SourcePath)
	assert.Equal(t, []string{"CN=from-B"}, rootSubjects(final.Roots))
}

func TestEnsureLocalRootsJSON_NoRegenWhenFresh(t *testing.T) {
	withTempCache(t)
	dir := t.TempDir()
	bundle := filepath.Join(dir, "bundle.pem")
	require.NoError(t, os.WriteFile(bundle, makeTestPEM(t, "stable"), 0o644))
	t.Setenv("SSL_CERT_FILE", bundle)
	t.Setenv("SSL_CERT_DIR", "")

	require.NoError(t, EnsureLocalRootsJSON(context.Background()))
	cachePath, err := LocalRootsPath()
	require.NoError(t, err)
	info1, err := os.Stat(cachePath)
	require.NoError(t, err)

	// Force the cache to look strictly newer than the bundle so the mtime
	// check unambiguously says "fresh."
	future := time.Now().Add(time.Hour).Truncate(time.Second)
	require.NoError(t, os.Chtimes(cachePath, future, future))

	require.NoError(t, EnsureLocalRootsJSON(context.Background()))
	info2, err := os.Stat(cachePath)
	require.NoError(t, err)
	assert.Equal(t, info1.Size(), info2.Size(), "cache size should be unchanged")
	assert.True(t, info2.ModTime().Equal(future) || info2.ModTime().After(future),
		"cache mtime should not have been rewritten")
}
