//go:build linux

package resources

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCertutilNickname(t *testing.T) {
	tests := []struct {
		name string
		line string
		want string
	}{
		{"blank line", "", ""},
		{"header line", "Certificate Nickname                                         Trust Attributes", ""},
		{"sub-header", "                                                             SSL,S/MIME,JAR/XPI", ""},
		{"simple nickname with C,,", "DigiCert Global Root CA                                      C,,", "DigiCert Global Root CA"},
		{"nickname containing spaces", "mkcert development CA 12345                                  C,,", "mkcert development CA 12345"},
		{"nickname containing commas", "Some, CA, Inc                                                CT,c,", "Some, CA, Inc"},
		{"trust attrs ,,", "Empty Trust                                                  ,,", "Empty Trust"},
		{"trailing whitespace", "Trailing Spaces                                              C,,   ", "Trailing Spaces"},
		{"random non-matching line", "totally not a cert listing", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, certutilNickname(tc.line))
		})
	}
}

func TestEnumerateNSSDB_CertutilMissing(t *testing.T) {
	t.Setenv("PATH", "")
	res := EnumerateNSSDB(context.Background(), t.TempDir(), OriginNSSUser)
	assert.Equal(t, NSSNotInstalled, res.Status)
	assert.NotEmpty(t, res.Message)
	assert.Empty(t, res.Entries)
}

func TestEnumerateNSSDB_DBMissing(t *testing.T) {
	withFakeCertutil(t, fakeCertutilSuccess())
	missing := filepath.Join(t.TempDir(), "no-such-dir")
	res := EnumerateNSSDB(context.Background(), missing, OriginNSSUser)
	assert.Equal(t, NSSDBMissing, res.Status)
	assert.Empty(t, res.Entries)
}

func TestEnumerateNSSDB_DBExistsButNoCertFile(t *testing.T) {
	withFakeCertutil(t, fakeCertutilSuccess())
	emptyDB := t.TempDir() // exists, but no cert9.db / cert8.db
	res := EnumerateNSSDB(context.Background(), emptyDB, OriginNSSUser)
	assert.Equal(t, NSSDBMissing, res.Status)
	assert.Contains(t, res.Message, "cert9.db")
}

func TestEnumerateNSSDB_Successful(t *testing.T) {
	dbDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dbDir, "cert9.db"), []byte("fake"), 0o600))

	cn := "fake-nss-cert"
	withFakeCertutil(t, fakeCertutilWithCert(cn, makeTestPEM(t, cn)))

	res := EnumerateNSSDB(context.Background(), dbDir, OriginNSSUser)
	require.Equal(t, NSSAvailable, res.Status, "message: %s", res.Message)
	require.Len(t, res.Entries, 1)
	assert.Equal(t, OriginNSSUser, res.Entries[0].OriginType)
	assert.Equal(t, dbDir, res.Entries[0].OriginPath)
	assert.Equal(t, cn, res.Entries[0].Cert.Subject.CommonName)
}

func TestEnumerateNSSDB_CertutilReadError(t *testing.T) {
	dbDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dbDir, "cert9.db"), []byte("fake"), 0o600))
	withFakeCertutil(t, fakeCertutilFailure())

	res := EnumerateNSSDB(context.Background(), dbDir, OriginNSSUser)
	assert.Equal(t, NSSReadError, res.Status)
	assert.NotEmpty(t, res.Message)
	assert.Empty(t, res.Entries)
}

func TestEnumerateAllNSSDBs_NoHome(t *testing.T) {
	// File is Linux-only via build tag, so no GOOS guard is needed.
	t.Setenv("HOME", "")
	// EnumerateAllNSSDBs uses os.UserHomeDir which on Linux falls back to
	// passwd lookup when HOME is empty; we can't reliably make it return
	// an error in all environments. So just assert it does not panic and
	// returns a slice.
	out := EnumerateAllNSSDBs(context.Background())
	_ = out // result depends on environment
}

func TestEnumerateAllNSSDBs_FindsPKINSSDB(t *testing.T) {
	home := t.TempDir()
	pki := filepath.Join(home, ".pki", "nssdb")
	require.NoError(t, os.MkdirAll(pki, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(pki, "cert9.db"), []byte("fake"), 0o600))

	cn := "pki-cert"
	withFakeCertutil(t, fakeCertutilWithCert(cn, makeTestPEM(t, cn)))
	t.Setenv("HOME", home)

	results := EnumerateAllNSSDBs(context.Background())
	require.NotEmpty(t, results)
	// First result is always the .pki/nssdb probe.
	assert.Equal(t, NSSAvailable, results[0].Status)
	require.Len(t, results[0].Entries, 1)
	assert.Equal(t, cn, results[0].Entries[0].Cert.Subject.CommonName)
	assert.Equal(t, OriginNSSUser, results[0].Entries[0].OriginType)
}

func TestEnumerateAllNSSDBs_FindsFirefoxProfiles(t *testing.T) {
	home := t.TempDir()
	// Two profiles: one valid (has cert9.db), one invalid (no cert9.db, should be skipped).
	validProfile := filepath.Join(home, ".mozilla", "firefox", "abcd1234.default-release")
	junkProfile := filepath.Join(home, ".mozilla", "firefox", "Crash Reports")
	require.NoError(t, os.MkdirAll(validProfile, 0o755))
	require.NoError(t, os.MkdirAll(junkProfile, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(validProfile, "cert9.db"), []byte("fake"), 0o600))

	cn := "firefox-profile-cert"
	withFakeCertutil(t, fakeCertutilWithCert(cn, makeTestPEM(t, cn)))
	t.Setenv("HOME", home)

	results := EnumerateAllNSSDBs(context.Background())
	// First result is .pki/nssdb (will be NSSDBMissing). Then the valid profile.
	require.GreaterOrEqual(t, len(results), 2)

	var firefoxResult *NSSResult
	for i := range results {
		if results[i].Path == validProfile {
			firefoxResult = &results[i]
		}
		assert.NotEqual(t, junkProfile, results[i].Path, "non-profile dirs should be skipped")
	}
	require.NotNil(t, firefoxResult, "expected a result for the valid Firefox profile")
	assert.Equal(t, NSSAvailable, firefoxResult.Status)
	require.Len(t, firefoxResult.Entries, 1)
	assert.Equal(t, OriginNSSFirefox, firefoxResult.Entries[0].OriginType)
}

// --- fake certutil helpers ---

// withFakeCertutil installs a temporary `certutil` shell script and
// prepends its directory to PATH so the fake is found ahead of any real
// certutil. Prepending (rather than replacing) keeps basic shell utilities
// like cat / printf available, which the fake's heredoc-based PEM emission
// depends on.
func withFakeCertutil(t *testing.T, body string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "certutil")
	require.NoError(t, os.WriteFile(path, []byte(body), 0o755))
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// fakeCertutilSuccess returns a `certutil -L` body that emits an empty
// listing — useful when a test only needs certutil to "exist" but does
// not exercise the parsed output.
func fakeCertutilSuccess() string {
	return `#!/bin/sh
echo ""
echo "Certificate Nickname                                         Trust Attributes"
echo "                                                             SSL,S/MIME,JAR/XPI"
echo ""
exit 0
`
}

// fakeCertutilFailure returns a body that always exits non-zero, simulating
// e.g. a corrupted DB or missing key file.
func fakeCertutilFailure() string {
	return `#!/bin/sh
echo "certutil: function failed: SEC_ERROR_LEGACY_DATABASE" >&2
exit 1
`
}

// fakeCertutilWithCert returns a body that lists one nickname when called
// without -n, and emits the supplied PEM when called with `-n <nickname>`.
func fakeCertutilWithCert(nickname string, pemBytes []byte) string {
	// Embed the nickname and PEM directly. Both are trusted test inputs.
	return fmt.Sprintf(`#!/bin/sh
nick=""
while [ $# -gt 0 ]; do
  case "$1" in
    -n) shift; nick="$1" ;;
  esac
  shift
done
if [ -z "$nick" ]; then
  echo ""
  echo "Certificate Nickname                                         Trust Attributes"
  echo "                                                             SSL,S/MIME,JAR/XPI"
  echo ""
  echo "%s                                                           C,,"
  exit 0
fi
cat <<'PEM_EOF'
%sPEM_EOF
exit 0
`, nickname, string(pemBytes))
}
