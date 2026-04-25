//go:build linux

package resources

import (
	"crypto/x509"
	"os"
	"path/filepath"
)

// Origin identifiers attached to certificates discovered by the various
// trust-source readers. They appear in local_roots.json's per-cert
// "origins" list and drive the per-source counts shown in the Trust
// Sources tab. Adding a new origin only requires choosing a new constant
// and emitting it from a new reader; downstream consumers (UI grouping,
// JSON schema) treat the value as opaque.
const (
	OriginSystemBundle   = "system-bundle"     // /etc/ssl/certs/ca-certificates.crt or distro equivalent
	OriginEnvOverride    = "env-override"      // SSL_CERT_FILE / SSL_CERT_DIR
	OriginDistroAnchorDir = "distro-anchor-dir" // /usr/local/share/ca-certificates etc.
	OriginNSSUser        = "nss-user"          // ~/.pki/nssdb
	OriginNSSFirefox     = "nss-firefox"       // ~/.mozilla/firefox/<profile>/cert9.db
)

// TrustSourceEntry pairs a parsed certificate with the origin metadata that
// describes where it was found. Multiple entries can refer to the same
// underlying certificate (same SHA-256) when a CA appears in more than one
// source — for example, a homelab CA that lives in /usr/local/share/ca-
// certificates AND has been concatenated into /etc/ssl/certs/ca-
// certificates.crt by update-ca-certificates. The merge step in
// localroots.go collapses such duplicates to a single LocalRootSummary
// with all origins recorded.
type TrustSourceEntry struct {
	Cert       *x509.Certificate
	OriginType string // one of the Origin* constants above
	OriginPath string // file (anchor PEM, NSS DB) or descriptor ("DIR:/a:/b") that produced this cert
}

// EnumerateAnchorDir reads every PEM certificate file in dir (non-recursive)
// and returns one TrustSourceEntry per parsed cert, tagged with origin
// "distro-anchor-dir" and the per-cert source file path. A missing dir is
// treated as "nothing to add" rather than an error, so callers can ask for
// the family-appropriate path unconditionally without first stat-ing it.
//
// File extensions accepted: .pem, .crt, .cer (matches isPEMFilename used
// elsewhere in this package). Files with other extensions and unparseable
// PEM blocks are skipped silently.
func EnumerateAnchorDir(dir string) ([]TrustSourceEntry, error) {
	if dir == "" {
		return nil, nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []TrustSourceEntry
	for _, e := range entries {
		if e.IsDir() || !isPEMFilename(e.Name()) {
			continue
		}
		path := filepath.Join(dir, e.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		for _, cert := range parsePEMCertificates(data) {
			out = append(out, TrustSourceEntry{
				Cert:       cert,
				OriginType: OriginDistroAnchorDir,
				OriginPath: path,
			})
		}
	}
	return out, nil
}
