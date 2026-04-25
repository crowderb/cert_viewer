package resources

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"cert_viewer/internal/certs"
	"cert_viewer/internal/prefs"
)

// ErrTrustedRootNotFound means no system trust-store certificate matched the given SKI.
var ErrTrustedRootNotFound = errors.New("trusted root certificate not found for subject key identifier")

const localRootsFileName = "local_roots.json"

// Origin identifiers attached to certificates discovered by the various
// trust-source readers. They appear in local_roots.json's per-cert
// Origins list and drive the per-source counts shown in the Trust Sources
// tab. Adding a new origin only requires choosing a new constant and
// emitting it from a new reader; downstream consumers (UI grouping, JSON
// schema) treat the value as opaque.
const (
	OriginSystemBundle    = "system-bundle"     // /etc/ssl/certs/ca-certificates.crt or distro equivalent
	OriginEnvOverride     = "env-override"      // SSL_CERT_FILE / SSL_CERT_DIR
	OriginDistroAnchorDir = "distro-anchor-dir" // /usr/local/share/ca-certificates etc.
	OriginNSSUser         = "nss-user"          // ~/.pki/nssdb
	OriginNSSFirefox      = "nss-firefox"       // ~/.mozilla/firefox/<profile>/cert9.db
)

// OriginRef identifies one trust source where a root certificate was
// observed. A single LocalRootSummary may carry multiple OriginRefs when
// the same cert appears in more than one source — for example, a CA in
// /usr/local/share/ca-certificates that update-ca-certificates has also
// concatenated into /etc/ssl/certs/ca-certificates.crt produces two
// entries: {Type: "system-bundle", …} and {Type: "distro-anchor-dir", …}.
type OriginRef struct {
	Type string `json:"type"`
	Path string `json:"path"`
}

// TrustSourceEntry pairs a parsed certificate with the origin metadata
// that describes where it was found. Used as the input to mergeTrustEntries
// — multiple entries with the same SHA-256 fingerprint collapse into one
// LocalRootSummary whose Origins list records every source it appeared in.
type TrustSourceEntry struct {
	Cert       *x509.Certificate
	OriginType string // one of the Origin* constants
	OriginPath string // file path or descriptor that produced this cert
}

type LocalRootSummary struct {
	Subject              string      `json:"subject"`
	SubjectKeyIdentifier string      `json:"subjectKeyIdentifier"`
	SerialHex            string      `json:"serialHex"`
	NotBefore            string      `json:"notBefore"`
	NotAfter             string      `json:"notAfter"`
	SHA256FingerprintHex string      `json:"sha256"`
	Origins              []OriginRef `json:"origins,omitempty"`
}

type localRootsFile struct {
	GeneratedAt string             `json:"generatedAt"`
	SourcePath  string             `json:"sourcePath"`
	Roots       []LocalRootSummary `json:"roots"`
}

// LocalRootsPath returns the cache path to local_roots.json.
func LocalRootsPath() (string, error) {
	cache, err := prefs.CacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(cache, localRootsFileName), nil
}

// EnsureLocalRootsJSON generates local_roots.json if it does not exist or needs
// regeneration. Platform-specific certificate collection is handled by collectRoots(),
// defined in localroots_linux.go / localroots_windows.go / localroots_unsupported.go.
//
// The cache is regenerated when any of the following are true:
//   - the file does not exist
//   - the file is legacy-format or malformed (needsRegen)
//   - the resolved trust-store source has changed since the cache was written
//     (e.g. SSL_CERT_FILE was set or unset between runs)
//   - the trust-store source's mtime is newer than the cache's mtime
//     (e.g. update-ca-certificates ran since the last cache write)
func EnsureLocalRootsJSON(ctx context.Context) error {
	path, err := LocalRootsPath()
	if err != nil {
		return err
	}
	if info, err := os.Stat(path); err == nil {
		if !needsRegen(path) && !sourceChangedOrFresher(path, info.ModTime()) {
			return nil
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	roots, source, err := collectRoots(ctx)
	if err != nil {
		return err
	}
	return writeLocalRoots(path, localRootsFile{
		GeneratedAt: time.Now().Format(time.RFC3339),
		SourcePath:  source,
		Roots:       roots,
	})
}

// sourceChangedOrFresher reports whether the cache at cachePath is stale because
// either the trust-store source identifier recorded in the cache no longer matches
// the currently-resolved source, or that source's content mtime is newer than the
// cache's mtime. Returns true on any read/parse error to force regeneration.
func sourceChangedOrFresher(cachePath string, cacheMTime time.Time) bool {
	b, err := os.ReadFile(cachePath)
	if err != nil {
		return true
	}
	var f localRootsFile
	if err := json.Unmarshal(b, &f); err != nil {
		return true
	}
	current := resolveTrustSource()
	if current != "" && f.SourcePath != "" && current != f.SourcePath {
		return true
	}
	if mt, ok := trustSourceMTime(current); ok && mt.After(cacheMTime) {
		return true
	}
	return false
}

func writeLocalRoots(path string, content localRootsFile) error {
	b, err := json.MarshalIndent(content, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

// summarizeCert builds a LocalRootSummary for a single certificate. The
// Origins slice is left empty; callers fill it in based on where the cert
// came from. Centralizing the formatting (date format, hex normalization)
// avoids drift between the Linux/Darwin/Windows collectRoots paths.
func summarizeCert(cert *x509.Certificate) LocalRootSummary {
	sha := sha256.Sum256(cert.Raw)
	return LocalRootSummary{
		Subject:              cert.Subject.String(),
		SubjectKeyIdentifier: hex.EncodeToString(cert.SubjectKeyId),
		SerialHex:            upperNoSep(cert.SerialNumber),
		NotBefore:            cert.NotBefore.Format("2006-01-02 15:04:05 MST"),
		NotAfter:             cert.NotAfter.Format("2006-01-02 15:04:05 MST"),
		SHA256FingerprintHex: hex.EncodeToString(sha[:]),
	}
}

// mergeTrustEntries collapses a slice of TrustSourceEntries into a
// LocalRootSummary list keyed by SHA-256 fingerprint. Each unique cert
// appears once; its Origins slice records every source where it was
// observed. Origins are deduplicated by (Type, Path) so a cert read twice
// from the same anchor file does not produce duplicate origin entries.
//
// Order is preserved by first-seen fingerprint, then by first-seen origin
// for each cert, which keeps cache output stable when the same set of
// trust sources is enumerated repeatedly.
func mergeTrustEntries(entries []TrustSourceEntry) []LocalRootSummary {
	type slot struct {
		index int
		seen  map[string]struct{}
	}
	bySHA := make(map[string]*slot, len(entries))
	out := make([]LocalRootSummary, 0, len(entries))

	for _, e := range entries {
		if e.Cert == nil {
			continue
		}
		sum := summarizeCert(e.Cert)
		key := sum.SHA256FingerprintHex
		s, ok := bySHA[key]
		if !ok {
			out = append(out, sum)
			s = &slot{index: len(out) - 1, seen: make(map[string]struct{})}
			bySHA[key] = s
		}
		originKey := e.OriginType + "|" + e.OriginPath
		if _, dup := s.seen[originKey]; dup {
			continue
		}
		s.seen[originKey] = struct{}{}
		out[s.index].Origins = append(out[s.index].Origins, OriginRef{
			Type: e.OriginType,
			Path: e.OriginPath,
		})
	}
	return out
}

func needsRegen(path string) bool {
	b, err := os.ReadFile(path)
	if err != nil {
		return true
	}
	var f localRootsFile
	if err := json.Unmarshal(b, &f); err != nil {
		return true
	}
	if len(f.Roots) == 0 {
		return false
	}
	// If first entry has empty SerialHex, assume legacy format and regenerate.
	if f.Roots[0].SerialHex == "" {
		return true
	}
	// If the first entry has no Origins, the cache predates the per-origin
	// schema introduced in 3.B. Regenerate so the new fields populate.
	return len(f.Roots[0].Origins) == 0
}

func upperNoSep(n *big.Int) string {
	if n == nil {
		return ""
	}
	s := n.Text(16)
	// Pad to even length.
	if len(s)%2 == 1 {
		s = "0" + s
	}
	out := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'f' {
			c = c - ('a' - 'A')
		}
		out[i] = c
	}
	return string(out)
}

// LoadLocalRootsSKISet loads local_roots.json and returns a map of normalized SKI → summary.
func LoadLocalRootsSKISet() (map[string]LocalRootSummary, error) {
	path, err := LocalRootsPath()
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return map[string]LocalRootSummary{}, nil
		}
		return nil, err
	}
	var file localRootsFile
	if err := json.Unmarshal(b, &file); err != nil {
		return nil, err
	}
	m := make(map[string]LocalRootSummary, len(file.Roots))
	for _, r := range file.Roots {
		if r.SubjectKeyIdentifier == "" {
			continue
		}
		key := normalizeHexString(r.SubjectKeyIdentifier)
		m[key] = r
	}
	return m, nil
}

func normalizeHexString(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9':
			out = append(out, c)
		case c >= 'a' && c <= 'f':
			out = append(out, c-('a'-'A'))
		case c >= 'A' && c <= 'F':
			out = append(out, c)
		default:
			// skip separators and non-hex characters
		}
	}
	return string(out)
}

// FindTrustedRootCertBySubjectKeyID returns a parsed root from the same source used to build
// local_roots.json whose Subject Key Identifier matches normalizedSKI (hex, no separators, A–F).
func FindTrustedRootCertBySubjectKeyID(ctx context.Context, normalizedSKI string) (*x509.Certificate, error) {
	if normalizedSKI == "" {
		return nil, ErrTrustedRootNotFound
	}
	parsed, _, err := enumerateSystemRootCertificates(ctx)
	if err != nil {
		return nil, err
	}
	for _, c := range parsed {
		if len(c.SubjectKeyId) == 0 {
			continue
		}
		if certs.NormalizeHexBytesNoSepUpper(c.SubjectKeyId) == normalizedSKI {
			return c, nil
		}
	}
	return nil, ErrTrustedRootNotFound
}
