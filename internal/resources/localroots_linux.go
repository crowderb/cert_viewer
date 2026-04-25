//go:build linux

package resources

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	defaultLinuxBundle = "/etc/ssl/certs/ca-certificates.crt"
	dirSourcePrefix    = "DIR:"
)

// resolveTrustSource picks the trust-store source path used to populate the
// local-roots cache. Resolution order:
//
//  1. SSL_CERT_FILE — alternate bundle path (the same override Go's crypto/x509
//     honors). Skipped silently if the value is unreadable, so a misconfigured
//     env var falls through to lower-precedence sources rather than failing.
//  2. SSL_CERT_DIR — colon-separated list of directories. Returned with a
//     "DIR:" prefix so downstream code can recognize multi-directory mode.
//  3. defaultLinuxBundle — the Debian/Ubuntu concatenated bundle.
func resolveTrustSource() string {
	if f := strings.TrimSpace(os.Getenv("SSL_CERT_FILE")); f != "" {
		if _, err := os.Stat(f); err == nil {
			return f
		}
	}
	if d := strings.TrimSpace(os.Getenv("SSL_CERT_DIR")); d != "" {
		return dirSourcePrefix + d
	}
	return defaultLinuxBundle
}

// trustSourceMTime reports the latest modification time relevant to the given
// source. For a single bundle file, this is the file's mtime. For a "DIR:"
// source, it is the maximum mtime across every *.pem / *.crt file in any of
// the listed directories — so adding, removing, or replacing any anchor in
// any directory advances the source mtime and invalidates the cache.
//
// Returns ok=false when the source cannot be inspected (e.g. all directories
// missing). The caller treats that as "skip the mtime check" rather than an
// error so that platforms without a meaningful mtime can no-op.
func trustSourceMTime(source string) (time.Time, bool) {
	if strings.HasPrefix(source, dirSourcePrefix) {
		var latest time.Time
		any := false
		for _, dir := range splitDirSource(source) {
			entries, err := os.ReadDir(dir)
			if err != nil {
				continue
			}
			for _, e := range entries {
				if e.IsDir() || !isPEMFilename(e.Name()) {
					continue
				}
				info, err := e.Info()
				if err != nil {
					continue
				}
				if info.ModTime().After(latest) {
					latest = info.ModTime()
				}
				any = true
			}
		}
		return latest, any
	}
	info, err := os.Stat(source)
	if err != nil {
		return time.Time{}, false
	}
	return info.ModTime(), true
}

// enumerateSystemRootCertificates parses certificates from the resolved trust
// source. For a single-bundle source the file is parsed as a stream of PEM
// blocks. For a "DIR:" source, every *.pem / *.crt file in every listed
// directory is parsed and the results concatenated; missing or unreadable
// directories are skipped silently to mirror Go's own SSL_CERT_DIR behavior.
func enumerateSystemRootCertificates(_ context.Context) ([]*x509.Certificate, string, error) {
	source := resolveTrustSource()
	if strings.HasPrefix(source, dirSourcePrefix) {
		certs, err := enumerateFromDirs(splitDirSource(source))
		return certs, source, err
	}
	certs, err := enumerateFromBundle(source)
	return certs, source, err
}

func enumerateFromBundle(path string) ([]*x509.Certificate, error) {
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}
	return parsePEMCertificates(data), nil
}

func enumerateFromDirs(dirs []string) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() || !isPEMFilename(e.Name()) {
				continue
			}
			data, err := os.ReadFile(filepath.Join(dir, e.Name()))
			if err != nil {
				continue
			}
			out = append(out, parsePEMCertificates(data)...)
		}
	}
	return out, nil
}

// parsePEMCertificates decodes consecutive PEM CERTIFICATE blocks from data.
// Non-CERTIFICATE blocks and unparseable certificates are skipped silently;
// the caller decides whether an empty result is an error.
func parsePEMCertificates(data []byte) []*x509.Certificate {
	var out []*x509.Certificate
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			return out
		}
		if block.Type != "CERTIFICATE" || len(block.Bytes) == 0 {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		out = append(out, cert)
	}
}

func splitDirSource(source string) []string {
	raw := strings.TrimPrefix(source, dirSourcePrefix)
	parts := strings.Split(raw, string(os.PathListSeparator))
	out := parts[:0]
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func isPEMFilename(name string) bool {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".pem", ".crt", ".cer":
		return true
	}
	return false
}

func collectRoots(ctx context.Context) ([]LocalRootSummary, string, error) {
	certs, source, err := enumerateSystemRootCertificates(ctx)
	if err != nil {
		return nil, source, err
	}
	roots := make([]LocalRootSummary, 0, len(certs))
	for _, cert := range certs {
		sha := sha256.Sum256(cert.Raw)
		roots = append(roots, LocalRootSummary{
			Subject:              cert.Subject.String(),
			SubjectKeyIdentifier: hex.EncodeToString(cert.SubjectKeyId),
			SerialHex:            upperNoSep(cert.SerialNumber),
			NotBefore:            cert.NotBefore.Format("2006-01-02 15:04:05 MST"),
			NotAfter:             cert.NotAfter.Format("2006-01-02 15:04:05 MST"),
			SHA256FingerprintHex: hex.EncodeToString(sha[:]),
		})
	}
	return roots, source, nil
}
