package resources

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"

	"cert_viewer/internal/prefs"
)

const localRootsFileName = "local_roots.json"
const defaultLinuxBundle = "/etc/ssl/certs/ca-certificates.crt"

type LocalRootSummary struct {
	Subject               string `json:"subject"`
	SubjectKeyIdentifier  string `json:"subjectKeyIdentifier"`
	NotBefore             string `json:"notBefore"`
	NotAfter              string `json:"notAfter"`
	SHA256FingerprintHex  string `json:"sha256"`
}

type localRootsFile struct {
	GeneratedAt string              `json:"generatedAt"`
	SourcePath  string              `json:"sourcePath"`
	Roots       []LocalRootSummary  `json:"roots"`
}

// LocalRootsPath returns the cache path to local_roots.json
func LocalRootsPath() (string, error) {
	cache, err := prefs.CacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(cache, localRootsFileName), nil
}

// EnsureLocalRootsJSON generates the local_roots.json if it does not exist.
func EnsureLocalRootsJSON(ctx context.Context) error {
	path, err := LocalRootsPath()
	if err != nil {
		return err
	}
	if _, err := os.Stat(path); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	// Try default Linux bundle
	bundle := defaultLinuxBundle
	f, err := os.Open(bundle)
	if err != nil {
		// If bundle not present, create empty file to avoid repeated attempts
		if errors.Is(err, os.ErrNotExist) {
			return writeLocalRoots(path, localRootsFile{GeneratedAt: time.Now().Format(time.RFC3339), SourcePath: bundle, Roots: nil})
		}
		return err
	}
	defer f.Close()
	data, err := io.ReadAll(f)
	if err != nil {
		return err
	}
	roots := make([]LocalRootSummary, 0, 200)
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" || len(block.Bytes) == 0 {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		sha := sha256.Sum256(cert.Raw)
		summary := LocalRootSummary{
			Subject:              cert.Subject.String(),
			SubjectKeyIdentifier: hex.EncodeToString(cert.SubjectKeyId),
			NotBefore:            cert.NotBefore.Format("2006-01-02 15:04:05 MST"),
			NotAfter:             cert.NotAfter.Format("2006-01-02 15:04:05 MST"),
			SHA256FingerprintHex: hex.EncodeToString(sha[:]),
		}
		roots = append(roots, summary)
	}
	file := localRootsFile{
		GeneratedAt: time.Now().Format(time.RFC3339),
		SourcePath:  bundle,
		Roots:      roots,
	}
	return writeLocalRoots(path, file)
}

func writeLocalRoots(path string, content localRootsFile) error {
	b, err := json.MarshalIndent(content, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

// LoadLocalRootsSKISet loads local_roots.json and returns a map of normalized SKI -> summary
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
			// skip
		}
	}
	return string(out)
}
