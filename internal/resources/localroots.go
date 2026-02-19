package resources

import (
	"context"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"cert_viewer/internal/prefs"
)

const localRootsFileName = "local_roots.json"

type LocalRootSummary struct {
	Subject               string `json:"subject"`
	SubjectKeyIdentifier  string `json:"subjectKeyIdentifier"`
	SerialHex             string `json:"serialHex"`
	NotBefore             string `json:"notBefore"`
	NotAfter              string `json:"notAfter"`
	SHA256FingerprintHex  string `json:"sha256"`
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
func EnsureLocalRootsJSON(ctx context.Context) error {
	path, err := LocalRootsPath()
	if err != nil {
		return err
	}
	if _, err := os.Stat(path); err == nil {
		if !needsRegen(path) {
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

func writeLocalRoots(path string, content localRootsFile) error {
	b, err := json.MarshalIndent(content, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
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
	return f.Roots[0].SerialHex == ""
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
