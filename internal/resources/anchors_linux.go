//go:build linux

package resources

import (
	"os"
	"path/filepath"
)

// (Origin* constants and TrustSourceEntry are defined in localroots.go so
// all platform builds can reference them.)

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
