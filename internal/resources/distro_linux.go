//go:build linux

package resources

import (
	"bufio"
	"errors"
	"io"
	"os"
	"strings"
)

// DistroFamily groups Linux distributions by the convention they use for the
// system trust store, since that — not the marketing brand — determines where
// admin-added root CAs live.
type DistroFamily string

const (
	DistroDebian  DistroFamily = "debian"  // also Ubuntu, Mint, Pop, Kali, …
	DistroRHEL    DistroFamily = "rhel"    // also Fedora, Rocky, Alma, CentOS, Amazon Linux
	DistroArch    DistroFamily = "arch"    // also Manjaro, EndeavourOS
	DistroSUSE    DistroFamily = "suse"    // openSUSE, SLE
	DistroAlpine  DistroFamily = "alpine"  // ca-certificates uses the Debian convention
	DistroUnknown DistroFamily = "unknown" // /etc/os-release missing or unrecognized
)

// DistroInfo describes the detected distribution and the directory where
// admin-added root CAs are expected to live for that distribution. Anchor
// dir paths follow each family's ca-certificates / ca-trust convention.
type DistroInfo struct {
	Family    DistroFamily
	Name      string // PRETTY_NAME from os-release, for display ("Ubuntu 24.04")
	AnchorDir string // empty when family is unknown
}

// osReleasePath is the file DetectDistroFamily reads. It is a package-level
// var (rather than a const) so tests can point it at a fixture without
// piping a path argument through every caller.
var osReleasePath = "/etc/os-release"

// DetectDistroFamily reads /etc/os-release and classifies the host's
// distribution into one of the supported families. Detection prefers ID over
// ID_LIKE, but falls back to ID_LIKE so derived distros (e.g. Mint, Manjaro,
// Rocky) inherit their parent family's anchor directory without each needing
// to be enumerated explicitly.
//
// Returns DistroUnknown with empty AnchorDir if /etc/os-release is missing or
// unparseable; callers should treat that as "no per-distro anchor dir to
// enumerate" rather than as an error.
func DetectDistroFamily() (DistroInfo, error) {
	return detectDistroFamilyAt(osReleasePath)
}

func detectDistroFamilyAt(path string) (DistroInfo, error) {
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return DistroInfo{Family: DistroUnknown}, nil
		}
		return DistroInfo{Family: DistroUnknown}, err
	}
	defer f.Close()

	id, idLike, prettyName, err := parseOSRelease(f)
	if err != nil {
		return DistroInfo{Family: DistroUnknown}, err
	}

	family := classify(id, idLike)
	return DistroInfo{
		Family:    family,
		Name:      prettyName,
		AnchorDir: anchorDirFor(family),
	}, nil
}

// parseOSRelease extracts ID, ID_LIKE, and PRETTY_NAME from an os-release
// stream. Lines that don't match KEY=VALUE are silently skipped. Quoted
// values have surrounding double or single quotes stripped.
func parseOSRelease(r io.Reader) (id, idLike, prettyName string, err error) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		eq := strings.IndexByte(line, '=')
		if eq < 0 {
			continue
		}
		key := strings.TrimSpace(line[:eq])
		val := unquote(strings.TrimSpace(line[eq+1:]))
		switch key {
		case "ID":
			id = strings.ToLower(val)
		case "ID_LIKE":
			idLike = strings.ToLower(val)
		case "PRETTY_NAME":
			prettyName = val
		}
	}
	if err := scanner.Err(); err != nil {
		return "", "", "", err
	}
	return id, idLike, prettyName, nil
}

func unquote(s string) string {
	if len(s) >= 2 {
		first, last := s[0], s[len(s)-1]
		if (first == '"' && last == '"') || (first == '\'' && last == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}

// classify reduces an os-release ID (and ID_LIKE for derivatives) to the
// family whose trust-store convention applies. ID_LIKE is space-separated
// per the spec; we check each token in order so the most specific parent
// family wins (e.g. ID_LIKE="ubuntu debian" → Debian).
func classify(id, idLike string) DistroFamily {
	if fam := matchID(id); fam != DistroUnknown {
		return fam
	}
	for _, token := range strings.Fields(idLike) {
		if fam := matchID(token); fam != DistroUnknown {
			return fam
		}
	}
	return DistroUnknown
}

func matchID(id string) DistroFamily {
	switch id {
	case "debian", "ubuntu", "linuxmint", "mint", "pop", "kali", "raspbian",
		"elementary", "neon", "zorin", "deepin", "parrot":
		return DistroDebian
	case "rhel", "fedora", "centos", "rocky", "almalinux", "ol", "oracle",
		"amzn", "amazon", "scientific":
		return DistroRHEL
	case "arch", "manjaro", "endeavouros", "garuda", "artix":
		return DistroArch
	case "opensuse", "opensuse-leap", "opensuse-tumbleweed", "sles", "sled", "suse":
		return DistroSUSE
	case "alpine":
		return DistroAlpine
	}
	return DistroUnknown
}

// anchorDirFor returns the conventional admin-added-CA directory for a
// family. Each family's update-ca-certificates / update-ca-trust tooling
// expects user-added PEMs in this directory, then concatenates them into
// the system bundle on the next refresh.
func anchorDirFor(f DistroFamily) string {
	switch f {
	case DistroDebian, DistroAlpine:
		return "/usr/local/share/ca-certificates"
	case DistroRHEL:
		return "/etc/pki/ca-trust/source/anchors"
	case DistroArch:
		return "/etc/ca-certificates/trust-source/anchors"
	case DistroSUSE:
		return "/etc/pki/trust/anchors"
	}
	return ""
}
