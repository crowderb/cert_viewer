//go:build linux

package resources

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

// NSSStatus describes the outcome of attempting to read an NSS certificate
// database. Each value maps to a user-visible message in the Trust Sources
// tab so a missing tool or absent DB is distinguishable from a genuine
// read failure without the UI having to inspect strings.
type NSSStatus int

const (
	NSSAvailable     NSSStatus = iota // Successfully read certutil output
	NSSNotInstalled                   // certutil binary not on PATH
	NSSDBMissing                      // Database directory or file does not exist
	NSSReadError                      // certutil ran but returned an error
)

// NSSResult bundles the entries pulled from a single NSS database with a
// status code describing whether the read succeeded, was skipped, or failed.
// The UI uses Status to decide between rendering the entry list, an
// informational note ("certutil not installed"), or a hard error.
type NSSResult struct {
	Path     string
	Status   NSSStatus
	Message  string // human-readable detail, especially for NSSReadError
	Entries  []TrustSourceEntry
}

// trustAttrsLine matches a trust-attributes triple at the end of a certutil
// listing line, e.g. "C,,", "CT,c,", or ",,". Three comma-separated fields
// of trust flags. Captures the nickname (everything before the attrs) and
// the attrs themselves; we only need the nickname today, but keeping the
// regex authoritative keeps the parser symmetric with certutil's format.
var trustAttrsLine = regexp.MustCompile(`^(.+?)\s+([^,\s]*,[^,\s]*,[^,\s]*)\s*$`)

// certutilNickname extracts the cert nickname from one line of `certutil -L`
// output, or "" if the line is a header / separator / blank. certutil's
// output is column-aligned but the column boundary moves with the longest
// nickname, so we anchor on the trust-attributes pattern at the end of the
// line rather than on a fixed column index.
func certutilNickname(line string) string {
	line = strings.TrimRight(line, "\r\n")
	if line == "" {
		return ""
	}
	if strings.HasPrefix(strings.TrimSpace(line), "Certificate Nickname") {
		return ""
	}
	if strings.HasPrefix(strings.TrimSpace(line), "SSL,") {
		return ""
	}
	m := trustAttrsLine.FindStringSubmatch(line)
	if m == nil {
		return ""
	}
	return strings.TrimSpace(m[1])
}

// EnumerateNSSDB lists every certificate stored in the NSS database at
// dbPath and returns one TrustSourceEntry per cert, tagged with originType
// (typically OriginNSSUser or OriginNSSFirefox).
//
// dbPath is the directory containing cert9.db / key4.db (the SQLite-backed
// "sql:" form). When the directory or the certutil binary is missing, the
// returned NSSResult uses Status = NSSDBMissing or NSSNotInstalled so the
// UI can show a graceful note instead of an error.
func EnumerateNSSDB(ctx context.Context, dbPath, originType string) NSSResult {
	res := NSSResult{Path: dbPath}

	// Probe certutil first — if it isn't installed, no point checking the DB.
	if _, err := exec.LookPath("certutil"); err != nil {
		res.Status = NSSNotInstalled
		res.Message = "certutil not installed (libnss3-tools)"
		return res
	}

	if info, err := os.Stat(dbPath); err != nil || !info.IsDir() {
		res.Status = NSSDBMissing
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			res.Message = err.Error()
		}
		return res
	}
	// cert9.db is the modern SQLite-backed format. cert8.db is the legacy
	// Berkeley-DB form; certutil reads either when given "sql:".
	if _, err := os.Stat(filepath.Join(dbPath, "cert9.db")); err != nil {
		if _, err2 := os.Stat(filepath.Join(dbPath, "cert8.db")); err2 != nil {
			res.Status = NSSDBMissing
			res.Message = "no cert9.db or cert8.db in " + dbPath
			return res
		}
	}

	nicknames, err := listNSSNicknames(ctx, dbPath)
	if err != nil {
		res.Status = NSSReadError
		res.Message = err.Error()
		return res
	}
	for _, nick := range nicknames {
		cert, err := exportNSSCertificate(ctx, dbPath, nick)
		if err != nil || cert == nil {
			continue
		}
		res.Entries = append(res.Entries, TrustSourceEntry{
			Cert:       cert,
			OriginType: originType,
			OriginPath: dbPath,
		})
	}
	res.Status = NSSAvailable
	return res
}

// listNSSNicknames runs `certutil -L -d sql:<dbPath>` and parses the
// nickname column from the output. Returns the slice of nicknames in the
// order certutil emits them. Lines that do not match the trust-attributes
// pattern (header rows, blanks) are skipped.
func listNSSNicknames(ctx context.Context, dbPath string) ([]string, error) {
	cmd := exec.CommandContext(ctx, "certutil", "-L", "-d", "sql:"+dbPath)
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("certutil -L: %w", err)
	}
	var nicks []string
	for _, line := range strings.Split(string(out), "\n") {
		if nick := certutilNickname(line); nick != "" {
			nicks = append(nicks, nick)
		}
	}
	return nicks, nil
}

// exportNSSCertificate runs `certutil -L -d sql:<dbPath> -n <nickname> -a`
// to export a single cert as PEM, then parses it. Returns nil and a nil
// error when certutil produces no parseable PEM (rare but possible for
// non-cert entries with cert-like trust attributes).
func exportNSSCertificate(ctx context.Context, dbPath, nickname string) (*x509.Certificate, error) {
	cmd := exec.CommandContext(ctx, "certutil", "-L", "-d", "sql:"+dbPath, "-n", nickname, "-a")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("certutil -L -n %q: %w", nickname, err)
	}
	for {
		var block *pem.Block
		block, out = pem.Decode(out)
		if block == nil {
			return nil, nil
		}
		if block.Type != "CERTIFICATE" || len(block.Bytes) == 0 {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		return cert, nil
	}
}

// EnumerateAllNSSDBs scans the standard per-user NSS database locations on
// Linux: ~/.pki/nssdb (used by Chrome/Chromium and many libnss-based apps)
// and every ~/.mozilla/firefox/*/cert9.db profile. Returns one NSSResult
// per probed location so the UI can show each independently — useful when
// a user has Chrome trust additions but no Firefox install, or vice versa.
//
// Returns an empty slice (not an error) when $HOME is not set; that case
// is realistic in some sandboxed contexts.
func EnumerateAllNSSDBs(ctx context.Context) []NSSResult {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return nil
	}

	var results []NSSResult
	results = append(results, EnumerateNSSDB(ctx, filepath.Join(home, ".pki", "nssdb"), OriginNSSUser))

	matches, _ := filepath.Glob(filepath.Join(home, ".mozilla", "firefox", "*"))
	for _, m := range matches {
		// Profile dirs contain cert9.db; non-profile dirs (e.g. Crash Reports)
		// don't, and EnumerateNSSDB will return NSSDBMissing for those — we
		// just skip emitting them so the UI list stays clean.
		if _, err := os.Stat(filepath.Join(m, "cert9.db")); err != nil {
			continue
		}
		results = append(results, EnumerateNSSDB(ctx, m, OriginNSSFirefox))
	}
	return results
}
