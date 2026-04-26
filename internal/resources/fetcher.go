package resources

import (
	"context"
	"encoding/base64"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"cert_viewer/internal/httpclient"
	"cert_viewer/internal/prefs"
)

// ccadbCSVURLRE matches the full CCADB CSV download URL inside an HTML page.
var ccadbCSVURLRE = regexp.MustCompile(`https?://[^\s"'<>]*AllCertificateRecordsCSVFormat[^\s"'<>]*`)

// discoverLatestCCADBURL fetches the CCADB resources page at resourcesURL and
// extracts the current AllCertificateRecordsCSVFormat download URL from its HTML.
// Returns an error if the page is unreachable or no matching URL is found.
func discoverLatestCCADBURL(ctx context.Context, resourcesURL string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, resourcesURL, nil)
	if err != nil {
		return "", err
	}
	resp, err := httpclient.Default().Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("CCADB resources page returned %s", resp.Status)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	match := ccadbCSVURLRE.Find(body)
	if match == nil {
		return "", fmt.Errorf("AllCertificateRecordsCSVFormat URL not found on resources page")
	}
	return string(match), nil
}

// EnsureCCADBCSV checks cache staleness and refreshes the file in the background.
// On each call it first fetches p.Resources.CCadbResourcesURL to discover the
// current AllCertificateRecordsCSVFormat download URL; if a new version is found
// the old cache file is deleted, prefs are updated on disk, and a fresh download
// is forced. If the resources page is unreachable the stored URL is used as-is.
// It returns immediately; any error is sent on the returned channel.
func EnsureCCADBCSV(ctx context.Context, p prefs.Preferences) <-chan error {
	ch := make(chan error, 1)
	go func() {
		defer close(ch)
		cacheDir, err := prefs.CacheDir()
		if err != nil {
			ch <- err
			return
		}

		prefsChanged := false

		// Step 1: discover the latest CSV download URL from the resources page.
		resourcesURL := p.Resources.CCadbResourcesURL
		if resourcesURL == "" {
			resourcesURL = prefs.Default().Resources.CCadbResourcesURL
		}
		if discovered, discErr := discoverLatestCCADBURL(ctx, resourcesURL); discErr == nil {
			if discovered != p.Resources.CCADBURL {
				p.Resources.CCADBURL = discovered
				prefsChanged = true
			}
		}
		// If discovery fails, silently continue with the stored URL.

		// Step 2: sync CachedFilename with current URL; delete old file on version change.
		newName := prefs.CacheFilenameFromURL(p.Resources.CCADBURL)
		if p.Resources.CachedFilename != newName {
			if p.Resources.CachedFilename != "" {
				_ = os.Remove(filepath.Join(cacheDir, p.Resources.CachedFilename))
			}
			p.Resources.CachedFilename = newName
			prefsChanged = true
		}

		if prefsChanged {
			_ = prefs.Save(p)
		}

		path := filepath.Join(cacheDir, p.Resources.CachedFilename)
		stale := true
		if info, err := os.Stat(path); err == nil {
			maxAge := time.Duration(p.Resources.RefreshDays) * 24 * time.Hour
			if time.Since(info.ModTime()) < maxAge {
				stale = false
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			ch <- err
			return
		}
		if !stale {
			return
		}

		// Step 3: download the file.
		url := p.Resources.CCADBURL
		if url == "" {
			url = prefs.Default().Resources.CCADBURL
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			ch <- err
			return
		}
		resp, err := httpclient.CCADBDownload().Do(req)
		if err != nil {
			ch <- err
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			ch <- fmt.Errorf("download failed: %s", resp.Status)
			return
		}
		tmpPath := path + ".tmp"
		f, err := os.Create(tmpPath)
		if err != nil {
			ch <- err
			return
		}
		if _, err := io.Copy(f, resp.Body); err != nil {
			f.Close()
			_ = os.Remove(tmpPath)
			ch <- err
			return
		}
		if err := f.Close(); err != nil {
			_ = os.Remove(tmpPath)
			ch <- err
			return
		}
		if err := os.Rename(tmpPath, path); err != nil {
			ch <- err
			return
		}
	}()
	return ch
}

// CachePath returns the expected cache file path for the CCADB CSV derived from p.
func CachePath(p prefs.Preferences) (string, error) {
	d, err := prefs.CacheDir()
	if err != nil {
		return "", err
	}
	name := p.Resources.CachedFilename
	if name == "" {
		name = prefs.CacheFilenameFromURL(p.Resources.CCADBURL)
	}
	return filepath.Join(d, name), nil
}

// LoadCCADBSKISet loads the Subject Key Identifier column values from cached CSV.
// Returns a set of normalized uppercase hex strings without separators.
func LoadCCADBSKISet(p prefs.Preferences) (map[string]struct{}, error) {
	path, err := CachePath(p)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return map[string]struct{}{}, nil
		}
		return nil, err
	}
	defer f.Close()
	r := csv.NewReader(f)
	header, err := r.Read()
	if err != nil {
		return nil, err
	}
	skiIdx := -1
	for i, h := range header {
		if equalFoldTrim(h, "Subject Key Identifier") {
			skiIdx = i
			break
		}
	}
	if skiIdx == -1 {
		// Column not found; return empty set
		return map[string]struct{}{}, nil
	}
	set := make(map[string]struct{})
	for {
		rec, err := r.Read()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return set, err
		}
		if skiIdx < len(rec) {
			norm := parseSKIToUpperHex(rec[skiIdx])
			if norm != "" {
				set[norm] = struct{}{}
			}
		}
	}
	return set, nil
}

// LoadCCADBSummary loads CCADB rows and returns a map SKI(hex upper) -> {subject, notAfter}
// If the CSV is missing columns, best-effort data is returned.
func LoadCCADBSummary(p prefs.Preferences) (map[string]struct {
	Subject  string
	NotAfter time.Time
}, error) {
	path, err := CachePath(p)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return map[string]struct {
				Subject  string
				NotAfter time.Time
			}{}, nil
		}
		return nil, err
	}
	defer f.Close()
	r := csv.NewReader(f)
	header, err := r.Read()
	if err != nil {
		return nil, err
	}
	skiIdx, subjectIdx, notAfterIdx := -1, -1, -1
	appleIdx, chromeIdx, msIdx, mozIdx := -1, -1, -1, -1
	for i, h := range header {
		switch {
		case equalFoldTrim(h, "Subject Key Identifier"):
			skiIdx = i
		case equalFoldTrim(h, "Certificate Name"):
			subjectIdx = i
		case equalFoldTrim(h, "Valid To (GMT)"):
			notAfterIdx = i
		case equalFoldTrim(h, "Apple Status"):
			appleIdx = i
		case equalFoldTrim(h, "Chrome Status"):
			chromeIdx = i
		case equalFoldTrim(h, "Microsoft Status"):
			msIdx = i
		case equalFoldTrim(h, "Mozilla Status"):
			mozIdx = i
		}
	}
	out := make(map[string]struct {
		Subject  string
		NotAfter time.Time
	})
	for {
		rec, err := r.Read()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return out, err
		}
		if skiIdx < 0 || skiIdx >= len(rec) {
			continue
		}
		// Exclude any row marked Not Trusted by major vendors
		if isNotTrusted(rec, appleIdx) || isNotTrusted(rec, chromeIdx) || isNotTrusted(rec, msIdx) || isNotTrusted(rec, mozIdx) {
			continue
		}
		ski := parseSKIToUpperHex(rec[skiIdx])
		if ski == "" {
			continue
		}
		subject := ""
		if subjectIdx >= 0 && subjectIdx < len(rec) {
			subject = strings.TrimSpace(rec[subjectIdx])
		}
		var notAfter time.Time
		if notAfterIdx >= 0 && notAfterIdx < len(rec) {
			notAfter = parseCCADBDate(rec[notAfterIdx])
		}
		out[ski] = struct {
			Subject  string
			NotAfter time.Time
		}{Subject: subject, NotAfter: notAfter}
	}
	return out, nil
}

// CCADBRow holds selected columns from one CCADB CSV row. Rows are keyed by
// normalized Subject Key Identifier when building an index for chain resolution.
type CCADBRow struct {
	CertificateName string
	RecordType      string
	ValidFrom       string
	ValidTo         string
	SHA256          string
	// AuthorityKeyID is normalized uppercase hex of the Authority Key Identifier column.
	AuthorityKeyID string
}

func betterCCADBRow(existing, candidate CCADBRow) CCADBRow {
	if existing.CertificateName == "" && existing.RecordType == "" {
		return candidate
	}
	cRoot := strings.Contains(strings.ToLower(candidate.RecordType), "root")
	eRoot := strings.Contains(strings.ToLower(existing.RecordType), "root")
	switch {
	case cRoot && !eRoot:
		return candidate
	case !cRoot && eRoot:
		return existing
	default:
		return candidate
	}
}

// LoadCCADBChainData reads the cached CCADB CSV once and returns both the SKI
// presence set (for “is this CA listed?” checks) and a map of row metadata by
// normalized Subject Key Identifier. The latter is used to resolve a parent CA
// when an intermediate has no CA Issuers URL but has an Authority Key Identifier
// that matches another row’s Subject Key Identifier (typical for trust roots).
func LoadCCADBChainData(p prefs.Preferences) (skiSet map[string]struct{}, bySKI map[string]CCADBRow, err error) {
	path, err := CachePath(p)
	if err != nil {
		return nil, nil, err
	}
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return map[string]struct{}{}, map[string]CCADBRow{}, nil
		}
		return map[string]struct{}{}, map[string]CCADBRow{}, err
	}
	defer f.Close()
	r := csv.NewReader(f)
	header, err := r.Read()
	if err != nil {
		return map[string]struct{}{}, map[string]CCADBRow{}, err
	}
	skiIdx, nameIdx, typeIdx, fromIdx, toIdx, shaIdx, akiIdx := -1, -1, -1, -1, -1, -1, -1
	appleIdx, chromeIdx, msIdx, mozIdx := -1, -1, -1, -1
	for i, h := range header {
		ht := strings.TrimSpace(h)
		switch {
		case equalFoldTrim(ht, "Subject Key Identifier"):
			skiIdx = i
		case equalFoldTrim(ht, "Certificate Name"):
			nameIdx = i
		case equalFoldTrim(ht, "Certificate Record Type"):
			typeIdx = i
		case equalFoldTrim(ht, "Valid From (GMT)"):
			fromIdx = i
		case equalFoldTrim(ht, "Valid To (GMT)"):
			toIdx = i
		case equalFoldTrim(ht, "SHA-256 Fingerprint"):
			shaIdx = i
		case equalFoldTrim(ht, "Authority Key Identifier"):
			akiIdx = i
		case equalFoldTrim(ht, "Apple Status"):
			appleIdx = i
		case equalFoldTrim(ht, "Chrome Status"):
			chromeIdx = i
		case equalFoldTrim(ht, "Microsoft Status"):
			msIdx = i
		case equalFoldTrim(ht, "Mozilla Status"):
			mozIdx = i
		}
	}
	if skiIdx < 0 {
		return map[string]struct{}{}, map[string]CCADBRow{}, nil
	}
	skiSet = make(map[string]struct{})
	bySKI = make(map[string]CCADBRow)
	for {
		rec, err := r.Read()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return skiSet, bySKI, err
		}
		if isNotTrusted(rec, appleIdx) || isNotTrusted(rec, chromeIdx) || isNotTrusted(rec, msIdx) || isNotTrusted(rec, mozIdx) {
			continue
		}
		if skiIdx >= len(rec) {
			continue
		}
		ski := parseSKIToUpperHex(rec[skiIdx])
		if ski == "" {
			continue
		}
		skiSet[ski] = struct{}{}
		row := CCADBRow{}
		if nameIdx >= 0 && nameIdx < len(rec) {
			row.CertificateName = strings.TrimSpace(rec[nameIdx])
		}
		if typeIdx >= 0 && typeIdx < len(rec) {
			row.RecordType = strings.TrimSpace(rec[typeIdx])
		}
		if fromIdx >= 0 && fromIdx < len(rec) {
			row.ValidFrom = strings.TrimSpace(rec[fromIdx])
		}
		if toIdx >= 0 && toIdx < len(rec) {
			row.ValidTo = strings.TrimSpace(rec[toIdx])
		}
		if shaIdx >= 0 && shaIdx < len(rec) {
			row.SHA256 = strings.TrimSpace(rec[shaIdx])
		}
		if akiIdx >= 0 && akiIdx < len(rec) {
			row.AuthorityKeyID = parseSKIToUpperHex(rec[akiIdx])
		}
		if prev, ok := bySKI[ski]; ok {
			bySKI[ski] = betterCCADBRow(prev, row)
		} else {
			bySKI[ski] = row
		}
	}
	return skiSet, bySKI, nil
}

func isNotTrusted(rec []string, idx int) bool {
	if idx < 0 || idx >= len(rec) {
		return false
	}
	v := strings.TrimSpace(rec[idx])
	return strings.EqualFold(v, "Not Trusted")
}

func parseCCADBDate(s string) time.Time {
	t := strings.TrimSpace(s)
	if t == "" {
		return time.Time{}
	}
	// CCADB uses formats like: Jan 02 15:04:05 2006 GMT
	// Try a couple of common layouts
	layouts := []string{
		"Jan 2 15:04:05 2006 MST",
		"Jan 02 15:04:05 2006 MST",
		time.RFC3339,
	}
	for _, layout := range layouts {
		if tt, err := time.Parse(layout, t); err == nil {
			return tt
		}
	}
	return time.Time{}
}

func equalFoldTrim(a, b string) bool {
	return strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(b))
}

func parseSKIToUpperHex(s string) string {
	t := strings.TrimSpace(s)
	if t == "" {
		return ""
	}
	// First try hex with common separators removed
	cleaned := make([]byte, 0, len(t))
	hexCandidate := true
	for i := 0; i < len(t); i++ {
		c := t[i]
		switch c {
		case ':', ' ', '\t', '\n', '\r':
			continue
		default:
			// check hex
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
				hexCandidate = false
			}
			cleaned = append(cleaned, c)
		}
	}
	if hexCandidate && len(cleaned)%2 == 0 && len(cleaned) > 0 {
		// Uppercase and return
		for i := 0; i < len(cleaned); i++ {
			if cleaned[i] >= 'a' && cleaned[i] <= 'f' {
				cleaned[i] -= 'a' - 'A'
			}
		}
		return string(cleaned)
	}
	// Fallback: base64 decode
	if b, err := base64.StdEncoding.DecodeString(t); err == nil {
		return bytesToUpperHex(b)
	}
	if b, err := base64.RawStdEncoding.DecodeString(t); err == nil {
		return bytesToUpperHex(b)
	}
	return ""
}

func bytesToUpperHex(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	var sb strings.Builder
	sb.Grow(len(b) * 2)
	for _, by := range b {
		sb.WriteString(fmt.Sprintf("%02X", by))
	}
	return sb.String()
}
