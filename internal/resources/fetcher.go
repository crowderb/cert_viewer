package resources

import (
	"context"
	"errors"
	"fmt"
	"io"
	"encoding/csv"
	"encoding/base64"
	"net/http"
	"os"
	"path/filepath"
	"time"
    "strings"

    "cert_viewer/internal/prefs"
)

const ccadbCachedName = "ccadb_all_certificate_records_v2.csv"

// EnsureCCADBCSV checks cache staleness and refreshes file in background.
// It returns immediately. Any download errors are reported via the returned channel
// if provided; pass nil if you don't need errors.
func EnsureCCADBCSV(ctx context.Context, p prefs.Preferences) <-chan error {
	ch := make(chan error, 1)
	go func() {
		defer close(ch)
		cacheDir, err := prefs.CacheDir()
		if err != nil {
			ch <- err
			return
		}
		path := filepath.Join(cacheDir, ccadbCachedName)
		stale := true
		if info, err := os.Stat(path); err == nil {
			// Exists; check age
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
		// Fetch
		url := p.Resources.CCADBURL
		if url == "" {
			url = prefs.Default().Resources.CCADBURL
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			ch <- err
			return
		}
		resp, err := http.DefaultClient.Do(req)
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

// CachePath returns the expected cache location for the CCADB csv.
func CachePath() (string, error) {
	d, err := prefs.CacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, ccadbCachedName), nil
}

// LoadCCADBSKISet loads the Subject Key Identifier column values from cached CSV.
// Returns a set of normalized uppercase hex strings without separators.
func LoadCCADBSKISet() (map[string]struct{}, error) {
    path, err := CachePath()
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
func LoadCCADBSummary() (map[string]struct{ Subject string; NotAfter time.Time }, error) {
    path, err := CachePath()
    if err != nil { return nil, err }
    f, err := os.Open(path)
    if err != nil {
        if errors.Is(err, os.ErrNotExist) { return map[string]struct{ Subject string; NotAfter time.Time }{}, nil }
        return nil, err
    }
    defer f.Close()
    r := csv.NewReader(f)
    header, err := r.Read()
    if err != nil { return nil, err }
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
    out := make(map[string]struct{ Subject string; NotAfter time.Time })
    for {
        rec, err := r.Read()
        if err != nil {
            if errors.Is(err, io.EOF) { break }
            return out, err
        }
        if skiIdx < 0 || skiIdx >= len(rec) { continue }
        // Exclude any row marked Not Trusted by major vendors
        if isNotTrusted(rec, appleIdx) || isNotTrusted(rec, chromeIdx) || isNotTrusted(rec, msIdx) || isNotTrusted(rec, mozIdx) {
            continue
        }
        ski := parseSKIToUpperHex(rec[skiIdx])
        if ski == "" { continue }
        subject := ""
        if subjectIdx >= 0 && subjectIdx < len(rec) { subject = strings.TrimSpace(rec[subjectIdx]) }
        var notAfter time.Time
        if notAfterIdx >= 0 && notAfterIdx < len(rec) {
            notAfter = parseCCADBDate(rec[notAfterIdx])
        }
        out[ski] = struct{ Subject string; NotAfter time.Time }{Subject: subject, NotAfter: notAfter}
    }
    return out, nil
}

func isNotTrusted(rec []string, idx int) bool {
    if idx < 0 || idx >= len(rec) { return false }
    v := strings.TrimSpace(rec[idx])
    return strings.EqualFold(v, "Not Trusted")
}

func parseCCADBDate(s string) time.Time {
    t := strings.TrimSpace(s)
    if t == "" { return time.Time{} }
    // CCADB uses formats like: Jan 02 15:04:05 2006 GMT
    // Try a couple of common layouts
    layouts := []string{
        "Jan 2 15:04:05 2006 MST",
        "Jan 02 15:04:05 2006 MST",
        time.RFC3339,
    }
    for _, layout := range layouts {
        if tt, err := time.Parse(layout, t); err == nil { return tt }
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
                cleaned[i] = cleaned[i] - ('a' - 'A')
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
    if len(b) == 0 { return "" }
    var sb strings.Builder
    sb.Grow(len(b) * 2)
    for _, by := range b {
        sb.WriteString(fmt.Sprintf("%02X", by))
    }
    return sb.String()
}
