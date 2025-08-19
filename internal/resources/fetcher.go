package resources

import (
	"context"
	"errors"
	"fmt"
	"io"
	"encoding/csv"
	"net/http"
	"os"
	"path/filepath"
	"time"
    "strings"

	"cert_viewier/internal/prefs"
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
            norm := normalizeHex(rec[skiIdx])
            if norm != "" {
                set[norm] = struct{}{}
            }
        }
    }
    return set, nil
}

func equalFoldTrim(a, b string) bool {
    return strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(b))
}

func normalizeHex(s string) string {
    // Keep hex chars only and uppercase
    out := make([]rune, 0, len(s))
    for _, r := range s {
        switch {
        case r >= '0' && r <= '9':
            out = append(out, r)
        case r >= 'a' && r <= 'f':
            out = append(out, r-('a'-'A'))
        case r >= 'A' && r <= 'F':
            out = append(out, r)
        default:
            // skip
        }
    }
    return string(out)
}
