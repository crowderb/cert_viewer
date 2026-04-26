package prefs

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
)

type NameStyle string
type HexSeparator string

const (
	OpenSSL NameStyle = "openssl"
	Windows NameStyle = "windows"
)

const (
	HexNone  HexSeparator = ""
	HexColon HexSeparator = ":"
	HexSpace HexSeparator = " "
)

type UISettings struct {
	NameStyle          NameStyle    `json:"nameStyle"`
	HexSep             HexSeparator `json:"hexSeparator"`
	LastDir            string       `json:"lastDir"`
	ShowCCADBOnlyCerts bool         `json:"showCCADBOnlyCerts"`
	ExpiryWarnDays     int          `json:"expiryWarnDays"` // 0 on old files → validated to 30
	RecentFiles        []string     `json:"recentFiles"`    // ordered newest-first, capped at MaxRecentFiles
}

type Resources struct {
	CCadbResourcesURL string `json:"ccadb_resources_url"`                       // page to discover the latest CSV download URL
	CCADBURL          string `json:"ccadb_org_root_intermediate_certs_csv_url"` // discovered CSV download URL
	RefreshDays       int    `json:"refresh_days"`
	CachedFilename    string `json:"cached_filename"`
}

// CacheFilenameFromURL derives the local cache filename from the CCADB download URL.
// It takes the last path segment of the URL, lowercases it, and appends ".csv".
// e.g. "...AllCertificateRecordsCSVFormatv2" → "allcertificaterecordscsvformatv2.csv"
func CacheFilenameFromURL(rawURL string) string {
	idx := strings.LastIndex(rawURL, "/")
	seg := rawURL
	if idx >= 0 {
		seg = rawURL[idx+1:]
	}
	if seg == "" {
		return "ccadb_cache.csv"
	}
	return strings.ToLower(seg) + ".csv"
}

type Preferences struct {
	UI        UISettings `json:"UI Settings"`
	Resources Resources  `json:"Resources"`
}

// MaxRecentFiles is the maximum number of recent file paths retained.
const MaxRecentFiles = 10

// AddRecentFile returns p with path moved to the front of UI.RecentFiles,
// deduplicated and capped at MaxRecentFiles.
func AddRecentFile(p Preferences, path string) Preferences {
	var filtered []string
	for _, f := range p.UI.RecentFiles {
		if f != path {
			filtered = append(filtered, f)
		}
	}
	recent := append([]string{path}, filtered...)
	if len(recent) > MaxRecentFiles {
		recent = recent[:MaxRecentFiles]
	}
	p.UI.RecentFiles = recent
	return p
}

func Default() Preferences {
	const resourcesURL = "https://www.ccadb.org/resources"
	const defaultCSVURL = "https://ccadb.my.salesforce-sites.com/ccadb/AllCertificateRecordsCSVFormatv2"
	return Preferences{
		UI: UISettings{
			NameStyle:          OpenSSL,
			HexSep:             HexColon,
			LastDir:            "",
			ShowCCADBOnlyCerts: false,
			ExpiryWarnDays:     30,
		},
		Resources: Resources{
			CCadbResourcesURL: resourcesURL,
			CCADBURL:          defaultCSVURL,
			RefreshDays:       30,
			CachedFilename:    CacheFilenameFromURL(defaultCSVURL),
		},
	}
}

func Load() (Preferences, error) {
	p := Default()
	dir, _, path, err := configPath()
	if err != nil {
		return p, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// Ensure directory exists for future saves. Failure here is not
			// fatal — the next prefs.Save() will surface a clearer error.
			if mkErr := os.MkdirAll(dir, 0o755); mkErr != nil {
				slog.Warn("config dir create failed", "dir", dir, "err", mkErr)
			}
			return p, nil
		}
		return p, err
	}
	if err := json.Unmarshal(data, &p); err != nil {
		return p, fmt.Errorf("invalid preferences: %w", err)
	}
	// Validate
	if p.UI.NameStyle != OpenSSL && p.UI.NameStyle != Windows {
		p.UI.NameStyle = OpenSSL
	}
	switch p.UI.HexSep {
	case HexNone, HexColon, HexSpace:
	default:
		p.UI.HexSep = HexColon
	}
	// ShowCCADBOnlyCerts defaults to false when missing; no further validation
	if p.UI.ExpiryWarnDays <= 0 {
		p.UI.ExpiryWarnDays = 30
	}
	if p.Resources.RefreshDays <= 0 {
		p.Resources.RefreshDays = 30
	}
	if p.Resources.CCadbResourcesURL == "" {
		p.Resources.CCadbResourcesURL = Default().Resources.CCadbResourcesURL
	}
	if p.Resources.CCADBURL == "" {
		p.Resources.CCADBURL = Default().Resources.CCADBURL
	}
	if p.Resources.CachedFilename == "" {
		p.Resources.CachedFilename = CacheFilenameFromURL(p.Resources.CCADBURL)
	}
	return p, nil
}

func Save(p Preferences) error {
	dir, _, path, err := configPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

// ConfigDir returns the directory where preferences and app data are stored.
func ConfigDir() (string, error) {
	dir, _, _, err := configPath()
	return dir, err
}

// CacheDir returns the cache directory for app data that can be re-fetched.
func CacheDir() (string, error) {
	base, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(base, "cert_viewer")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	return dir, nil
}

func configPath() (configDir string, fileName string, fullPath string, err error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", "", "", err
	}
	dir := filepath.Join(base, "cert_viewer")
	name := "preferences.json"
	return dir, name, filepath.Join(dir, name), nil
}
