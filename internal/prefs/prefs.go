package prefs

import (
    "encoding/json"
    "errors"
    "fmt"
    "os"
    "path/filepath"
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
    NameStyle NameStyle   `json:"nameStyle"`
    HexSep    HexSeparator `json:"hexSeparator"`
    LastDir   string       `json:"lastDir"`
}

type Resources struct {
    CCADBURL    string `json:"ccadb_org_root_intermediate_certs_csv_url"`
    RefreshDays int    `json:"refresh_days"`
}

type Preferences struct {
    UI        UISettings `json:"UI Settings"`
    Resources Resources  `json:"Resources"`
}

func Default() Preferences {
    return Preferences{
        UI: UISettings{
            NameStyle: OpenSSL,
            HexSep:    HexColon,
            LastDir:   "",
        },
        Resources: Resources{
            CCADBURL:    "https://ccadb.my.salesforce-sites.com/ccadb/AllCertificateRecordsCSVFormatv2",
            RefreshDays: 30,
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
            // Ensure directory exists for future saves
            _ = os.MkdirAll(dir, 0o755)
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
    if p.Resources.RefreshDays <= 0 {
        p.Resources.RefreshDays = 30
    }
    if p.Resources.CCADBURL == "" {
        p.Resources.CCADBURL = Default().Resources.CCADBURL
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
