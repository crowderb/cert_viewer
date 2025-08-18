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

type Preferences struct {
	NameStyle NameStyle `json:"nameStyle"`
    HexSep    HexSeparator `json:"hexSeparator"`
    LastDir   string       `json:"lastDir"`
}

func Default() Preferences {
	return Preferences{
		NameStyle: OpenSSL,
        HexSep:    HexColon,
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
	if p.NameStyle != OpenSSL && p.NameStyle != Windows {
		p.NameStyle = OpenSSL
	}
    switch p.HexSep {
    case HexNone, HexColon, HexSpace:
    default:
        p.HexSep = HexColon
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

func configPath() (configDir string, fileName string, fullPath string, err error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", "", "", err
	}
	dir := filepath.Join(base, "cert_viewier")
	name := "preferences.json"
	return dir, name, filepath.Join(dir, name), nil
}
