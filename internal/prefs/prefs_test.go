package prefs

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// isolatePrefs redirects both the config and cache directories to a temp dir
// for the duration of the test. On Linux, os.UserConfigDir respects
// $XDG_CONFIG_HOME and os.UserCacheDir respects $XDG_CACHE_HOME.
func isolatePrefs(t *testing.T) {
	t.Helper()
	tmp := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(tmp, "config"))
	t.Setenv("XDG_CACHE_HOME", filepath.Join(tmp, "cache"))
}

func TestDefault(t *testing.T) {
	d := Default()
	assert.Equal(t, OpenSSL, d.UI.NameStyle)
	assert.Equal(t, HexColon, d.UI.HexSep)
	assert.Equal(t, "", d.UI.LastDir)
	assert.False(t, d.UI.ShowCCADBOnlyCerts)
	assert.Equal(t, 30, d.Resources.RefreshDays)
	assert.NotEmpty(t, d.Resources.CCadbResourcesURL)
	assert.NotEmpty(t, d.Resources.CCADBURL)
	assert.Equal(t, CacheFilenameFromURL(d.Resources.CCADBURL), d.Resources.CachedFilename)

	// Mutations to one returned value must not affect a subsequent call.
	d.UI.NameStyle = Windows
	d2 := Default()
	assert.Equal(t, OpenSSL, d2.UI.NameStyle)
}

func TestCacheFilenameFromURL(t *testing.T) {
	tests := []struct {
		name  string
		url   string
		want  string
	}{
		{"v2 URL", "https://ccadb.my.salesforce-sites.com/ccadb/AllCertificateRecordsCSVFormatv2", "allcertificaterecordscsvformatv2.csv"},
		{"v3 URL", "https://ccadb.my.salesforce-sites.com/ccadb/AllCertificateRecordsCSVFormatv3", "allcertificaterecordscsvformatv3.csv"},
		{"URL with no path segment", "https://example.com", "example.com.csv"},
		{"URL ending in slash", "https://example.com/", "ccadb_cache.csv"},
		{"mixed case segment", "https://example.com/SomeName", "somename.csv"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, CacheFilenameFromURL(tc.url))
		})
	}
}

func TestLoad_NoFile(t *testing.T) {
	isolatePrefs(t)
	p, err := Load()
	require.NoError(t, err)
	assert.Equal(t, Default(), p)

	// Load should have created the config directory.
	dir, err := ConfigDir()
	require.NoError(t, err)
	_, statErr := os.Stat(dir)
	assert.NoError(t, statErr)
}

func TestLoad_RoundTrip(t *testing.T) {
	isolatePrefs(t)
	require.NoError(t, Save(Default()))
	p, err := Load()
	require.NoError(t, err)
	assert.Equal(t, Default(), p)
}

func TestLoad_Validation(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Preferences)
		check  func(t *testing.T, p Preferences)
	}{
		{
			"invalid NameStyle resets to OpenSSL",
			func(p *Preferences) { p.UI.NameStyle = "custom" },
			func(t *testing.T, p Preferences) { assert.Equal(t, OpenSSL, p.UI.NameStyle) },
		},
		{
			"invalid HexSep resets to HexColon",
			func(p *Preferences) { p.UI.HexSep = "-" },
			func(t *testing.T, p Preferences) { assert.Equal(t, HexColon, p.UI.HexSep) },
		},
		{
			"RefreshDays zero resets to 30",
			func(p *Preferences) { p.Resources.RefreshDays = 0 },
			func(t *testing.T, p Preferences) { assert.Equal(t, 30, p.Resources.RefreshDays) },
		},
		{
			"RefreshDays negative resets to 30",
			func(p *Preferences) { p.Resources.RefreshDays = -5 },
			func(t *testing.T, p Preferences) { assert.Equal(t, 30, p.Resources.RefreshDays) },
		},
		{
			"empty CCadbResourcesURL resets to default",
			func(p *Preferences) { p.Resources.CCadbResourcesURL = "" },
			func(t *testing.T, p Preferences) {
				assert.Equal(t, Default().Resources.CCadbResourcesURL, p.Resources.CCadbResourcesURL)
			},
		},
		{
			"empty CCADBURL resets to default",
			func(p *Preferences) { p.Resources.CCADBURL = "" },
			func(t *testing.T, p Preferences) {
				assert.Equal(t, Default().Resources.CCADBURL, p.Resources.CCADBURL)
			},
		},
		{
			"empty CachedFilename is derived from CCADBURL",
			func(p *Preferences) { p.Resources.CachedFilename = "" },
			func(t *testing.T, p Preferences) {
				assert.Equal(t, CacheFilenameFromURL(p.Resources.CCADBURL), p.Resources.CachedFilename)
			},
		},
		{
			"ShowCCADBOnlyCerts true is preserved",
			func(p *Preferences) { p.UI.ShowCCADBOnlyCerts = true },
			func(t *testing.T, p Preferences) { assert.True(t, p.UI.ShowCCADBOnlyCerts) },
		},
		{
			"valid Windows NameStyle is preserved",
			func(p *Preferences) { p.UI.NameStyle = Windows },
			func(t *testing.T, p Preferences) { assert.Equal(t, Windows, p.UI.NameStyle) },
		},
		{
			"valid HexNone is preserved",
			func(p *Preferences) { p.UI.HexSep = HexNone },
			func(t *testing.T, p Preferences) { assert.Equal(t, HexNone, p.UI.HexSep) },
		},
		{
			"valid HexSpace is preserved",
			func(p *Preferences) { p.UI.HexSep = HexSpace },
			func(t *testing.T, p Preferences) { assert.Equal(t, HexSpace, p.UI.HexSep) },
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			isolatePrefs(t)
			def := Default()
			tc.mutate(&def)
			require.NoError(t, Save(def))
			loaded, err := Load()
			require.NoError(t, err)
			tc.check(t, loaded)
		})
	}
}

func TestLoad_InvalidJSON(t *testing.T) {
	isolatePrefs(t)
	dir, err := ConfigDir()
	require.NoError(t, err)
	require.NoError(t, os.MkdirAll(dir, 0o755))
	path := filepath.Join(dir, "preferences.json")
	require.NoError(t, os.WriteFile(path, []byte("not json {{{"), 0o600))
	_, err = Load()
	assert.ErrorContains(t, err, "invalid preferences")
}

func TestSave_FilePermissions(t *testing.T) {
	isolatePrefs(t)
	require.NoError(t, Save(Default()))
	dir, err := ConfigDir()
	require.NoError(t, err)
	info, err := os.Stat(filepath.Join(dir, "preferences.json"))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
}

func TestSave_CreatesDirectory(t *testing.T) {
	isolatePrefs(t)
	// The config directory does not exist yet; Save should create it.
	require.NoError(t, Save(Default()))
	dir, err := ConfigDir()
	require.NoError(t, err)
	_, statErr := os.Stat(dir)
	assert.NoError(t, statErr)
}

func TestConfigDir(t *testing.T) {
	isolatePrefs(t)
	dir, err := ConfigDir()
	require.NoError(t, err)
	assert.NotEmpty(t, dir)
	assert.Equal(t, "cert_viewer", filepath.Base(dir))
}

func TestCacheDir(t *testing.T) {
	isolatePrefs(t)
	dir, err := CacheDir()
	require.NoError(t, err)
	assert.NotEmpty(t, dir)
	assert.Equal(t, "cert_viewer", filepath.Base(dir))

	// Cache dir must be distinct from config dir.
	cfgDir, err := ConfigDir()
	require.NoError(t, err)
	assert.NotEqual(t, cfgDir, dir)
}

func TestCacheDir_CreatesDirectory(t *testing.T) {
	isolatePrefs(t)
	dir, err := CacheDir()
	require.NoError(t, err)
	_, statErr := os.Stat(dir)
	assert.NoError(t, statErr, "CacheDir should create the directory")
}

func TestAddRecentFile(t *testing.T) {
	make10 := func() []string {
		out := make([]string, MaxRecentFiles)
		for i := range out {
			out[i] = filepath.Join("/certs", fmt.Sprintf("cert%d.pem", i))
		}
		return out
	}

	tests := []struct {
		name     string
		initial  []string
		path     string
		wantLen  int
		wantHead string // expected first element
		wantDup  bool   // path must appear exactly once
	}{
		{
			name:     "add to empty list",
			initial:  nil,
			path:     "/a/cert.pem",
			wantLen:  1,
			wantHead: "/a/cert.pem",
			wantDup:  true,
		},
		{
			name:     "prepend to existing",
			initial:  []string{"/a/cert.pem"},
			path:     "/b/other.crt",
			wantLen:  2,
			wantHead: "/b/other.crt",
			wantDup:  true,
		},
		{
			name:     "dedup already first",
			initial:  []string{"/a/cert.pem", "/b/other.crt"},
			path:     "/a/cert.pem",
			wantLen:  2,
			wantHead: "/a/cert.pem",
			wantDup:  true,
		},
		{
			name:     "dedup promotes to front",
			initial:  []string{"/a/cert.pem", "/b/other.crt"},
			path:     "/b/other.crt",
			wantLen:  2,
			wantHead: "/b/other.crt",
			wantDup:  true,
		},
		{
			name:     "cap at MaxRecentFiles",
			initial:  make10(),
			path:     "/new/cert.pem",
			wantLen:  MaxRecentFiles,
			wantHead: "/new/cert.pem",
			wantDup:  true,
		},
		{
			name:     "add existing in full list",
			initial:  make10(),
			path:     filepath.Join("/certs", "cert4.pem"),
			wantLen:  MaxRecentFiles,
			wantHead: filepath.Join("/certs", "cert4.pem"),
			wantDup:  true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := Default()
			p.UI.RecentFiles = tc.initial
			got := AddRecentFile(p, tc.path)

			assert.Equal(t, tc.wantLen, len(got.UI.RecentFiles), "length")
			assert.Equal(t, tc.wantHead, got.UI.RecentFiles[0], "first element")

			if tc.wantDup {
				count := 0
				for _, f := range got.UI.RecentFiles {
					if f == tc.path {
						count++
					}
				}
				assert.Equal(t, 1, count, "path must appear exactly once")
			}
		})
	}
}
