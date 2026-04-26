package resources

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"cert_viewer/internal/prefs"
)

// --- Pure function tests (no I/O) ---

func TestEqualFoldTrim(t *testing.T) {
	tests := []struct {
		a, b string
		want bool
	}{
		{"", "", true},
		{"hello", "hello", true},
		{"Hello", "hello", true},
		{"  hello  ", "HELLO", true},
		{"subject key identifier", "Subject Key Identifier", true},
		{"hello", "world", false},
		{" a ", "b ", false},
	}
	for _, tc := range tests {
		t.Run(tc.a+"|"+tc.b, func(t *testing.T) {
			assert.Equal(t, tc.want, equalFoldTrim(tc.a, tc.b))
		})
	}
}

func TestParseCCADBDate(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantZero bool
		wantYear int
	}{
		{"empty string", "", true, 0},
		{"whitespace only", "   ", true, 0},
		{"invalid format", "garbage-date", true, 0},
		{"two-digit day format", "Jan 15 00:00:00 2024 GMT", false, 2024},
		{"single-digit day format", "Jun 5 00:00:00 2024 GMT", false, 2024},
		{"RFC3339 format", "2024-06-15T00:00:00Z", false, 2024},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := parseCCADBDate(tc.input)
			if tc.wantZero {
				assert.True(t, result.IsZero(), "expected zero time for input %q", tc.input)
			} else {
				assert.False(t, result.IsZero(), "expected non-zero time for input %q", tc.input)
				assert.Equal(t, tc.wantYear, result.Year())
			}
		})
	}
}

func TestIsNotTrusted(t *testing.T) {
	tests := []struct {
		name string
		rec  []string
		idx  int
		want bool
	}{
		{"idx negative", []string{"a", "b"}, -1, false},
		{"idx out of bounds", []string{"a"}, 2, false},
		{"exact match", []string{"Not Trusted"}, 0, true},
		{"lowercase", []string{"not trusted"}, 0, true},
		{"uppercase", []string{"NOT TRUSTED"}, 0, true},
		{"with surrounding spaces", []string{"  Not Trusted  "}, 0, true},
		{"Included", []string{"Included"}, 0, false},
		{"empty value", []string{""}, 0, false},
		{"multi-column correct idx", []string{"Included", "Not Trusted"}, 1, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, isNotTrusted(tc.rec, tc.idx))
		})
	}
}

func TestParseSKIToUpperHex(t *testing.T) {
	b64Val := base64.StdEncoding.EncodeToString([]byte{0xDE, 0xAD, 0xBE, 0xEF})

	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"empty", "", ""},
		{"whitespace only", "   ", ""},
		{"colon-separated hex", "AB:CD:EF", "ABCDEF"},
		{"space-separated hex", "AB CD EF", "ABCDEF"},
		{"lowercase colon-sep", "ab:cd:ef", "ABCDEF"},
		{"already normalized uppercase", "ABCDEF", "ABCDEF"},
		{"base64 std encoding", b64Val, "DEADBEEF"},
		{"garbage non-hex non-base64", "!!!!", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, parseSKIToUpperHex(tc.input))
		})
	}
}

func TestBytesToUpperHex(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		want  string
	}{
		{"empty", []byte{}, ""},
		{"zero byte", []byte{0x00}, "00"},
		{"0xFF", []byte{0xFF}, "FF"},
		{"multi byte", []byte{0xAB, 0xCD}, "ABCD"},
		{"leading zero nibble", []byte{0x0A}, "0A"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, bytesToUpperHex(tc.input))
		})
	}
}

// --- Discovery tests ---

func TestDiscoverLatestCCADBURL(t *testing.T) {
	t.Run("extracts v2 URL from page HTML", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`<html><body>` + //nolint:errcheck
				`<a href="https://ccadb.my.salesforce-sites.com/ccadb/AllCertificateRecordsCSVFormatv2">Download</a>` +
				`</body></html>`))
		}))
		defer srv.Close()
		url, err := discoverLatestCCADBURL(context.Background(), srv.URL)
		require.NoError(t, err)
		assert.Equal(t, "https://ccadb.my.salesforce-sites.com/ccadb/AllCertificateRecordsCSVFormatv2", url)
	})

	t.Run("extracts v3 URL from page HTML", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`<html><body>` + //nolint:errcheck
				`<a href="https://ccadb.my.salesforce-sites.com/ccadb/AllCertificateRecordsCSVFormatv3">Download</a>` +
				`</body></html>`))
		}))
		defer srv.Close()
		url, err := discoverLatestCCADBURL(context.Background(), srv.URL)
		require.NoError(t, err)
		assert.Equal(t, "https://ccadb.my.salesforce-sites.com/ccadb/AllCertificateRecordsCSVFormatv3", url)
	})

	t.Run("returns error when no matching URL found", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`<html><body><p>No CSV link here</p></body></html>`)) //nolint:errcheck
		}))
		defer srv.Close()
		_, err := discoverLatestCCADBURL(context.Background(), srv.URL)
		assert.Error(t, err)
	})

	t.Run("returns error on non-2xx response", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))
		defer srv.Close()
		_, err := discoverLatestCCADBURL(context.Background(), srv.URL)
		assert.Error(t, err)
	})
}

// --- Filesystem-dependent tests ---

func TestCachePath(t *testing.T) {
	withTempCache(t)
	p := prefs.Default()
	path, err := CachePath(p)
	require.NoError(t, err)
	assert.Equal(t, p.Resources.CachedFilename, filepath.Base(path))
}

func TestLoadCCADBSKISet(t *testing.T) {
	p := prefs.Default()

	t.Run("file does not exist returns empty map", func(t *testing.T) {
		withTempCache(t)
		set, err := LoadCCADBSKISet(p)
		require.NoError(t, err)
		assert.Empty(t, set)
	})

	t.Run("CSV with SKI column populates set", func(t *testing.T) {
		cacheDir := withTempCache(t)
		csv := "Certificate Name,Subject Key Identifier,Other\n" +
			"Cert One,AB:CD:EF,x\n" +
			"Cert Two,12:34:56,y\n"
		writeTempCSV(t, cacheDir, csv, p)
		set, err := LoadCCADBSKISet(p)
		require.NoError(t, err)
		assert.Contains(t, set, "ABCDEF")
		assert.Contains(t, set, "123456")
	})

	t.Run("empty SKI entries are skipped", func(t *testing.T) {
		cacheDir := withTempCache(t)
		csv := "Certificate Name,Subject Key Identifier\n" +
			"Cert One,\n" +
			"Cert Two,AB:CD:EF\n"
		writeTempCSV(t, cacheDir, csv, p)
		set, err := LoadCCADBSKISet(p)
		require.NoError(t, err)
		assert.Len(t, set, 1)
		assert.Contains(t, set, "ABCDEF")
	})

	t.Run("CSV missing SKI column returns empty set", func(t *testing.T) {
		cacheDir := withTempCache(t)
		csv := "Certificate Name,Other Column\n" +
			"Cert One,value\n"
		writeTempCSV(t, cacheDir, csv, p)
		set, err := LoadCCADBSKISet(p)
		require.NoError(t, err)
		assert.Empty(t, set)
	})
}

func TestLoadCCADBChainData(t *testing.T) {
	p := prefs.Default()
	cacheDir := withTempCache(t)
	csv := "Certificate Name,Certificate Record Type,Subject Key Identifier,Authority Key Identifier," +
		"Valid From (GMT),Valid To (GMT),SHA-256 Fingerprint," +
		"Apple Status,Chrome Status,Microsoft Status,Mozilla Status\n" +
		"Inter CA,Intermediate Certificate,AA:AA:AA,BB:BB:BB," +
		"2020.01.01,2030.01.01,INTERHASH," +
		"Included,Included,Included,Included\n" +
		"My Root,Root Certificate,BB:BB:BB,," +
		"2012.01.01,2038.01.01,ROOTHASH," +
		"Included,Included,Included,Included\n"
	writeTempCSV(t, cacheDir, csv, p)
	set, bySKI, err := LoadCCADBChainData(p)
	require.NoError(t, err)
	assert.Contains(t, set, "AAAAAA")
	assert.Contains(t, set, "BBBBBB")
	rootRow := bySKI["BBBBBB"]
	assert.Contains(t, strings.ToLower(rootRow.RecordType), "root")
	assert.Equal(t, "My Root", rootRow.CertificateName)
	assert.Equal(t, "ROOTHASH", rootRow.SHA256)
}

func TestLoadCCADBSummary(t *testing.T) {
	p := prefs.Default()

	t.Run("file does not exist returns empty map", func(t *testing.T) {
		withTempCache(t)
		m, err := LoadCCADBSummary(p)
		require.NoError(t, err)
		assert.Empty(t, m)
	})

	t.Run("Not Trusted row is excluded, Included row is kept", func(t *testing.T) {
		cacheDir := withTempCache(t)
		csv := "Certificate Name,Subject Key Identifier,Valid To (GMT)," +
			"Apple Status,Chrome Status,Microsoft Status,Mozilla Status\n" +
			"TrustedCert,AB:CD:EF,Jan 15 00:00:00 2030 GMT," +
			"Included,Included,Included,Included\n" +
			"NotTrustedCert,12:34:56,Jan 15 00:00:00 2030 GMT," +
			"Not Trusted,Included,Included,Included\n"
		writeTempCSV(t, cacheDir, csv, p)
		m, err := LoadCCADBSummary(p)
		require.NoError(t, err)
		assert.Len(t, m, 1)
		assert.Contains(t, m, "ABCDEF")
		assert.NotContains(t, m, "123456")
	})

	t.Run("valid date is parsed into NotAfter", func(t *testing.T) {
		cacheDir := withTempCache(t)
		csv := "Certificate Name,Subject Key Identifier,Valid To (GMT)," +
			"Apple Status,Chrome Status,Microsoft Status,Mozilla Status\n" +
			"MyCert,AB:CD:EF,Jan 15 00:00:00 2030 GMT," +
			"Included,Included,Included,Included\n"
		writeTempCSV(t, cacheDir, csv, p)
		m, err := LoadCCADBSummary(p)
		require.NoError(t, err)
		entry := m["ABCDEF"]
		assert.Equal(t, 2030, entry.NotAfter.Year())
	})

	t.Run("invalid date gives zero NotAfter", func(t *testing.T) {
		cacheDir := withTempCache(t)
		csv := "Certificate Name,Subject Key Identifier,Valid To (GMT)," +
			"Apple Status,Chrome Status,Microsoft Status,Mozilla Status\n" +
			"MyCert,AB:CD:EF,not-a-date," +
			"Included,Included,Included,Included\n"
		writeTempCSV(t, cacheDir, csv, p)
		m, err := LoadCCADBSummary(p)
		require.NoError(t, err)
		entry := m["ABCDEF"]
		assert.True(t, entry.NotAfter.IsZero())
	})

	t.Run("subject name is populated", func(t *testing.T) {
		cacheDir := withTempCache(t)
		csv := "Certificate Name,Subject Key Identifier,Valid To (GMT)," +
			"Apple Status,Chrome Status,Microsoft Status,Mozilla Status\n" +
			"My Root CA,AB:CD:EF,Jan 15 00:00:00 2030 GMT," +
			"Included,Included,Included,Included\n"
		writeTempCSV(t, cacheDir, csv, p)
		m, err := LoadCCADBSummary(p)
		require.NoError(t, err)
		assert.Equal(t, "My Root CA", m["ABCDEF"].Subject)
	})
}

// --- Network tests ---

// mockPrefs builds a Preferences where both the resources discovery page and
// the CSV download use the supplied server URLs, sharing the same URL path
// segment so CacheFilenameFromURL stays consistent.
func mockPrefs(resourcesSrvURL, csvSrvURL string) prefs.Preferences {
	p := prefs.Default()
	p.Resources.CCadbResourcesURL = resourcesSrvURL
	p.Resources.CCADBURL = csvSrvURL
	p.Resources.CachedFilename = prefs.CacheFilenameFromURL(csvSrvURL)
	return p
}

// noDiscoverySrv returns a server that always responds 404, causing
// discoverLatestCCADBURL to fail and fall back to the stored URL.
func noDiscoverySrv(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// resourcesSrvReturning creates a resources page that embeds csvURL in an href.
func resourcesSrvReturning(t *testing.T, csvURL string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<a href="` + csvURL + `">Download</a>`)) //nolint:errcheck
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestEnsureCCADBCSV(t *testing.T) {
	csvContent := "col1,Subject Key Identifier\nval1,AB:CD:EF\n"

	// urlSegment gives a recognisable last path segment so
	// CacheFilenameFromURL produces "allcertificaterecordscsvformatv2.csv".
	const urlSegment = "/AllCertificateRecordsCSVFormatv2"

	t.Run("downloads when cache is missing", func(t *testing.T) {
		cacheDir := withTempCache(t)
		csvSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(csvContent)) //nolint:errcheck
		}))
		defer csvSrv.Close()

		csvURL := csvSrv.URL + urlSegment
		p := mockPrefs(noDiscoverySrv(t).URL, csvURL)

		ch := EnsureCCADBCSV(context.Background(), p)
		require.NoError(t, <-ch)

		data, readErr := os.ReadFile(filepath.Join(cacheDir, p.Resources.CachedFilename))
		require.NoError(t, readErr)
		assert.Equal(t, csvContent, string(data))
	})

	t.Run("skips download when cache is fresh", func(t *testing.T) {
		cacheDir := withTempCache(t)

		downloaded := false
		csvSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			downloaded = true
			w.Write([]byte(csvContent)) //nolint:errcheck
		}))
		defer csvSrv.Close()

		csvURL := csvSrv.URL + urlSegment
		p := mockPrefs(noDiscoverySrv(t).URL, csvURL)
		p.Resources.RefreshDays = 30

		// Pre-seed a fresh cache file.
		require.NoError(t, os.MkdirAll(cacheDir, 0o755))
		require.NoError(t, os.WriteFile(
			filepath.Join(cacheDir, p.Resources.CachedFilename), []byte("cached"), 0o644))

		ch := EnsureCCADBCSV(context.Background(), p)
		require.NoError(t, <-ch)
		assert.False(t, downloaded, "should not download when cache is fresh")
	})

	t.Run("error on non-2xx response", func(t *testing.T) {
		withTempCache(t)
		csvSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer csvSrv.Close()

		csvURL := csvSrv.URL + urlSegment
		p := mockPrefs(noDiscoverySrv(t).URL, csvURL)

		ch := EnsureCCADBCSV(context.Background(), p)
		assert.ErrorContains(t, <-ch, "download failed")
	})

	t.Run("discovery updates URL and downloads under new name", func(t *testing.T) {
		cacheDir := withTempCache(t)
		require.NoError(t, os.MkdirAll(cacheDir, 0o755))

		// CSV server serves under the v3 path.
		csvSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(csvContent)) //nolint:errcheck
		}))
		defer csvSrv.Close()

		v3URL := csvSrv.URL + "/AllCertificateRecordsCSVFormatv3"

		// Resources page advertises the v3 URL.
		resSrv := resourcesSrvReturning(t, v3URL)

		// Prefs start with v2 (old stored state).
		p := prefs.Default()
		p.Resources.CCadbResourcesURL = resSrv.URL
		// p.Resources.CCADBURL stays as the default v2 URL
		// p.Resources.CachedFilename stays as the default v2 filename

		// Seed an old v2 cache file.
		oldPath := filepath.Join(cacheDir, p.Resources.CachedFilename)
		require.NoError(t, os.WriteFile(oldPath, []byte("old v2 content"), 0o644))

		ch := EnsureCCADBCSV(context.Background(), p)
		require.NoError(t, <-ch)

		// Old v2 file must be gone.
		_, statErr := os.Stat(oldPath)
		assert.True(t, os.IsNotExist(statErr), "old v2 cache file should be deleted")

		// New v3 file must exist with the downloaded content.
		newName := prefs.CacheFilenameFromURL(v3URL)
		data, readErr := os.ReadFile(filepath.Join(cacheDir, newName))
		require.NoError(t, readErr)
		assert.Equal(t, csvContent, string(data))
	})

	t.Run("discovery failure falls back to stored URL", func(t *testing.T) {
		cacheDir := withTempCache(t)

		csvSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(csvContent)) //nolint:errcheck
		}))
		defer csvSrv.Close()

		csvURL := csvSrv.URL + urlSegment
		// noDiscoverySrv causes discovery to fail — stored URL is used.
		p := mockPrefs(noDiscoverySrv(t).URL, csvURL)

		ch := EnsureCCADBCSV(context.Background(), p)
		require.NoError(t, <-ch)

		data, readErr := os.ReadFile(filepath.Join(cacheDir, p.Resources.CachedFilename))
		require.NoError(t, readErr)
		assert.Equal(t, csvContent, string(data))
	})
}
