package resources

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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
	// Precompute a base64-encoded value with a known hex output.
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

// --- Filesystem-dependent tests ---

func TestCachePath(t *testing.T) {
	withTempCache(t)
	path, err := CachePath()
	require.NoError(t, err)
	assert.Equal(t, ccadbCachedName, filepath.Base(path))
}

func TestLoadCCADBSKISet(t *testing.T) {
	t.Run("file does not exist returns empty map", func(t *testing.T) {
		withTempCache(t)
		set, err := LoadCCADBSKISet()
		require.NoError(t, err)
		assert.Empty(t, set)
	})

	t.Run("CSV with SKI column populates set", func(t *testing.T) {
		cacheDir := withTempCache(t)
		csv := "Certificate Name,Subject Key Identifier,Other\n" +
			"Cert One,AB:CD:EF,x\n" +
			"Cert Two,12:34:56,y\n"
		writeTempCSV(t, cacheDir, csv)
		set, err := LoadCCADBSKISet()
		require.NoError(t, err)
		assert.Contains(t, set, "ABCDEF")
		assert.Contains(t, set, "123456")
	})

	t.Run("empty SKI entries are skipped", func(t *testing.T) {
		cacheDir := withTempCache(t)
		csv := "Certificate Name,Subject Key Identifier\n" +
			"Cert One,\n" +
			"Cert Two,AB:CD:EF\n"
		writeTempCSV(t, cacheDir, csv)
		set, err := LoadCCADBSKISet()
		require.NoError(t, err)
		assert.Len(t, set, 1)
		assert.Contains(t, set, "ABCDEF")
	})

	t.Run("CSV missing SKI column returns empty set", func(t *testing.T) {
		cacheDir := withTempCache(t)
		csv := "Certificate Name,Other Column\n" +
			"Cert One,value\n"
		writeTempCSV(t, cacheDir, csv)
		set, err := LoadCCADBSKISet()
		require.NoError(t, err)
		assert.Empty(t, set)
	})
}

func TestLoadCCADBSummary(t *testing.T) {
	t.Run("file does not exist returns empty map", func(t *testing.T) {
		withTempCache(t)
		m, err := LoadCCADBSummary()
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
		writeTempCSV(t, cacheDir, csv)
		m, err := LoadCCADBSummary()
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
		writeTempCSV(t, cacheDir, csv)
		m, err := LoadCCADBSummary()
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
		writeTempCSV(t, cacheDir, csv)
		m, err := LoadCCADBSummary()
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
		writeTempCSV(t, cacheDir, csv)
		m, err := LoadCCADBSummary()
		require.NoError(t, err)
		assert.Equal(t, "My Root CA", m["ABCDEF"].Subject)
	})
}

// --- Network tests ---

func TestEnsureCCADBCSV(t *testing.T) {
	csvContent := "col1,Subject Key Identifier\nval1,AB:CD:EF\n"

	t.Run("downloads when cache is missing", func(t *testing.T) {
		cacheDir := withTempCache(t)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(csvContent)) //nolint:errcheck
		}))
		defer srv.Close()

		p := prefs.Default()
		p.Resources.CCADBURL = srv.URL

		ch := EnsureCCADBCSV(context.Background(), p)
		err := <-ch
		require.NoError(t, err)

		data, readErr := os.ReadFile(filepath.Join(cacheDir, ccadbCachedName))
		require.NoError(t, readErr)
		assert.Equal(t, csvContent, string(data))
	})

	t.Run("skips download when cache is fresh", func(t *testing.T) {
		cacheDir := withTempCache(t)
		// Write a file just now — it is well within 30-day max age.
		require.NoError(t, os.MkdirAll(cacheDir, 0o755))
		require.NoError(t, os.WriteFile(
			filepath.Join(cacheDir, ccadbCachedName), []byte("cached"), 0o644))

		downloaded := false
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			downloaded = true
			w.Write([]byte(csvContent)) //nolint:errcheck
		}))
		defer srv.Close()

		p := prefs.Default()
		p.Resources.CCADBURL = srv.URL
		p.Resources.RefreshDays = 30

		ch := EnsureCCADBCSV(context.Background(), p)
		err := <-ch
		require.NoError(t, err)
		assert.False(t, downloaded, "should not download when cache is fresh")
	})

	t.Run("error on non-2xx response", func(t *testing.T) {
		withTempCache(t)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer srv.Close()

		p := prefs.Default()
		p.Resources.CCADBURL = srv.URL

		ch := EnsureCCADBCSV(context.Background(), p)
		err := <-ch
		assert.ErrorContains(t, err, "download failed")
	})
}
