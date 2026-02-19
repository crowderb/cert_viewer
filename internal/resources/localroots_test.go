package resources

import (
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Pure function tests ---

func TestUpperNoSep(t *testing.T) {
	tests := []struct {
		name  string
		input *big.Int
		want  string
	}{
		{"nil", nil, ""},
		{"zero", big.NewInt(0), "00"},
		{"one padded to even", big.NewInt(1), "01"},
		{"0xABCD even-length", big.NewInt(0xABCD), "ABCD"},
		{"0xABCDE odd-length padded", big.NewInt(0xABCDE), "0ABCDE"},
		{"large serial", new(big.Int).SetBytes([]byte{0xDE, 0xAD, 0xBE, 0xEF}), "DEADBEEF"},
		{"lowercase from Text(16)", new(big.Int).SetBytes([]byte{0xDE, 0xAD}), "DEAD"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, upperNoSep(tc.input))
		})
	}
}

func TestNormalizeHexString(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"empty", "", ""},
		{"already normalized uppercase", "ABCDEF", "ABCDEF"},
		{"colon-separated lowercase", "ab:cd:ef", "ABCDEF"},
		{"space-separated", "AB CD EF", "ABCDEF"},
		{"mixed separators", "ab:CD ef", "ABCDEF"},
		{"non-hex letters dropped", "xyz", ""},
		{"digits only", "0123456789", "0123456789"},
		{"all non-hex chars", "!!!---===", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, normalizeHexString(tc.input))
		})
	}
}

// --- Filesystem tests ---

func TestNeedsRegen(t *testing.T) {
	t.Run("file not found returns true", func(t *testing.T) {
		assert.True(t, needsRegen("/nonexistent/path/local_roots.json"))
	})

	t.Run("malformed JSON returns true", func(t *testing.T) {
		f := filepath.Join(t.TempDir(), "bad.json")
		require.NoError(t, os.WriteFile(f, []byte("not json {{{"), 0o644))
		assert.True(t, needsRegen(f))
	})

	t.Run("empty Roots slice returns false", func(t *testing.T) {
		f := filepath.Join(t.TempDir(), "empty.json")
		lrf := localRootsFile{
			GeneratedAt: time.Now().Format(time.RFC3339),
			Roots:       nil,
		}
		require.NoError(t, writeLocalRoots(f, lrf))
		assert.False(t, needsRegen(f))
	})

	t.Run("first root with empty SerialHex returns true (legacy)", func(t *testing.T) {
		f := filepath.Join(t.TempDir(), "legacy.json")
		lrf := localRootsFile{
			Roots: []LocalRootSummary{
				{Subject: "CN=Test", SerialHex: ""},
			},
		}
		require.NoError(t, writeLocalRoots(f, lrf))
		assert.True(t, needsRegen(f))
	})

	t.Run("first root with non-empty SerialHex returns false", func(t *testing.T) {
		f := filepath.Join(t.TempDir(), "current.json")
		lrf := localRootsFile{
			Roots: []LocalRootSummary{
				{Subject: "CN=Test", SerialHex: "ABCDEF"},
			},
		}
		require.NoError(t, writeLocalRoots(f, lrf))
		assert.False(t, needsRegen(f))
	})
}

func TestWriteLocalRoots(t *testing.T) {
	f := filepath.Join(t.TempDir(), "roots.json")
	content := localRootsFile{
		GeneratedAt: "2024-01-01T00:00:00Z",
		SourcePath:  "/some/path",
		Roots: []LocalRootSummary{
			{Subject: "CN=Test Root", SubjectKeyIdentifier: "ABCDEF", SerialHex: "01"},
		},
	}
	require.NoError(t, writeLocalRoots(f, content))

	data, err := os.ReadFile(f)
	require.NoError(t, err)
	s := string(data)
	assert.Contains(t, s, "CN=Test Root")
	assert.Contains(t, s, "ABCDEF")
	assert.Contains(t, s, "01")
}

func TestLoadLocalRootsSKISet(t *testing.T) {
	t.Run("file does not exist returns empty map", func(t *testing.T) {
		withTempCache(t)
		m, err := LoadLocalRootsSKISet()
		require.NoError(t, err)
		assert.Empty(t, m)
	})

	t.Run("loads roots and normalizes SKI keys", func(t *testing.T) {
		cacheDir := withTempCache(t)
		lrPath := filepath.Join(cacheDir, localRootsFileName)
		require.NoError(t, os.MkdirAll(cacheDir, 0o755))
		lrf := localRootsFile{
			Roots: []LocalRootSummary{
				{Subject: "CN=Root1", SubjectKeyIdentifier: "ab:cd:ef", SerialHex: "01"},
				{Subject: "CN=Root2", SubjectKeyIdentifier: "", SerialHex: "02"}, // empty SKI — skipped
				{Subject: "CN=Root3", SubjectKeyIdentifier: "12:34:56", SerialHex: "03"},
			},
		}
		require.NoError(t, writeLocalRoots(lrPath, lrf))

		m, err := LoadLocalRootsSKISet()
		require.NoError(t, err)
		assert.Len(t, m, 2)
		assert.Contains(t, m, "ABCDEF")
		assert.Contains(t, m, "123456")
		assert.Equal(t, "CN=Root1", m["ABCDEF"].Subject)
	})

	t.Run("invalid JSON returns error", func(t *testing.T) {
		cacheDir := withTempCache(t)
		lrPath := filepath.Join(cacheDir, localRootsFileName)
		require.NoError(t, os.MkdirAll(cacheDir, 0o755))
		require.NoError(t, os.WriteFile(lrPath, []byte("not json"), 0o644))
		_, err := LoadLocalRootsSKISet()
		assert.Error(t, err)
	})
}
