package trustsources

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"cert_viewer/internal/resources"
)

func TestOrderedOrigins(t *testing.T) {
	t.Run("known origins emerge in display order", func(t *testing.T) {
		m := map[string][]certEntry{
			resources.OriginNSSUser:         nil,
			resources.OriginSystemBundle:    nil,
			resources.OriginDistroAnchorDir: nil,
		}
		got := orderedOrigins(m)
		assert.Equal(t, []string{
			resources.OriginSystemBundle,
			resources.OriginDistroAnchorDir,
			resources.OriginNSSUser,
		}, got)
	})

	t.Run("unknown origins appended alphabetically after known ones", func(t *testing.T) {
		m := map[string][]certEntry{
			resources.OriginSystemBundle: nil,
			"zzz-future-source":          nil,
			"aaa-future-source":          nil,
		}
		got := orderedOrigins(m)
		assert.Equal(t, []string{
			resources.OriginSystemBundle,
			"aaa-future-source",
			"zzz-future-source",
		}, got)
	})

	t.Run("empty map returns empty slice", func(t *testing.T) {
		assert.Empty(t, orderedOrigins(map[string][]certEntry{}))
	})
}

func TestOriginLabel(t *testing.T) {
	tests := []struct {
		origin string
		want   string
	}{
		{resources.OriginSystemBundle, "System bundle"},
		{resources.OriginEnvOverride, "Env override (SSL_CERT_FILE / SSL_CERT_DIR)"},
		{resources.OriginDistroAnchorDir, "Distro anchor dir"},
		{resources.OriginNSSUser, "NSS — user (~/.pki/nssdb)"},
		{resources.OriginNSSFirefox, "NSS — Firefox profile"},
		{"future-source", "future-source"}, // pass-through for unknowns
	}
	for _, tc := range tests {
		t.Run(tc.origin, func(t *testing.T) {
			assert.Equal(t, tc.want, originLabel(tc.origin))
		})
	}
}

func TestNormalizeUpper(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", ""},
		{"already normalized", "ABCDEF", "ABCDEF"},
		{"lower hex", "abcdef", "ABCDEF"},
		{"colons stripped", "ab:cd:ef", "ABCDEF"},
		{"spaces stripped", "AB CD EF", "ABCDEF"},
		{"non-hex chars dropped", "x12y34z", "1234"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, normalizeUpper(tc.in))
		})
	}
}

func TestIsInCCADB(t *testing.T) {
	t.Run("nil map returns false", func(t *testing.T) {
		assert.False(t, isInCCADB("ABCDEF", nil))
	})

	t.Run("present after normalization", func(t *testing.T) {
		ccadb := map[string]struct{}{"ABCDEF": {}}
		assert.True(t, isInCCADB("ab:cd:ef", ccadb))
		assert.True(t, isInCCADB("AB CD EF", ccadb))
		assert.True(t, isInCCADB("ABCDEF", ccadb))
	})

	t.Run("absent returns false", func(t *testing.T) {
		ccadb := map[string]struct{}{"ABCDEF": {}}
		assert.False(t, isInCCADB("123456", ccadb))
	})
}
