package advanced

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"cert_viewer/internal/resources"
)

func TestOriginSummary(t *testing.T) {
	tests := []struct {
		name string
		in   []resources.OriginRef
		want string
	}{
		{"empty", nil, ""},
		{
			"single origin",
			[]resources.OriginRef{{Type: resources.OriginSystemBundle, Path: "/etc/ssl/certs/ca-certificates.crt"}},
			resources.OriginSystemBundle,
		},
		{
			"multiple distinct types",
			[]resources.OriginRef{
				{Type: resources.OriginSystemBundle, Path: "/p"},
				{Type: resources.OriginDistroAnchorDir, Path: "/q"},
			},
			resources.OriginSystemBundle + ", " + resources.OriginDistroAnchorDir,
		},
		{
			"duplicate types collapsed",
			[]resources.OriginRef{
				{Type: resources.OriginSystemBundle, Path: "/p"},
				{Type: resources.OriginSystemBundle, Path: "/q"}, // same type, different path
				{Type: resources.OriginDistroAnchorDir, Path: "/r"},
			},
			resources.OriginSystemBundle + ", " + resources.OriginDistroAnchorDir,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, originSummary(tc.in))
		})
	}
}
