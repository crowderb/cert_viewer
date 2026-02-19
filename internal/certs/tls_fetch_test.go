package certs

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseHostPort(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantHost  string
		wantPort  string
		wantError bool
	}{
		{
			name:     "bare hostname",
			input:    "example.com",
			wantHost: "example.com",
			wantPort: "443",
		},
		{
			name:     "host:port pair",
			input:    "example.com:8443",
			wantHost: "example.com",
			wantPort: "8443",
		},
		{
			name:     "https URL no port",
			input:    "https://example.com",
			wantHost: "example.com",
			wantPort: "443",
		},
		{
			name:     "https URL with port",
			input:    "https://example.com:9443",
			wantHost: "example.com",
			wantPort: "9443",
		},
		{
			name:     "https URL with path",
			input:    "https://example.com/some/path",
			wantHost: "example.com",
			wantPort: "443",
		},
		{
			name:      "empty input",
			input:     "",
			wantError: true,
		},
		{
			name:      "whitespace only",
			input:     "   ",
			wantError: true,
		},
		{
			name:      "scheme only no host",
			input:     "https://",
			wantError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			host, port, err := ParseHostPort(tc.input)
			if tc.wantError {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.wantHost, host)
			assert.Equal(t, tc.wantPort, port)
		})
	}
}
