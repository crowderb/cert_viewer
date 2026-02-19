package certs

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/ocsp"
)

func TestFormatOCSPStatus(t *testing.T) {
	tests := []struct {
		name string
		resp *ocsp.Response
		want string
	}{
		{
			name: "good",
			resp: &ocsp.Response{Status: ocsp.Good},
			want: "Good",
		},
		{
			name: "unknown",
			resp: &ocsp.Response{Status: ocsp.Unknown},
			want: "Unknown",
		},
		{
			name: "revoked unspecified",
			resp: &ocsp.Response{
				Status:           ocsp.Revoked,
				RevokedAt:        time.Date(2024, 1, 15, 10, 0, 0, 0, time.UTC),
				RevocationReason: ocsp.Unspecified,
			},
			want: "Revoked (Unspecified) at 2024-01-15 10:00:00 UTC",
		},
		{
			name: "revoked key compromise",
			resp: &ocsp.Response{
				Status:           ocsp.Revoked,
				RevokedAt:        time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC),
				RevocationReason: ocsp.KeyCompromise,
			},
			want: "Revoked (KeyCompromise) at 2024-06-01 00:00:00 UTC",
		},
		{
			name: "revoked CA compromise",
			resp: &ocsp.Response{
				Status:           ocsp.Revoked,
				RevokedAt:        time.Date(2023, 3, 20, 8, 30, 0, 0, time.UTC),
				RevocationReason: ocsp.CACompromise,
			},
			want: "Revoked (CACompromise) at 2023-03-20 08:30:00 UTC",
		},
		{
			name: "unknown status code",
			resp: &ocsp.Response{Status: 99},
			want: "Unknown status (99)",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := FormatOCSPStatus(tc.resp)
			assert.Equal(t, tc.want, got)
		})
	}
}
