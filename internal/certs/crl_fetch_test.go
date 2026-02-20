package certs

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFormatRevocationReason(t *testing.T) {
	cases := []struct {
		code int
		want string
	}{
		{0, "Unspecified"},
		{1, "KeyCompromise"},
		{2, "CACompromise"},
		{3, "AffiliationChanged"},
		{4, "Superseded"},
		{5, "CessationOfOperation"},
		{6, "CertificateHold"},
		{8, "RemoveFromCRL"},
		{9, "PrivilegeWithdrawn"},
		{10, "AACompromise"},
		{99, "Reason(99)"},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, FormatRevocationReason(tc.code))
	}
}
