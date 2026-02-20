package certs

import (
	"crypto/x509"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func TestCheckCertInCRL(t *testing.T) {
	serial1 := big.NewInt(1001)
	serial2 := big.NewInt(1002)
	entry := x509.RevocationListEntry{
		SerialNumber:   serial1,
		RevocationTime: time.Now(),
		ReasonCode:     1, // KeyCompromise
	}
	rl := &x509.RevocationList{
		RevokedCertificateEntries: []x509.RevocationListEntry{entry},
	}

	// cert with serial1 is revoked
	cert1 := &x509.Certificate{SerialNumber: serial1}
	got := CheckCertInCRL(cert1, rl)
	require.NotNil(t, got)
	assert.Equal(t, 0, got.SerialNumber.Cmp(serial1))

	// cert with serial2 is not revoked
	cert2 := &x509.Certificate{SerialNumber: serial2}
	assert.Nil(t, CheckCertInCRL(cert2, rl))
}
