package certs

import (
	"crypto/x509"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthorityKeyIdentifierKeyID_GTSRootR4CrossSigned(t *testing.T) {
	der, err := os.ReadFile("/tmp/ct03.der")
	if err != nil {
		t.Skip("run openssl save to /tmp/ct03.der first, or skip")
	}
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	kid := AuthorityKeyIdentifierKeyID(cert)
	require.NotEmpty(t, kid)
	want := "607B661A450D97CA89502F7D04CD34A8FFFCFD4B"
	assert.Equal(t, want, NormalizeHexBytesNoSepUpper(kid))
}
