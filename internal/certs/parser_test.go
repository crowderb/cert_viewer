package certs

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mustMakeCert generates a self-signed ECDSA certificate for testing.
// Returns both the raw DER bytes and the PEM-encoded form.
func mustMakeCert(t *testing.T) (derBytes []byte, pemBytes []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	var buf bytes.Buffer
	err = pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	require.NoError(t, err)
	return der, buf.Bytes()
}

func TestParseCertificate(t *testing.T) {
	der, pemData := mustMakeCert(t)

	t.Run("valid PEM", func(t *testing.T) {
		cert, err := ParseCertificate(pemData)
		require.NoError(t, err)
		assert.Equal(t, "test", cert.Subject.CommonName)
	})

	t.Run("valid DER", func(t *testing.T) {
		cert, err := ParseCertificate(der)
		require.NoError(t, err)
		assert.Equal(t, "test", cert.Subject.CommonName)
	})

	t.Run("PEM skips non-CERTIFICATE block and parses cert", func(t *testing.T) {
		var buf bytes.Buffer
		// Leading PRIVATE KEY block should be skipped
		err := pem.Encode(&buf, &pem.Block{Type: "PRIVATE KEY", Bytes: []byte("not really a key")})
		require.NoError(t, err)
		buf.Write(pemData)
		cert, err := ParseCertificate(buf.Bytes())
		require.NoError(t, err)
		assert.Equal(t, "test", cert.Subject.CommonName)
	})

	t.Run("PEM with only wrong block type returns error", func(t *testing.T) {
		var buf bytes.Buffer
		err := pem.Encode(&buf, &pem.Block{Type: "PRIVATE KEY", Bytes: []byte("not a cert")})
		require.NoError(t, err)
		_, err = ParseCertificate(buf.Bytes())
		assert.Error(t, err)
	})

	t.Run("empty input", func(t *testing.T) {
		_, err := ParseCertificate([]byte{})
		assert.ErrorContains(t, err, "no certificate data found")
	})

	t.Run("nil input", func(t *testing.T) {
		_, err := ParseCertificate(nil)
		assert.ErrorContains(t, err, "no certificate data found")
	})

	t.Run("whitespace only input", func(t *testing.T) {
		_, err := ParseCertificate([]byte("   \n\t  "))
		assert.ErrorContains(t, err, "no certificate data found")
	})

	t.Run("malformed DER bytes", func(t *testing.T) {
		_, err := ParseCertificate([]byte{0x00, 0x01, 0x02, 0x03})
		assert.Error(t, err)
	})

	t.Run("PEM CERTIFICATE block with zero-length bytes is skipped, falls to DER error", func(t *testing.T) {
		var buf bytes.Buffer
		// Block with CERTIFICATE type but empty Bytes — loop skips it (len == 0 check)
		err := pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: []byte{}})
		require.NoError(t, err)
		// After the loop, data is the remainder (empty), derBytes stays empty,
		// so "no certificate data found" is returned.
		_, err = ParseCertificate(buf.Bytes())
		assert.Error(t, err)
	})
}
