package certs

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mozilla.org/pkcs7"
	"golang.org/x/crypto/pkcs12"
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

// mustMakePKCS7 wraps cert in a degenerate PKCS#7 SignedData bundle (no signers).
func mustMakePKCS7(t *testing.T, cert *x509.Certificate) []byte {
	t.Helper()
	sd, err := pkcs7.NewSignedData(nil)
	require.NoError(t, err)
	sd.AddCertificate(cert)
	p7bytes, err := sd.Finish()
	require.NoError(t, err)
	return p7bytes
}

// mustMakeCSR generates a self-signed ECDSA CSR for testing.
// Returns both the raw DER bytes and the PEM-encoded form.
func mustMakeCSR(t *testing.T) (derBytes []byte, pemBytes []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "test-csr"},
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	require.NoError(t, err)
	var buf bytes.Buffer
	err = pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
	require.NoError(t, err)
	return der, buf.Bytes()
}

func TestParseCSR(t *testing.T) {
	der, pemData := mustMakeCSR(t)

	t.Run("valid PEM", func(t *testing.T) {
		csr, err := ParseCSR(pemData)
		require.NoError(t, err)
		assert.Equal(t, "test-csr", csr.Subject.CommonName)
	})

	t.Run("valid DER", func(t *testing.T) {
		csr, err := ParseCSR(der)
		require.NoError(t, err)
		assert.Equal(t, "test-csr", csr.Subject.CommonName)
	})

	t.Run("PEM skips non-CSR block and parses CSR", func(t *testing.T) {
		var buf bytes.Buffer
		err := pem.Encode(&buf, &pem.Block{Type: "PRIVATE KEY", Bytes: []byte("not a key")})
		require.NoError(t, err)
		buf.Write(pemData)
		csr, err := ParseCSR(buf.Bytes())
		require.NoError(t, err)
		assert.Equal(t, "test-csr", csr.Subject.CommonName)
	})

	t.Run("PEM with only wrong block type returns error", func(t *testing.T) {
		var buf bytes.Buffer
		err := pem.Encode(&buf, &pem.Block{Type: "PRIVATE KEY", Bytes: []byte("not a csr")})
		require.NoError(t, err)
		_, err = ParseCSR(buf.Bytes())
		assert.Error(t, err)
	})

	t.Run("empty input", func(t *testing.T) {
		_, err := ParseCSR([]byte{})
		assert.ErrorContains(t, err, "no CSR data found")
	})

	t.Run("nil input", func(t *testing.T) {
		_, err := ParseCSR(nil)
		assert.ErrorContains(t, err, "no CSR data found")
	})

	t.Run("whitespace only input", func(t *testing.T) {
		_, err := ParseCSR([]byte("   \n\t  "))
		assert.ErrorContains(t, err, "no CSR data found")
	})

	t.Run("malformed DER bytes", func(t *testing.T) {
		_, err := ParseCSR([]byte{0x00, 0x01, 0x02, 0x03})
		assert.Error(t, err)
	})

	t.Run("NEW CERTIFICATE REQUEST PEM type accepted", func(t *testing.T) {
		var buf bytes.Buffer
		err := pem.Encode(&buf, &pem.Block{Type: "NEW CERTIFICATE REQUEST", Bytes: der})
		require.NoError(t, err)
		csr, err := ParseCSR(buf.Bytes())
		require.NoError(t, err)
		assert.Equal(t, "test-csr", csr.Subject.CommonName)
	})
}

// Pre-generated PKCS#12 test fixtures (OpenSSL, EC P-256, legacy PBE + SHA-1 MAC
// for compatibility with golang.org/x/crypto/pkcs12 v0.47.0).
// nopassPFX: CN=pkcs12-test, no password.
// withpassPFX: CN=pkcs12-test, password "testpassword".
// chainPFX: leaf CN=test-leaf signed by CA CN=test-ca, no password.
const (
	nopassPFX   = "MIIDggIBAzCCA0gGCSqGSIb3DQEHAaCCAzkEggM1MIIDMTCCAicGCSqGSIb3DQEHBqCCAhgwggIUAgEAMIICDQYJKoZIhvcNAQcBMBwGCiqGSIb3DQEMAQMwDgQIE6Q3XlnjImsCAggAgIIB4H0dUQ3DLSUK8ZUFaPUFrfzrgwUwbAUtNurt4EpGECeZw9tEKzYbBVudB2zg/a5nCdOABsQcOXDSxSn4sUriMCMtRyVK0Df8sYPBFI3XafVUhglFEUOxeZc5tWoL8C55ShUiywGPU5SuYsW+svrWQSiKKFgV2m9uOjnQ5+RvgjV9F+BunDE9Pl/+tffskzhTzTBMG2/7xNEJhY5LOUJ0+tE8rDW9W+NFnKVxwK+KZ9rLE8myjVXw+QW00SxaDSRQoOp3w4NMd8Rjp3ZLAdqRoSIk+1icWvrYtsssJheJql+HVGqk8LvcY9uPx0dylalS5uA8YhwqSf1bZleCLRIYFg/WRlwsnup+NUo2qkVLQIwkU40/dWEg3STyuXSjMQZS3jb5k4Pv29GJAaQk1QyUPsWUCzSIAyxsMl4uq7FCwQmTTAjmzJWyaC4p6X7axPGCzXI5kNZTGj/44khCbYdnxgvZJ8jQScKkflCEL0JsDj2XqMthoMqYUBG5WQ8vxwg94gBBbbvM/AQrXCs8SaqlKOZAjam/speDj+9FGiKaOf6AUf3Upz6ZnWLAnolk4DBO0Js5C/QuOC/GTlzWsuk+HqMmMkkfOdAwcwTiUdndsv6Dym1DILzJhK0PbYdxWYy0cjCCAQIGCSqGSIb3DQEHAaCB9ASB8TCB7jCB6wYLKoZIhvcNAQwKAQKggbQwgbEwHAYKKoZIhvcNAQwBAzAOBAi7gnVLE2dFPQICCAAEgZBj/ISPVQv9lsYs+X/iIf9Ti2gDng+iO8L/w3+J0QG1X0+yBNgtsFHc4hWr+xV/ouZeJzH/5/lJ5fPpBEwIRTgwMpqAQGUf5DPAn4PcPagTKbTqZdp++f48jDBG0PqdrDiak4r3yfWZuf6UMSYrr4sJBCtMtQoGzlft1OW81XcerkGb7N6+bfnfM7goUYEoi7UxJTAjBgkqhkiG9w0BCRUxFgQUcUlDfn3NVUB7tpZjR/rAEIqw+DowMTAhMAkGBSsOAwIaBQAEFL5GuxbPv15MQo/frtJkrKCieXcKBAiKBxSb3BMXxwICCAA="
	withpassPFX = "MIIDggIBAzCCA0gGCSqGSIb3DQEHAaCCAzkEggM1MIIDMTCCAicGCSqGSIb3DQEHBqCCAhgwggIUAgEAMIICDQYJKoZIhvcNAQcBMBwGCiqGSIb3DQEMAQMwDgQIm4DrwbNyLFMCAggAgIIB4B52yRFuI7D8W5NI5zNwIbcGkpvUnyQX1k9lZU59SVqXbj8JhC3N3L5KMA1/cIfqGoIEzc+BDYpGLlqp9AzUYte8fSiLvUY7bez2iwrvkNwXH10QfTS6wG9vM1yhVvsL20madIqBh7e39nShSD/M4G3Y6lhrydU5wCiPfkoNtQQbdmszqbZt2pTa2oZ86w/3mOWTzxNsWfWU8Ek6nO79WVCjpKvB2/njQSj0flA18ni91pcuBLKU6xlq3Kq57xWYEEMJvmSCSGwvSI1srPOQ+k2+qSvKRPK4MZFxlt9PRHDahC0wdvRWhgBZUfR+vrSDGiODBv90XAbXz/a8H8fcbPeV0rc74wLDU57ey94VpgEAbaGMNQTXwJNXyFgHhsx53l91FGT9pyYA3Cx8YSoBRukCCy5xVG6Q5fvBPSTseehWdIJkXSGf7I1LDtunuB9pJPRui+9eMgRYKFQo1bgIogXpbjP5OZHF3POAQQzbh6W0tKc3EJOToo0zszqFhrguJ//ULTMCdD7Phryz9xDF/at9d1V7J+7TVzMYgvkH2SOWZN3YzoGjJgZvlsmVIaUZ8cwFTrGzlp8CVUCdIDibaB3Vf5qQ7339p+lTh9CGbn2XuVUv9Xlw7W9WJb19xvd4UzCCAQIGCSqGSIb3DQEHAaCB9ASB8TCB7jCB6wYLKoZIhvcNAQwKAQKggbQwgbEwHAYKKoZIhvcNAQwBAzAOBAhPUvu2C9YcXQICCAAEgZBDyKyMRmSToWTnkQFC5ol2n6RMvUqbHozFSh6IFWdrKksAjwfGoh66vLH/lhrUD2kH6ZGuqqMjLu6qiY7HYzt6N5y54CZUkrMA9ZG2tCY10jcF7QBpqIE0Bcr5949N0PQLwaCPwKcC9389TpiFHwcmril/gVGU0q2wYEn564f3g3njwcpsIGYsXguMEm+QRTIxJTAjBgkqhkiG9w0BCRUxFgQUt+jjpgugjRg6iKqP/sFXLMKzNG0wMTAhMAkGBSsOAwIaBQAEFFythxxBfQX3oDi6VNQ2BVzo8Cj2BAhmjnjwM6uKRQICCAA="
	// chainPFX: leaf CN=test-leaf (signed by CA) + CA CN=test-ca, no password.
	chainPFX = "MIIEygIBAzCCBJAGCSqGSIb3DQEHAaCCBIEEggR9MIIEeTCCA28GCSqGSIb3DQEHBqCCA2AwggNcAgEAMIIDVQYJKoZIhvcNAQcBMBwGCiqGSIb3DQEMAQMwDgQIhM9TTv+62hACAggAgIIDKK7ESXcJGLH8DmBhIa/CxH5yE5f32OIwZxZ8mI6AIx5yx7xsDRRbzCeisILlvKuDYWqV6QZ0Vn79hbEnf3ovtaQdCUQsNDe4EqDNCu2c1Ml+9PtN/Vy36GYVaPGJrHfIxeBDvdIboHQvYqY302j35Gf2p3VyawEU4ACNC/cIC4Q6YsB7/4jq22JYJbm3JynoYNrczusGXgDMeO9N4UxwdPF8Z17nhGmQUzqPttD4U6cdebh+JJ4Zc0Zu82sLOINhEE+dXYBWcBinPJ3OkXqV+CHP0HYDpbVJ2qwwJfxYa2fH3yw0Zm37gdxP8f1jRvnp9nWqKAtUx/4e+vE9Isga8ws0hhjrlbClZImh/Bcf896NNawohYhzjcduTIK03EQRjMghNMyyb57sNZ+Kx6fWMSIMJQperhrtGBEZF7VKyewS22d/FuxKb7/dXjSzf5efLV1J/RMFqFD9XGRosERtHfAtbWmUw7Q6jkdvssjZ3HQhFuJi1bgjiJPPS4lzdCPb5FUemzF5XOmUChXej1zLmVPYZZxvgZDDq97g/UlXokkUfEHZKMzXN2yUtFI/y/1K0Pve1zTHqGMrSeOuGTO7MMn07U4fnQz6pZkOVNnDOvrhvib9/5I/gTi3+UGuKmlwo/VefjFfIYNzbNXcEPPJBDMpxq7n8Nhd4V3MA6tKaq0mZE62RS1jS7szMQ43aIC0WhF5kYd8QAnpIDkMHvKiWXkq5Fc8ew2FhVQIa4IG2PpOKxBUu2ogr3VQzjrPJ7xQoHMvjQpAZXugG+JiSi99XJVtq01aXyemI4fpuztoGck1Xv7ZJz4e1Uyu9rY8luGuguV7O4f4C3MhaY4yjBi2h/LQMbyS8GfrPQ6495cq9hfbeX+dtJMVLJoYeN99HhPZf/ofOARw3opPofqKGSTVOW11yc6X0L36kCTa3/T6El1al0CT2x9TCRyavgeFiLnN03RNiTZM3/WhVki9JOENk1eGg5fG1qHeGw9tpD5lyTcL9A2ZriOjOZ4Gb+AewpkmRAwu8kKMebwl9AeWknBR3YFgoO+W+tEfpfmz8NJsfkcXruMeVKOsF0kwggECBgkqhkiG9w0BBwGggfQEgfEwge4wgesGCyqGSIb3DQEMCgECoIG0MIGxMBwGCiqGSIb3DQEMAQMwDgQIbiQuy7GXfNsCAggABIGQki2nZW9FOPVLZH9pdfkoRJ9ZoxASjtUxpAHX53greGkhznJ2HGQSxJEgkOxyS/xFcfQyyywuzMIc3cM102RmR2nV0enBStRSZsZTJVfQm9CWVGHSyaYUMsG/VmAmsLpmdlv/YwXuxfg4E/3KDUR5sL97FFWyljsuNZxvfxSprOTsqPljMZacDQ2FbS+b9ws8MSUwIwYJKoZIhvcNAQkVMRYEFP29ZpgMCccPcEjNOQYW6PYFlZgRMDEwITAJBgUrDgMCGgUABBQh2ZEiV3XrcT3afTwzNhdS4Vd80QQIxUsWLmv+77ACAggA"
)

// mustDecodePFX decodes a base64-encoded PFX fixture for use in tests.
func mustDecodePFX(t *testing.T, b64 string) []byte {
	t.Helper()
	data, err := base64.StdEncoding.DecodeString(b64)
	require.NoError(t, err)
	return data
}

func TestParsePKCS12(t *testing.T) {
	t.Run("valid PFX with empty password returns leaf cert", func(t *testing.T) {
		pfxData := mustDecodePFX(t, nopassPFX)
		leaf, caCerts, err := ParsePKCS12(pfxData, "")
		require.NoError(t, err)
		assert.Equal(t, "pkcs12-test", leaf.Subject.CommonName)
		assert.Empty(t, caCerts)
	})

	t.Run("valid PFX with correct password returns leaf cert", func(t *testing.T) {
		pfxData := mustDecodePFX(t, withpassPFX)
		leaf, caCerts, err := ParsePKCS12(pfxData, "testpassword")
		require.NoError(t, err)
		assert.Equal(t, "pkcs12-test", leaf.Subject.CommonName)
		assert.Empty(t, caCerts)
	})

	t.Run("valid PFX with wrong password returns ErrIncorrectPassword", func(t *testing.T) {
		pfxData := mustDecodePFX(t, withpassPFX)
		_, _, err := ParsePKCS12(pfxData, "wrong")
		require.Error(t, err)
		assert.True(t, errors.Is(err, pkcs12.ErrIncorrectPassword))
	})

	t.Run("invalid bytes returns error", func(t *testing.T) {
		_, _, err := ParsePKCS12([]byte{0xDE, 0xAD, 0xBE, 0xEF}, "")
		assert.Error(t, err)
	})

	t.Run("empty input returns error", func(t *testing.T) {
		_, _, err := ParsePKCS12([]byte{}, "")
		assert.Error(t, err)
	})

	t.Run("valid PFX with CA chain returns leaf and caCerts", func(t *testing.T) {
		pfxData := mustDecodePFX(t, chainPFX)
		leaf, caCerts, err := ParsePKCS12(pfxData, "")
		require.NoError(t, err)
		assert.Equal(t, "test-leaf", leaf.Subject.CommonName)
		require.Len(t, caCerts, 1)
		assert.Equal(t, "test-ca", caCerts[0].Subject.CommonName)
	})
}

func TestParseCertificateOrPKCS7(t *testing.T) {
	der, pemData := mustMakeCert(t)

	// Parse the DER to get an *x509.Certificate for use in PKCS#7 construction.
	origCert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	t.Run("valid PEM falls through to fast path", func(t *testing.T) {
		cert, err := ParseCertificateOrPKCS7(pemData)
		require.NoError(t, err)
		assert.Equal(t, "test", cert.Subject.CommonName)
	})

	t.Run("valid DER falls through to fast path", func(t *testing.T) {
		cert, err := ParseCertificateOrPKCS7(der)
		require.NoError(t, err)
		assert.Equal(t, "test", cert.Subject.CommonName)
	})

	t.Run("valid PKCS#7 bundle returns first certificate", func(t *testing.T) {
		p7bytes := mustMakePKCS7(t, origCert)
		cert, err := ParseCertificateOrPKCS7(p7bytes)
		require.NoError(t, err)
		assert.Equal(t, origCert.Subject.CommonName, cert.Subject.CommonName)
		assert.Equal(t, origCert.SerialNumber, cert.SerialNumber)
	})

	t.Run("PKCS#7 bundle with no certificates returns error", func(t *testing.T) {
		// Build a degenerate SignedData containing no certificates.
		sd, err := pkcs7.NewSignedData(nil)
		require.NoError(t, err)
		p7bytes, err := sd.Finish()
		require.NoError(t, err)
		_, err = ParseCertificateOrPKCS7(p7bytes)
		assert.ErrorContains(t, err, "no certificates")
	})

	t.Run("garbage bytes return error", func(t *testing.T) {
		_, err := ParseCertificateOrPKCS7([]byte{0xDE, 0xAD, 0xBE, 0xEF})
		assert.Error(t, err)
	})

	t.Run("empty input returns error", func(t *testing.T) {
		_, err := ParseCertificateOrPKCS7([]byte{})
		assert.Error(t, err)
	})
}
