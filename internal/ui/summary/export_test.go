package summary

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"cert_viewer/internal/prefs"
)

func TestExportText_ContainsKeyFields(t *testing.T) {
	cert := &x509.Certificate{
		Subject:      pkix.Name{CommonName: "test.example.com"},
		Issuer:       pkix.Name{CommonName: "Test CA"},
		SerialNumber: big.NewInt(12345),
		NotBefore:    time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		Version:      3,
	}
	text := ExportText(cert, prefs.Default())

	assert.Contains(t, text, "test.example.com")
	assert.Contains(t, text, "Test CA")
	assert.Contains(t, text, "2024-01-01")
	assert.Contains(t, text, "2025-01-01")
	assert.Contains(t, text, "Certificate Summary")
	assert.Contains(t, text, "Certificate Details")
	assert.Contains(t, text, "Not Before") // OpenSSL style (default)
	assert.Contains(t, text, "Not After")
	assert.Contains(t, text, "SHA-256 Fingerprint")
	assert.Contains(t, text, "SHA-1 Fingerprint")
	assert.Contains(t, text, "Serial Number")
}

func TestExportText_WindowsNameStyle(t *testing.T) {
	cert := &x509.Certificate{
		Subject:      pkix.Name{CommonName: "win.example.com"},
		Issuer:       pkix.Name{},
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	p := prefs.Default()
	p.UI.NameStyle = prefs.Windows
	text := ExportText(cert, p)

	assert.Contains(t, text, "Valid From")
	assert.Contains(t, text, "Valid To")
	assert.NotContains(t, text, "Not Before")
	assert.NotContains(t, text, "Not After")
}

func TestExportCSRText_ContainsKeyFields(t *testing.T) {
	csr := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "csr.example.com"},
	}
	text := ExportCSRText(csr, prefs.Default())

	assert.Contains(t, text, "csr.example.com")
	assert.Contains(t, text, "Certificate Signing Request")
	assert.Contains(t, text, "SHA-256 Fingerprint")
	assert.Contains(t, text, "SHA-1 Fingerprint")
	assert.Contains(t, text, "Type")
}
