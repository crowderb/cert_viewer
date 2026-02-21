package compare

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"cert_viewer/internal/prefs"
)

// minimalCert returns a bare *x509.Certificate with only Raw populated so
// that fingerprint fields can be computed. Other fields are left at zero values.
func minimalCert() *x509.Certificate {
	return &x509.Certificate{
		Raw: []byte("test-cert-data"),
	}
}

// fullCert returns a *x509.Certificate with all fields that ExtractFields reads.
func fullCert() *x509.Certificate {
	notBefore := time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC)
	notAfter := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)

	u, _ := url.Parse("https://example.com")

	return &x509.Certificate{
		Raw: []byte("full-cert-data"),
		Subject: pkix.Name{
			CommonName:   "example.com",
			Organization: []string{"Example Org"},
		},
		Issuer: pkix.Name{
			CommonName:   "Example CA",
			Organization: []string{"Example CA Org"},
		},
		SerialNumber:          big.NewInt(12345),
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		MaxPathLen:            -1,
		SubjectKeyId:          []byte{0x01, 0x02, 0x03},
		AuthorityKeyId:        []byte{0x04, 0x05, 0x06},
		DNSNames:              []string{"example.com", "www.example.com"},
		EmailAddresses:        []string{"admin@example.com"},
		IPAddresses:           []net.IP{net.ParseIP("192.168.1.1")},
		URIs:                  []*url.URL{u},
		OCSPServer:            []string{"http://ocsp.example.com"},
		IssuingCertificateURL: []string{"http://ca.example.com/cert.crt"},
		CRLDistributionPoints: []string{"http://crl.example.com/crl.crl"},
	}
}

func defaultPrefs() prefs.Preferences {
	p := prefs.Default()
	return p
}

func TestExtractFields_Count(t *testing.T) {
	p := defaultPrefs()
	fields := ExtractFields(minimalCert(), p)
	// Always returns exactly 23 fields
	assert.Len(t, fields, 23, "ExtractFields should always return 23 fields")
}

func TestExtractFields_FieldNames(t *testing.T) {
	p := defaultPrefs()
	fields := ExtractFields(minimalCert(), p)

	expectedNames := []string{
		"Common Name",
		"Subject",
		"Issuer",
		"Serial Number",
		"Not Before",
		"Not After",
		"Signature Algorithm",
		"Public Key Algorithm",
		"Public Key Size",
		"Key Usage",
		"Extended Key Usage",
		"Basic Constraints",
		"Subject Key Identifier",
		"Authority Key Identifier",
		"DNS Names",
		"Email Addresses",
		"IP Addresses",
		"URIs",
		"OCSP Servers",
		"CA Issuers",
		"CRL Distribution Points",
		"SHA-256 Fingerprint",
		"SHA-1 Fingerprint",
	}

	for i, want := range expectedNames {
		assert.Equal(t, want, fields[i].Name, "field[%d] name mismatch", i)
	}
}

func TestExtractFields_CommonNameFallback(t *testing.T) {
	cert := minimalCert()
	cert.Subject.CommonName = ""
	fields := ExtractFields(cert, defaultPrefs())
	assert.Equal(t, "(none)", fields[0].Value, "empty CommonName should render as (none)")
}

func TestExtractFields_CommonNamePresent(t *testing.T) {
	cert := fullCert()
	fields := ExtractFields(cert, defaultPrefs())
	assert.Equal(t, "example.com", fields[0].Value)
}

func TestExtractFields_EmptySANsProduceEmptyString(t *testing.T) {
	cert := minimalCert()
	fields := ExtractFields(cert, defaultPrefs())

	// DNS Names (index 14), Email (15), IP (16), URIs (17)
	for _, idx := range []int{14, 15, 16, 17} {
		assert.Equal(t, "", fields[idx].Value, "field[%d] (%s) should be empty string when absent", idx, fields[idx].Name)
	}
}

func TestExtractFields_BasicConstraintsCA(t *testing.T) {
	cert := minimalCert()
	cert.BasicConstraintsValid = true
	cert.IsCA = true
	cert.MaxPathLen = 0

	fields := ExtractFields(cert, defaultPrefs())
	// Basic Constraints is index 11
	assert.Equal(t, "CA:TRUE, pathlen:0", fields[11].Value)
}

func TestExtractFields_BasicConstraintsNotCA(t *testing.T) {
	cert := minimalCert()
	cert.BasicConstraintsValid = true
	cert.IsCA = false

	fields := ExtractFields(cert, defaultPrefs())
	assert.Equal(t, "CA:FALSE", fields[11].Value)
}

func TestExtractFields_BasicConstraintsAbsent(t *testing.T) {
	cert := minimalCert()
	cert.BasicConstraintsValid = false

	fields := ExtractFields(cert, defaultPrefs())
	assert.Equal(t, "", fields[11].Value, "absent BasicConstraints should produce empty string")
}

func TestExtractFields_DNSNames(t *testing.T) {
	cert := fullCert()
	fields := ExtractFields(cert, defaultPrefs())
	assert.Equal(t, "example.com, www.example.com", fields[14].Value)
}

func TestExtractFields_IPAddresses(t *testing.T) {
	cert := fullCert()
	fields := ExtractFields(cert, defaultPrefs())
	// IPv4-mapped v6 addresses print as IPv4
	assert.Contains(t, fields[16].Value, "192.168.1.1")
}

func TestExtractFields_FingerprintsNotEmpty(t *testing.T) {
	cert := fullCert()
	fields := ExtractFields(cert, defaultPrefs())
	sha256Field := fields[21]
	sha1Field := fields[22]
	assert.Equal(t, "SHA-256 Fingerprint", sha256Field.Name)
	assert.Equal(t, "SHA-1 Fingerprint", sha1Field.Name)
	assert.NotEmpty(t, sha256Field.Value)
	assert.NotEmpty(t, sha1Field.Value)
}

func TestExtractFields_StableOrdering(t *testing.T) {
	cert := fullCert()
	p := defaultPrefs()
	f1 := ExtractFields(cert, p)
	f2 := ExtractFields(cert, p)
	require.Equal(t, len(f1), len(f2))
	for i := range f1 {
		assert.Equal(t, f1[i].Name, f2[i].Name, "field ordering must be stable")
		assert.Equal(t, f1[i].Value, f2[i].Value, "field values must be stable")
	}
}

func TestBuildRows_SameCert(t *testing.T) {
	cert := fullCert()
	p := defaultPrefs()
	rows := BuildRows(cert, cert, p)

	for _, row := range rows {
		assert.False(t, row.Differs, "rows should not differ when comparing a cert with itself (field: %s)", row.Name)
		assert.Equal(t, row.ValueA, row.ValueB)
	}
}

func TestBuildRows_DifferentCerts(t *testing.T) {
	certA := fullCert()
	certB := fullCert()
	certB.Subject.CommonName = "other.example.com"
	certB.SerialNumber = big.NewInt(99999)
	certB.Raw = []byte("different-raw-data") // different fingerprints

	p := defaultPrefs()
	rows := BuildRows(certA, certB, p)

	require.Len(t, rows, 23)

	// Find Common Name row (index 0) — should differ
	cnRow := rows[0]
	assert.Equal(t, "Common Name", cnRow.Name)
	assert.True(t, cnRow.Differs, "Common Name should differ")
	assert.Equal(t, "example.com", cnRow.ValueA)
	assert.Equal(t, "other.example.com", cnRow.ValueB)

	// Issuer should NOT differ (same issuer in both)
	issuerRow := rows[2]
	assert.Equal(t, "Issuer", issuerRow.Name)
	assert.False(t, issuerRow.Differs, "Issuer should not differ")
}

func TestBuildRows_RowCount(t *testing.T) {
	certA := fullCert()
	certB := minimalCert()
	rows := BuildRows(certA, certB, defaultPrefs())
	assert.Len(t, rows, 23, "BuildRows should always return 23 rows")
}

func TestBuildRows_DifferentFieldNames(t *testing.T) {
	certA := fullCert()
	certB := fullCert()
	rows := BuildRows(certA, certB, defaultPrefs())

	fieldsA := ExtractFields(certA, defaultPrefs())
	for i, row := range rows {
		assert.Equal(t, fieldsA[i].Name, row.Name, "row name must match ExtractFields name at index %d", i)
	}
}
