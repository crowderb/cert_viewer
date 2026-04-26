package certs

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestOIDToString(t *testing.T) {
	tests := []struct {
		name string
		oid  asn1.ObjectIdentifier
		want string
	}{
		{"empty", asn1.ObjectIdentifier{}, ""},
		{"single element", asn1.ObjectIdentifier{2}, "2"},
		{"CN OID", asn1.ObjectIdentifier{2, 5, 4, 3}, "2.5.4.3"},
		{"email OID", asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}, "1.2.840.113549.1.9.1"},
		{"DC OID", asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 25}, "0.9.2342.19200300.100.1.25"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, OIDToString(tc.oid))
		})
	}
}

func TestMapOIDToName(t *testing.T) {
	known := []struct {
		oid     asn1.ObjectIdentifier
		openssl string
		windows string
	}{
		{asn1.ObjectIdentifier{2, 5, 4, 3}, "CN", "Common Name"},
		{asn1.ObjectIdentifier{2, 5, 4, 6}, "C", "Country"},
		{asn1.ObjectIdentifier{2, 5, 4, 7}, "L", "Locality"},
		{asn1.ObjectIdentifier{2, 5, 4, 8}, "ST", "State/Province"},
		{asn1.ObjectIdentifier{2, 5, 4, 10}, "O", "Organization"},
		{asn1.ObjectIdentifier{2, 5, 4, 11}, "OU", "Organizational Unit"},
		{asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}, "emailAddress", "E-Mail"},
		{asn1.ObjectIdentifier{2, 5, 4, 9}, "street", "Street"},
		{asn1.ObjectIdentifier{2, 5, 4, 17}, "postalCode", "Postal Code"},
		{asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 25}, "DC", "Domain Component"},
		{asn1.ObjectIdentifier{2, 5, 4, 5}, "serialNumber", "Serial Number"},
	}
	for _, tc := range known {
		t.Run("openssl/"+OIDToString(tc.oid), func(t *testing.T) {
			assert.Equal(t, tc.openssl, MapOIDToName(tc.oid, false))
		})
		t.Run("windows/"+OIDToString(tc.oid), func(t *testing.T) {
			assert.Equal(t, tc.windows, MapOIDToName(tc.oid, true))
		})
	}

	unknown := asn1.ObjectIdentifier{9, 9, 9, 9}
	t.Run("unknown OID openssl returns dot-notation", func(t *testing.T) {
		assert.Equal(t, "9.9.9.9", MapOIDToName(unknown, false))
	})
	t.Run("unknown OID windows returns dot-notation", func(t *testing.T) {
		assert.Equal(t, "9.9.9.9", MapOIDToName(unknown, true))
	})
}

func TestExtractNameAttributes(t *testing.T) {
	cnOID := asn1.ObjectIdentifier{2, 5, 4, 3}
	oOID := asn1.ObjectIdentifier{2, 5, 4, 10}
	unknownOID := asn1.ObjectIdentifier{9, 9, 9}

	t.Run("empty slice returns empty not nil", func(t *testing.T) {
		result := ExtractNameAttributes(nil, false, "")
		assert.Equal(t, [][]string{}, result)
	})

	t.Run("no prefix openssl style", func(t *testing.T) {
		attrs := []pkix.AttributeTypeAndValue{
			{Type: cnOID, Value: "example.com"},
		}
		result := ExtractNameAttributes(attrs, false, "")
		assert.Equal(t, [][]string{{"CN", "example.com"}}, result)
	})

	t.Run("with prefix windows style", func(t *testing.T) {
		attrs := []pkix.AttributeTypeAndValue{
			{Type: cnOID, Value: "example.com"},
			{Type: oOID, Value: "Acme Corp"},
		}
		result := ExtractNameAttributes(attrs, true, "Subject")
		assert.Equal(t, [][]string{
			{"Subject Common Name", "example.com"},
			{"Subject Organization", "Acme Corp"},
		}, result)
	})

	t.Run("unknown OID uses dot-notation", func(t *testing.T) {
		attrs := []pkix.AttributeTypeAndValue{
			{Type: unknownOID, Value: "thing"},
		}
		result := ExtractNameAttributes(attrs, false, "")
		assert.Equal(t, [][]string{{"9.9.9", "thing"}}, result)
	})

	t.Run("non-string value formatted with %v", func(t *testing.T) {
		attrs := []pkix.AttributeTypeAndValue{
			{Type: cnOID, Value: 42},
		}
		result := ExtractNameAttributes(attrs, false, "")
		assert.Equal(t, [][]string{{"CN", "42"}}, result)
	})

	t.Run("order preserved", func(t *testing.T) {
		attrs := []pkix.AttributeTypeAndValue{
			{Type: oOID, Value: "Org"},
			{Type: cnOID, Value: "Name"},
		}
		result := ExtractNameAttributes(attrs, false, "")
		assert.Equal(t, "O", result[0][0])
		assert.Equal(t, "CN", result[1][0])
	})
}

func TestKeyUsageNames(t *testing.T) {
	tests := []struct {
		name string
		ku   x509.KeyUsage
		want string
	}{
		{"none", 0, ""},
		{"digital signature", x509.KeyUsageDigitalSignature, "Digital Signature"},
		{"content commitment", x509.KeyUsageContentCommitment, "Non Repudiation"},
		{"key encipherment", x509.KeyUsageKeyEncipherment, "Key Encipherment"},
		{"data encipherment", x509.KeyUsageDataEncipherment, "Data Encipherment"},
		{"key agreement", x509.KeyUsageKeyAgreement, "Key Agreement"},
		{"cert sign", x509.KeyUsageCertSign, "Certificate Sign"},
		{"crl sign", x509.KeyUsageCRLSign, "CRL Sign"},
		{"encipher only", x509.KeyUsageEncipherOnly, "Encipher Only"},
		{"decipher only", x509.KeyUsageDecipherOnly, "Decipher Only"},
		{
			"two bits",
			x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
			"Digital Signature, Certificate Sign",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, KeyUsageNames(tc.ku))
		})
	}
}

func TestExtKeyUsageNames(t *testing.T) {
	t.Run("nil slice", func(t *testing.T) {
		assert.Equal(t, "", ExtKeyUsageNames(nil))
	})
	t.Run("empty slice", func(t *testing.T) {
		assert.Equal(t, "", ExtKeyUsageNames([]x509.ExtKeyUsage{}))
	})

	known := []struct {
		usage x509.ExtKeyUsage
		want  string
	}{
		{x509.ExtKeyUsageAny, "Any"},
		{x509.ExtKeyUsageServerAuth, "TLS Web Server Authentication"},
		{x509.ExtKeyUsageClientAuth, "TLS Web Client Authentication"},
		{x509.ExtKeyUsageCodeSigning, "Code Signing"},
		{x509.ExtKeyUsageEmailProtection, "E-mail Protection"},
		{x509.ExtKeyUsageIPSECEndSystem, "IPSec End System"},
		{x509.ExtKeyUsageIPSECTunnel, "IPSec Tunnel"},
		{x509.ExtKeyUsageIPSECUser, "IPSec User"},
		{x509.ExtKeyUsageTimeStamping, "Time Stamping"},
		{x509.ExtKeyUsageOCSPSigning, "OCSP Signing"},
		{x509.ExtKeyUsageMicrosoftServerGatedCrypto, "Microsoft Server Gated Crypto"},
		{x509.ExtKeyUsageNetscapeServerGatedCrypto, "Netscape Server Gated Crypto"},
		{x509.ExtKeyUsageMicrosoftCommercialCodeSigning, "Microsoft Commercial Code Signing"},
		{x509.ExtKeyUsageMicrosoftKernelCodeSigning, "Microsoft Kernel Code Signing"},
	}
	for _, tc := range known {
		t.Run(tc.want, func(t *testing.T) {
			assert.Equal(t, tc.want, ExtKeyUsageNames([]x509.ExtKeyUsage{tc.usage}))
		})
	}

	t.Run("unknown value", func(t *testing.T) {
		assert.Equal(t, "Unknown (999)", ExtKeyUsageNames([]x509.ExtKeyUsage{999}))
	})
	t.Run("multiple values joined by comma", func(t *testing.T) {
		assert.Equal(t, "Any, Code Signing", ExtKeyUsageNames([]x509.ExtKeyUsage{
			x509.ExtKeyUsageAny, x509.ExtKeyUsageCodeSigning,
		}))
	})
}

func TestNISTCurveName(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"P-256", "P-256"},
		{"prime256v1", "P-256"},
		{"P-384", "P-384"},
		{"secp384r1", "P-384"},
		{"P-521", "P-521"},
		{"secp521r1", "P-521"},
		{"secp256k1", "secp256k1"},
		{"", ""},
		{"unknown", "unknown"},
	}
	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			assert.Equal(t, tc.want, NISTCurveName(tc.input))
		})
	}
}

func TestBytesToHexNoSepUpper(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		want  string
	}{
		{"nil", nil, ""},
		{"empty", []byte{}, ""},
		{"zero byte", []byte{0x00}, "00"},
		{"0xFF", []byte{0xFF}, "FF"},
		{"leading zero nibble", []byte{0x0A}, "0A"},
		{"multi byte", []byte{0xAB, 0xCD, 0xEF}, "ABCDEF"},
		{"all zeros", []byte{0x00, 0x00}, "0000"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, BytesToHexNoSepUpper(tc.input))
		})
	}
}

func TestFormatHex(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		sep   string
		want  string
	}{
		{"empty no sep", []byte{}, "", ""},
		{"empty with colon sep", []byte{}, ":", ""},
		{"two bytes no sep", []byte{0xAB, 0xCD}, "", "ABCD"},
		{"two bytes colon sep", []byte{0xAB, 0xCD}, ":", "AB:CD"},
		{"two bytes space sep", []byte{0xAB, 0xCD}, " ", "AB CD"},
		{"single byte no sep", []byte{0xAB}, "", "AB"},
		{"single byte colon sep has no colon", []byte{0xAB}, ":", "AB"},
		{"leading zero nibble", []byte{0x0A, 0x0B}, ":", "0A:0B"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, FormatHex(tc.input, tc.sep))
		})
	}

	t.Run("no sep matches BytesToHexNoSepUpper", func(t *testing.T) {
		input := []byte{0xDE, 0xAD, 0xBE, 0xEF}
		assert.Equal(t, BytesToHexNoSepUpper(input), FormatHex(input, ""))
	})
}

func TestFormatSerialWithSep(t *testing.T) {
	tests := []struct {
		name string
		n    *big.Int
		sep  string
		want string
	}{
		{"nil", nil, ":", ""},
		{"zero no sep", big.NewInt(0), "", "00"},
		{"zero colon sep", big.NewInt(0), ":", "00"},
		{"one padded to even", big.NewInt(1), "", "01"},
		{"one colon sep", big.NewInt(1), ":", "01"},
		{"0xABCD even-length no sep", big.NewInt(0xABCD), "", "ABCD"},
		{"0xABCD colon sep", big.NewInt(0xABCD), ":", "AB:CD"},
		{"0xABCD space sep", big.NewInt(0xABCD), " ", "AB CD"},
		{"0xABCDE odd-length padded", big.NewInt(0xABCDE), ":", "0A:BC:DE"},
		{"large serial colon sep", new(big.Int).SetBytes([]byte{0xDE, 0xAD, 0xBE, 0xEF}), ":", "DE:AD:BE:EF"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, FormatSerialWithSep(tc.n, tc.sep))
		})
	}
}

func TestNormalizeHexBytesNoSepUpper(t *testing.T) {
	inputs := [][]byte{
		nil,
		{},
		{0x00},
		{0xFF},
		{0x0A, 0xBC},
		{0xDE, 0xAD, 0xBE, 0xEF},
	}
	for _, input := range inputs {
		assert.Equal(t, BytesToHexNoSepUpper(input), NormalizeHexBytesNoSepUpper(input),
			"NormalizeHexBytesNoSepUpper should be identical to BytesToHexNoSepUpper")
	}
}
