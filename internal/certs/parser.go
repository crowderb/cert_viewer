package certs

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"go.mozilla.org/pkcs7"
	"golang.org/x/crypto/pkcs12"
)

// ParseCertificate tries to parse a certificate from PEM or DER bytes.
func ParseCertificate(data []byte) (*x509.Certificate, error) {
	// Try PEM first (may contain multiple blocks)
	var derBytes []byte
	var pemBlock *pem.Block
	for {
		pemBlock, data = pem.Decode(data)
		if pemBlock == nil {
			break
		}
		if pemBlock.Type == "CERTIFICATE" && len(pemBlock.Bytes) > 0 {
			derBytes = pemBlock.Bytes
			break
		}
	}
	if len(derBytes) == 0 {
		// Not PEM or no CERTIFICATE block found, assume raw DER
		derBytes = data
	}
	if len(bytes.TrimSpace(derBytes)) == 0 {
		return nil, fmt.Errorf("no certificate data found")
	}
	return x509.ParseCertificate(derBytes)
}

// ParsePKCS12 decodes a PKCS#12 / PFX bundle and returns the leaf certificate
// and any CA certificates embedded in the bundle. The private key is discarded.
// If the password is wrong, the error wraps pkcs12.ErrIncorrectPassword.
func ParsePKCS12(data []byte, password string) (leaf *x509.Certificate, caCerts []*x509.Certificate, err error) {
	blocks, err := pkcs12.ToPEM(data, password)
	if err != nil {
		return nil, nil, err
	}
	var all []*x509.Certificate
	for _, block := range blocks {
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, parseErr := x509.ParseCertificate(block.Bytes)
		if parseErr != nil {
			continue
		}
		all = append(all, cert)
	}
	if len(all) == 0 {
		return nil, nil, fmt.Errorf("pkcs12: no certificates found in bundle")
	}
	return all[0], all[1:], nil
}

// ParseCertificateOrPKCS7 parses a single certificate from PEM, DER, or a
// PKCS#7 degenerate SignedData bundle (common in AIA CA Issuers responses).
// It returns the first certificate found.
func ParseCertificateOrPKCS7(data []byte) (*x509.Certificate, error) {
	// Fast path: try existing PEM / DER parser.
	if cert, err := ParseCertificate(data); err == nil {
		return cert, nil
	}
	// Slow path: try PKCS#7.
	p7, err := pkcs7.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("not PEM, DER, or valid PKCS#7: %w", err)
	}
	if len(p7.Certificates) == 0 {
		return nil, fmt.Errorf("PKCS#7 bundle contains no certificates")
	}
	return p7.Certificates[0], nil
}
