package certs

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
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
