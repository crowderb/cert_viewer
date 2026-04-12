//go:build darwin

package resources

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os/exec"
)

const macOSSystemRootKeychain = "/System/Library/Keychains/SystemRootCertificates.keychain"

// enumerateSystemRootCertificates loads PEM-encoded roots from the macOS system root keychain.
func enumerateSystemRootCertificates(ctx context.Context) ([]*x509.Certificate, string, error) {
	source := "macOS Keychain: " + macOSSystemRootKeychain

	cmd := exec.CommandContext(ctx, "security", "find-certificate", "-a", "-p", macOSSystemRootKeychain)
	out, err := cmd.Output()
	if err != nil {
		return nil, source, fmt.Errorf("security find-certificate: %w", err)
	}

	var outCerts []*x509.Certificate
	data := out
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" || len(block.Bytes) == 0 {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		outCerts = append(outCerts, cert)
	}
	return outCerts, source, nil
}

func collectRoots(ctx context.Context) ([]LocalRootSummary, string, error) {
	certs, source, err := enumerateSystemRootCertificates(ctx)
	if err != nil {
		return nil, source, err
	}
	roots := make([]LocalRootSummary, 0, len(certs))
	for _, cert := range certs {
		sha := sha256.Sum256(cert.Raw)
		roots = append(roots, LocalRootSummary{
			Subject:              cert.Subject.String(),
			SubjectKeyIdentifier: hex.EncodeToString(cert.SubjectKeyId),
			SerialHex:            upperNoSep(cert.SerialNumber),
			NotBefore:            cert.NotBefore.Format("2006-01-02 15:04:05 MST"),
			NotAfter:             cert.NotAfter.Format("2006-01-02 15:04:05 MST"),
			SHA256FingerprintHex: hex.EncodeToString(sha[:]),
		})
	}
	return roots, source, nil
}
