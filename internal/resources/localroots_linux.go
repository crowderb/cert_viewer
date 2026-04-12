//go:build linux

package resources

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io"
	"os"
)

const defaultLinuxBundle = "/etc/ssl/certs/ca-certificates.crt"

// enumerateSystemRootCertificates parses PEM certificates from the system CA bundle.
func enumerateSystemRootCertificates(_ context.Context) ([]*x509.Certificate, string, error) {
	source := defaultLinuxBundle
	f, err := os.Open(source)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, source, nil
		}
		return nil, source, err
	}
	defer f.Close()
	data, err := io.ReadAll(f)
	if err != nil {
		return nil, source, err
	}
	var out []*x509.Certificate
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
		out = append(out, cert)
	}
	return out, source, nil
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
