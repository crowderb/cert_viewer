//go:build windows

package resources

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const windowsRootStoreName = "ROOT"

// enumerateSystemRootCertificates returns parsed certificates from the Windows ROOT store.
func enumerateSystemRootCertificates(_ context.Context) ([]*x509.Certificate, string, error) {
	source := "Windows Certificate Store: " + windowsRootStoreName

	storeName, err := windows.UTF16PtrFromString(windowsRootStoreName)
	if err != nil {
		return nil, source, fmt.Errorf("encode store name: %w", err)
	}
	store, err := windows.CertOpenSystemStore(0, storeName)
	if err != nil {
		return nil, source, fmt.Errorf("open Windows ROOT store: %w", err)
	}
	defer windows.CertCloseStore(store, 0) //nolint:errcheck

	var out []*x509.Certificate
	var prev *windows.CertContext
	for {
		ctx, err := windows.CertEnumCertificatesInStore(store, prev)
		if err != nil {
			// CRYPT_E_NOT_FOUND (0x80092004) signals end of store — not an error.
			if errors.Is(err, syscall.Errno(0x80092004)) {
				break
			}
			return nil, source, fmt.Errorf("enumerate Windows ROOT store: %w", err)
		}

		// Copy DER bytes out of the Windows-owned memory before the context is freed.
		der := make([]byte, ctx.Length)
		copy(der, unsafe.Slice(ctx.EncodedCert, ctx.Length))

		cert, err := x509.ParseCertificate(der)
		if err != nil {
			prev = ctx
			continue
		}
		out = append(out, cert)
		prev = ctx
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
