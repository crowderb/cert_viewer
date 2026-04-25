//go:build windows

package resources

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const windowsRootStoreName = "ROOT"

// resolveTrustSource returns the source identifier recorded in local_roots.json
// on Windows. Matches the source string set by enumerateSystemRootCertificates
// so that EnsureLocalRootsJSON's source-changed check is a no-op on this platform.
func resolveTrustSource() string {
	return "Windows Certificate Store: " + windowsRootStoreName
}

// trustSourceMTime is unsupported on Windows — the system certificate store is
// backed by the registry, not a stat-able file. Returning ok=false skips the
// mtime-based regen check.
func trustSourceMTime(string) (time.Time, bool) { return time.Time{}, false }

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
	systemCerts, source, err := enumerateSystemRootCertificates(ctx)
	if err != nil {
		return nil, source, err
	}
	entries := make([]TrustSourceEntry, 0, len(systemCerts))
	for _, c := range systemCerts {
		entries = append(entries, TrustSourceEntry{
			Cert:       c,
			OriginType: OriginSystemBundle,
			OriginPath: source,
		})
	}
	return mergeTrustEntries(entries), source, nil
}
