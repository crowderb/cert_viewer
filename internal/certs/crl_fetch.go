package certs

import (
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"

	"cert_viewer/internal/httpclient"
)

// FetchCRL downloads the CRL at url and parses it.
func FetchCRL(ctx context.Context, url string) (*x509.RevocationList, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("building CRL request: %w", err)
	}
	resp, err := httpclient.Default().Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching CRL from %s: %w", url, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading CRL response: %w", err)
	}
	rl, err := x509.ParseRevocationList(data)
	if err != nil {
		return nil, fmt.Errorf("parsing CRL: %w", err)
	}
	return rl, nil
}

// CheckCertInCRL reports whether cert's serial number appears in the revocation
// list. Returns the matching entry (non-nil) if revoked, or nil if not found.
func CheckCertInCRL(cert *x509.Certificate, rl *x509.RevocationList) *x509.RevocationListEntry {
	for i := range rl.RevokedCertificateEntries {
		if rl.RevokedCertificateEntries[i].SerialNumber.Cmp(cert.SerialNumber) == 0 {
			return &rl.RevokedCertificateEntries[i]
		}
	}
	return nil
}

// FormatRevocationReason maps an RFC 5280 reason code to its name.
func FormatRevocationReason(code int) string {
	switch code {
	case 0:
		return "Unspecified"
	case 1:
		return "KeyCompromise"
	case 2:
		return "CACompromise"
	case 3:
		return "AffiliationChanged"
	case 4:
		return "Superseded"
	case 5:
		return "CessationOfOperation"
	case 6:
		return "CertificateHold"
	case 8:
		return "RemoveFromCRL"
	case 9:
		return "PrivilegeWithdrawn"
	case 10:
		return "AACompromise"
	default:
		return fmt.Sprintf("Reason(%d)", code)
	}
}
