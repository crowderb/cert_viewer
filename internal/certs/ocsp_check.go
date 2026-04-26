package certs

import (
	"bytes"
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"

	"golang.org/x/crypto/ocsp"

	"cert_viewer/internal/httpclient"
)

// CheckOCSP queries the first OCSP URL in cert.OCSPServer and returns the
// parsed response. If issuer is nil, it is fetched from the first AIA CA
// Issuers URL. The context is respected for all network operations.
func CheckOCSP(ctx context.Context, cert, issuer *x509.Certificate) (*ocsp.Response, error) {
	if len(cert.OCSPServer) == 0 {
		return nil, fmt.Errorf("certificate has no OCSP URL")
	}

	if issuer == nil {
		if len(cert.IssuingCertificateURL) == 0 {
			return nil, fmt.Errorf("no issuer certificate available and no AIA CA Issuers URL")
		}
		var err error
		issuer, err = fetchIssuerCert(ctx, cert.IssuingCertificateURL[0])
		if err != nil {
			return nil, fmt.Errorf("fetching issuer certificate: %w", err)
		}
	}

	reqDER, err := ocsp.CreateRequest(cert, issuer, nil)
	if err != nil {
		return nil, fmt.Errorf("creating OCSP request: %w", err)
	}

	ocspURL := cert.OCSPServer[0]
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, ocspURL, bytes.NewReader(reqDER))
	if err != nil {
		return nil, fmt.Errorf("building OCSP HTTP request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/ocsp-request")

	resp, err := httpclient.Default().Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("OCSP request to %s: %w", ocspURL, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading OCSP response: %w", err)
	}

	ocspResp, err := ocsp.ParseResponse(body, issuer)
	if err != nil {
		return nil, fmt.Errorf("parsing OCSP response: %w", err)
	}
	return ocspResp, nil
}

// FormatOCSPStatus converts an *ocsp.Response to a human-readable string:
//
//	Good    → "Good"
//	Unknown → "Unknown"
//	Revoked → "Revoked (ReasonName) at YYYY-MM-DD HH:MM:SS UTC"
func FormatOCSPStatus(resp *ocsp.Response) string {
	switch resp.Status {
	case ocsp.Good:
		return "Good"
	case ocsp.Unknown:
		return "Unknown"
	case ocsp.Revoked:
		return fmt.Sprintf("Revoked (%s) at %s",
			ocspReasonName(resp.RevocationReason),
			resp.RevokedAt.UTC().Format("2006-01-02 15:04:05 UTC"))
	default:
		return fmt.Sprintf("Unknown status (%d)", resp.Status)
	}
}

// fetchIssuerCert downloads a certificate from url and parses it (PEM, DER, or PKCS#7).
func fetchIssuerCert(ctx context.Context, url string) (*x509.Certificate, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := httpclient.Default().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return ParseCertificateOrPKCS7(data)
}

// ocspReasonName maps a revocation reason code to its RFC 5280 name.
func ocspReasonName(reason int) string {
	switch reason {
	case ocsp.Unspecified:
		return "Unspecified"
	case ocsp.KeyCompromise:
		return "KeyCompromise"
	case ocsp.CACompromise:
		return "CACompromise"
	case ocsp.AffiliationChanged:
		return "AffiliationChanged"
	case ocsp.Superseded:
		return "Superseded"
	case ocsp.CessationOfOperation:
		return "CessationOfOperation"
	case ocsp.CertificateHold:
		return "CertificateHold"
	case ocsp.RemoveFromCRL:
		return "RemoveFromCRL"
	case ocsp.PrivilegeWithdrawn:
		return "PrivilegeWithdrawn"
	case ocsp.AACompromise:
		return "AACompromise"
	default:
		return fmt.Sprintf("Reason(%d)", reason)
	}
}
