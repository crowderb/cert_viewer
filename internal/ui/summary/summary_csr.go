package summary

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/widget"

	"cert_viewer/internal/certs"
	"cert_viewer/internal/prefs"
	"cert_viewer/internal/ui"
)

// oidSAN is the Subject Alternative Name OID (2.5.29.17).
// Extensions with this OID are already shown via convenience fields and are skipped
// when iterating csr.Extensions to avoid duplication.
var oidSAN = asn1.ObjectIdentifier{2, 5, 29, 17}

// RenderCSR populates summaryGrid (Summary tab) and details (Details tab) from a
// CertificateRequest. The first row of the summary is a "Type" banner clearly
// indicating this is a request, not an issued certificate.
func RenderCSR(win fyne.Window, summaryGrid *fyne.Container, details *fyne.Container, csr *x509.CertificateRequest, p prefs.Preferences) {
	sep := string(p.UI.HexSep)

	// --- Summary tab ---
	summaryGrid.Objects = nil
	addSummaryRow := func(name, value string) {
		summaryGrid.Add(ui.BoldLabel(name))
		summaryGrid.Add(ui.CopyRow(win, value))
	}
	// Clear indication that this is a CSR, not an issued certificate.
	addSummaryRow("Type", "Certificate Signing Request (not yet issued)")
	cn := csr.Subject.CommonName
	if cn == "" {
		cn = "(none)"
	}
	addSummaryRow("Common Name", cn)
	addSummaryRow("Subject", csr.Subject.String())
	addSummaryRow("Public Key Algorithm", csr.PublicKeyAlgorithm.String())
	addSummaryRow("Signature Algorithm", csr.SignatureAlgorithm.String())
	sha256Sum := sha256.Sum256(csr.Raw)
	sha1Sum := sha1.Sum(csr.Raw)
	addSummaryRow("SHA-256 Fingerprint", certs.FormatHex(sha256Sum[:], sep))
	addSummaryRow("SHA-1 Fingerprint", certs.FormatHex(sha1Sum[:], sep))
	summaryGrid.Refresh()

	// --- Details tab ---
	details.Objects = nil
	addHeader := func(title string) {
		details.Add(ui.BoldLabel(title))
		details.Add(widget.NewLabel(""))
	}
	addPair := func(name, value string) {
		details.Add(widget.NewLabel(name))
		v := widget.NewRichTextWithText(value)
		v.Wrapping = fyne.TextWrapWord
		details.Add(v)
	}

	// General — no serial, no issuer, no validity dates.
	addHeader("Certificate Signing Request")
	addPair("Version", fmt.Sprintf("%d", csr.Version))
	addPair("Signature Algorithm", csr.SignatureAlgorithm.String())
	addPair("Subject", csr.Subject.String())

	// Subject Attributes
	addHeader("Subject Attributes")
	for _, pair := range certs.ExtractNameAttributes(csr.Subject.Names, p.UI.NameStyle == prefs.Windows, "") {
		addPair(pair[0], pair[1])
	}

	// Subject Public Key Info — same type switch as summary.Render
	addHeader("Subject Public Key Info")
	addPair("Public Key Algorithm", csr.PublicKeyAlgorithm.String())
	switch pk := csr.PublicKey.(type) {
	case *rsa.PublicKey:
		addPair("Public-Key", fmt.Sprintf("(%d bit)", pk.N.BitLen()))
		addPair("RSA Exponent", fmt.Sprintf("%d", pk.E))
	case *ecdsa.PublicKey:
		bits := pk.Params().BitSize
		addPair("Public-Key", fmt.Sprintf("(%d bit)", bits))
		if pk.Curve != nil && pk.Curve.Params() != nil {
			addPair("ASN1 OID", pk.Curve.Params().Name)
			addPair("NIST CURVE", certs.NISTCurveName(pk.Curve.Params().Name))
		}
		xBytes := pk.X.Bytes()
		yBytes := pk.Y.Bytes()
		byteLen := (bits + 7) / 8
		if len(xBytes) < byteLen {
			xBytes = append(make([]byte, byteLen-len(xBytes)), xBytes...)
		}
		if len(yBytes) < byteLen {
			yBytes = append(make([]byte, byteLen-len(yBytes)), yBytes...)
		}
		pub := make([]byte, 1+len(xBytes)+len(yBytes))
		pub[0] = 0x04
		copy(pub[1:], xBytes)
		copy(pub[1+len(xBytes):], yBytes)
		addPair("pub", certs.FormatHex(pub, sep))
	case ed25519.PublicKey:
		addPair("Public-Key", "(256 bit)")
		addPair("Ed25519", certs.FormatHex([]byte(pk), sep))
	default:
		addPair("Public-Key", "(unknown)")
	}

	// Requested Extensions — SANs from convenience fields, then raw non-SAN extensions.
	addHeader("Requested Extensions")
	if len(csr.DNSNames) > 0 {
		addPair("DNS", strings.Join(csr.DNSNames, ", "))
	}
	if len(csr.EmailAddresses) > 0 {
		addPair("Email", strings.Join(csr.EmailAddresses, ", "))
	}
	if len(csr.IPAddresses) > 0 {
		ips := make([]string, len(csr.IPAddresses))
		for i, ip := range csr.IPAddresses {
			ips[i] = ip.String()
		}
		addPair("IP", strings.Join(ips, ", "))
	}
	if len(csr.URIs) > 0 {
		uris := make([]string, len(csr.URIs))
		for i, u := range csr.URIs {
			uris[i] = u.String()
		}
		addPair("URI", strings.Join(uris, ", "))
	}
	// Raw extensions (skip SAN OID — already shown via convenience fields above).
	for _, ext := range csr.Extensions {
		if ext.Id.Equal(oidSAN) {
			continue
		}
		addPair(certs.OIDToString(ext.Id), certs.FormatHex(ext.Value, sep))
	}

	// Signature
	addHeader("Signature")
	addPair("Signature Algorithm", csr.SignatureAlgorithm.String())
	if len(csr.Signature) > 0 {
		addPair("Signature Value", certs.FormatHex(csr.Signature, sep))
	}

	details.Refresh()
}
