package summary

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/widget"

	"cert_viewer/internal/certs"
	"cert_viewer/internal/prefs"
	"cert_viewer/internal/ui"
)

// Render populates summaryGrid (Summary tab) and details (Details tab) from cert.
func Render(win fyne.Window, summaryGrid *fyne.Container, details *fyne.Container, cert *x509.Certificate, p prefs.Preferences) {
	// Summary content: clear and add name/value rows
	summaryGrid.Objects = nil
	cn := cert.Subject.CommonName
	if cn == "" {
		cn = "(none)"
	}
	addSummaryRow := func(name, value string) {
		summaryGrid.Add(ui.BoldLabel(name))
		summaryGrid.Add(ui.CopyRow(win, value))
	}
	addSummaryRow("Common Name", cn)
	addSummaryRow("Subject", cert.Subject.String())
	addSummaryRow("Issuer", cert.Issuer.String())
	// Serial uses same separator preference as fingerprints
	addSummaryRow("Serial Number", certs.FormatSerialWithSep(cert.SerialNumber, string(p.UI.HexSep)))
	// Validity rows labeled based on preference
	if p.UI.NameStyle == prefs.Windows {
		addSummaryRow("Valid From", cert.NotBefore.Format("2006-01-02 15:04:05 MST"))
		addSummaryRow("Valid To", cert.NotAfter.Format("2006-01-02 15:04:05 MST"))
	} else {
		addSummaryRow("Not Before", cert.NotBefore.Format("2006-01-02 15:04:05 MST"))
		addSummaryRow("Not After", cert.NotAfter.Format("2006-01-02 15:04:05 MST"))
	}

	sha256Sum := sha256.Sum256(cert.Raw)
	sha1Sum := sha1.Sum(cert.Raw)
	addSummaryRow("SHA-256 Fingerprint", certs.FormatHex(sha256Sum[:], string(p.UI.HexSep)))
	addSummaryRow("SHA-1 Fingerprint", certs.FormatHex(sha1Sum[:], string(p.UI.HexSep)))
	summaryGrid.Refresh()

	// Details rows expanded with group headers -> render into container
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

	// General
	addHeader("General")
	addPair("Version", fmt.Sprintf("%d", cert.Version))
	addPair("Serial Number", certs.FormatSerialWithSep(cert.SerialNumber, string(p.UI.HexSep)))
	addPair("Signature Algorithm", cert.SignatureAlgorithm.String())
	addPair("Issuer", cert.Issuer.String())
	if p.UI.NameStyle == prefs.Windows {
		addPair("Valid From", cert.NotBefore.Format("2006-01-02 15:04:05 MST"))
		addPair("Valid To", cert.NotAfter.Format("2006-01-02 15:04:05 MST"))
	} else {
		addPair("Not Before", cert.NotBefore.Format("2006-01-02 15:04:05 MST"))
		addPair("Not After", cert.NotAfter.Format("2006-01-02 15:04:05 MST"))
	}
	addPair("Subject", cert.Subject.String())
	// Subject and Issuer attribute breakdown
	addHeader("Subject Attributes")
	for _, pair := range certs.ExtractNameAttributes(cert.Subject.Names, p.UI.NameStyle == prefs.Windows, "") {
		addPair(pair[0], pair[1])
	}
	addHeader("Issuer Attributes")
	for _, pair := range certs.ExtractNameAttributes(cert.Issuer.Names, p.UI.NameStyle == prefs.Windows, "") {
		addPair(pair[0], pair[1])
	}

	// Subject Public Key Info
	addHeader("Subject Public Key Info")
	addPair("Public Key Algorithm", cert.PublicKeyAlgorithm.String())
	switch pk := cert.PublicKey.(type) {
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
		// Uncompressed point 0x04 || X || Y
		xBytes := pk.X.Bytes()
		yBytes := pk.Y.Bytes()
		// Pad to curve size
		byteLen := (bits + 7) / 8
		if len(xBytes) < byteLen {
			xBytes = append(make([]byte, byteLen-len(xBytes)), xBytes...)
		}
		if len(yBytes) < byteLen {
			yBytes = append(make([]byte, byteLen-len(yBytes)), yBytes...)
		}
		pub := make([]byte, 1+len(xBytes)+len(yBytes))
		pub[0] = 0x04
		copy(pub[1:1+len(xBytes)], xBytes)
		copy(pub[1+len(xBytes):], yBytes)
		addPair("pub", certs.FormatHex(pub, string(p.UI.HexSep)))
	case ed25519.PublicKey:
		addPair("Public-Key", "(256 bit)")
		addPair("Ed25519", certs.FormatHex([]byte(pk), string(p.UI.HexSep)))
	default:
		addPair("Public-Key", "(unknown)")
	}

	// X509v3 extensions
	addHeader("X509v3 extensions")
	if ku := certs.KeyUsageNames(cert.KeyUsage); ku != "" {
		addPair("X509v3 Key Usage", ku)
	}
	if eku := certs.ExtKeyUsageNames(cert.ExtKeyUsage); eku != "" {
		addPair("X509v3 Extended Key Usage", eku)
	}
	if cert.BasicConstraintsValid {
		bc := "CA:FALSE"
		if cert.IsCA {
			bc = "CA:TRUE"
		}
		if cert.MaxPathLen >= 0 {
			bc = fmt.Sprintf("%s, pathlen:%d", bc, cert.MaxPathLen)
		}
		addPair("X509v3 Basic Constraints", bc)
	}
	if len(cert.SubjectKeyId) > 0 {
		addPair("X509v3 Subject Key Identifier", certs.FormatHex(cert.SubjectKeyId, string(p.UI.HexSep)))
	}
	if len(cert.AuthorityKeyId) > 0 {
		addPair("X509v3 Authority Key Identifier", certs.FormatHex(cert.AuthorityKeyId, string(p.UI.HexSep)))
	}
	// AIA
	if len(cert.OCSPServer) > 0 {
		addPair("OCSP", strings.Join(cert.OCSPServer, ", "))
	}
	if len(cert.IssuingCertificateURL) > 0 {
		addPair("CA Issuers", strings.Join(cert.IssuingCertificateURL, ", "))
	}
	// SANs
	if len(cert.DNSNames) > 0 {
		addPair("DNS", strings.Join(cert.DNSNames, ", "))
	}
	if len(cert.EmailAddresses) > 0 {
		addPair("Email", strings.Join(cert.EmailAddresses, ", "))
	}
	if len(cert.IPAddresses) > 0 {
		ips := make([]string, len(cert.IPAddresses))
		for i, ip := range cert.IPAddresses {
			ips[i] = ip.String()
		}
		addPair("IP", strings.Join(ips, ", "))
	}
	if len(cert.URIs) > 0 {
		uris := make([]string, len(cert.URIs))
		for i, u := range cert.URIs {
			uris[i] = u.String()
		}
		addPair("URI", strings.Join(uris, ", "))
	}
	// Policies
	if len(cert.PolicyIdentifiers) > 0 {
		oids := make([]string, len(cert.PolicyIdentifiers))
		for i, oid := range cert.PolicyIdentifiers {
			oids[i] = certs.OIDToString(oid)
		}
		addPair("Certificate Policies", strings.Join(oids, ", "))
	}
	// CRL Distribution Points
	if len(cert.CRLDistributionPoints) > 0 {
		addPair("CRL Distribution Points", strings.Join(cert.CRLDistributionPoints, ", "))
	}

	// Signature
	addHeader("Signature")
	addPair("Signature Algorithm", cert.SignatureAlgorithm.String())
	if len(cert.Signature) > 0 {
		addPair("Signature Value", certs.FormatHex(cert.Signature, string(p.UI.HexSep)))
	}

	details.Refresh()
}
