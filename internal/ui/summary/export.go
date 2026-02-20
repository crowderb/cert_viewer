package summary

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // SHA-1 used only for fingerprint display
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"strings"

	"cert_viewer/internal/certs"
	"cert_viewer/internal/prefs"
)

// ExportText returns a human-readable plain-text representation of cert's
// Summary and Details, formatted according to the user's preferences.
func ExportText(cert *x509.Certificate, p prefs.Preferences) string {
	var sb strings.Builder
	sep := string(p.UI.HexSep)
	windowsStyle := p.UI.NameStyle == prefs.Windows

	pair := func(label, value string) { fmt.Fprintf(&sb, "%s: %s\n", label, value) }
	group := func(title string) { fmt.Fprintf(&sb, "\n--- %s ---\n", title) }

	// === Certificate Summary ===
	fmt.Fprintf(&sb, "=== Certificate Summary ===\n\n")
	cn := cert.Subject.CommonName
	if cn == "" {
		cn = "(none)"
	}
	pair("Common Name", cn)
	pair("Subject", cert.Subject.String())
	pair("Issuer", cert.Issuer.String())
	pair("Serial Number", certs.FormatSerialWithSep(cert.SerialNumber, sep))
	if windowsStyle {
		pair("Valid From", cert.NotBefore.Format("2006-01-02 15:04:05 MST"))
		pair("Valid To", cert.NotAfter.Format("2006-01-02 15:04:05 MST"))
	} else {
		pair("Not Before", cert.NotBefore.Format("2006-01-02 15:04:05 MST"))
		pair("Not After", cert.NotAfter.Format("2006-01-02 15:04:05 MST"))
	}
	sha256Sum := sha256.Sum256(cert.Raw)
	sha1Sum := sha1.Sum(cert.Raw) //nolint:gosec
	pair("SHA-256 Fingerprint", certs.FormatHex(sha256Sum[:], sep))
	pair("SHA-1 Fingerprint", certs.FormatHex(sha1Sum[:], sep))

	// === Certificate Details ===
	fmt.Fprintf(&sb, "\n=== Certificate Details ===\n")
	group("General")
	pair("Version", fmt.Sprintf("%d", cert.Version))
	pair("Serial Number", certs.FormatSerialWithSep(cert.SerialNumber, sep))
	pair("Signature Algorithm", cert.SignatureAlgorithm.String())
	pair("Issuer", cert.Issuer.String())
	if windowsStyle {
		pair("Valid From", cert.NotBefore.Format("2006-01-02 15:04:05 MST"))
		pair("Valid To", cert.NotAfter.Format("2006-01-02 15:04:05 MST"))
	} else {
		pair("Not Before", cert.NotBefore.Format("2006-01-02 15:04:05 MST"))
		pair("Not After", cert.NotAfter.Format("2006-01-02 15:04:05 MST"))
	}
	pair("Subject", cert.Subject.String())

	group("Subject Attributes")
	for _, kv := range certs.ExtractNameAttributes(cert.Subject.Names, windowsStyle, "") {
		pair(kv[0], kv[1])
	}

	group("Issuer Attributes")
	for _, kv := range certs.ExtractNameAttributes(cert.Issuer.Names, windowsStyle, "") {
		pair(kv[0], kv[1])
	}

	group("Subject Public Key Info")
	pair("Public Key Algorithm", cert.PublicKeyAlgorithm.String())
	switch pk := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		pair("Public-Key", fmt.Sprintf("(%d bit)", pk.N.BitLen()))
		pair("RSA Exponent", fmt.Sprintf("%d", pk.E))
	case *ecdsa.PublicKey:
		bits := pk.Params().BitSize
		pair("Public-Key", fmt.Sprintf("(%d bit)", bits))
		if pk.Curve != nil && pk.Curve.Params() != nil {
			pair("ASN1 OID", pk.Curve.Params().Name)
			pair("NIST CURVE", certs.NISTCurveName(pk.Curve.Params().Name))
		}
		xBytes, yBytes := pk.X.Bytes(), pk.Y.Bytes()
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
		pair("pub", certs.FormatHex(pub, sep))
	case ed25519.PublicKey:
		pair("Public-Key", "(256 bit)")
		pair("Ed25519", certs.FormatHex([]byte(pk), sep))
	default:
		pair("Public-Key", "(unknown)")
	}

	group("X509v3 Extensions")
	if ku := certs.KeyUsageNames(cert.KeyUsage); ku != "" {
		pair("X509v3 Key Usage", ku)
	}
	if eku := certs.ExtKeyUsageNames(cert.ExtKeyUsage); eku != "" {
		pair("X509v3 Extended Key Usage", eku)
	}
	if cert.BasicConstraintsValid {
		bc := "CA:FALSE"
		if cert.IsCA {
			bc = "CA:TRUE"
		}
		if cert.MaxPathLen >= 0 {
			bc = fmt.Sprintf("%s, pathlen:%d", bc, cert.MaxPathLen)
		}
		pair("X509v3 Basic Constraints", bc)
	}
	if len(cert.SubjectKeyId) > 0 {
		pair("X509v3 Subject Key Identifier", certs.FormatHex(cert.SubjectKeyId, sep))
	}
	if len(cert.AuthorityKeyId) > 0 {
		pair("X509v3 Authority Key Identifier", certs.FormatHex(cert.AuthorityKeyId, sep))
	}
	if len(cert.OCSPServer) > 0 {
		pair("OCSP", strings.Join(cert.OCSPServer, ", "))
	}
	if len(cert.IssuingCertificateURL) > 0 {
		pair("CA Issuers", strings.Join(cert.IssuingCertificateURL, ", "))
	}
	if len(cert.DNSNames) > 0 {
		pair("DNS", strings.Join(cert.DNSNames, ", "))
	}
	if len(cert.EmailAddresses) > 0 {
		pair("Email", strings.Join(cert.EmailAddresses, ", "))
	}
	if len(cert.IPAddresses) > 0 {
		ips := make([]string, len(cert.IPAddresses))
		for i, ip := range cert.IPAddresses {
			ips[i] = ip.String()
		}
		pair("IP", strings.Join(ips, ", "))
	}
	if len(cert.URIs) > 0 {
		uris := make([]string, len(cert.URIs))
		for i, u := range cert.URIs {
			uris[i] = u.String()
		}
		pair("URI", strings.Join(uris, ", "))
	}
	if len(cert.PolicyIdentifiers) > 0 {
		oids := make([]string, len(cert.PolicyIdentifiers))
		for i, oid := range cert.PolicyIdentifiers {
			oids[i] = certs.OIDToString(oid)
		}
		pair("Certificate Policies", strings.Join(oids, ", "))
	}
	if len(cert.CRLDistributionPoints) > 0 {
		pair("CRL Distribution Points", strings.Join(cert.CRLDistributionPoints, ", "))
	}

	group("Signature")
	pair("Signature Algorithm", cert.SignatureAlgorithm.String())
	if len(cert.Signature) > 0 {
		pair("Signature Value", certs.FormatHex(cert.Signature, sep))
	}

	return sb.String()
}

// oidSANExport is the Subject Alternative Name OID (2.5.29.17), used to skip
// duplicate SAN entries when iterating raw CSR extensions.
var oidSANExport = asn1.ObjectIdentifier{2, 5, 29, 17}

// ExportCSRText returns a human-readable plain-text representation of a
// CertificateRequest's Summary and Details, formatted per user preferences.
func ExportCSRText(csr *x509.CertificateRequest, p prefs.Preferences) string {
	var sb strings.Builder
	sep := string(p.UI.HexSep)
	windowsStyle := p.UI.NameStyle == prefs.Windows

	pair := func(label, value string) { fmt.Fprintf(&sb, "%s: %s\n", label, value) }
	group := func(title string) { fmt.Fprintf(&sb, "\n--- %s ---\n", title) }

	// === CSR Summary ===
	fmt.Fprintf(&sb, "=== Certificate Signing Request Summary ===\n\n")
	pair("Type", "Certificate Signing Request (not yet issued)")
	cn := csr.Subject.CommonName
	if cn == "" {
		cn = "(none)"
	}
	pair("Common Name", cn)
	pair("Subject", csr.Subject.String())
	pair("Public Key Algorithm", csr.PublicKeyAlgorithm.String())
	pair("Signature Algorithm", csr.SignatureAlgorithm.String())
	sha256Sum := sha256.Sum256(csr.Raw)
	sha1Sum := sha1.Sum(csr.Raw) //nolint:gosec
	pair("SHA-256 Fingerprint", certs.FormatHex(sha256Sum[:], sep))
	pair("SHA-1 Fingerprint", certs.FormatHex(sha1Sum[:], sep))

	// === CSR Details ===
	fmt.Fprintf(&sb, "\n=== Certificate Signing Request Details ===\n")
	group("Certificate Signing Request")
	pair("Version", fmt.Sprintf("%d", csr.Version))
	pair("Signature Algorithm", csr.SignatureAlgorithm.String())
	pair("Subject", csr.Subject.String())

	group("Subject Attributes")
	for _, kv := range certs.ExtractNameAttributes(csr.Subject.Names, windowsStyle, "") {
		pair(kv[0], kv[1])
	}

	group("Subject Public Key Info")
	pair("Public Key Algorithm", csr.PublicKeyAlgorithm.String())
	switch pk := csr.PublicKey.(type) {
	case *rsa.PublicKey:
		pair("Public-Key", fmt.Sprintf("(%d bit)", pk.N.BitLen()))
		pair("RSA Exponent", fmt.Sprintf("%d", pk.E))
	case *ecdsa.PublicKey:
		bits := pk.Params().BitSize
		pair("Public-Key", fmt.Sprintf("(%d bit)", bits))
		if pk.Curve != nil && pk.Curve.Params() != nil {
			pair("ASN1 OID", pk.Curve.Params().Name)
			pair("NIST CURVE", certs.NISTCurveName(pk.Curve.Params().Name))
		}
		xBytes, yBytes := pk.X.Bytes(), pk.Y.Bytes()
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
		pair("pub", certs.FormatHex(pub, sep))
	case ed25519.PublicKey:
		pair("Public-Key", "(256 bit)")
		pair("Ed25519", certs.FormatHex([]byte(pk), sep))
	default:
		pair("Public-Key", "(unknown)")
	}

	group("Requested Extensions")
	if len(csr.DNSNames) > 0 {
		pair("DNS", strings.Join(csr.DNSNames, ", "))
	}
	if len(csr.EmailAddresses) > 0 {
		pair("Email", strings.Join(csr.EmailAddresses, ", "))
	}
	if len(csr.IPAddresses) > 0 {
		ips := make([]string, len(csr.IPAddresses))
		for i, ip := range csr.IPAddresses {
			ips[i] = ip.String()
		}
		pair("IP", strings.Join(ips, ", "))
	}
	if len(csr.URIs) > 0 {
		uris := make([]string, len(csr.URIs))
		for i, u := range csr.URIs {
			uris[i] = u.String()
		}
		pair("URI", strings.Join(uris, ", "))
	}
	for _, ext := range csr.Extensions {
		if ext.Id.Equal(oidSANExport) {
			continue
		}
		pair(certs.OIDToString(ext.Id), certs.FormatHex(ext.Value, sep))
	}

	group("Signature")
	pair("Signature Algorithm", csr.SignatureAlgorithm.String())
	if len(csr.Signature) > 0 {
		pair("Signature Value", certs.FormatHex(csr.Signature, sep))
	}

	return sb.String()
}
