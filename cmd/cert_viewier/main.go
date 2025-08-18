package main

import (
    "crypto/sha1"
    "crypto/sha256"
    "crypto/ecdsa"
    "crypto/ed25519"
    "crypto/rsa"
    "crypto/x509"
    "crypto/x509/pkix"
    "encoding/asn1"
    "fmt"
    "io"
    "strings"
    "math/big"

    "fyne.io/fyne/v2"
    "fyne.io/fyne/v2/app"
    "fyne.io/fyne/v2/container"
    "fyne.io/fyne/v2/dialog"
    "fyne.io/fyne/v2/theme"
    "fyne.io/fyne/v2/storage"
    "fyne.io/fyne/v2/widget"

    "cert_viewier/internal/certs"
    "cert_viewier/internal/prefs"
    "cert_viewier/internal/ui"
)

func main() {
    application := app.NewWithID("io.github.crowderb.cert_viewier")
	window := application.NewWindow("Certificate Viewer")
	window.Resize(fyne.NewSize(800, 600))

	// Load preferences
	userPreferences, _ := prefs.Load()

	// UI state
	var currentCert *x509.Certificate

    // Summary tab contents: tight two-column layout (name | value)
    summaryGrid := container.New(ui.NewTightTwoColLayout(),
        boldLabel("Open a certificate to view its summary."),
        copyRow(window, ""),
    )

    // Details view as tight two-column layout inside a scroll container
    detailsContainer := container.New(ui.NewTightTwoColLayout())
    detailsScroll := container.NewVScroll(detailsContainer)

	// Tabs
    tabs := container.NewAppTabs(
        container.NewTabItem("Summary", container.NewVScroll(summaryGrid)),
        container.NewTabItem("Details", detailsScroll),
    )

	// Menu actions
    openCert := func() {
        fd := dialog.NewFileOpen(func(rc fyne.URIReadCloser, err error) {
			if err != nil {
				dialog.ShowError(err, window)
				return
			}
			if rc == nil {
				return
			}
			defer rc.Close()

			data, readErr := io.ReadAll(rc)
			if readErr != nil {
				dialog.ShowError(readErr, window)
				return
			}

            cert, parseErr := certs.ParseCertificate(data)
			if parseErr != nil {
				dialog.ShowError(parseErr, window)
				return
			}
			currentCert = cert
            // Save last directory from the opened file's URI
            if rc.URI() != nil {
                if parent, perr := storage.Parent(rc.URI()); perr == nil && parent != nil {
                    userPreferences.LastDir = parent.String()
                    _ = prefs.Save(userPreferences)
                }
            }
            refreshSummaryAndDetails(window, summaryGrid, detailsContainer, currentCert, userPreferences)
        }, window)
        // Set initial location from preferences if present
        if userPreferences.LastDir != "" {
            if u, err := storage.ParseURI(userPreferences.LastDir); err == nil && u != nil {
                if l, lerr := storage.ListerForURI(u); lerr == nil && l != nil {
                    fd.SetLocation(l)
                }
            }
        }
        fd.SetFilter(storage.NewExtensionFileFilter([]string{".cer", ".crt", ".pem", ".der"}))
        fd.Show()
	}

    preferencesDialog := func() {
        // Name style
        nameOptions := []string{"OpenSSL", "Windows"}
        var nameSelected string
        if userPreferences.NameStyle == prefs.Windows {
            nameSelected = nameOptions[1]
        } else {
            nameSelected = nameOptions[0]
        }
        nameRadio := widget.NewRadioGroup(nameOptions, func(string) {})
        nameRadio.Horizontal = false
        nameRadio.SetSelected(nameSelected)

        // Hex separator style
        hexOptions := []string{"None", ":", "Space"}
        var hexSelected string
        switch userPreferences.HexSep {
        case prefs.HexNone:
            hexSelected = hexOptions[0]
        case prefs.HexSpace:
            hexSelected = hexOptions[2]
        default:
            hexSelected = hexOptions[1]
        }
        hexRadio := widget.NewRadioGroup(hexOptions, func(string) {})
        hexRadio.Horizontal = true
        hexRadio.SetSelected(hexSelected)

        content := container.NewVBox(
            widget.NewLabel("Attribute name style:"),
            nameRadio,
            widget.NewSeparator(),
            widget.NewLabel("Hex value separator:"),
            hexRadio,
        )
        d := dialog.NewCustomConfirm("Preferences", "Save", "Cancel", content, func(ok bool) {
            if !ok {
                return
            }
            // Name style
            switch nameRadio.Selected {
            case "Windows":
                userPreferences.NameStyle = prefs.Windows
            default:
                userPreferences.NameStyle = prefs.OpenSSL
            }
            // Hex sep
            switch hexRadio.Selected {
            case "None":
                userPreferences.HexSep = prefs.HexNone
            case "Space":
                userPreferences.HexSep = prefs.HexSpace
            default:
                userPreferences.HexSep = prefs.HexColon
            }
            _ = prefs.Save(userPreferences)
            if currentCert != nil {
                refreshSummaryAndDetails(window, summaryGrid, detailsContainer, currentCert, userPreferences)
            }
        }, window)
        d.Resize(fyne.NewSize(420, 260))
        d.Show()
    }

	fileMenu := fyne.NewMenu("File",
		fyne.NewMenuItem("Open...", openCert),
		fyne.NewMenuItemSeparator(),
		fyne.NewMenuItem("Quit", func() { application.Quit() }),
	)
	editMenu := fyne.NewMenu("Edit",
		fyne.NewMenuItem("Preferences", preferencesDialog),
	)
	mainMenu := fyne.NewMainMenu(fileMenu, editMenu)
	window.SetMainMenu(mainMenu)

	window.SetContent(tabs)
	window.ShowAndRun()
}

func refreshSummaryAndDetails(win fyne.Window, summaryGrid *fyne.Container, details *fyne.Container, cert *x509.Certificate, p prefs.Preferences) {
    // Summary content: clear and add name/value rows
    summaryGrid.Objects = nil
    cn := cert.Subject.CommonName
    if cn == "" {
        cn = "(none)"
    }
    addSummaryRow := func(name, value string) {
        summaryGrid.Add(boldLabel(name))
        summaryGrid.Add(copyRow(win, value))
    }
    addSummaryRow("Common Name", cn)
    addSummaryRow("Subject", cert.Subject.String())
    addSummaryRow("Issuer", cert.Issuer.String())
    // Serial uses same separator preference as fingerprints
    addSummaryRow("Serial Number", formatSerialWithSep(cert.SerialNumber, p.HexSep))
    // Validity rows labeled based on preference
    if p.NameStyle == prefs.Windows {
        addSummaryRow("Valid From", cert.NotBefore.Format("2006-01-02 15:04:05 MST"))
        addSummaryRow("Valid To", cert.NotAfter.Format("2006-01-02 15:04:05 MST"))
    } else {
        addSummaryRow("Not Before", cert.NotBefore.Format("2006-01-02 15:04:05 MST"))
        addSummaryRow("Not After", cert.NotAfter.Format("2006-01-02 15:04:05 MST"))
    }

    sha256Sum := sha256.Sum256(cert.Raw)
    sha1Sum := sha1.Sum(cert.Raw)
    addSummaryRow("SHA-256 Fingerprint", formatHex(sha256Sum[:], p.HexSep))
    addSummaryRow("SHA-1 Fingerprint", formatHex(sha1Sum[:], p.HexSep))
    summaryGrid.Refresh()

    // Details rows expanded with group headers -> render into container
    details.Objects = nil
    addHeader := func(title string) {
        details.Add(boldLabel(title))
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
    addPair("Serial Number", formatSerialWithSep(cert.SerialNumber, p.HexSep))
    addPair("Signature Algorithm", cert.SignatureAlgorithm.String())
    addPair("Issuer", cert.Issuer.String())
    if p.NameStyle == prefs.Windows {
        addPair("Valid From", cert.NotBefore.Format("2006-01-02 15:04:05 MST"))
        addPair("Valid To", cert.NotAfter.Format("2006-01-02 15:04:05 MST"))
    } else {
        addPair("Not Before", cert.NotBefore.Format("2006-01-02 15:04:05 MST"))
        addPair("Not After", cert.NotAfter.Format("2006-01-02 15:04:05 MST"))
    }
    addPair("Subject", cert.Subject.String())
    // Subject and Issuer attribute breakdown
    addHeader("Subject Attributes")
    for _, pair := range extractNameAttributes(cert.Subject.Names, p.NameStyle, "") {
        addPair(pair[0], pair[1])
    }
    addHeader("Issuer Attributes")
    for _, pair := range extractNameAttributes(cert.Issuer.Names, p.NameStyle, "") {
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
            addPair("NIST CURVE", nistCurveName(pk.Curve.Params().Name))
        }
        // Uncompressed point 0x04 || X || Y
        xBytes := pk.X.Bytes()
        yBytes := pk.Y.Bytes()
        // Pad to curve size
        byteLen := (bits + 7) / 8
        if len(xBytes) < byteLen { xBytes = append(make([]byte, byteLen-len(xBytes)), xBytes...) }
        if len(yBytes) < byteLen { yBytes = append(make([]byte, byteLen-len(yBytes)), yBytes...) }
        pub := make([]byte, 1+len(xBytes)+len(yBytes))
        pub[0] = 0x04
        copy(pub[1:1+len(xBytes)], xBytes)
        copy(pub[1+len(xBytes):], yBytes)
        addPair("pub", formatHex(pub, p.HexSep))
    case ed25519.PublicKey:
        addPair("Public-Key", "(256 bit)")
        addPair("Ed25519", formatHex([]byte(pk), p.HexSep))
    default:
        addPair("Public-Key", "(unknown)")
    }

    // X509v3 extensions
    addHeader("X509v3 extensions")
    if ku := keyUsageNames(cert.KeyUsage); ku != "" { addPair("X509v3 Key Usage", ku) }
    if eku := extKeyUsageNames(cert.ExtKeyUsage); eku != "" { addPair("X509v3 Extended Key Usage", eku) }
    if cert.BasicConstraintsValid {
        bc := "CA:FALSE"
        if cert.IsCA { bc = "CA:TRUE" }
        if cert.MaxPathLen >= 0 { bc = fmt.Sprintf("%s, pathlen:%d", bc, cert.MaxPathLen) }
        addPair("X509v3 Basic Constraints", bc)
    }
    if len(cert.SubjectKeyId) > 0 { addPair("X509v3 Subject Key Identifier", formatHex(cert.SubjectKeyId, p.HexSep)) }
    if len(cert.AuthorityKeyId) > 0 { addPair("X509v3 Authority Key Identifier", formatHex(cert.AuthorityKeyId, p.HexSep)) }
    // AIA
    if len(cert.OCSPServer) > 0 { addPair("OCSP", strings.Join(cert.OCSPServer, ", ")) }
    if len(cert.IssuingCertificateURL) > 0 { addPair("CA Issuers", strings.Join(cert.IssuingCertificateURL, ", ")) }
    // SANs
    if len(cert.DNSNames) > 0 { addPair("DNS", strings.Join(cert.DNSNames, ", ")) }
    if len(cert.EmailAddresses) > 0 { addPair("Email", strings.Join(cert.EmailAddresses, ", ")) }
    if len(cert.IPAddresses) > 0 {
        ips := make([]string, len(cert.IPAddresses))
        for i, ip := range cert.IPAddresses { ips[i] = ip.String() }
        addPair("IP", strings.Join(ips, ", "))
    }
    if len(cert.URIs) > 0 {
        uris := make([]string, len(cert.URIs))
        for i, u := range cert.URIs { uris[i] = u.String() }
        addPair("URI", strings.Join(uris, ", "))
    }
    // Policies
    if len(cert.PolicyIdentifiers) > 0 {
        oids := make([]string, len(cert.PolicyIdentifiers))
        for i, oid := range cert.PolicyIdentifiers { oids[i] = oidToString(oid) }
        addPair("Certificate Policies", strings.Join(oids, ", "))
    }
    // CRL Distribution Points
    if len(cert.CRLDistributionPoints) > 0 { addPair("CRL Distribution Points", strings.Join(cert.CRLDistributionPoints, ", ")) }
    // CT SCTs
    // Note: crypto/x509 does not expose parsed SCTs; skip detailed listing.

    // Signature
    addHeader("Signature")
    addPair("Signature Algorithm", cert.SignatureAlgorithm.String())
    if len(cert.Signature) > 0 { addPair("Signature Value", formatHex(cert.Signature, p.HexSep)) }

    details.Refresh()
}

func extractNameAttributes(attrs []pkix.AttributeTypeAndValue, style prefs.NameStyle, prefix string) [][]string {
	pairs := [][]string{}
	for _, atv := range attrs {
        name := mapOIDToName(atv.Type, style)
		value := fmt.Sprintf("%v", atv.Value)
        label := name
        if prefix != "" {
            label = fmt.Sprintf("%s %s", prefix, name)
        }
        pairs = append(pairs, []string{label, value})
	}
	return pairs
}

func mapOIDToName(oid asn1.ObjectIdentifier, style prefs.NameStyle) string {
	// Common OIDs for Subject/Issuer attributes
    oidStr := oidToString(oid)
	var openssl = map[string]string{
		"2.5.4.3":  "CN",
		"2.5.4.6":  "C",
		"2.5.4.7":  "L",
		"2.5.4.8":  "ST",
		"2.5.4.10": "O",
		"2.5.4.11": "OU",
		"1.2.840.113549.1.9.1": "emailAddress",
		"2.5.4.9":  "street",
		"2.5.4.17": "postalCode",
		"0.9.2342.19200300.100.1.25": "DC",
		"2.5.4.5":  "serialNumber",
	}
	var windows = map[string]string{
		"2.5.4.3":  "Common Name",
		"2.5.4.6":  "Country",
		"2.5.4.7":  "Locality",
		"2.5.4.8":  "State/Province",
		"2.5.4.10": "Organization",
		"2.5.4.11": "Organizational Unit",
		"1.2.840.113549.1.9.1": "E-Mail",
		"2.5.4.9":  "Street",
		"2.5.4.17": "Postal Code",
		"0.9.2342.19200300.100.1.25": "Domain Component",
		"2.5.4.5":  "Serial Number",
	}
	if style == prefs.Windows {
        if v, ok := windows[oidStr]; ok {
			return v
		}
        return oidStr
	}
    if v, ok := openssl[oidStr]; ok {
		return v
	}
    return oidStr
}

func oidToString(oid asn1.ObjectIdentifier) string {
    parts := make([]string, len(oid))
    for i, n := range oid {
		parts[i] = fmt.Sprintf("%d", n)
	}
	return strings.Join(parts, ".")
}

func keyUsageNames(ku x509.KeyUsage) string {
    names := []string{}
    if ku&x509.KeyUsageDigitalSignature != 0 { names = append(names, "Digital Signature") }
    if ku&x509.KeyUsageContentCommitment != 0 { names = append(names, "Non Repudiation") }
    if ku&x509.KeyUsageKeyEncipherment != 0 { names = append(names, "Key Encipherment") }
    if ku&x509.KeyUsageDataEncipherment != 0 { names = append(names, "Data Encipherment") }
    if ku&x509.KeyUsageKeyAgreement != 0 { names = append(names, "Key Agreement") }
    if ku&x509.KeyUsageCertSign != 0 { names = append(names, "Certificate Sign") }
    if ku&x509.KeyUsageCRLSign != 0 { names = append(names, "CRL Sign") }
    if ku&x509.KeyUsageEncipherOnly != 0 { names = append(names, "Encipher Only") }
    if ku&x509.KeyUsageDecipherOnly != 0 { names = append(names, "Decipher Only") }
    return strings.Join(names, ", ")
}

func extKeyUsageNames(usages []x509.ExtKeyUsage) string {
    if len(usages) == 0 { return "" }
    names := make([]string, 0, len(usages))
    for _, u := range usages {
        switch u {
        case x509.ExtKeyUsageAny: names = append(names, "Any")
        case x509.ExtKeyUsageServerAuth: names = append(names, "TLS Web Server Authentication")
        case x509.ExtKeyUsageClientAuth: names = append(names, "TLS Web Client Authentication")
        case x509.ExtKeyUsageCodeSigning: names = append(names, "Code Signing")
        case x509.ExtKeyUsageEmailProtection: names = append(names, "E-mail Protection")
        case x509.ExtKeyUsageIPSECEndSystem: names = append(names, "IPSec End System")
        case x509.ExtKeyUsageIPSECTunnel: names = append(names, "IPSec Tunnel")
        case x509.ExtKeyUsageIPSECUser: names = append(names, "IPSec User")
        case x509.ExtKeyUsageTimeStamping: names = append(names, "Time Stamping")
        case x509.ExtKeyUsageOCSPSigning: names = append(names, "OCSP Signing")
        case x509.ExtKeyUsageMicrosoftServerGatedCrypto: names = append(names, "Microsoft Server Gated Crypto")
        case x509.ExtKeyUsageNetscapeServerGatedCrypto: names = append(names, "Netscape Server Gated Crypto")
        case x509.ExtKeyUsageMicrosoftCommercialCodeSigning: names = append(names, "Microsoft Commercial Code Signing")
        case x509.ExtKeyUsageMicrosoftKernelCodeSigning: names = append(names, "Microsoft Kernel Code Signing")
        default:
            names = append(names, fmt.Sprintf("Unknown (%d)", u))
        }
    }
    return strings.Join(names, ", ")
}

func nistCurveName(oidOrName string) string {
    // The Go stdlib exposes curve param Name already as a friendly string (e.g., P-256)
    // For completeness we pass-through here.
    switch oidOrName {
    case "P-256", "prime256v1":
        return "P-256"
    case "P-384", "secp384r1":
        return "P-384"
    case "P-521", "secp521r1":
        return "P-521"
    default:
        return oidOrName
    }
}

// boldLabel returns a name label with bold style.
func boldLabel(text string) *widget.Label {
    lbl := widget.NewLabel(text)
    lbl.TextStyle = fyne.TextStyle{Bold: true}
    return lbl
}

// copyRow builds a value widget with monospace text and a copy button.
func copyRow(win fyne.Window, text string) fyne.CanvasObject {
    value := widget.NewRichTextWithText(text)
    value.Wrapping = fyne.TextWrapWord
    // Apply monospace style
    value.Segments = []widget.RichTextSegment{
        &widget.TextSegment{Text: text, Style: widget.RichTextStyle{TextStyle: fyne.TextStyle{Monospace: true}}},
    }
    copyBtn := widget.NewButtonWithIcon("", theme.ContentCopyIcon(), func() {
        win.Clipboard().SetContent(text)
    })
    copyBtn.Importance = widget.LowImportance
    // Keep button narrow; arrange inline with value using a grid of 2 columns
    row := container.NewBorder(nil, nil, nil, copyBtn, value)
    return row
}

func formatHex(sum []byte, sep prefs.HexSeparator) string {
    if len(sum) == 0 {
        return ""
    }
    if sep == prefs.HexNone {
        // Compact upper hex, 2 chars per byte
        var b strings.Builder
        b.Grow(len(sum) * 2)
        for _, by := range sum {
            fmt.Fprintf(&b, "%02X", by)
        }
        return b.String()
    }
    // Separated format
    parts := make([]string, len(sum))
    for i, by := range sum {
        parts[i] = fmt.Sprintf("%02X", by)
    }
    return strings.Join(parts, string(sep))
}

// formatSerialNumberHex prints the big.Int serial as 2-digit uppercase hex bytes preserving leading zeros.
func formatSerialWithSep(n *big.Int, sep prefs.HexSeparator) string {
    if n == nil {
        return ""
    }
    // big.Int.Bytes() returns the absolute value as big-endian bytes, no sign, no leading zeros.
    // However, RFC recommends serials up to 20 bytes; if leading zeros are significant for display,
    // we can detect by using Text(16) and padding to even length, then group in byte pairs.
    hexStr := strings.ToUpper(n.Text(16))
    if len(hexStr)%2 == 1 {
        hexStr = "0" + hexStr
    }
    // Group every 2 chars using the chosen separator
    var b strings.Builder
    for i := 0; i < len(hexStr); i += 2 {
        if i > 0 {
            if sep == prefs.HexNone {
                // no separator, just append
            } else {
                b.WriteString(string(sep))
            }
        }
        b.WriteString(hexStr[i : i+2])
    }
    return b.String()
}

func escapeMarkdown(s string) string {
	s = strings.ReplaceAll(s, "*", "\\*")
	s = strings.ReplaceAll(s, "_", "\\_")
	s = strings.ReplaceAll(s, "`", "\\`")
	return s
}
