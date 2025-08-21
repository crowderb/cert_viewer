package main

import (
    "crypto/sha1"
    "crypto/sha256"
    "crypto/ecdsa"
    "crypto/ed25519"
    "crypto/rsa"
    "crypto/x509"
    "fmt"
    "io"
    "strings"
    "math/big"
    "context"
    "net/http"
    "os"
    "image/color"
    "time"

    "fyne.io/fyne/v2"
    "fyne.io/fyne/v2/app"
    "fyne.io/fyne/v2/container"
    "fyne.io/fyne/v2/dialog"
    "fyne.io/fyne/v2/theme"
    "fyne.io/fyne/v2/storage"
    "fyne.io/fyne/v2/widget"
    "fyne.io/fyne/v2/canvas"

    "cert_viewer/internal/certs"
    "cert_viewer/internal/prefs"
    "cert_viewer/internal/ui"
    "cert_viewer/internal/resources"
)

func main() {
    application := app.NewWithID("io.github.crowderb.cert_viewer")
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
    chainTabs := container.NewAppTabs()
    // Advanced tab content placeholder
    advancedContent := container.NewVBox()

	// Tabs
    tabs := container.NewAppTabs(
        container.NewTabItem("Summary", container.NewVScroll(summaryGrid)),
        container.NewTabItem("Details", detailsScroll),
        container.NewTabItem("Chain", chainTabs),
        container.NewTabItem("Advanced", container.NewVScroll(advancedContent)),
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
                    userPreferences.UI.LastDir = parent.String()
                    _ = prefs.Save(userPreferences)
                }
            }
            refreshSummaryAndDetails(window, summaryGrid, detailsContainer, currentCert, userPreferences)
            // Build chain asynchronously and render
            buildAndRenderChain(window, chainTabs, currentCert, userPreferences)
        }, window)
        // Set initial location from preferences if present
        if userPreferences.UI.LastDir != "" {
            if u, err := storage.ParseURI(userPreferences.UI.LastDir); err == nil && u != nil {
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
        if userPreferences.UI.NameStyle == prefs.Windows {
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
        switch userPreferences.UI.HexSep {
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
                userPreferences.UI.NameStyle = prefs.Windows
            default:
                userPreferences.UI.NameStyle = prefs.OpenSSL
            }
            // Hex sep
            switch hexRadio.Selected {
            case "None":
                userPreferences.UI.HexSep = prefs.HexNone
            case "Space":
                userPreferences.UI.HexSep = prefs.HexSpace
            default:
                userPreferences.UI.HexSep = prefs.HexColon
            }
            _ = prefs.Save(userPreferences)
            if currentCert != nil {
                refreshSummaryAndDetails(window, summaryGrid, detailsContainer, currentCert, userPreferences)
                buildAndRenderChain(window, chainTabs, currentCert, userPreferences)
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
    resourcesMenu := fyne.NewMenu("Resources",
        fyne.NewMenuItem("CCADB CSV", func() { showCCADBDialog(window, userPreferences) }),
        fyne.NewMenuItemSeparator(),
        fyne.NewMenuItem("Compare Local vs CCADB", func() {
            // Show placeholder and build in background to keep UI responsive
            advancedContent.Objects = []fyne.CanvasObject{widget.NewLabel("Building comparison...")}
            advancedContent.Refresh()
            go func() {
                _ = resources.EnsureLocalRootsJSON(context.Background())
                buildAdvancedComparison(advancedContent, userPreferences)
            }()
            tabs.SelectIndex(3) // Advanced tab
        }),
    )
    mainMenu := fyne.NewMainMenu(fileMenu, editMenu, resourcesMenu)
	window.SetMainMenu(mainMenu)

    // Prepare background context
    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()
    // Defer local roots generation until requested to avoid blocking startup

    // Enable drag-and-drop to open certificate files
    window.SetOnDropped(func(pos fyne.Position, uris []fyne.URI) {
            for _, u := range uris {
                if u == nil || u.Scheme() != "file" {
                    continue
                }
                path := u.Path()
                // Filter by extension
                lower := strings.ToLower(path)
                if !(strings.HasSuffix(lower, ".cer") || strings.HasSuffix(lower, ".crt") || strings.HasSuffix(lower, ".pem") || strings.HasSuffix(lower, ".der")) {
                    continue
                }
                // Read and open first matching file
                data, err := os.ReadFile(path)
                if err != nil {
                    dialog.ShowError(err, window)
                    return
                }
                cert, err := certs.ParseCertificate(data)
                if err != nil {
                    dialog.ShowError(err, window)
                    return
                }
                currentCert = cert
                if parent, perr := storage.Parent(storage.NewFileURI(path)); perr == nil && parent != nil {
                    userPreferences.UI.LastDir = parent.String()
                }
                _ = prefs.Save(userPreferences)
                refreshSummaryAndDetails(window, summaryGrid, detailsContainer, currentCert, userPreferences)
                buildAndRenderChain(window, chainTabs, currentCert, userPreferences)
                return
            }
        })

    window.SetContent(tabs)

    // Start CCADB refresh in background (no auto-rebuild)
    go func() { <-resources.EnsureCCADBCSV(ctx, userPreferences) }()

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
    addSummaryRow("Serial Number", formatSerialWithSep(cert.SerialNumber, p.UI.HexSep))
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
        if len(xBytes) < byteLen { xBytes = append(make([]byte, byteLen-len(xBytes)), xBytes...) }
        if len(yBytes) < byteLen { yBytes = append(make([]byte, byteLen-len(yBytes)), yBytes...) }
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
    if ku := certs.KeyUsageNames(cert.KeyUsage); ku != "" { addPair("X509v3 Key Usage", ku) }
    if eku := certs.ExtKeyUsageNames(cert.ExtKeyUsage); eku != "" { addPair("X509v3 Extended Key Usage", eku) }
    if cert.BasicConstraintsValid {
        bc := "CA:FALSE"
        if cert.IsCA { bc = "CA:TRUE" }
        if cert.MaxPathLen >= 0 { bc = fmt.Sprintf("%s, pathlen:%d", bc, cert.MaxPathLen) }
        addPair("X509v3 Basic Constraints", bc)
    }
    if len(cert.SubjectKeyId) > 0 { addPair("X509v3 Subject Key Identifier", certs.FormatHex(cert.SubjectKeyId, string(p.UI.HexSep))) }
    if len(cert.AuthorityKeyId) > 0 { addPair("X509v3 Authority Key Identifier", certs.FormatHex(cert.AuthorityKeyId, string(p.UI.HexSep))) }
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
        for i, oid := range cert.PolicyIdentifiers { oids[i] = certs.OIDToString(oid) }
        addPair("Certificate Policies", strings.Join(oids, ", "))
    }
    // CRL Distribution Points
    if len(cert.CRLDistributionPoints) > 0 { addPair("CRL Distribution Points", strings.Join(cert.CRLDistributionPoints, ", ")) }
    // CT SCTs
    // Note: crypto/x509 does not expose parsed SCTs; skip detailed listing.

    // Signature
    addHeader("Signature")
    addPair("Signature Algorithm", cert.SignatureAlgorithm.String())
    if len(cert.Signature) > 0 { addPair("Signature Value", certs.FormatHex(cert.Signature, string(p.UI.HexSep))) }

    details.Refresh()
}

// buildAndRenderChain constructs a chain up to 5 levels using AIA and CCADB CSV, then renders tabs.
func buildAndRenderChain(win fyne.Window, chainTabs *container.AppTabs, leaf *x509.Certificate, p prefs.Preferences) {
    // Reset tabs
    chainTabs.Items = nil
    addCertTab := func(title string, cert *x509.Certificate) {
        // Reuse summary renderer into a compact container
        grid := container.New(ui.NewTightTwoColLayout())
        // Use a throwaway details container to satisfy function signature
        tmp := container.New(ui.NewTightTwoColLayout())
        refreshSummaryAndDetails(win, grid, tmp, cert, p)
        // Add SKI / AKI rows for chain visibility
        if len(cert.SubjectKeyId) > 0 {
            grid.Add(boldLabel("Subject Key Identifier"))
            grid.Add(copyRow(win, certs.FormatHex(cert.SubjectKeyId, string(p.UI.HexSep))))
        }
        if len(cert.AuthorityKeyId) > 0 {
            grid.Add(boldLabel("Authority Key Identifier"))
            grid.Add(copyRow(win, certs.FormatHex(cert.AuthorityKeyId, string(p.UI.HexSep))))
        }
        chainTabs.Append(container.NewTabItem(title, container.NewVScroll(grid)))
    }
    addCertTab("Leaf", leaf)

    // Load local roots and CCADB SKI sets if available
    localSet, _ := resources.LoadLocalRootsSKISet()
    ccadbSet, _ := resources.LoadCCADBSKISet()
    current := leaf
    for depth := 1; depth <= 5; depth++ {
        // Self-signed if AKI equals SKI
        if len(current.AuthorityKeyId) > 0 && len(current.SubjectKeyId) > 0 {
            if normalizeHex(current.AuthorityKeyId) == normalizeHex(current.SubjectKeyId) {
                chainTabs.Append(container.NewTabItem("Self-signed", widget.NewLabel("Authority Key Identifier equals Subject Key Identifier")))
                chainTabs.Refresh()
                return
            }
        }
        // AIA: CA Issuers URL
        var aiaURL string
        if len(current.IssuingCertificateURL) > 0 {
            aiaURL = current.IssuingCertificateURL[0]
        } else {
            break
        }
        // Fetch issuer cert
        issuerCert, err := fetchRemoteCert(aiaURL)
        if err != nil {
            dialog.ShowError(fmt.Errorf("chain fetch failed at depth %d: %w", depth, err), win)
            return
        }
        // Render tab
        title := fmt.Sprintf("Issuer %d", depth)
        c := issuerCert
        addCertTab(title, c)
        chainTabs.Refresh()
        // Check local roots first, then CCADB
        if len(c.SubjectKeyId) > 0 {
            key := certs.NormalizeHexBytesNoSepUpper(c.SubjectKeyId)
            if _, ok := localSet[key]; ok {
                chainTabs.Append(container.NewTabItem("Root (from Local Store)", widget.NewLabel("Found Subject Key Identifier in local system trust bundle")))
                chainTabs.Refresh()
                return
            }
            if _, ok := ccadbSet[key]; ok {
                chainTabs.Append(container.NewTabItem("Root (from CCADB)", widget.NewLabel("Found Subject Key Identifier in CCADB CSV")))
                chainTabs.Refresh()
                return
            }
        }
        // Continue
        current = issuerCert
    }
}

func fetchRemoteCert(url string) (*x509.Certificate, error) {
    // Fetch bytes
    resp, err := http.Get(url)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()
    if resp.StatusCode < 200 || resp.StatusCode >= 300 {
        return nil, fmt.Errorf("http error: %s", resp.Status)
    }
    data, err := io.ReadAll(resp.Body)
    if err != nil {
        return nil, err
    }
    // AIA CA Issuers often returns DER or PKCS7; try to extract first cert
    if cert, err := tryParseSingleCert(data); err == nil && cert != nil {
        return cert, nil
    }
    return nil, fmt.Errorf("no certificate found at URL")
}

func tryParseSingleCert(data []byte) (*x509.Certificate, error) {
    // Try PEM or DER
    if cert, err := certs.ParseCertificate(data); err == nil {
        return cert, nil
    }
    // Try simplistic PKCS7 DER decode using x509 to parse any embedded certs is not in stdlib.
    // As a fallback, attempt to locate BEGIN CERTIFICATE blocks if text.
    return nil, fmt.Errorf("unsupported format")
}

func normalizeHex(b []byte) string {
    // Convert to uppercase hex without separators
    if len(b) == 0 { return "" }
    var sb strings.Builder
    sb.Grow(len(b) * 2)
    for _, by := range b { fmt.Fprintf(&sb, "%02X", by) }
    return sb.String()
}

func showCCADBDialog(win fyne.Window, p prefs.Preferences) {
    path, err := resources.CachePath()
    var infoText string
    if err != nil {
        infoText = fmt.Sprintf("Error determining cache path: %v", err)
    } else {
        st, statErr := os.Stat(path)
        if statErr != nil {
            infoText = fmt.Sprintf("File: %s\nStatus: not downloaded", path)
        } else {
            infoText = fmt.Sprintf("File: %s\nModified: %s", path, st.ModTime().Format("2006-01-02 15:04:05 MST"))
        }
    }
    content := container.NewVBox(
        widget.NewLabel("CCADB All Certificate Records CSV"),
        widget.NewRichTextWithText(infoText),
    )
    d := dialog.NewCustomConfirm("CCADB CSV", "Fetch Now", "OK", content, func(fetch bool) {
        if !fetch {
            return
        }
        ctx := context.Background()
        errCh := resources.EnsureCCADBCSV(ctx, p)
        go func() {
            if err := <-errCh; err != nil {
                dialog.ShowError(err, win)
            } else {
                // Refresh dialog to show new timestamp
                showCCADBDialog(win, p)
            }
        }()
    }, win)
    d.Resize(fyne.NewSize(520, 220))
    d.Show()
}

// buildAdvancedComparison populates the Advanced tab with three sections:
// Local only, CCADB only, and Both (by SKI), listing Subject (bold), SKI, Serial.
func buildAdvancedComparison(containerRoot *fyne.Container, p prefs.Preferences) {
    containerRoot.Objects = nil
    // Headers
    addHeader := func(title string) {
        lbl := widget.NewLabel(title)
        lbl.TextStyle = fyne.TextStyle{Bold: true}
        // Light gray background row
        bg := canvas.NewRectangle(color.NRGBA{R: 240, G: 240, B: 240, A: 255})
        // Ensure background stretches
        row := container.NewMax(bg, container.NewPadded(lbl))
        containerRoot.Add(row)
    }
    addEntry := func(subject, ski, serial string) {
        // Subject bold
        subj := widget.NewLabel(subject)
        subj.TextStyle = fyne.TextStyle{Bold: true}
        containerRoot.Add(subj)
        // Minimal vertical spacing rows
        containerRoot.Add(widget.NewLabel("SKI: " + ski))
        if serial != "" {
            containerRoot.Add(widget.NewLabel("Serial: " + serial))
        }
        // Single blank line between certificates
        containerRoot.Add(widget.NewLabel(""))
    }
    // Load data
    localMap, lerr := resources.LoadLocalRootsSKISet()
    ccadbSummary, cerr := resources.LoadCCADBSummary()
    if lerr != nil {
        containerRoot.Add(widget.NewLabel("Error loading local roots: "+lerr.Error()))
    }
    if cerr != nil {
        containerRoot.Add(widget.NewLabel("Error loading CCADB set: "+cerr.Error()))
    }

    // Compute sets
    localOnly := []resources.LocalRootSummary{}
    both := []resources.LocalRootSummary{}
    ccadbOnly := []struct{ Subject string; SKI string }{}

    for ski, sum := range localMap {
        if _, ok := ccadbSummary[ski]; ok {
            both = append(both, sum)
        } else {
            localOnly = append(localOnly, sum)
        }
    }
    now := time.Now().UTC()
    for ski, summary := range ccadbSummary {
        if _, ok := localMap[ski]; ok {
            continue
        }
        // Skip expired
        if !summary.NotAfter.IsZero() && summary.NotAfter.Before(now) {
            continue
        }
        ccadbOnly = append(ccadbOnly, struct{ Subject string; SKI string }{Subject: summary.Subject, SKI: ski})
    }

    // Render sections
    addHeader("Certificates in Local Store Only")
    for _, s := range localOnly {
        addEntry(s.Subject, s.SubjectKeyIdentifier, s.SerialHex)
    }
    if len(localOnly) == 0 {
        containerRoot.Add(widget.NewLabel("(none)"))
    } else {
        containerRoot.Add(widget.NewLabel(fmt.Sprintf("(%d)", len(localOnly))))
    }
    if p.UI.ShowCCADBOnlyCerts {
        addHeader("Certificates in CCADB Only")
        for _, row := range ccadbOnly {
            subj := row.Subject
            if subj == "" { subj = "(unknown subject)" }
            addEntry(subj, row.SKI, "")
        }
        if len(ccadbOnly) == 0 {
            containerRoot.Add(widget.NewLabel("(none)"))
        } else {
            containerRoot.Add(widget.NewLabel(fmt.Sprintf("(%d)", len(ccadbOnly))))
        }
    }
    addHeader("Certificates in Both")
    for _, s := range both {
        addEntry(s.Subject, s.SubjectKeyIdentifier, s.SerialHex)
    }
    if len(both) == 0 {
        containerRoot.Add(widget.NewLabel("(none)"))
    } else {
        containerRoot.Add(widget.NewLabel(fmt.Sprintf("(%d)", len(both))))
    }
    containerRoot.Refresh()
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
