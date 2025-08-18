package main

import (
    "crypto/sha1"
    "crypto/sha256"
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
        monoLabel(""),
    )

	// Details table model
	detailRows := [][]string{}
	detailsTable := widget.NewTable(
		func() (int, int) { // rows, cols
			return len(detailRows), 2
		},
		func() fyne.CanvasObject { // create
			return widget.NewLabel("")
		},
		func(i widget.TableCellID, o fyne.CanvasObject) { // update
			if i.Row < len(detailRows) && i.Col < 2 {
				label := o.(*widget.Label)
				label.SetText(detailRows[i.Row][i.Col])
			}
		},
	)
	detailsTable.SetColumnWidth(0, 240)

	// Tabs
    tabs := container.NewAppTabs(
        container.NewTabItem("Summary", container.NewVScroll(summaryGrid)),
		container.NewTabItem("Details", container.NewMax(detailsTable)),
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
            refreshSummaryAndDetails(summaryGrid, detailsTable, &detailRows, currentCert, userPreferences)
		}, window)
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
                refreshSummaryAndDetails(summaryGrid, detailsTable, &detailRows, currentCert, userPreferences)
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

func refreshSummaryAndDetails(summaryGrid *fyne.Container, details *widget.Table, rows *[][]string, cert *x509.Certificate, p prefs.Preferences) {
    // Summary content: clear and add name/value rows
    summaryGrid.Objects = nil
    cn := cert.Subject.CommonName
    if cn == "" {
        cn = "(none)"
    }
    addSummaryRow := func(name, value string) {
        summaryGrid.Add(boldLabel(name))
        summaryGrid.Add(monoLabel(value))
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

	// Details rows (Subject and Issuer attributes based on preference)
	var newRows [][]string
	newRows = append(newRows, []string{"Section", "Value"})
    for _, pair := range extractNameAttributes(cert.Subject.Names, p.NameStyle, "Subject") {
		newRows = append(newRows, pair)
	}
    for _, pair := range extractNameAttributes(cert.Issuer.Names, p.NameStyle, "Issuer") {
		newRows = append(newRows, pair)
	}
	*rows = newRows
	details.Refresh()
}

func extractNameAttributes(attrs []pkix.AttributeTypeAndValue, style prefs.NameStyle, prefix string) [][]string {
	pairs := [][]string{}
	for _, atv := range attrs {
        name := mapOIDToName(atv.Type, style)
		value := fmt.Sprintf("%v", atv.Value)
		pairs = append(pairs, []string{fmt.Sprintf("%s %s", prefix, name), value})
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

// boldLabel returns a name label with bold style.
func boldLabel(text string) *widget.Label {
    lbl := widget.NewLabel(text)
    lbl.TextStyle = fyne.TextStyle{Bold: true}
    return lbl
}

// monoLabel returns a value text with monospace font. RichText supports selection/copy.
func monoLabel(text string) *widget.RichText {
    rt := widget.NewRichText()
    rt.Wrapping = fyne.TextWrapWord
    rt.Segments = []widget.RichTextSegment{
        &widget.TextSegment{Text: text, Style: widget.RichTextStyle{TextStyle: fyne.TextStyle{Monospace: true}}},
    }
    rt.Refresh()
    return rt
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
