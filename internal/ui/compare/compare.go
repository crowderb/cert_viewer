package compare

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
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"cert_viewer/internal/certs"
	"cert_viewer/internal/prefs"
	"cert_viewer/internal/ui"
)

// CompareLayout is a 3-column layout where:
//   - column 1 is sized to the max min-width of all column-1 widgets (field names)
//   - columns 2 and 3 share the remaining width equally
//
// Objects must be provided in triples: [label, valueA, valueB, label, valueA, valueB, …]
type CompareLayout struct{}

// NewCompareLayout returns a new CompareLayout.
func NewCompareLayout() *CompareLayout { return &CompareLayout{} }

func (c *CompareLayout) col1Width(objects []fyne.CanvasObject) float32 {
	w := float32(0)
	for i := 0; i < len(objects); i += 3 {
		if objects[i].MinSize().Width > w {
			w = objects[i].MinSize().Width
		}
	}
	return w
}

// Layout positions all objects in the 3-column grid.
func (c *CompareLayout) Layout(objects []fyne.CanvasObject, containerSize fyne.Size) {
	col1W := c.col1Width(objects)
	remaining := containerSize.Width - col1W
	col2W := float32(int(remaining / 2))
	col3W := remaining - col2W

	y := float32(0)
	for i := 0; i+2 < len(objects); i += 3 {
		h0 := objects[i].MinSize().Height
		h1 := objects[i+1].MinSize().Height
		h2 := objects[i+2].MinSize().Height
		rowH := h0
		if h1 > rowH {
			rowH = h1
		}
		if h2 > rowH {
			rowH = h2
		}

		objects[i].Move(fyne.NewPos(0, y))
		objects[i].Resize(fyne.NewSize(col1W, rowH))

		objects[i+1].Move(fyne.NewPos(col1W, y))
		objects[i+1].Resize(fyne.NewSize(col2W, rowH))

		objects[i+2].Move(fyne.NewPos(col1W+col2W, y))
		objects[i+2].Resize(fyne.NewSize(col3W, rowH))

		y += rowH
	}
}

// MinSize returns the minimum size needed to display all rows.
func (c *CompareLayout) MinSize(objects []fyne.CanvasObject) fyne.Size {
	col1W := c.col1Width(objects)
	maxValW := float32(0)
	totalH := float32(0)
	for i := 0; i+2 < len(objects); i += 3 {
		for _, idx := range []int{i + 1, i + 2} {
			if objects[idx].MinSize().Width > maxValW {
				maxValW = objects[idx].MinSize().Width
			}
		}
		h0 := objects[i].MinSize().Height
		h1 := objects[i+1].MinSize().Height
		h2 := objects[i+2].MinSize().Height
		rowH := h0
		if h1 > rowH {
			rowH = h1
		}
		if h2 > rowH {
			rowH = h2
		}
		totalH += rowH
	}
	return fyne.NewSize(col1W+maxValW*2, totalH)
}

// Field is a displayable name/value pair extracted from a certificate.
type Field struct {
	Name  string
	Value string
}

// Row is one comparison row with the field name and both certificate values.
type Row struct {
	Name    string
	ValueA  string
	ValueB  string
	Differs bool
}

// ExtractFields returns an ordered list of displayable fields from cert as plain strings.
// Absent or empty fields produce an empty string value. The ordering is stable across
// calls so that BuildRows can zip two calls by index.
func ExtractFields(cert *x509.Certificate, p prefs.Preferences) []Field {
	sep := string(p.UI.HexSep)

	cn := cert.Subject.CommonName
	if cn == "" {
		cn = "(none)"
	}

	// Public key size string
	var keySize string
	switch pk := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		keySize = fmt.Sprintf("(%d bit)", pk.N.BitLen())
	case *ecdsa.PublicKey:
		keySize = fmt.Sprintf("(%d bit)", pk.Params().BitSize)
	case ed25519.PublicKey:
		keySize = "(256 bit)"
	default:
		keySize = "(unknown)"
	}

	// Basic constraints
	var bc string
	if cert.BasicConstraintsValid {
		if cert.IsCA {
			bc = "CA:TRUE"
		} else {
			bc = "CA:FALSE"
		}
		if cert.MaxPathLen >= 0 && cert.IsCA {
			bc = fmt.Sprintf("%s, pathlen:%d", bc, cert.MaxPathLen)
		}
	}

	// IP addresses
	var ips []string
	for _, ip := range cert.IPAddresses {
		ips = append(ips, ip.String())
	}

	// URIs
	var uris []string
	for _, u := range cert.URIs {
		uris = append(uris, u.String())
	}

	sha256Sum := sha256.Sum256(cert.Raw)
	sha1Sum := sha1.Sum(cert.Raw)

	const timeFmt = "2006-01-02 15:04:05 MST"

	return []Field{
		{Name: "Common Name", Value: cn},
		{Name: "Subject", Value: cert.Subject.String()},
		{Name: "Issuer", Value: cert.Issuer.String()},
		{Name: "Serial Number", Value: certs.FormatSerialWithSep(cert.SerialNumber, sep)},
		{Name: "Not Before", Value: cert.NotBefore.Format(timeFmt)},
		{Name: "Not After", Value: cert.NotAfter.Format(timeFmt)},
		{Name: "Signature Algorithm", Value: cert.SignatureAlgorithm.String()},
		{Name: "Public Key Algorithm", Value: cert.PublicKeyAlgorithm.String()},
		{Name: "Public Key Size", Value: keySize},
		{Name: "Key Usage", Value: certs.KeyUsageNames(cert.KeyUsage)},
		{Name: "Extended Key Usage", Value: certs.ExtKeyUsageNames(cert.ExtKeyUsage)},
		{Name: "Basic Constraints", Value: bc},
		{Name: "Subject Key Identifier", Value: certs.FormatHex(cert.SubjectKeyId, sep)},
		{Name: "Authority Key Identifier", Value: certs.FormatHex(cert.AuthorityKeyId, sep)},
		{Name: "DNS Names", Value: strings.Join(cert.DNSNames, ", ")},
		{Name: "Email Addresses", Value: strings.Join(cert.EmailAddresses, ", ")},
		{Name: "IP Addresses", Value: strings.Join(ips, ", ")},
		{Name: "URIs", Value: strings.Join(uris, ", ")},
		{Name: "OCSP Servers", Value: strings.Join(cert.OCSPServer, ", ")},
		{Name: "CA Issuers", Value: strings.Join(cert.IssuingCertificateURL, ", ")},
		{Name: "CRL Distribution Points", Value: strings.Join(cert.CRLDistributionPoints, ", ")},
		{Name: "SHA-256 Fingerprint", Value: certs.FormatHex(sha256Sum[:], sep)},
		{Name: "SHA-1 Fingerprint", Value: certs.FormatHex(sha1Sum[:], sep)},
	}
}

// BuildRows combines fields from two certificates into comparison rows, setting
// Differs=true for any row where the two values are not identical.
func BuildRows(certA, certB *x509.Certificate, p prefs.Preferences) []Row {
	fieldsA := ExtractFields(certA, p)
	fieldsB := ExtractFields(certB, p)
	rows := make([]Row, len(fieldsA))
	for i, fa := range fieldsA {
		fb := fieldsB[i]
		rows[i] = Row{
			Name:    fa.Name,
			ValueA:  fa.Value,
			ValueB:  fb.Value,
			Differs: fa.Value != fb.Value,
		}
	}
	return rows
}

// diffValueWidget returns a copyable RichText widget rendered in the warning color,
// used to highlight values that differ between the two certificates.
func diffValueWidget(win fyne.Window, value string) fyne.CanvasObject {
	rt := widget.NewRichText(&widget.TextSegment{
		Text: value,
		Style: widget.RichTextStyle{
			ColorName: theme.ColorNameWarning,
		},
	})
	rt.Wrapping = fyne.TextWrapWord
	copyBtn := widget.NewButtonWithIcon("", theme.ContentCopyIcon(), func() {
		win.Clipboard().SetContent(value)
	})
	return container.NewBorder(nil, nil, nil, copyBtn, rt)
}

// Render clears grid and populates it with a 3-column comparison of certA vs certB.
// Rows where values differ are rendered in the warning theme color on both sides.
// The grid must use NewCompareLayout().
func Render(win fyne.Window, grid *fyne.Container, certA, certB *x509.Certificate, p prefs.Preferences) {
	rows := BuildRows(certA, certB, p)

	grid.Objects = nil

	// Header row
	grid.Objects = append(grid.Objects,
		ui.BoldLabel("Field"),
		ui.BoldLabel("Certificate A"),
		ui.BoldLabel("Certificate B"),
	)

	for _, row := range rows {
		nameWidget := ui.BoldLabel(row.Name)
		var valAWidget, valBWidget fyne.CanvasObject
		if row.Differs {
			valAWidget = diffValueWidget(win, row.ValueA)
			valBWidget = diffValueWidget(win, row.ValueB)
		} else {
			valAWidget = ui.CopyRow(win, row.ValueA)
			valBWidget = ui.CopyRow(win, row.ValueB)
		}
		grid.Objects = append(grid.Objects, nameWidget, valAWidget, valBWidget)
	}

	grid.Refresh()
}
