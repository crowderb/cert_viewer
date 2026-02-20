package dialogs

import (
	"crypto/x509"
	"fmt"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"

	"cert_viewer/internal/certs"
)

// ShowCRL displays a CRL viewer dialog with header info and a searchable list
// of revoked certificate entries.
func ShowCRL(win fyne.Window, rl *x509.RevocationList, url string) {
	header := fmt.Sprintf(
		"URL: %s\nIssuer: %s\nThis Update: %s\nNext Update: %s\nEntries: %d",
		url,
		rl.Issuer.String(),
		rl.ThisUpdate.UTC().Format("2006-01-02 15:04:05 UTC"),
		rl.NextUpdate.UTC().Format("2006-01-02 15:04:05 UTC"),
		len(rl.RevokedCertificateEntries),
	)
	headerLabel := widget.NewRichTextWithText(header)
	headerLabel.Wrapping = fyne.TextWrapWord

	// Pre-format all entries for filtering.
	type row struct{ display, lower string }
	rows := make([]row, len(rl.RevokedCertificateEntries))
	for i, e := range rl.RevokedCertificateEntries {
		s := fmt.Sprintf("Serial: %s  Revoked: %s  Reason: %s",
			e.SerialNumber.Text(16),
			e.RevocationTime.UTC().Format("2006-01-02"),
			certs.FormatRevocationReason(e.ReasonCode),
		)
		rows[i] = row{s, strings.ToLower(s)}
	}

	// filtered holds indices into rows matching the current search query.
	filtered := make([]int, len(rows))
	for i := range rows {
		filtered[i] = i
	}

	lst := widget.NewList(
		func() int { return len(filtered) },
		func() fyne.CanvasObject { return widget.NewLabel("") },
		func(id widget.ListItemID, obj fyne.CanvasObject) {
			obj.(*widget.Label).SetText(rows[filtered[id]].display)
		},
	)

	searchEntry := widget.NewEntry()
	searchEntry.SetPlaceHolder("Filter by serial, date, or reason...")
	searchEntry.OnChanged = func(q string) {
		q = strings.ToLower(q)
		filtered = filtered[:0]
		for i, r := range rows {
			if q == "" || strings.Contains(r.lower, q) {
				filtered = append(filtered, i)
			}
		}
		lst.Refresh()
	}

	content := container.NewBorder(
		container.NewVBox(headerLabel, widget.NewSeparator(), searchEntry),
		nil, nil, nil,
		lst,
	)

	d := dialog.NewCustom("CRL Viewer", "Close", content, win)
	d.Resize(fyne.NewSize(720, 540))
	d.Show()
}
