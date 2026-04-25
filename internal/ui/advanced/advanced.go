package advanced

import (
	"fmt"
	"image/color"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"

	"cert_viewer/internal/prefs"
	"cert_viewer/internal/resources"
)

// originSummary collapses an Origins slice into a comma-separated set of
// distinct origin types. Paths are omitted to keep the Advanced row
// compact; the Trust Sources tab shows full per-origin paths.
func originSummary(origins []resources.OriginRef) string {
	seen := make(map[string]struct{}, len(origins))
	var labels []string
	for _, o := range origins {
		if _, dup := seen[o.Type]; dup {
			continue
		}
		seen[o.Type] = struct{}{}
		labels = append(labels, o.Type)
	}
	return strings.Join(labels, ", ")
}

// Build populates containerRoot with the Advanced tab: three sections showing
// Local only, CCADB only, and Both (by SKI), listing Subject, SKI, and Serial.
func Build(containerRoot *fyne.Container, p prefs.Preferences) {
	containerRoot.Objects = nil
	addHeader := func(title string) {
		lbl := widget.NewLabel(title)
		lbl.TextStyle = fyne.TextStyle{Bold: true}
		// Light gray background row
		bg := canvas.NewRectangle(color.NRGBA{R: 240, G: 240, B: 240, A: 255})
		row := container.NewMax(bg, container.NewPadded(lbl))
		containerRoot.Add(row)
	}
	addEntry := func(subject, ski, serial string, origins []resources.OriginRef) {
		subj := widget.NewLabel(subject)
		subj.TextStyle = fyne.TextStyle{Bold: true}
		containerRoot.Add(subj)
		containerRoot.Add(widget.NewLabel("SKI: " + ski))
		if serial != "" {
			containerRoot.Add(widget.NewLabel("Serial: " + serial))
		}
		if len(origins) > 0 {
			containerRoot.Add(widget.NewLabel("Origins: " + originSummary(origins)))
		}
		containerRoot.Add(widget.NewLabel(""))
	}

	// Load data
	localMap, lerr := resources.LoadLocalRootsSKISet()
	ccadbSummary, cerr := resources.LoadCCADBSummary(p)
	if lerr != nil {
		containerRoot.Add(widget.NewLabel("Error loading local roots: " + lerr.Error()))
	}
	if cerr != nil {
		containerRoot.Add(widget.NewLabel("Error loading CCADB set: " + cerr.Error()))
	}

	// Compute sets
	localOnly := []resources.LocalRootSummary{}
	both := []resources.LocalRootSummary{}
	ccadbOnly := []struct {
		Subject string
		SKI     string
	}{}

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
		ccadbOnly = append(ccadbOnly, struct {
			Subject string
			SKI     string
		}{Subject: summary.Subject, SKI: ski})
	}

	// Render sections
	addHeader("Certificates in Local Store Only")
	for _, s := range localOnly {
		addEntry(s.Subject, s.SubjectKeyIdentifier, s.SerialHex, s.Origins)
	}
	if len(localOnly) == 0 {
		t := canvas.NewText("(none)", color.NRGBA{R: 0, G: 180, B: 0, A: 255})
		containerRoot.Add(t)
	} else {
		t := canvas.NewText(fmt.Sprintf("(%d)", len(localOnly)), color.NRGBA{R: 200, G: 0, B: 0, A: 255})
		containerRoot.Add(t)
	}
	if p.UI.ShowCCADBOnlyCerts {
		addHeader("Certificates in CCADB Only")
		for _, row := range ccadbOnly {
			subj := row.Subject
			if subj == "" {
				subj = "(unknown subject)"
			}
			addEntry(subj, row.SKI, "", nil)
		}
		if len(ccadbOnly) == 0 {
			containerRoot.Add(widget.NewLabel("(none)"))
		} else {
			containerRoot.Add(widget.NewLabel(fmt.Sprintf("(%d)", len(ccadbOnly))))
		}
	}
	addHeader("Certificates in Both")
	for _, s := range both {
		addEntry(s.Subject, s.SubjectKeyIdentifier, s.SerialHex, s.Origins)
	}
	if len(both) == 0 {
		containerRoot.Add(widget.NewLabel("(none)"))
	} else {
		containerRoot.Add(widget.NewLabel(fmt.Sprintf("(%d)", len(both))))
	}
	containerRoot.Refresh()
}
