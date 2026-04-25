// Package trustsources renders the "Trust Sources" tab: a per-origin
// breakdown of every root certificate the local cache has indexed,
// labelled with where it came from (system bundle, env override, distro
// anchor dir, NSS user / Firefox DBs) and tagged with whether the cert
// is in CCADB.
package trustsources

import (
	"fmt"
	"image/color"
	"sort"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"

	"cert_viewer/internal/prefs"
	"cert_viewer/internal/resources"
)

// originDisplayOrder controls the order in which origin sections appear in
// the UI. The system bundle goes first (the dominant source by count),
// followed by env overrides, distro anchors, then NSS-backed sources.
// Unknown origins fall to the bottom in alphabetical order.
var originDisplayOrder = []string{
	resources.OriginSystemBundle,
	resources.OriginEnvOverride,
	resources.OriginDistroAnchorDir,
	resources.OriginNSSUser,
	resources.OriginNSSFirefox,
}

// originLabel maps an origin constant to a human-readable section title.
// Unknown origins are passed through as-is so a future reader's contribution
// at least appears in the UI without code changes.
func originLabel(origin string) string {
	switch origin {
	case resources.OriginSystemBundle:
		return "System bundle"
	case resources.OriginEnvOverride:
		return "Env override (SSL_CERT_FILE / SSL_CERT_DIR)"
	case resources.OriginDistroAnchorDir:
		return "Distro anchor dir"
	case resources.OriginNSSUser:
		return "NSS — user (~/.pki/nssdb)"
	case resources.OriginNSSFirefox:
		return "NSS — Firefox profile"
	}
	return origin
}

// Build renders the Trust Sources tab into root. Loads the cached
// LocalRootSummary list, groups by origin (a single cert appears in
// multiple groups when it carries multiple origins), and emits one
// expandable accordion section per origin annotated with cert subject,
// SKI, source path, and CCADB membership.
//
// Caller is responsible for invoking resources.EnsureLocalRootsJSON
// before Build so the cache is fresh; Build only consumes the cache.
func Build(root *fyne.Container, p prefs.Preferences) {
	root.Objects = nil

	roots, lerr := resources.LoadLocalRootsSKISet()
	if lerr != nil {
		root.Add(widget.NewLabel("Error loading local roots: " + lerr.Error()))
		root.Refresh()
		return
	}
	if len(roots) == 0 {
		root.Add(widget.NewLabel("No trusted roots indexed yet. Try Resources → Compare Local vs CCADB to build the cache."))
		root.Refresh()
		return
	}

	ccadb, _ := resources.LoadCCADBSKISet(p) // best-effort; nil map is fine

	// Group certs by origin type. Using SHA-256 as the dedup key so a cert
	// with multiple origins appears once per group, not duplicated within
	// a group when two paths share an origin type.
	byOrigin := make(map[string][]certEntry)
	for _, r := range roots {
		seen := make(map[string]struct{})
		for _, o := range r.Origins {
			if _, dup := seen[o.Type]; dup {
				continue
			}
			seen[o.Type] = struct{}{}
			byOrigin[o.Type] = append(byOrigin[o.Type], certEntry{
				summary:  r,
				path:     o.Path,
				inCCADB:  isInCCADB(r.SubjectKeyIdentifier, ccadb),
			})
		}
	}

	// Header with totals.
	totalUnique := len(roots)
	root.Add(boldLabel(fmt.Sprintf("Trusted roots indexed: %d unique certificates", totalUnique)))

	// Render each origin section in display order. Unknown origins (not in
	// originDisplayOrder) appended in alphabetical order at the bottom.
	for _, origin := range orderedOrigins(byOrigin) {
		entries := byOrigin[origin]
		if len(entries) == 0 {
			continue
		}
		renderOriginSection(root, origin, entries)
	}

	root.Refresh()
}

type certEntry struct {
	summary resources.LocalRootSummary
	path    string
	inCCADB bool
}

func renderOriginSection(root *fyne.Container, origin string, entries []certEntry) {
	header := canvas.NewText(fmt.Sprintf("%s (%d)", originLabel(origin), len(entries)),
		color.NRGBA{R: 50, G: 80, B: 160, A: 255})
	header.TextStyle = fyne.TextStyle{Bold: true}
	header.TextSize = 14
	bg := canvas.NewRectangle(color.NRGBA{R: 235, G: 240, B: 250, A: 255})
	root.Add(container.NewStack(bg, container.NewPadded(header)))

	// Sort entries by Subject for stable display.
	sort.SliceStable(entries, func(i, j int) bool {
		return entries[i].summary.Subject < entries[j].summary.Subject
	})

	var accordionItems []*widget.AccordionItem
	for _, e := range entries {
		title := e.summary.Subject
		if title == "" {
			title = "(unknown subject)"
		}
		ccadbTag := "not in CCADB"
		ccadbColor := color.NRGBA{R: 180, G: 100, B: 0, A: 255}
		if e.inCCADB {
			ccadbTag = "in CCADB"
			ccadbColor = color.NRGBA{R: 0, G: 130, B: 0, A: 255}
		}
		ccadbText := canvas.NewText(ccadbTag, ccadbColor)
		ccadbText.TextStyle = fyne.TextStyle{Italic: true}

		body := container.NewVBox(
			labeledRow("SKI", e.summary.SubjectKeyIdentifier),
			labeledRow("Serial", e.summary.SerialHex),
			labeledRow("Not Before", e.summary.NotBefore),
			labeledRow("Not After", e.summary.NotAfter),
			labeledRow("SHA-256", e.summary.SHA256FingerprintHex),
			labeledRow("Source path", e.path),
			ccadbText,
		)
		accordionItems = append(accordionItems, widget.NewAccordionItem(title, body))
	}
	accordion := widget.NewAccordion(accordionItems...)
	root.Add(accordion)
	root.Add(widget.NewSeparator())
}

// labeledRow renders a single bold-label / value row for an accordion body.
// Plain HBox so the label stays close to the value; the surrounding VBox
// stacks rows vertically.
func labeledRow(label, value string) *fyne.Container {
	l := widget.NewLabel(label + ":")
	l.TextStyle = fyne.TextStyle{Bold: true}
	v := widget.NewLabel(value)
	v.Wrapping = fyne.TextWrapBreak
	return container.NewHBox(l, v)
}

func boldLabel(text string) *widget.Label {
	l := widget.NewLabel(text)
	l.TextStyle = fyne.TextStyle{Bold: true}
	return l
}

func isInCCADB(skiHex string, ccadb map[string]struct{}) bool {
	if ccadb == nil {
		return false
	}
	_, ok := ccadb[normalizeUpper(skiHex)]
	return ok
}

func normalizeUpper(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9':
			out = append(out, c)
		case c >= 'a' && c <= 'f':
			out = append(out, c-('a'-'A'))
		case c >= 'A' && c <= 'F':
			out = append(out, c)
		}
	}
	return string(out)
}

// orderedOrigins returns the keys of m in display order: known origins
// first (per originDisplayOrder), then unknown origins alphabetically.
func orderedOrigins(m map[string][]certEntry) []string {
	known := make(map[string]bool, len(originDisplayOrder))
	out := make([]string, 0, len(m))
	for _, o := range originDisplayOrder {
		if _, present := m[o]; present {
			out = append(out, o)
			known[o] = true
		}
	}
	var unknown []string
	for o := range m {
		if !known[o] {
			unknown = append(unknown, o)
		}
	}
	sort.Strings(unknown)
	return append(out, unknown...)
}
