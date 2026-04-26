package dialogs

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"

	"cert_viewer/internal/updates"
	"cert_viewer/internal/version"
)

// updateCheckTimeout caps the network call so a captive portal or hung
// host can't lock the result label in "Checking..." indefinitely. Same
// budget the design doc on 5.D specifies.
const updateCheckTimeout = 10 * time.Second

// RepoURL is the canonical GitHub project location, surfaced in the
// About dialog and the Help menu's "GitHub Repository" item.
const RepoURL = "https://github.com/crowderb/cert_viewer"

// InstallGuides maps a human label to the github.com URL of each
// platform-specific build/install guide. Sourced from the repo's main
// branch so users always see the latest version.
var InstallGuides = []struct {
	Label string
	URL   string
}{
	{Label: "Linux", URL: RepoURL + "/blob/main/BUILD_GUIDE_LINUX.md"},
	{Label: "macOS", URL: RepoURL + "/blob/main/BUILD_GUIDE_MACOS.md"},
	{Label: "Windows", URL: RepoURL + "/blob/main/BUILD_GUIDE_WINDOWS.md"},
}

// ShowAbout opens the About dialog showing the build identity strings
// from internal/version plus clickable links to the repo and install
// guides. The dialog is informational only — no settings are mutated.
//
// The "Check for Updates" button issues a single network request to the
// GitHub tags API only when clicked. There is no startup-time check, no
// background polling, and no telemetry — this is a deliberate privacy
// stance for users on air-gapped or metered networks.
func ShowAbout(win fyne.Window) {
	form := container.NewVBox(
		labelValueRow("Version", version.Version),
		labelValueRow("Commit", version.Commit),
		labelValueRow("Build date", version.BuildDate),
	)

	repoLink := widget.NewHyperlink("GitHub Repository", mustParseURL(RepoURL))

	guides := container.NewVBox(widget.NewLabel("Install Guides:"))
	for _, g := range InstallGuides {
		guides.Add(widget.NewHyperlink(g.Label, mustParseURL(g.URL)))
	}

	updateRow := newUpdateCheckRow()

	content := container.NewVBox(
		form,
		widget.NewSeparator(),
		repoLink,
		widget.NewSeparator(),
		guides,
		widget.NewSeparator(),
		updateRow,
	)

	d := dialog.NewCustom("About cert_viewer", "Close", content, win)
	d.Resize(fyne.NewSize(420, 380))
	d.Show()
}

// newUpdateCheckRow builds the "Check for Updates" button + result label
// pair. The button issues one HTTP request per click; the label echoes
// the outcome. Errors are stringified into a user-friendly message —
// the underlying error already lives in the slog log file for diagnostics.
func newUpdateCheckRow() fyne.CanvasObject {
	resultLabel := widget.NewLabel("")
	resultLabel.Wrapping = fyne.TextWrapWord

	var btn *widget.Button
	btn = widget.NewButton("Check for Updates", func() {
		btn.Disable()
		resultLabel.SetText("Checking…")
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), updateCheckTimeout)
			defer cancel()
			latest, isNewer, err := updates.CheckLatestTag(ctx)

			// Fyne v2.5.3 does not expose a fyne.Do queue; widget
			// mutators (SetText, Enable/Disable) are documented as
			// goroutine-safe in this version, matching the pattern
			// used elsewhere in the codebase (see summary.go and
			// the chain/CRL/OCSP refresh sites in main.go).
			defer btn.Enable()
			switch {
			case errors.Is(err, updates.ErrNoMatchingTags):
				resultLabel.SetText("No release tags published yet.")
			case err != nil:
				slog.Warn("update check failed", "err", err)
				resultLabel.SetText("Update check failed: " + err.Error())
			case isNewer:
				resultLabel.SetText(fmt.Sprintf(
					"Update available: %s — see %s",
					latest, updates.ReleasesURL,
				))
			default:
				resultLabel.SetText("You're on the latest version.")
			}
		}()
	})

	return container.NewVBox(btn, resultLabel)
}

// labelValueRow renders a fixed-width label paired with a selectable
// value entry — using a read-only Entry rather than a Label gives the
// user copy-to-clipboard support for free.
func labelValueRow(label, value string) fyne.CanvasObject {
	name := widget.NewLabelWithStyle(label+":", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
	val := widget.NewLabel(value)
	val.Wrapping = fyne.TextWrapBreak
	return container.NewBorder(nil, nil, name, nil, val)
}

// mustParseURL returns a *url.URL or nil. A nil URL passed to a Fyne
// Hyperlink renders as plain text — acceptable degradation; we log the
// parse failure so it shows up in the user's log file but never block
// the dialog from opening. raw is a build-time constant in this file
// so a parse error indicates a code mistake, not user input.
func mustParseURL(raw string) *url.URL {
	u, err := url.Parse(raw)
	if err != nil {
		slog.Warn("about dialog URL parse failed", "url", raw, "err", err)
		return nil
	}
	return u
}
