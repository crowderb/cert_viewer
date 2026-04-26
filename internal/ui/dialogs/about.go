package dialogs

import (
	"log/slog"
	"net/url"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"

	"cert_viewer/internal/version"
)

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

	content := container.NewVBox(
		form,
		widget.NewSeparator(),
		repoLink,
		widget.NewSeparator(),
		guides,
	)

	d := dialog.NewCustom("About cert_viewer", "Close", content, win)
	d.Resize(fyne.NewSize(420, 320))
	d.Show()
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
