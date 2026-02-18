package main

import (
	"context"
	"crypto/x509"
	"io"
	"os"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/storage"
	"fyne.io/fyne/v2/widget"

	"cert_viewer/internal/certs"
	"cert_viewer/internal/prefs"
	"cert_viewer/internal/resources"
	"cert_viewer/internal/ui"
	"cert_viewer/internal/ui/advanced"
	"cert_viewer/internal/ui/chain"
	"cert_viewer/internal/ui/dialogs"
	"cert_viewer/internal/ui/summary"
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
		ui.BoldLabel("Open a certificate to view its summary."),
		ui.CopyRow(window, ""),
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

	// renderCert re-renders all certificate-dependent views.
	renderCert := func() {
		summary.Render(window, summaryGrid, detailsContainer, currentCert, userPreferences)
		chain.Build(window, chainTabs, currentCert, userPreferences)
	}

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
			renderCert()
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
		dialogs.ShowPreferences(window, userPreferences, func(p prefs.Preferences) {
			userPreferences = p
			if currentCert != nil {
				renderCert()
			}
		})
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
		fyne.NewMenuItem("CCADB CSV", func() { dialogs.ShowCCADB(window, userPreferences) }),
		fyne.NewMenuItemSeparator(),
		fyne.NewMenuItem("Compare Local vs CCADB", func() {
			// Show placeholder and build in background to keep UI responsive
			advancedContent.Objects = []fyne.CanvasObject{widget.NewLabel("Building comparison...")}
			advancedContent.Refresh()
			go func() {
				_ = resources.EnsureLocalRootsJSON(context.Background())
				advanced.Build(advancedContent, userPreferences)
			}()
			tabs.SelectIndex(3) // Advanced tab
		}),
	)
	mainMenu := fyne.NewMainMenu(fileMenu, editMenu, resourcesMenu)
	window.SetMainMenu(mainMenu)

	// Prepare background context
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

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
			renderCert()
			return
		}
	})

	window.SetContent(tabs)

	// Start CCADB refresh in background (no auto-rebuild)
	go func() { <-resources.EnsureCCADBCSV(ctx, userPreferences) }()

	window.ShowAndRun()
}
