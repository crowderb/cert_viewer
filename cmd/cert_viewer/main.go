package main

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/storage"
	"fyne.io/fyne/v2/widget"
	"golang.org/x/crypto/pkcs12"

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
	var currentCSR *x509.CertificateRequest // non-nil when a CSR is open
	var cancelChain context.CancelFunc
	var pkcs12Chain []*x509.Certificate // non-nil when a PKCS#12 bundle is open

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

	// Background context — cancelled on application exit.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// renderCert re-renders all certificate-dependent views.
	renderCert := func() {
		if cancelChain != nil {
			cancelChain()
		}
		summary.Render(window, summaryGrid, detailsContainer, currentCert, userPreferences)
		if pkcs12Chain != nil {
			chain.BuildFromCerts(window, chainTabs, pkcs12Chain, userPreferences)
		} else {
			var chainCtx context.Context
			chainCtx, cancelChain = context.WithCancel(ctx)
			chain.Build(chainCtx, window, chainTabs, currentCert, userPreferences)
		}
	}

	// renderCSR re-renders all CSR-dependent views.
	renderCSR := func() {
		if cancelChain != nil {
			cancelChain()
			cancelChain = nil
		}
		summary.RenderCSR(window, summaryGrid, detailsContainer, currentCSR, userPreferences)
		// Chain is not applicable for CSRs.
		chainTabs.Items = nil
		chainTabs.Append(container.NewTabItem("Not Applicable", widget.NewLabel("Certificate chain is not available for certificate signing requests.")))
		chainTabs.Refresh()
	}

	// openPKCS12 parses a PKCS#12 bundle, prompting for a password if needed.
	// It tries an empty password first (for unencrypted files), then shows a
	// password dialog on ErrIncorrectPassword.
	openPKCS12 := func(data []byte, name string) {
		var tryOpen func(password string)
		tryOpen = func(password string) {
			leaf, caChain, err := certs.ParsePKCS12(data, password)
			if err != nil {
				if errors.Is(err, pkcs12.ErrIncorrectPassword) {
					dialogs.ShowPasswordPrompt(window, name, tryOpen)
					return
				}
				dialog.ShowError(fmt.Errorf("PKCS#12 parse failed: %w", err), window)
				return
			}
			currentCSR = nil
			currentCert = leaf
			pkcs12Chain = append([]*x509.Certificate{leaf}, caChain...)
			renderCert()
		}
		tryOpen("") // try empty password first (handles unencrypted PFX silently)
	}

	// openURL dials an HTTPS server and loads its TLS certificate chain.
	openURL := func() {
		dialogs.ShowOpenURL(window, func(rawInput string, skipVerify bool) {
			go func() {
				certChain, err := certs.FetchTLSCerts(rawInput, skipVerify)
				if err != nil {
					dialog.ShowError(err, window)
					return
				}
				currentCSR = nil
				currentCert = certChain[0]
				pkcs12Chain = certChain
				renderCert()
			}()
		})
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

			// Save last directory from the opened file's URI
			if rc.URI() != nil {
				if parent, perr := storage.Parent(rc.URI()); perr == nil && parent != nil {
					userPreferences.UI.LastDir = parent.String()
					_ = prefs.Save(userPreferences)
				}
			}

			name := strings.ToLower(rc.URI().Name())
			if strings.HasSuffix(name, ".p12") || strings.HasSuffix(name, ".pfx") {
				pkcs12Chain = nil
				openPKCS12(data, rc.URI().Name())
				return
			}
			if strings.HasSuffix(name, ".csr") || strings.HasSuffix(name, ".req") {
				csr, parseErr := certs.ParseCSR(data)
				if parseErr != nil {
					dialog.ShowError(parseErr, window)
					return
				}
				currentCSR = csr
				currentCert = nil
				pkcs12Chain = nil
				renderCSR()
				return
			}

			cert, parseErr := certs.ParseCertificate(data)
			if parseErr != nil {
				dialog.ShowError(parseErr, window)
				return
			}
			currentCSR = nil
			pkcs12Chain = nil
			currentCert = cert
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
		fd.SetFilter(storage.NewExtensionFileFilter([]string{".cer", ".crt", ".pem", ".der", ".p12", ".pfx", ".csr", ".req"}))
		fd.Show()
	}

	preferencesDialog := func() {
		dialogs.ShowPreferences(window, userPreferences, func(p prefs.Preferences) {
			userPreferences = p
			if currentCSR != nil {
				renderCSR()
			} else if currentCert != nil {
				renderCert()
			}
		})
	}

	fileMenu := fyne.NewMenu("File",
		fyne.NewMenuItem("Open...", openCert),
		fyne.NewMenuItem("Open URL...", openURL),
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

	// Enable drag-and-drop to open certificate files
	window.SetOnDropped(func(pos fyne.Position, uris []fyne.URI) {
		for _, u := range uris {
			if u == nil || u.Scheme() != "file" {
				continue
			}
			path := u.Path()
			lower := strings.ToLower(path)
			// Filter by extension
			isPKCS12 := strings.HasSuffix(lower, ".p12") || strings.HasSuffix(lower, ".pfx")
			isCSR := strings.HasSuffix(lower, ".csr") || strings.HasSuffix(lower, ".req")
			isCert := strings.HasSuffix(lower, ".cer") || strings.HasSuffix(lower, ".crt") || strings.HasSuffix(lower, ".pem") || strings.HasSuffix(lower, ".der")
			if !isPKCS12 && !isCSR && !isCert {
				continue
			}
			// Read and open first matching file
			data, err := os.ReadFile(path)
			if err != nil {
				dialog.ShowError(err, window)
				return
			}
			if parent, perr := storage.Parent(storage.NewFileURI(path)); perr == nil && parent != nil {
				userPreferences.UI.LastDir = parent.String()
			}
			_ = prefs.Save(userPreferences)

			if isPKCS12 {
				pkcs12Chain = nil
				openPKCS12(data, filepath.Base(path))
				return
			}
			if isCSR {
				csr, err := certs.ParseCSR(data)
				if err != nil {
					dialog.ShowError(err, window)
					return
				}
				currentCSR = csr
				currentCert = nil
				pkcs12Chain = nil
				renderCSR()
				return
			}

			cert, err := certs.ParseCertificate(data)
			if err != nil {
				dialog.ShowError(err, window)
				return
			}
			currentCSR = nil
			pkcs12Chain = nil
			currentCert = cert
			renderCert()
			return
		}
	})

	window.SetContent(tabs)

	// Start CCADB refresh in background (no auto-rebuild)
	go func() { <-resources.EnsureCCADBCSV(ctx, userPreferences) }()

	window.ShowAndRun()
}
