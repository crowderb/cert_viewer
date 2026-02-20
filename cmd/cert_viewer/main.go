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

	"image/color"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/canvas"
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
	var cancelOCSP context.CancelFunc
	var cancelCRL context.CancelFunc
	var pkcs12Chain []*x509.Certificate // non-nil when a PKCS#12 bundle is open
	var rebuildMainMenu func()

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
		if cancelOCSP != nil {
			cancelOCSP()
			cancelOCSP = nil
		}
		if cancelCRL != nil {
			cancelCRL()
			cancelCRL = nil
		}
		summary.Render(window, summaryGrid, detailsContainer, currentCert, userPreferences)
		// Append OCSP Status row if the cert has an OCSP URL.
		if len(currentCert.OCSPServer) > 0 {
			ocspStatus := widget.NewLabel("")
			checkBtn := widget.NewButton("Check OCSP", nil)
			var ocspCtx context.Context
			ocspCtx, cancelOCSP = context.WithCancel(ctx)
			// Capture per-cert values for the button closure.
			buttonCtx := ocspCtx
			cert := currentCert
			var issuer *x509.Certificate
			if len(pkcs12Chain) > 1 {
				issuer = pkcs12Chain[1]
			}
			checkBtn.OnTapped = func() {
				checkBtn.Disable()
				ocspStatus.SetText("Checking...")
				go func() {
					resp, err := certs.CheckOCSP(buttonCtx, cert, issuer)
					if buttonCtx.Err() != nil {
						return // cert was replaced; discard result
					}
					if err != nil {
						ocspStatus.SetText("Error: " + err.Error())
					} else {
						ocspStatus.SetText(certs.FormatOCSPStatus(resp))
					}
					ocspStatus.Refresh()
					checkBtn.Enable()
				}()
			}
			summaryGrid.Add(ui.BoldLabel("OCSP Status"))
			summaryGrid.Add(container.NewHBox(ocspStatus, checkBtn))
			summaryGrid.Refresh()
		}
		if len(currentCert.CRLDistributionPoints) > 0 {
			crlStatus := widget.NewLabel("")
			fetchBtn := widget.NewButton("Fetch CRL", nil)
			var crlCtx context.Context
			crlCtx, cancelCRL = context.WithCancel(ctx)
			buttonCtx := crlCtx
			urls := currentCert.CRLDistributionPoints
			fetchBtn.OnTapped = func() {
				fetchBtn.Disable()
				crlStatus.SetText("Fetching...")
				go func() {
					var rl *x509.RevocationList
					var fetchErr error
					for _, url := range urls {
						if buttonCtx.Err() != nil {
							return
						}
						rl, fetchErr = certs.FetchCRL(buttonCtx, url)
						if fetchErr == nil {
							break
						}
					}
					if buttonCtx.Err() != nil {
						return
					}
					if fetchErr != nil {
						crlStatus.SetText("Error: " + fetchErr.Error())
					} else {
						crlStatus.SetText(fmt.Sprintf("%d revoked", len(rl.RevokedCertificateEntries)))
						dialogs.ShowCRL(window, rl, urls[0])
					}
					crlStatus.Refresh()
					fetchBtn.Enable()
				}()
			}
			summaryGrid.Add(ui.BoldLabel("CRL"))
			summaryGrid.Add(container.NewHBox(crlStatus, fetchBtn))
			// Check CRL row — checks this certificate's serial against the CRL.
			checkCRLText := canvas.NewText("", color.Black)
			checkCRLBtn := widget.NewButton("Check CRL", nil)
			checkCert := currentCert
			checkCRLBtn.OnTapped = func() {
				checkCRLBtn.Disable()
				checkCRLText.Text = "Checking..."
				checkCRLText.Color = color.Black
				checkCRLText.Refresh()
				go func() {
					var rl *x509.RevocationList
					var fetchErr error
					for _, url := range urls {
						if buttonCtx.Err() != nil {
							return
						}
						rl, fetchErr = certs.FetchCRL(buttonCtx, url)
						if fetchErr == nil {
							break
						}
					}
					if buttonCtx.Err() != nil {
						return
					}
					if fetchErr != nil {
						checkCRLText.Text = "Error: " + fetchErr.Error()
						checkCRLText.Color = color.Black
					} else if entry := certs.CheckCertInCRL(checkCert, rl); entry != nil {
						checkCRLText.Text = fmt.Sprintf("REVOKED (%s) %s",
							certs.FormatRevocationReason(entry.ReasonCode),
							entry.RevocationTime.UTC().Format("2006-01-02"))
						checkCRLText.Color = color.NRGBA{R: 200, G: 0, B: 0, A: 255}
					} else {
						checkCRLText.Text = "Good"
						checkCRLText.Color = color.NRGBA{R: 0, G: 180, B: 0, A: 255}
					}
					checkCRLText.Refresh()
					checkCRLBtn.Enable()
				}()
			}
			summaryGrid.Add(ui.BoldLabel("Check CRL"))
			summaryGrid.Add(container.NewHBox(checkCRLText, checkCRLBtn))
			summaryGrid.Refresh()
		}
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
		if cancelOCSP != nil {
			cancelOCSP()
			cancelOCSP = nil
		}
		if cancelCRL != nil {
			cancelCRL()
			cancelCRL = nil
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

	// openRecentFile opens a cert/CSR/PKCS#12 file directly by OS path.
	openRecentFile := func(path string) {
		data, err := os.ReadFile(path)
		if err != nil {
			dialog.ShowError(fmt.Errorf("cannot open %s: %w", filepath.Base(path), err), window)
			return
		}
		if parent, perr := storage.Parent(storage.NewFileURI(path)); perr == nil && parent != nil {
			userPreferences.UI.LastDir = parent.String()
		}
		userPreferences = prefs.AddRecentFile(userPreferences, path)
		_ = prefs.Save(userPreferences)
		rebuildMainMenu()

		name := filepath.Base(path)
		lower := strings.ToLower(name)
		if strings.HasSuffix(lower, ".p12") || strings.HasSuffix(lower, ".pfx") {
			pkcs12Chain = nil
			openPKCS12(data, name)
			return
		}
		if strings.HasSuffix(lower, ".csr") || strings.HasSuffix(lower, ".req") {
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

			// Save last directory and recent files from the opened file's URI
			if rc.URI() != nil {
				if parent, perr := storage.Parent(rc.URI()); perr == nil && parent != nil {
					userPreferences.UI.LastDir = parent.String()
				}
				userPreferences = prefs.AddRecentFile(userPreferences, rc.URI().Path())
				_ = prefs.Save(userPreferences)
				rebuildMainMenu()
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
	rebuildMainMenu = func() {
		// Prune non-existent files and persist if the list shrank
		var alive []string
		for _, p := range userPreferences.UI.RecentFiles {
			if _, err := os.Stat(p); err == nil {
				alive = append(alive, p)
			}
		}
		if len(alive) != len(userPreferences.UI.RecentFiles) {
			userPreferences.UI.RecentFiles = alive
			_ = prefs.Save(userPreferences)
		}

		recentItem := fyne.NewMenuItem("Open Recent", nil)
		if len(alive) == 0 {
			recentItem.Disabled = true
		} else {
			subItems := make([]*fyne.MenuItem, 0, len(alive)+2)
			for _, p := range alive {
				p := p // capture loop variable
				subItems = append(subItems, fyne.NewMenuItem(filepath.Base(p), func() {
					openRecentFile(p)
				}))
			}
			subItems = append(subItems, fyne.NewMenuItemSeparator())
			subItems = append(subItems, fyne.NewMenuItem("Clear Recent", func() {
				userPreferences.UI.RecentFiles = nil
				_ = prefs.Save(userPreferences)
				rebuildMainMenu()
			}))
			recentItem.ChildMenu = fyne.NewMenu("", subItems...)
		}

		// Export menu items — enabled only when a cert or CSR is open.
		nothingOpen := currentCert == nil && currentCSR == nil

		exportDetailsItem := fyne.NewMenuItem("Export Details...", func() {
			var text string
			if currentCert != nil {
				text = summary.ExportText(currentCert, userPreferences)
			} else if currentCSR != nil {
				text = summary.ExportCSRText(currentCSR, userPreferences)
			}
			fd := dialog.NewFileSave(func(wc fyne.URIWriteCloser, err error) {
				if err != nil {
					dialog.ShowError(err, window)
					return
				}
				if wc == nil {
					return
				}
				defer wc.Close()
				if _, writeErr := wc.Write([]byte(text)); writeErr != nil {
					dialog.ShowError(writeErr, window)
				}
			}, window)
			if userPreferences.UI.LastDir != "" {
				if u, err := storage.ParseURI(userPreferences.UI.LastDir); err == nil {
					if l, lerr := storage.ListerForURI(u); lerr == nil {
						fd.SetLocation(l)
					}
				}
			}
			fd.SetFileName("certificate_details.txt")
			fd.SetFilter(storage.NewExtensionFileFilter([]string{".txt"}))
			fd.Show()
		})
		exportDetailsItem.Disabled = nothingOpen

		copyAllItem := fyne.NewMenuItem("Copy All to Clipboard", func() {
			var text string
			if currentCert != nil {
				text = summary.ExportText(currentCert, userPreferences)
			} else if currentCSR != nil {
				text = summary.ExportCSRText(currentCSR, userPreferences)
			}
			window.Clipboard().SetContent(text)
		})
		copyAllItem.Disabled = nothingOpen

		newFileMenu := fyne.NewMenu("File",
			fyne.NewMenuItem("Open...", openCert),
			fyne.NewMenuItem("Open URL...", openURL),
			recentItem,
			fyne.NewMenuItemSeparator(),
			exportDetailsItem,
			copyAllItem,
			fyne.NewMenuItemSeparator(),
			fyne.NewMenuItem("Quit", func() { application.Quit() }),
		)
		window.SetMainMenu(fyne.NewMainMenu(newFileMenu, editMenu, resourcesMenu))
	}
	rebuildMainMenu()

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
			userPreferences = prefs.AddRecentFile(userPreferences, path)
			_ = prefs.Save(userPreferences)
			rebuildMainMenu()

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
