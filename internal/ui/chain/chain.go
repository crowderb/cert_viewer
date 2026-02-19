package chain

import (
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"

	"cert_viewer/internal/certs"
	"cert_viewer/internal/prefs"
	"cert_viewer/internal/resources"
	"cert_viewer/internal/ui"
	"cert_viewer/internal/ui/summary"
)

// buildCertTab constructs a tab item displaying certificate details.
func buildCertTab(win fyne.Window, title string, cert *x509.Certificate, p prefs.Preferences) *container.TabItem {
	grid := container.New(ui.NewTightTwoColLayout())
	tmp := container.New(ui.NewTightTwoColLayout())
	summary.Render(win, grid, tmp, cert, p)
	if len(cert.SubjectKeyId) > 0 {
		grid.Add(ui.BoldLabel("Subject Key Identifier"))
		grid.Add(ui.CopyRow(win, certs.FormatHex(cert.SubjectKeyId, string(p.UI.HexSep))))
	}
	if len(cert.AuthorityKeyId) > 0 {
		grid.Add(ui.BoldLabel("Authority Key Identifier"))
		grid.Add(ui.CopyRow(win, certs.FormatHex(cert.AuthorityKeyId, string(p.UI.HexSep))))
	}
	return container.NewTabItem(title, container.NewVScroll(grid))
}

// Build constructs a certificate chain up to 5 levels using AIA and renders tabs
// into chainTabs. It returns immediately after showing a progress indicator and
// performs all network I/O on a background goroutine. Cancelling ctx stops the
// in-flight fetch and leaves whatever tabs were already populated.
func Build(ctx context.Context, win fyne.Window, chainTabs *container.AppTabs, leaf *x509.Certificate, p prefs.Preferences) {
	// Sync preamble on the calling (UI) goroutine: show progress indicator.
	chainTabs.Items = nil
	chainTabs.Append(container.NewTabItem("Building chain...", widget.NewProgressBarInfinite()))
	chainTabs.Refresh()

	go func() {
		// Clear the spinner and add the leaf tab.
		chainTabs.Items = nil
		chainTabs.Append(buildCertTab(win, "Leaf", leaf, p))
		chainTabs.Refresh()

		// Disk I/O off the UI goroutine.
		localSet, _ := resources.LoadLocalRootsSKISet()
		ccadbSet, _ := resources.LoadCCADBSKISet(p)

		current := leaf
		for depth := 1; depth <= 5; depth++ {
			// Self-signed: AKI == SKI.
			if len(current.AuthorityKeyId) > 0 && len(current.SubjectKeyId) > 0 {
				if certs.NormalizeHexBytesNoSepUpper(current.AuthorityKeyId) == certs.NormalizeHexBytesNoSepUpper(current.SubjectKeyId) {
					chainTabs.Append(container.NewTabItem("Self-signed", widget.NewLabel("Authority Key Identifier equals Subject Key Identifier")))
					chainTabs.Refresh()
					return
				}
			}

			// AIA: CA Issuers URL.
			if len(current.IssuingCertificateURL) == 0 {
				break
			}
			aiaURL := current.IssuingCertificateURL[0]

			// Fetch — blocks until complete or context cancelled.
			issuerCert, err := fetchRemoteCert(ctx, aiaURL)
			if ctx.Err() != nil {
				// Cancelled by the user opening a new certificate — stop silently.
				return
			}
			if err != nil {
				errMsg := fmt.Sprintf("Fetch failed: %v", err)
				chainTabs.Append(container.NewTabItem(
					fmt.Sprintf("Error (depth %d)", depth),
					widget.NewLabel(errMsg),
				))
				chainTabs.Refresh()
				return
			}

			// Append issuer tab.
			chainTabs.Append(buildCertTab(win, fmt.Sprintf("Issuer %d", depth), issuerCert, p))
			chainTabs.Refresh()

			// Check local roots first, then CCADB.
			if len(issuerCert.SubjectKeyId) > 0 {
				key := certs.NormalizeHexBytesNoSepUpper(issuerCert.SubjectKeyId)
				if _, ok := localSet[key]; ok {
					chainTabs.Append(container.NewTabItem("Root (from Local Store)", widget.NewLabel("Found Subject Key Identifier in local system trust bundle")))
					chainTabs.Refresh()
					return
				}
				if _, ok := ccadbSet[key]; ok {
					chainTabs.Append(container.NewTabItem("Root (from CCADB)", widget.NewLabel("Found Subject Key Identifier in CCADB CSV")))
					chainTabs.Refresh()
					return
				}
			}

			current = issuerCert
		}
	}()
}

// BuildFromCerts renders a pre-built certificate chain directly into chainTabs
// without any AIA fetching. certs[0] is displayed as the leaf; remaining
// entries are displayed as issuers. The final cert is checked against the local
// trust store and CCADB for a root match label.
func BuildFromCerts(win fyne.Window, chainTabs *container.AppTabs, certList []*x509.Certificate, p prefs.Preferences) {
	chainTabs.Items = nil
	if len(certList) == 0 {
		chainTabs.Append(container.NewTabItem("No certificates", widget.NewLabel("The PKCS#12 bundle contained no certificates.")))
		chainTabs.Refresh()
		return
	}

	chainTabs.Append(buildCertTab(win, "Leaf", certList[0], p))

	issuerNum := 1
	for i := 1; i < len(certList); i++ {
		chainTabs.Append(buildCertTab(win, fmt.Sprintf("Issuer %d", issuerNum), certList[i], p))
		issuerNum++
	}

	// Check the last cert against local trust store and CCADB.
	last := certList[len(certList)-1]
	if len(last.SubjectKeyId) > 0 {
		key := certs.NormalizeHexBytesNoSepUpper(last.SubjectKeyId)
		localSet, _ := resources.LoadLocalRootsSKISet()
		if _, ok := localSet[key]; ok {
			chainTabs.Append(container.NewTabItem("Root (from Local Store)", widget.NewLabel("Found Subject Key Identifier in local system trust bundle")))
			chainTabs.Refresh()
			return
		}
		ccadbSet, _ := resources.LoadCCADBSKISet(p)
		if _, ok := ccadbSet[key]; ok {
			chainTabs.Append(container.NewTabItem("Root (from CCADB)", widget.NewLabel("Found Subject Key Identifier in CCADB CSV")))
			chainTabs.Refresh()
			return
		}
	}

	chainTabs.Refresh()
}

func fetchRemoteCert(ctx context.Context, url string) (*x509.Certificate, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("http error: %s", resp.Status)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if cert, err := tryParseSingleCert(data); err == nil && cert != nil {
		return cert, nil
	}
	return nil, fmt.Errorf("no certificate found at URL")
}

func tryParseSingleCert(data []byte) (*x509.Certificate, error) {
	return certs.ParseCertificateOrPKCS7(data)
}
