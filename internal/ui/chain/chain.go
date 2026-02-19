package chain

import (
	"crypto/x509"
	"fmt"
	"io"
	"net/http"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"

	"cert_viewer/internal/certs"
	"cert_viewer/internal/prefs"
	"cert_viewer/internal/resources"
	"cert_viewer/internal/ui"
	"cert_viewer/internal/ui/summary"
)

// Build constructs a certificate chain up to 5 levels using AIA and renders tabs
// into chainTabs.
func Build(win fyne.Window, chainTabs *container.AppTabs, leaf *x509.Certificate, p prefs.Preferences) {
	// Reset tabs
	chainTabs.Items = nil
	addCertTab := func(title string, cert *x509.Certificate) {
		// Reuse summary renderer into a compact container
		grid := container.New(ui.NewTightTwoColLayout())
		// Use a throwaway details container to satisfy function signature
		tmp := container.New(ui.NewTightTwoColLayout())
		summary.Render(win, grid, tmp, cert, p)
		// Add SKI / AKI rows for chain visibility
		if len(cert.SubjectKeyId) > 0 {
			grid.Add(ui.BoldLabel("Subject Key Identifier"))
			grid.Add(ui.CopyRow(win, certs.FormatHex(cert.SubjectKeyId, string(p.UI.HexSep))))
		}
		if len(cert.AuthorityKeyId) > 0 {
			grid.Add(ui.BoldLabel("Authority Key Identifier"))
			grid.Add(ui.CopyRow(win, certs.FormatHex(cert.AuthorityKeyId, string(p.UI.HexSep))))
		}
		chainTabs.Append(container.NewTabItem(title, container.NewVScroll(grid)))
	}
	addCertTab("Leaf", leaf)

	// Load local roots and CCADB SKI sets if available
	localSet, _ := resources.LoadLocalRootsSKISet()
	ccadbSet, _ := resources.LoadCCADBSKISet(p)
	current := leaf
	for depth := 1; depth <= 5; depth++ {
		// Self-signed if AKI equals SKI
		if len(current.AuthorityKeyId) > 0 && len(current.SubjectKeyId) > 0 {
			if certs.NormalizeHexBytesNoSepUpper(current.AuthorityKeyId) == certs.NormalizeHexBytesNoSepUpper(current.SubjectKeyId) {
				chainTabs.Append(container.NewTabItem("Self-signed", widget.NewLabel("Authority Key Identifier equals Subject Key Identifier")))
				chainTabs.Refresh()
				return
			}
		}
		// AIA: CA Issuers URL
		var aiaURL string
		if len(current.IssuingCertificateURL) > 0 {
			aiaURL = current.IssuingCertificateURL[0]
		} else {
			break
		}
		// Fetch issuer cert
		issuerCert, err := fetchRemoteCert(aiaURL)
		if err != nil {
			dialog.ShowError(fmt.Errorf("chain fetch failed at depth %d: %w", depth, err), win)
			return
		}
		// Render tab
		title := fmt.Sprintf("Issuer %d", depth)
		c := issuerCert
		addCertTab(title, c)
		chainTabs.Refresh()
		// Check local roots first, then CCADB
		if len(c.SubjectKeyId) > 0 {
			key := certs.NormalizeHexBytesNoSepUpper(c.SubjectKeyId)
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
		// Continue
		current = issuerCert
	}
}

func fetchRemoteCert(url string) (*x509.Certificate, error) {
	resp, err := http.Get(url) //nolint:noctx
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
	// AIA CA Issuers often returns DER or PKCS7; try to extract first cert
	if cert, err := tryParseSingleCert(data); err == nil && cert != nil {
		return cert, nil
	}
	return nil, fmt.Errorf("no certificate found at URL")
}

func tryParseSingleCert(data []byte) (*x509.Certificate, error) {
	return certs.ParseCertificateOrPKCS7(data)
}
