package chain

import (
	"context"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"cert_viewer/internal/certs"
	"cert_viewer/internal/httpclient"
	"cert_viewer/internal/prefs"
	"cert_viewer/internal/resources"
	"cert_viewer/internal/ui"
	"cert_viewer/internal/ui/summary"
)

const rootLocalNotCCADBMsg = "Root Certificate was found in local store, not found in CCADB"

// trustAnchorNotRootNoAIAMsg is shown when chain building stops on a non-self-signed CA
// that appears in a trust database but has no AIA URL to fetch the parent.
const trustAnchorNotRootNoAIAMsg = "This certificate is not a self-signed root. There is no CA Issuers URL to fetch the parent."

// resolvedParentViaAKIMsg explains metadata-only parent resolution when AIA is absent.
const resolvedParentViaAKIMsg = "Parent CA was matched using this certificate's Authority Key Identifier against the local store / CCADB (this certificate has no CA Issuers URL)."

// isSelfSigned reports whether cert is a trust root: signature verifies against itself when Go
// allows it, or Authority Key Identifier equals Subject Key Identifier (common for CA roots).
func isSelfSigned(cert *x509.Certificate) bool {
	if cert == nil {
		return false
	}
	if cert.CheckSignatureFrom(cert) == nil {
		return true
	}
	aki := certs.AuthorityKeyIdentifierKeyID(cert)
	if len(aki) > 0 && len(cert.SubjectKeyId) > 0 {
		return certs.NormalizeHexBytesNoSepUpper(aki) == certs.NormalizeHexBytesNoSepUpper(cert.SubjectKeyId)
	}
	return false
}

// certDetailScroll returns a scrollable two-column summary for cert (same content as Leaf/Issuer tabs).
func certDetailScroll(win fyne.Window, cert *x509.Certificate, p prefs.Preferences) fyne.CanvasObject {
	grid := container.New(ui.NewTightTwoColLayout())
	tmp := container.New(ui.NewTightTwoColLayout())
	summary.Render(win, grid, tmp, cert, p)
	if len(cert.SubjectKeyId) > 0 {
		grid.Add(ui.BoldLabel("Subject Key Identifier"))
		grid.Add(ui.CopyRow(win, certs.FormatHex(cert.SubjectKeyId, string(p.UI.HexSep))))
	}
	if aki := certs.AuthorityKeyIdentifierKeyID(cert); len(aki) > 0 {
		grid.Add(ui.BoldLabel("Authority Key Identifier"))
		grid.Add(ui.CopyRow(win, certs.FormatHex(aki, string(p.UI.HexSep))))
	}
	return container.NewVScroll(grid)
}

// buildCertTab constructs a tab item displaying certificate details.
func buildCertTab(win fyne.Window, title string, cert *x509.Certificate, p prefs.Preferences) *container.TabItem {
	return container.NewTabItem(title, certDetailScroll(win, cert, p))
}

// buildRootTab builds a tab with full certificate details. errorMsg uses error color (e.g. local-only
// trust); warningMsg uses warning color (e.g. chain stopped on an intermediate); infoMsg uses muted italic.
func buildRootTab(win fyne.Window, title string, cert *x509.Certificate, p prefs.Preferences, errorMsg, warningMsg, infoMsg string) *container.TabItem {
	scroll := certDetailScroll(win, cert, p)
	body := tabBodyWithNotices(scroll, errorMsg, warningMsg, infoMsg)
	return container.NewTabItem(title, body)
}

func trustKey(cert *x509.Certificate) string {
	if cert == nil || len(cert.SubjectKeyId) == 0 {
		return ""
	}
	return certs.NormalizeHexBytesNoSepUpper(cert.SubjectKeyId)
}

// appendTerminalRootTab adds a Root tab for a self-signed certificate using CCADB / local classification.
func appendTerminalRootTab(chainTabs *container.AppTabs, win fyne.Window, root *x509.Certificate, p prefs.Preferences, ccadbSet map[string]struct{}, localSet map[string]resources.LocalRootSummary) {
	key := trustKey(root)
	_, inCCADB := ccadbSet[key]
	_, inLocal := localSet[key]
	switch {
	case inCCADB:
		chainTabs.Append(buildRootTab(win, "Root (from CCADB)", root, p, "", "", ""))
	case inLocal:
		errMsg := ""
		if !inCCADB {
			errMsg = rootLocalNotCCADBMsg
		}
		chainTabs.Append(buildRootTab(win, "Root (from Local Store)", root, p, errMsg, "", ""))
	default:
		chainTabs.Append(buildRootTab(win, "Root (self-signed)", root, p, "", "", ""))
	}
}

// appendTrustAnchorTab adds a tab when the chain stops on a trusted intermediate (no AIA).
func appendTrustAnchorTab(chainTabs *container.AppTabs, win fyne.Window, cert *x509.Certificate, p prefs.Preferences, inCCADB, inLocal bool) {
	var title string
	var errMsg string
	switch {
	case inCCADB:
		title = "Trusted intermediate (from CCADB)"
	case inLocal:
		title = "Trusted intermediate (from Local Store)"
		if !inCCADB {
			errMsg = rootLocalNotCCADBMsg
		}
	default:
		return
	}
	chainTabs.Append(buildRootTab(win, title, cert, p, errMsg, trustAnchorNotRootNoAIAMsg, ""))
}

func isRootRecordType(recordType string) bool {
	return strings.Contains(strings.ToLower(recordType), "root")
}

// walkCCADBCAParent follows Authority Key Identifier links between CCADB rows until a root
// record or a dead end (max hops), starting from the SKI that matches an intermediate’s AKI.
// The returned skiKey is the map key for the final row (normalized subject key id of that CA).
func walkCCADBCAParent(bySKI map[string]resources.CCADBRow, startKey string) (row resources.CCADBRow, skiKey string, ok bool) {
	const maxHops = 8
	seen := make(map[string]bool)
	key := startKey
	var last resources.CCADBRow
	var lastKey string
	var foundAny bool
	for hop := 0; hop < maxHops; hop++ {
		if key == "" || seen[key] {
			break
		}
		seen[key] = true
		r, found := bySKI[key]
		if !found {
			break
		}
		last, lastKey, foundAny = r, key, true
		if isRootRecordType(r.RecordType) {
			return r, key, true
		}
		next := r.AuthorityKeyID
		if next == "" || next == key {
			return r, key, true
		}
		key = next
	}
	return last, lastKey, foundAny
}

func tabBodyWithNotices(scroll fyne.CanvasObject, errorMsg, warningMsg, infoMsg string) fyne.CanvasObject {
	var parts []fyne.CanvasObject
	if errorMsg != "" {
		rt := widget.NewRichText(&widget.TextSegment{
			Text: errorMsg,
			Style: widget.RichTextStyle{
				ColorName: theme.ColorNameError,
				TextStyle: fyne.TextStyle{Bold: true},
			},
		})
		rt.Wrapping = fyne.TextWrapWord
		parts = append(parts, rt)
	}
	if warningMsg != "" {
		wt := widget.NewRichText(&widget.TextSegment{
			Text:  warningMsg,
			Style: widget.RichTextStyle{ColorName: theme.ColorNameWarning},
		})
		wt.Wrapping = fyne.TextWrapWord
		parts = append(parts, wt)
	}
	if infoMsg != "" {
		it := widget.NewRichText(&widget.TextSegment{
			Text: infoMsg,
			Style: widget.RichTextStyle{
				ColorName: theme.ColorNameDisabled,
				TextStyle: fyne.TextStyle{Italic: true},
			},
		})
		it.Wrapping = fyne.TextWrapWord
		parts = append(parts, container.NewThemeOverride(it, infoNoticeTheme{}))
	}
	if len(parts) == 0 {
		return scroll
	}
	top := container.NewVBox(parts...)
	return container.NewBorder(top, nil, nil, nil, scroll)
}

func formatUpperHexKey(key string, sep string) string {
	if len(key) < 2 || len(key)%2 != 0 {
		return key
	}
	raw, err := hex.DecodeString(key)
	if err != nil {
		return key
	}
	return certs.FormatHex(raw, sep)
}

func formatLocalSKIStored(s, sep string) string {
	if s == "" {
		return ""
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') {
			b.WriteByte(c)
		}
	}
	keyUpper := strings.ToUpper(b.String())
	if len(keyUpper)%2 != 0 {
		return s
	}
	raw, err := hex.DecodeString(keyUpper)
	if err != nil {
		return s
	}
	return certs.FormatHex(raw, sep)
}

func buildLocalMetadataRootTab(win fyne.Window, loc resources.LocalRootSummary, p prefs.Preferences, errorMsg, warningMsg, infoMsg string) *container.TabItem {
	grid := container.New(ui.NewTightTwoColLayout())
	sep := string(p.UI.HexSep)
	add := func(k, v string) {
		if v == "" {
			return
		}
		grid.Add(ui.BoldLabel(k))
		grid.Add(ui.CopyRow(win, v))
	}
	add("Subject", loc.Subject)
	if loc.SubjectKeyIdentifier != "" {
		add("Subject Key Identifier", formatLocalSKIStored(loc.SubjectKeyIdentifier, sep))
	}
	add("Serial (hex)", loc.SerialHex)
	add("Not Before", loc.NotBefore)
	add("Not After", loc.NotAfter)
	add("SHA-256", loc.SHA256FingerprintHex)
	scroll := container.NewVScroll(grid)
	body := tabBodyWithNotices(scroll, errorMsg, warningMsg, infoMsg)
	return container.NewTabItem("Root (from Local Store)", body)
}

// tryAppendParentViaAuthorityKeyID adds a root/parent tab from local store or CCADB when the
// intermediate has no CA Issuers URL but its AKI matches another CA’s SKI in those sources.
func tryAppendParentViaAuthorityKeyID(
	ctx context.Context,
	chainTabs *container.AppTabs,
	win fyne.Window,
	intermediate *x509.Certificate,
	p prefs.Preferences,
	localSet map[string]resources.LocalRootSummary,
	ccadbSet map[string]struct{},
	ccadbBySKI map[string]resources.CCADBRow,
) bool {
	aki := certs.AuthorityKeyIdentifierKeyID(intermediate)
	if len(aki) == 0 {
		return false
	}
	parentKey := certs.NormalizeHexBytesNoSepUpper(aki)
	if parentKey == "" {
		return false
	}

	// Prefer the live system trust bundle (same source as collectRoots). The local_roots.json
	// index can be stale or disagree on normalization with cert AKI bytes; skipping that gate
	// avoids showing the intermediate again under a "trusted root" tab when the parent exists
	// on disk but was missing from the JSON map.
	if rootCert, err := resources.FindTrustedRootCertBySubjectKeyID(ctx, parentKey); err == nil && rootCert != nil {
		errMsg := ""
		if _, inC := ccadbSet[parentKey]; !inC {
			errMsg = rootLocalNotCCADBMsg
		}
		chainTabs.Append(buildRootTab(win, "Root (from Local Store)", rootCert, p, errMsg, "", resolvedParentViaAKIMsg))
		return true
	}

	if loc, ok := localSet[parentKey]; ok {
		errMsg := ""
		if _, inC := ccadbSet[parentKey]; !inC {
			errMsg = rootLocalNotCCADBMsg
		}
		chainTabs.Append(buildLocalMetadataRootTab(win, loc, p, errMsg, "", resolvedParentViaAKIMsg))
		return true
	}

	if row, resolvedSKI, ok := walkCCADBCAParent(ccadbBySKI, parentKey); ok {
		title := "Root (from CCADB)"
		if !isRootRecordType(row.RecordType) {
			title = "Parent CA (from CCADB)"
		}
		grid := container.New(ui.NewTightTwoColLayout())
		sep := string(p.UI.HexSep)
		add := func(k, v string) {
			if v == "" {
				return
			}
			grid.Add(ui.BoldLabel(k))
			grid.Add(ui.CopyRow(win, v))
		}
		add("Certificate name (CCADB)", row.CertificateName)
		add("Record type", row.RecordType)
		add("Valid from (GMT)", row.ValidFrom)
		add("Valid to (GMT)", row.ValidTo)
		if row.SHA256 != "" {
			add("SHA-256 fingerprint", strings.ToUpper(row.SHA256))
		}
		if resolvedSKI != "" {
			add("Subject Key Identifier", formatUpperHexKey(resolvedSKI, sep))
		}
		if row.AuthorityKeyID != "" {
			add("Authority Key Identifier (CCADB)", formatUpperHexKey(row.AuthorityKeyID, sep))
		}
		scroll := container.NewVScroll(grid)
		body := tabBodyWithNotices(scroll, "", "", resolvedParentViaAKIMsg)
		chainTabs.Append(container.NewTabItem(title, body))
		return true
	}

	return false
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
		ccadbSet, ccadbBySKI, _ := resources.LoadCCADBChainData(p)

		current := leaf
		for depth := 1; depth <= 5; depth++ {
			// Self-signed leaf or CA already in hand (crypto check; AKI/SKI alone can miss some roots).
			if isSelfSigned(current) {
				chainTabs.Append(container.NewTabItem("Self-signed", widget.NewLabel("This certificate is self-signed (signature verifies against itself).")))
				chainTabs.Refresh()
				return
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

			// True root is self-signed. CCADB lists intermediates too, so SKI match alone must not stop the walk.
			if isSelfSigned(issuerCert) {
				appendTerminalRootTab(chainTabs, win, issuerCert, p, ccadbSet, localSet)
				chainTabs.Refresh()
				return
			}

			key := trustKey(issuerCert)
			_, inCCADB := ccadbSet[key]
			_, inLocal := localSet[key]
			if inCCADB || inLocal {
				// Resolve parent by AKI against CCADB / OS trust store before relying on AIA.
				// Otherwise a CCADB-listed CA that still has a CA Issuers URL never gets
				// tryAppendParentViaAuthorityKeyID (BuildFromCerts had the same gap).
				if tryAppendParentViaAuthorityKeyID(ctx, chainTabs, win, issuerCert, p, localSet, ccadbSet, ccadbBySKI) {
					chainTabs.Refresh()
					return
				}
				if len(issuerCert.IssuingCertificateURL) == 0 {
					appendTrustAnchorTab(chainTabs, win, issuerCert, p, inCCADB, inLocal)
					chainTabs.Refresh()
					return
				}
				// Trusted in CCADB/local but parent not resolved here — follow CA Issuers URL next.
			}

			current = issuerCert
		}
	}()
}

// BuildFromCerts renders a pre-built certificate chain directly into chainTabs
// without any AIA fetching. certs[0] is the leaf; following entries are issuers
// toward the root. A self-signed last certificate is shown only as a Root tab, not
// duplicated as Issuer N. ctx is propagated to issuer-resolution helpers so
// long-running lookups can be cancelled with the surrounding request.
func BuildFromCerts(ctx context.Context, win fyne.Window, chainTabs *container.AppTabs, certList []*x509.Certificate, p prefs.Preferences) {
	chainTabs.Items = nil
	if len(certList) == 0 {
		chainTabs.Append(container.NewTabItem("No certificates", widget.NewLabel("The PKCS#12 bundle contained no certificates.")))
		chainTabs.Refresh()
		return
	}

	chainTabs.Append(buildCertTab(win, "Leaf", certList[0], p))

	n := len(certList)
	if n == 1 {
		chainTabs.Refresh()
		return
	}

	last := certList[n-1]
	ccadbSet, ccadbBySKI, _ := resources.LoadCCADBChainData(p)
	localSet, _ := resources.LoadLocalRootsSKISet()

	issuerNum := 1
	for i := 1; i < n; i++ {
		if i == n-1 && isSelfSigned(last) {
			break
		}
		chainTabs.Append(buildCertTab(win, fmt.Sprintf("Issuer %d", issuerNum), certList[i], p))
		issuerNum++
	}

	if isSelfSigned(last) {
		appendTerminalRootTab(chainTabs, win, last, p, ccadbSet, localSet)
		chainTabs.Refresh()
		return
	}

	key := trustKey(last)
	_, inCCADB := ccadbSet[key]
	_, inLocal := localSet[key]
	if inCCADB || inLocal {
		if tryAppendParentViaAuthorityKeyID(ctx, chainTabs, win, last, p, localSet, ccadbSet, ccadbBySKI) {
			chainTabs.Refresh()
			return
		}
		appendTrustAnchorTab(chainTabs, win, last, p, inCCADB, inLocal)
	}

	chainTabs.Refresh()
}

func fetchRemoteCert(ctx context.Context, url string) (*x509.Certificate, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := httpclient.Default().Do(req)
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
