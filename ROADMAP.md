# Roadmap

Items are organized into phases in rough priority order. Phases are not strictly
sequential — items within a phase can be worked in any order. Use this file to track
planned work and archive completed items over time.

Completed phases are archived in [docs/roadmaps/](docs/roadmaps/).

---

## Phase 2 — Platform Support & Distribution

### Windows Trust Store

- [x] Implement Windows system trust store reading using `golang.org/x/sys/windows`
  to enumerate the `ROOT` store via `CertEnumCertificatesInStore`
- [x] Generate `local_roots.json` equivalent on Windows
- [x] Verify "Compare Local vs CCADB" works end-to-end on Windows

**Completed 2026-02-18.**

### macOS Trust Store

- [x] Implement macOS system trust store reading using `security` CLI
  (`security find-certificate -a -p /System/Library/Keychains/SystemRootCertificates.keychain`)
- [x] Generate `local_roots.json` equivalent on macOS
- [x] Verify "Compare Local vs CCADB" works end-to-end on macOS

**Completed 2026-02-18.**

### GitHub Actions CI / Release Pipeline

- [x] Add `.github/workflows/ci.yml` — run `go test ./...` on push/PR for Linux
- [x] Add `.github/workflows/release.yml` — build release artifacts on tag push:
  - `cert_viewer-linux-amd64`
  - `cert_viewer-windows-amd64.exe` (cross-compile via `GOOS=windows`)
  - `cert_viewer-darwin-amd64` and `cert_viewer-darwin-arm64`
- [x] Add `README.md` build status badge once CI is configured

**Completed 2026-02-18.**

### Installers / Bundles

- [ ] macOS: `.app` bundle and `.dmg` disk image
- [ ] Windows: installer via NSIS or WiX (or `go-msi`)
- [ ] Linux: AppImage for distro-agnostic distribution (optional)

---

## Phase 3 — Core Feature Gaps

### Preferences: Editable CCADB URL and Refresh Interval

- [x] Extend the Preferences dialog (Edit → Preferences) with a "Resources" section
  containing two editable fields:
  - **CCADB URL** — text entry pre-populated from `prefs.Preferences.Resources.CCADBURL`;
    saved back to `preferences.json` on confirm; validated to be non-empty (resets to
    default if cleared)
  - **Refresh Days** — numeric entry pre-populated from
    `prefs.Preferences.Resources.RefreshDays`; controls how many days the cached CSV is
    considered fresh before a background re-download is triggered
- [x] Implementation in `internal/ui/dialogs/dialogs.go` (`ShowPreferences`): add a
  `widget.Separator` and two `widget.Entry` fields below the existing hex-separator radio
  group; bind the `onApply` callback to persist both values via `prefs.Save`
- [x] Validation mirrors `prefs.Load()` rules: empty CCADB URL → reset to default;
  RefreshDays ≤ 0 → reset to 30

**Completed 2026-02-18.**

### CCADB Version Auto-Discovery

- [x] During each CCADB refresh cycle (`EnsureCCADBCSV` in `internal/resources/fetcher.go`),
  fetch `https://www.ccadb.org/resources` (stored as `prefs.Resources.CCadbResourcesURL`)
  and parse the HTML to extract the current "All Certificate Records" CSV download URL
  via regex match on `AllCertificateRecordsCSVFormat`
- [x] Compare the discovered URL against `p.Resources.CCADBURL`; if they differ, update
  `prefs.CCADBURL` and call `prefs.Save()` before downloading
- [x] Derive the local cache filename dynamically from the URL path segment via
  `prefs.CacheFilenameFromURL`; store as `prefs.Resources.CachedFilename`
- [x] When the filename changes between versions, delete the stale cache file so the new
  version is fetched fresh
- [x] If the resources page is unreachable, fall back gracefully to the stored URL
- [x] Unit tests in `internal/resources/fetcher_test.go`: `TestDiscoverLatestCCADBURL`
  (mock HTML for v2/v3, no-match, 404) and `TestEnsureCCADBCSV` covering discovery
  update, version-change file deletion, and discovery-failure fallback
- [x] CCADB CSV dialog shows Discovery URL, download URL, and cache file status

**Completed 2026-02-18.**

### PKCS#7 Support in AIA Downloads

- [x] In `tryParseSingleCert()` (chain builder), detect PKCS#7/CMS `Content-Type`
  response header or attempt PKCS#7 parse using `go.mozilla.org/pkcs7`
- [x] Extract the signer certificate (or all certificates) from the bundle
- [x] Fall back gracefully with a clear error if parsing fails

**Completed 2026-02-18.**

### Asynchronous Chain Building

- [ ] Move `chain.Build()` HTTP fetches off the UI goroutine
- [ ] Show a progress indicator (spinner or status label) while chain is being built
- [ ] Allow cancellation if the user opens a different certificate mid-build
- [ ] Display partial chain if any intermediate fetch fails (currently stops at first error)

### PKCS#12 / PFX File Support

- [ ] Add `.pfx` / `.p12` to the file open dialog filter
- [ ] Parse PKCS#12 bundles using `golang.org/x/crypto/pkcs12`
- [ ] Display the end-entity certificate (ignore private key material entirely)
- [ ] If the bundle contains a chain, display it in the Chain tab directly
  (no AIA fetching needed)
- [ ] Prompt for password if the bundle is encrypted (most are)

### Certificate Signing Request (CSR) Viewing

- [ ] Add `.csr` / `.req` to the file open dialog filter
- [ ] Parse CSR using `crypto/x509.ParseCertificateRequest()`
- [ ] Display requested Subject, SANs, public key, and requested extensions
- [ ] Show a clear indication in the UI that this is a request, not an issued cert

---

## Phase 4 — Advanced Features

### URL-Based Certificate Loading

- [ ] Add a "Open URL" option in the File menu
- [ ] Accept an HTTPS URL, connect via `crypto/tls`, and retrieve the server's
  leaf certificate (and any chain presented by the server)
- [ ] Load the leaf cert into the viewer; populate the Chain tab from the TLS handshake
  chain directly (no AIA fetching needed if server provides the full chain)

### OCSP Status Checking

- [ ] Add an "OCSP Status" row to the Summary tab for certificates that have an
  OCSP URL in their AIA extension
- [ ] Query the OCSP responder using `golang.org/x/crypto/ocsp` when the cert is loaded
  (or on demand via a button to avoid latency on every open)
- [ ] Display: Good / Revoked (with revocation time and reason) / Unknown / Error

### Advanced Tab: Local-Only Certificate Count Color-Coding

- [x] In the "Certificates in Local Store Only" section of the Advanced tab, color the
  count/status indicator based on whether any local-only certs are present:
  - Green text if the count is zero ("(none)") — local store is fully covered by CCADB
  - Red text if one or more certificates are found locally but not in CCADB — signals
    certs that are trusted locally but not tracked in the common authority database
- [x] Implementation in `internal/ui/advanced/advanced.go`: replace the plain
  `widget.NewLabel("(none)")` / `widget.NewLabel(fmt.Sprintf("(%d)", ...))` calls with
  `canvas.NewText(...)` using `color.NRGBA` for green (e.g. `{R:0, G:180, B:0, A:255}`)
  and red (e.g. `{R:200, G:0, B:0, A:255}`)

### Validity Color-Coding

- [ ] Color the "Not After" / "Valid To" field red if the certificate is expired
- [ ] Color it yellow/amber if expiration is within a configurable threshold (default: 30 days)
- [ ] Apply the same coloring to chain sub-tabs

### Recent Files

- [ ] Persist the last N (default: 10) opened file paths in preferences
- [ ] Add a "Recent Files" submenu under File menu
- [ ] Remove entries from the list if the file no longer exists

### Certificate Details Export

- [ ] Add an "Export Details" option (File menu or context menu) that writes a
  human-readable `.txt` file of the current certificate's Summary + Details content
- [ ] Include an option to copy all details to clipboard in one action

### Multiple Certificate Comparison

- [ ] Allow opening two certificates side-by-side in a split view
- [ ] Highlight fields that differ between the two certificates

### CRL Distribution Point Viewer

- [ ] When a certificate contains CRL Distribution Points, add a button to fetch and
  display the CRL (list of revoked serial numbers)
- [ ] Show: issuer, this update, next update, entry count, and a searchable list of
  revoked serials with revocation dates and reasons

---

## Completed

_Summary of completed phases. Full details in [docs/roadmaps/](docs/roadmaps/)._

- **2026-Q1** ([archive](docs/roadmaps/2026-Q1.md)) — Phase 1 Foundation complete:
  project setup (CLAUDE.md, ROADMAP.md, TECHNOLOGY.md, README.md), unit test suite
  (certs 100%, prefs 82.6%, resources 83.3%), and full refactoring of `main.go` into
  `internal/ui/` sub-packages.
