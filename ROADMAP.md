# Roadmap

Items are organized into four phases in rough priority order. Phases are not strictly
sequential — items within a phase can be worked in any order. Use this file to track
planned work and archive completed items over time.

---

## Phase 1 — Foundation (Testing & Refactoring)

These items improve the stability and maintainability of the existing codebase before
adding significant new functionality. They have no user-visible impact but are critical
for sustainable development.

### Testing

- [x] Add `testify` as a **direct** dependency in `go.mod` (currently only indirect)
- [x] Unit tests for `internal/certs/format.go`
  - `FormatHex()` — all three separator modes, empty input, odd-length input
  - `FormatSerialWithSep()` — leading-zero preservation, zero value, large serial
  - `MapOIDToName()` — known OIDs in both name styles, unknown OID passthrough
  - `ExtractNameAttributes()` — multi-value RDNs, empty input
  - `KeyUsageNames()` / `ExtKeyUsageNames()` — all flag combinations
  - `NISTCurveName()` — known and unknown curve names
- [x] Unit tests for `internal/certs/parser.go`
  - Valid PEM (single cert, multi-block bundle)
  - Valid DER
  - Invalid / empty input error handling
  - PEM block with wrong type (non-CERTIFICATE block)
- [x] Unit tests for `internal/prefs/prefs.go`
  - `Default()` returns all expected fields
  - `Load()` round-trips through `Save()`
  - `Load()` falls back to defaults for missing or invalid fields
  - `Load()` returns defaults when file does not exist
- [x] Unit tests for `internal/resources/fetcher.go`
  - `parseSKIToUpperHex()` — colon-separated hex, space-separated hex, base64, empty
  - `parseCCADBDate()` — all supported layouts, invalid input
  - `LoadCCADBSKISet()` / `LoadCCADBSummary()` — mock CSV input covering edge cases
- [x] Unit tests for `internal/resources/localroots.go`
  - `needsRegen()` — legacy JSON detection
  - JSON generation from a synthetic PEM bundle (no filesystem dependency)

### Refactoring

- [x] Remove dead code: `escapeMarkdown()` in `cmd/cert_viewer/main.go` (never called)
- [x] Consolidate duplicate hex formatting — `formatHex()` and `formatSerialWithSep()`
  in `main.go` duplicate logic from `internal/certs/format.go`; make `main.go` call
  the `certs` package versions
- [x] Refactor `main.go` — extract UI rendering functions into `internal/ui/` packages:
  - `internal/ui/summary/` — `refreshSummaryAndDetails()` rendering logic
  - `internal/ui/chain/` — `buildAndRenderChain()` and `tryParseSingleCert()`
  - `internal/ui/advanced/` — `buildAdvancedComparison()` rendering
  - `internal/ui/dialogs/` — preferences dialog, CCADB status dialog
  - Leave `main()` as a thin wiring layer (window setup, menu, event routing)

---

## Phase 2 — Platform Support & Distribution

### Windows Trust Store

- [ ] Implement Windows system trust store reading using `crypto/x509.SystemCertPool()`
  or the `golang.org/x/sys/windows` package to enumerate the `ROOT` store
- [ ] Generate `local_roots.json` equivalent on Windows
- [ ] Verify "Compare Local vs CCADB" works end-to-end on Windows

### macOS Trust Store

- [ ] Implement macOS system trust store reading using `crypto/x509.SystemCertPool()`
  or `security` CLI (`security find-certificate -a -p /System/Library/...`)
- [ ] Generate `local_roots.json` equivalent on macOS
- [ ] Verify "Compare Local vs CCADB" works end-to-end on macOS

### GitHub Actions CI / Release Pipeline

- [ ] Add `.github/workflows/ci.yml` — run `go test ./...` on push/PR for Linux
- [ ] Add `.github/workflows/release.yml` — build release artifacts on tag push:
  - `cert_viewer-linux-amd64`
  - `cert_viewer-windows-amd64.exe` (cross-compile via `GOOS=windows`)
  - `cert_viewer-darwin-amd64` and `cert_viewer-darwin-arm64`
- [ ] Add `README.md` build status badge once CI is configured

### Installers / Bundles

- [ ] macOS: `.app` bundle and `.dmg` disk image
- [ ] Windows: installer via NSIS or WiX (or `go-msi`)
- [ ] Linux: AppImage for distro-agnostic distribution (optional)

---

## Phase 3 — Core Feature Gaps

### PKCS#7 Support in AIA Downloads

- [ ] In `tryParseSingleCert()` (chain builder), detect PKCS#7/CMS `Content-Type`
  response header or attempt PKCS#7 parse using `golang.org/x/crypto/pkcs12` or
  `go.mozilla.org/pkcs7`
- [ ] Extract the signer certificate (or all certificates) from the bundle
- [ ] Fall back gracefully with a clear error if parsing fails

### Asynchronous Chain Building

- [ ] Move `buildAndRenderChain()` HTTP fetches off the UI goroutine
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

_Items will be moved here when done. Include the date and a short note._

- [x] **2026-02-18** — Added CLAUDE.md, ROADMAP.md, rewrote TECHNOLOGY.md, and updated
  README.md to establish a Claude Code-idiomatic development workflow for ongoing feature work.
- [x] **2026-02-18** — Phase 1 testing: added unit tests for all internal packages
  (`internal/certs`, `internal/prefs`, `internal/resources`). Coverage: certs 100%,
  prefs 82.6%, resources 83.3%. Promoted testify to direct dependency.
- [x] **2026-02-18** — Phase 1 refactoring: removed dead code (`escapeMarkdown`, `formatHex`,
  `normalizeHex`), consolidated duplicate helpers (`formatSerialWithSep`), and extracted
  all UI rendering from `main.go` into `internal/ui/{summary,chain,advanced,dialogs}` sub-packages.
  `main.go` reduced from 723 lines to ~165 lines.
