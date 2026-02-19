# Roadmap

Items are organized into phases in rough priority order. Phases are not strictly
sequential — items within a phase can be worked in any order. Use this file to track
planned work and archive completed items over time.

Completed phases are archived in [docs/roadmaps/](docs/roadmaps/).

---

## Phase 2 — Platform Support & Distribution

### Installers / Bundles

- [ ] macOS: `.app` bundle and `.dmg` disk image
- [ ] Windows: installer via NSIS or WiX (or `go-msi`)
- [ ] Linux: AppImage for distro-agnostic distribution (optional)

---

## Phase 3 — Core Feature Gaps

### Asynchronous Chain Building

- [x] Move `chain.Build()` HTTP fetches off the UI goroutine
- [x] Show a progress indicator (spinner or status label) while chain is being built
- [x] Allow cancellation if the user opens a different certificate mid-build
- [x] Display partial chain if any intermediate fetch fails (currently stops at first error)

**Completed 2026-02-18.**

### PKCS#12 / PFX File Support

- [x] Add `.pfx` / `.p12` to the file open dialog filter
- [x] Parse PKCS#12 bundles using `golang.org/x/crypto/pkcs12`
- [x] Display the end-entity certificate (ignore private key material entirely)
- [x] If the bundle contains a chain, display it in the Chain tab directly
  (no AIA fetching needed)
- [x] Prompt for password if the bundle is encrypted (most are)

**Completed 2026-02-19.**

### Certificate Signing Request (CSR) Viewing

- [x] Add `.csr` / `.req` to the file open dialog filter
- [x] Parse CSR using `crypto/x509.ParseCertificateRequest()`
- [x] Display requested Subject, SANs, public key, and requested extensions
- [x] Show a clear indication in the UI that this is a request, not an issued cert

**Completed 2026-02-19.**

---

## Phase 4 — Advanced Features

### URL-Based Certificate Loading

- [x] Add a "Open URL" option in the File menu
- [x] Accept an HTTPS URL, connect via `crypto/tls`, and retrieve the server's
  leaf certificate (and any chain presented by the server)
- [x] Load the leaf cert into the viewer; populate the Chain tab from the TLS handshake
  chain directly (no AIA fetching needed if server provides the full chain)

**Completed 2026-02-19.**

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

_Summary of completed phases. Full details in [docs/roadmaps/](docs/roadmaps/)._

- **2026-Q1** ([archive](docs/roadmaps/2026-Q1.md)) — Phase 1 Foundation complete:
  project setup (CLAUDE.md, ROADMAP.md, TECHNOLOGY.md, README.md), unit test suite
  (certs 100%, prefs 82.6%, resources 83.3%), and full refactoring of `main.go` into
  `internal/ui/` sub-packages. Phase 2 platform support (Windows trust store, macOS
  trust store, GitHub Actions CI/release pipeline). Phase 3 core features (preferences
  CCADB/refresh UI, CCADB version auto-discovery, PKCS#7 AIA support). Phase 4 partial
  (Advanced tab color-coding).
