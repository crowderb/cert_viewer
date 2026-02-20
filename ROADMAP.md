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

## Phase 4 — Advanced Features

### Multiple Certificate Comparison

- [ ] Allow opening two certificates side-by-side in a split view
- [ ] Highlight fields that differ between the two certificates

### Add Check CRL button ✅ Completed 2026-02-19
- [x] add button on summary page with label 'Check CRL'
- [x] When Check CRL button is pressed, fetch the CRL, and check the current certificate against it. If not on CRL list, indicate 'Good' with green text. If on crl list, indicate 'REVOKED' with red text
---

## Completed

_Summary of completed phases. Full details in [docs/roadmaps/](docs/roadmaps/)._

- **2026-Q1** ([archive](docs/roadmaps/2026-Q1.md)) — Phase 1 Foundation complete:
  project setup (CLAUDE.md, ROADMAP.md, TECHNOLOGY.md, README.md), unit test suite
  (certs 100%, prefs 82.6%, resources 83.3%), and full refactoring of `main.go` into
  `internal/ui/` sub-packages. Phase 2 platform support (Windows trust store, macOS
  trust store, GitHub Actions CI/release pipeline). Phase 3 core features complete
  (async chain building, PKCS#12/PFX, CSR viewing, preferences CCADB/refresh UI, CCADB
  version auto-discovery, PKCS#7 AIA support). Phase 4 advanced features complete
  (URL-based cert loading, OCSP status checking, validity color-coding, recent files,
  certificate details export, CRL Distribution Point Viewer).
