# Roadmap

Items are organized into phases in rough priority order. Phases are not strictly
sequential — items within a phase can be worked in any order. Use this file to track
planned work and archive completed items over time.

Completed phases are archived in [docs/roadmaps/](docs/roadmaps/).

---

## Phase 2 — Platform Support & Distribution

### Installers / Bundles

- [x] macOS: `.app` bundle and `.dmg` disk image
- [x] Windows: installer via NSIS or WiX (or `go-msi`)
- [x] Linux: AppImage for distro-agnostic distribution (optional)

### Build Guides

One step-by-step Markdown guide per supported OS, covering: fetching the latest (or a
specific tagged) version of the source, installing all system prerequisites, running the
test suite, and producing the final distributable package (binary + installer/bundle).
Target files: `BUILD_GUIDE_LINUX.md`, `BUILD_GUIDE_WINDOWS.md`, `BUILD_GUIDE_MACOS.md`.

- [x] `BUILD_GUIDE_LINUX.md` — Debian/Ubuntu: apt dependencies, `go test`, binary + AppImage
- [x] `BUILD_GUIDE_WINDOWS.md` — TDM-GCC/MSYS2, cross-compile from Linux or native Windows build, NSIS installer
- [x] `BUILD_GUIDE_MACOS.md` — Xcode CLT, `go test`, binary + `.app` bundle + `.dmg`

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
  certificate details export, CRL Distribution Point Viewer, Check CRL button, multiple
  certificate comparison, documentation refresh).
