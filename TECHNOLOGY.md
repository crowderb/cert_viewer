# Technology Reference

## Stack

| Component | Technology | Version | Rationale |
|-----------|------------|---------|-----------|
| Language | Go | 1.21+ | Cross-platform compilation, strong stdlib crypto, excellent concurrency |
| GUI framework | [Fyne](https://fyne.io) | v2.5.3 | Native cross-platform GUI in pure Go; no CGo required at the Go layer |
| Certificate parsing | `crypto/x509` (stdlib) | — | Full X.509 support built into Go's standard library |
| Rendering backend | OpenGL/GLFW | (indirect, via Fyne) | Hardware-accelerated rendering on Linux/Windows/macOS |
| Test assertions | `github.com/stretchr/testify` | (indirect) | Table-driven test helpers; already in dependency graph via Fyne |

---

## Architecture

### Package Map

```
cert_viewer/
├── cmd/cert_viewer/
│   └── main.go               # Application entry point and UI orchestration
└── internal/
    ├── certs/
    │   ├── parser.go         # Certificate loading (PEM / DER)
    │   └── format.go         # Pure formatting helpers (hex, OID, key usage, curves)
    ├── prefs/
    │   └── prefs.go          # User preferences: types, load, save, OS path helpers
    ├── resources/
    │   ├── fetcher.go        # CCADB CSV: download, cache, SKI/summary extraction
    │   └── localroots.go     # Linux system trust store → local_roots.json
    └── ui/
        └── tightform.go      # TightTwoColLayout: custom Fyne compact two-column layout
```

### Layer Responsibilities

**`cmd/cert_viewer/main.go`** is the orchestration layer. It owns:
- Window and tab lifecycle (Fyne `TabContainer`)
- File open dialog and drag-and-drop handling
- `refreshSummaryAndDetails()` — renders Summary and Details tabs
- `buildAndRenderChain()` — walks AIA CA Issuers URLs up to 5 hops
- `buildAdvancedComparison()` — local store vs CCADB diff view
- All dialog construction (preferences, CCADB status)

This file is deliberately the integration point; data concerns live in `internal/`.
The file is currently large (~723 lines) and targeted for refactoring into
`internal/ui/` sub-packages (see ROADMAP.md Phase 1).

**`internal/certs/`** is pure and side-effect-free. Every function takes plain Go
values and returns plain Go values or errors — no I/O, no globals, no Fyne types.
This makes it the easiest layer to unit test.

**`internal/prefs/`** owns all user-facing configuration. It uses OS-standard paths
(`os.UserConfigDir()`, `os.UserCacheDir()`) so preferences and caches land in the
right place on each platform. JSON serialization with `0o600` file permissions.

**`internal/resources/`** handles external data acquisition:
- CCADB CSV from Salesforce (network, cached locally)
- Linux system trust bundle (filesystem)

Both use goroutines so they do not block application startup. The CCADB fetch uses
an atomic write pattern (download to `.tmp`, then `os.Rename()`).

**`internal/ui/`** currently contains only `TightTwoColLayout`. As `main.go` is
refactored, additional UI component packages will be added here.

---

## Key Data Flows

### Opening a Certificate

```
User action (file dialog / drag-drop)
  → main.go reads file bytes
  → certs.ParseCertificate()        tries PEM blocks, falls back to raw DER
  → *x509.Certificate
  → refreshSummaryAndDetails()      builds Summary + Details tabs
  → buildAndRenderChain()           follows AIA CA Issuers links
      → HTTP GET issuer cert
      → certs.ParseCertificate()    on fetched bytes
      → check SKI against local trust store (resources.LoadLocalRootsSKISet)
      → check SKI against CCADB     (resources.LoadCCADBSKISet)
      → render chain sub-tab
```

### CCADB Refresh (background, on startup)

```
main() startup
  → resources.EnsureCCADBCSV()     returns a channel, spawns goroutine
      goroutine:
        check ~/.cache/.../ccadb_all_certificate_records_v2.csv mtime
        if stale (> RefreshDays days):
          HTTP GET CSV from Salesforce
          write to .tmp file
          os.Rename() to final path
        send result (nil or error) on channel
  channel result logged if error; CSV available for subsequent reads
```

### Local Trust Store Comparison (on demand, Linux)

```
User selects Resources > Compare Local vs CCADB
  → goroutine: resources.EnsureLocalRootsJSON()
      open /etc/ssl/certs/ca-certificates.crt
      parse all PEM blocks → []x509.Certificate
      extract per-cert: Subject, SKI, serial, SHA-256, NotBefore, NotAfter
      write ~/.cache/cert_viewer/local_roots.json
  → resources.LoadLocalRootsSKISet()  → map[SKI]LocalRootSummary
  → resources.LoadCCADBSummary()      → map[SKI]CCADBSummary
  → set operations: local-only, CCADB-only, both
  → buildAdvancedComparison() renders three sections
```

---

## SKI Normalization

Subject Key Identifier comparison is the core matching mechanism used in chain
building and the local-vs-CCADB comparison. The CCADB CSV contains SKIs in
multiple formats (colon-separated hex, space-separated hex, and base64). The
`resources.parseSKIToUpperHex()` function handles all variants:

1. Strip all colons, spaces, and dashes from the input
2. If the result is valid hex: use it (uppercased)
3. Otherwise: attempt base64 decode and re-encode as uppercase hex

All internal comparisons use this normalized form.

---

## Certificate Format Support

| Format | Read | Notes |
|--------|------|-------|
| PEM (single cert) | Yes | `CERTIFICATE` block type |
| PEM (multi-cert bundle) | Yes | First `CERTIFICATE` block is used |
| DER (raw binary) | Yes | Fallback after PEM parse fails |
| PKCS#7 (p7b) | No | Returned by some AIA CA Issuers URLs — roadmap item |
| PKCS#12 (pfx) | No | Combined cert+key bundles — roadmap item |
| CSR (certificate request) | No | Roadmap item |

---

## Platform Support Matrix

| Feature | Linux | Windows | macOS |
|---------|-------|---------|-------|
| GUI (Fyne) | Yes | Yes | Yes |
| Certificate parsing | Yes | Yes | Yes |
| Preferences / cache | Yes | Yes | Yes |
| CCADB comparison | Yes | Yes | Yes |
| Local trust store | Yes (Debian/Ubuntu) | No | No |
| System trust store read | Partial | Roadmap | Roadmap |

### Build Prerequisites

**Linux (Debian/Ubuntu):**
```bash
sudo apt install -y build-essential libgl1-mesa-dev xorg-dev \
  libxcursor-dev libxrandr-dev libxinerama-dev libxi-dev
```

**Windows:** Fyne requires a C compiler. Install [TDM-GCC](https://jmeubank.github.io/tdm-gcc/)
or use MSYS2. Set `CGO_ENABLED=1`.

**macOS:** Xcode Command Line Tools provide the required C compiler:
```bash
xcode-select --install
```

---

## Distribution (Planned)

GitHub Actions CI will build release binaries for all three platforms on each tagged
release. See ROADMAP.md Phase 2 for the full distribution plan.

Planned artifacts:
- `cert_viewer-linux-amd64` (statically linked where possible)
- `cert_viewer-windows-amd64.exe`
- `cert_viewer-darwin-amd64` and `cert_viewer-darwin-arm64` (Apple Silicon)
- macOS `.app` bundle / `.dmg`
- Windows installer (NSIS or WiX)

---

## Known Technical Debt

See [CLAUDE.md](CLAUDE.md) for the full annotated list. Summary:

- No test coverage — highest priority gap
- Monolithic `main.go` — targeted for refactoring
- Duplicate hex formatting between `main.go` and `internal/certs/format.go`
- Dead code: `escapeMarkdown()` in `main.go`
- Linux-only trust store (Windows/macOS show empty comparison)
- Synchronous HTTP in chain builder (blocks UI goroutine)
- No PKCS#7 support in AIA downloads
