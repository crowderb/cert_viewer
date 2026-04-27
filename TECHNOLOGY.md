# Technology Reference

## Stack

| Component | Technology | Version | Rationale |
|-----------|------------|---------|-----------|
| Language | Go | 1.21+ | Cross-platform compilation, strong stdlib crypto, excellent concurrency |
| GUI framework | [Fyne](https://fyne.io) | v2.5.3 | Native cross-platform GUI in pure Go; no CGo required at the Go layer |
| Certificate parsing | `crypto/x509` (stdlib) | — | Full X.509 support built into Go's standard library |
| PKCS#7 parsing | `go.mozilla.org/pkcs7` | v0.9.0 | Handles PKCS#7 bundles returned by some AIA CA Issuers URLs |
| PKCS#12 / OCSP | `golang.org/x/crypto` | v0.47+ | PKCS#12 bundle parsing; OCSP request construction and response decoding |
| Windows trust store | `golang.org/x/sys` | v0.41+ | Windows `CertOpenSystemStore` / `CertEnumCertificatesInStore` API access |
| Rendering backend | OpenGL/GLFW | (indirect, via Fyne) | Hardware-accelerated rendering on Linux/Windows/macOS |
| Test assertions | `github.com/stretchr/testify` | v1.8.4 | Table-driven test helpers |

---

## Architecture

### Package Map

```
cert_viewer/
├── cmd/cert_viewer/
│   └── main.go                    # App entry point; file open / drag-drop / menu wiring
└── internal/
    ├── certs/
    │   ├── parser.go              # PEM/DER, PKCS#12, CSR, PKCS#7 parsing
    │   ├── format.go              # Pure formatting helpers (hex, OID, key usage, curves)
    │   ├── ocsp_check.go          # OCSP request construction and status decoding
    │   ├── crl_fetch.go           # CRL HTTP fetch, serial lookup, reason formatting
    │   └── tls_fetch.go           # TLS dial, host:port parsing, chain extraction
    ├── prefs/
    │   └── prefs.go               # Preferences: types, load, save, OS paths, recent files
    ├── resources/
    │   ├── fetcher.go             # CCADB CSV download, caching, SKI/summary extraction
    │   ├── localroots_linux.go    # Debian/Ubuntu: parse /etc/ssl/certs/ca-certificates.crt
    │   ├── localroots_windows.go  # Windows: read ROOT store via golang.org/x/sys
    │   ├── localroots_darwin.go   # macOS: Keychain extraction via `security find-certificate`
    │   └── localroots_unsupported.go  # Fallback for other platforms
    └── ui/
        ├── tightform.go           # TightTwoColLayout: compact two-column Fyne layout
        ├── widgets.go             # BoldLabel, CopyRow, ColoredCopyRow helpers
        ├── summary/               # Summary + Details tab rendering, validity colors, export
        ├── chain/                 # Async AIA chain building; PKCS#12 / TLS chain rendering
        ├── advanced/              # Local-vs-CCADB set comparison view
        ├── compare/               # Side-by-side certificate comparison (3-column diff)
        └── dialogs/               # Preferences, CCADB status, URL input, password, CRL viewer
```

### Layer Responsibilities

**`cmd/cert_viewer/main.go`** is the wiring layer. It owns:
- Window and tab lifecycle (Fyne `AppTabs`)
- File open dialog, drag-and-drop, Open URL dialog, and recent files
- Main menu construction and per-cert state (`currentCert`, `currentCertB`, cancel funcs)
- Delegating all rendering to `internal/ui/` sub-packages

All heavy logic and UI component construction lives in `internal/`:

**`internal/certs/`** is pure and side-effect-free. Every function takes plain Go
values and returns plain Go values or errors — no I/O, no globals, no Fyne types.
This makes it the easiest layer to unit test (100% coverage).

**`internal/prefs/`** owns all user-facing configuration. Uses OS-standard paths
(`os.UserConfigDir()`, `os.UserCacheDir()`) so preferences and caches land in the
right place on each platform. JSON serialization with `0o600` file permissions.

**`internal/resources/`** handles external data acquisition:
- CCADB CSV from Salesforce (network, cached locally, atomic write)
- Platform-specific system trust store (Linux crt bundle, Windows cert store API, macOS stub)

Both use goroutines so they do not block application startup.

**`internal/ui/`** contains all Fyne widget construction and layout logic:

| Sub-package | Responsibility |
|-------------|---------------|
| `ui` (top-level) | `TightTwoColLayout` custom layout; `BoldLabel`, `CopyRow`, `ColoredCopyRow` shared widgets |
| `ui/summary` | `Render()` — populates Summary + Details tabs; `ValidityColorName()`; `ExportText()` |
| `ui/chain` | `Build()` — async AIA walking; `BuildFromCerts()` — pre-built PKCS#12 or TLS chains |
| `ui/advanced` | `Build()` — local vs CCADB set comparison with three sections |
| `ui/compare` | `CompareLayout`, `ExtractFields()`, `BuildRows()`, `Render()` — 3-column diff view |
| `ui/dialogs` | `ShowPreferences()`, `ShowCCADB()`, `ShowOpenURL()`, `ShowPasswordPrompt()`, `ShowCRL()` |

---

## Key Data Flows

### Opening a Certificate File

```
User action (file dialog / drag-drop / Open Recent)
  → main.go reads file bytes
  → extension routing:
      .p12/.pfx  → certs.ParsePKCS12()    leaf + CA chain; password prompt if needed
      .csr/.req  → certs.ParseCSR()       CSR summary + details; no chain
      other      → certs.ParseCertificate()  PEM blocks then raw DER fallback
  → summary.Render()     populates Summary + Details tabs
  → chain.Build()        async AIA walk (goroutine); or chain.BuildFromCerts() for PKCS#12
  → compare.Render()     if Certificate B is loaded, refreshes Compare tab
```

### Opening a URL / Hostname

```
User: File > Open URL…  →  dialogs.ShowOpenURL()
  → certs.ParseHostPort()    normalises hostname:port input
  → certs.FetchTLSCerts()    dials TLS with 15s timeout
      → conn.ConnectionState().PeerCertificates  (leaf + intermediates)
  → main.go sets currentCert = chain[0], pkcs12Chain = chain
  → summary.Render() + chain.BuildFromCerts()
```

### OCSP Status Check

```
User clicks "Check OCSP" in Summary tab
  → goroutine: certs.CheckOCSP(ctx, cert, issuer)
      → fetches issuer cert via AIA if not already known
      → constructs OCSP request (golang.org/x/crypto/ocsp)
      → HTTP POST to cert.OCSPServer[0]
      → parses response → Good / Revoked / Unknown
  → certs.FormatOCSPStatus() → label text updated on UI goroutine
```

### CRL Fetch and Revocation Check

```
User clicks "Fetch CRL"
  → goroutine: certs.FetchCRL(ctx, url)
      → HTTP GET CRL Distribution Point URL
      → x509.ParseRevocationList()
  → dialogs.ShowCRL()  opens searchable dialog of revoked serials

User clicks "Check CRL"
  → goroutine: same FetchCRL path
  → certs.CheckCertInCRL(cert, rl)  linear scan of RevokedCertificateEntries
  → result shown as "Good" (green) or "REVOKED reason date" (red)
```

### Certificate Comparison

```
User opens Compare tab → clicks "Load Certificate B…"
  → file dialog (cert files only; no PKCS#12 or CSR)
  → certs.ParseCertificate()
  → compare.ExtractFields(certA, prefs) + compare.ExtractFields(certB, prefs)
      → 23 named fields (CN, Subject, Issuer, Serial, validity, key info, extensions, SANs, fingerprints)
  → compare.BuildRows()  zips field lists, sets Differs=true on mismatches
  → compare.Render()     populates 3-column grid; differing rows in theme.ColorNameWarning
```

### CCADB Refresh (background, on startup)

```
main() startup
  → resources.EnsureCCADBCSV()   returns a channel, spawns goroutine
      goroutine:
        fetch CCADB resources page → discover current CSV URL
        check ~/.cache/.../csv mtime
        if stale (> RefreshDays days):
          HTTP GET CSV from Salesforce
          write to .tmp file
          os.Rename() to final path
        send result (nil or error) on channel
  channel result logged if error; CSV available for subsequent reads
```

### Local Trust Store Comparison (on demand)

```
User selects Resources > Compare Local vs CCADB
  → goroutine: resources.EnsureLocalRootsJSON()
      Linux:   parse /etc/ssl/certs/ca-certificates.crt
      Windows: enumerate ROOT store via golang.org/x/sys Windows APIs
      macOS:   extract PEM from System Keychain via `security find-certificate` and parse
      → write ~/.cache/cert_viewer/local_roots.json
  → resources.LoadLocalRootsSKISet()  → map[SKI]LocalRootSummary
  → resources.LoadCCADBSummary()      → map[SKI]CCADBSummary
  → set operations: local-only, CCADB-only, both
  → advanced.Build() renders three sections
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

| Format | Supported | Notes |
|--------|-----------|-------|
| PEM (single cert) | Yes | `CERTIFICATE` block type |
| PEM (multi-cert bundle) | Yes | First `CERTIFICATE` block is used |
| DER (raw binary) | Yes | Fallback after PEM parse fails |
| PKCS#7 (p7b) | Yes (AIA only) | Parsed via `go.mozilla.org/pkcs7`; used when AIA CA Issuers URL returns a bundle |
| PKCS#12 (pfx) | Yes | Full chain extracted; encrypted bundles prompt for password |
| CSR (certificate request) | Yes | PEM and DER; Summary + Details view; chain not applicable |

---

## Platform Support Matrix

| Feature | Linux | Windows | macOS |
|---------|-------|---------|-------|
| GUI (Fyne) | Yes | Yes | Yes |
| Certificate parsing | Yes | Yes | Yes |
| Preferences / cache | Yes | Yes | Yes |
| CCADB comparison | Yes | Yes | Yes |
| Local trust store | Yes (Debian/Ubuntu) | Yes (Windows cert store) | Yes (Security framework) |
| GitHub Actions CI | Yes | Yes | Yes |

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

## Distribution

GitHub Actions CI runs on every push and pull request. Tagged releases automatically
build and attach binaries for all three platforms.

Release artifacts:
- `cert_viewer-linux-amd64`
- `cert_viewer-windows-amd64.exe`
- `cert_viewer-darwin-amd64` and `cert_viewer-darwin-arm64` (Apple Silicon)

---

## Known Technical Debt

See [CLAUDE.md](CLAUDE.md) for the full annotated list. Current outstanding items:

- **Partial test coverage** — `internal/certs/`, `internal/prefs/`, and
  `internal/resources/` have meaningful coverage; `cmd/cert_viewer/` and most
  `internal/ui/` sub-packages have none. UI testing requires `fyne.io/fyne/v2/test`.
- **macOS trust store (implemented)** — `localroots_darwin.go` now parses PEM output
  from `security find-certificate` and returns platform roots for comparison.
  (Previously listed as a stub; now implemented.)
- **Chain building is async** — `ui/chain.Build()` performs network I/O on a
  background goroutine, shows a spinner, and supports cancellation via
  `context.Context`.
