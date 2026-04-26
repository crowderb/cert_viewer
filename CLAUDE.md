# cert_viewer – Claude Code Guide

This file gives Claude Code context about this project so it can assist effectively
without re-discovering the same information each session.

---

## Project Overview

`cert_viewer` is a cross-platform desktop GUI application for inspecting X.509 digital
certificates. Think of it as a native GUI alternative to `openssl x509 -text`, with
additional capabilities: certificate chain building via AIA URLs, comparison of local
system trust roots against the CCADB (Mozilla CA Certificate Database), and flexible
formatting preferences.

**Target platforms:** Linux, Windows, macOS
**Distribution:** GitHub release binaries built via GitHub Actions CI

---

## Quick Start

The Go toolchain is pinned in `go.mod` (`toolchain go1.25.9`). Contributors
should install at least that version (Go's `toolchain` directive will fetch
it automatically on first build if a newer version is installed locally; on
older versions the `go` command refuses to build until you upgrade). Grab a
release from <https://go.dev/dl/> if needed.

```bash
# Install system dependencies (Linux/Debian-Ubuntu only)
sudo apt install -y build-essential libgl1-mesa-dev xorg-dev \
  libxcursor-dev libxrandr-dev libxinerama-dev libxi-dev

# Fetch Go module dependencies
go mod tidy

# Run from source
go run ./cmd/cert_viewer

# Build binary
go build -o bin/cert_viewer ./cmd/cert_viewer

# Run tests
go test ./...

# Run lint (matches CI; pin matches .golangci.yml + ci.yml)
go install github.com/golangci/golangci-lint/cmd/golangci-lint@v1.64.8
golangci-lint run ./...

# Vulnerability scan (matches CI vuln job; blocking)
go install golang.org/x/vuln/cmd/govulncheck@v1.3.0
govulncheck ./...

# One-time: install both pre-commit and pre-push hooks
#   pre-commit stage: gofmt, goimports, incremental golangci-lint (fast)
#   pre-push   stage: go test -race ./..., govulncheck ./... (slower; once per push)
pip install --user pre-commit   # or: pipx install pre-commit
pre-commit install --hook-type pre-commit --hook-type pre-push
```

---

## Architecture

The project uses a four-layer architecture inside a standard Go module layout:

```
cmd/cert_viewer/main.go          ← Application entry point; all UI orchestration
internal/
  certs/                         ← Pure certificate parsing and formatting (no UI)
    parser.go                    ← PEM/DER parsing
    format.go                    ← Hex, OID, key usage, curve name formatting
  prefs/
    prefs.go                     ← Preferences types, JSON load/save, OS path helpers
  resources/
    fetcher.go                   ← CCADB CSV download, caching, SKI set loading
    localroots.go                ← Linux trust bundle parsing → local_roots.json
  ui/
    tightform.go                 ← Custom Fyne two-column compact layout
```

**Data flow — opening a certificate:**
1. User opens a file (dialog or drag-and-drop) → `main.go`
2. `certs.ParseCertificate()` tries PEM then falls back to raw DER
3. `refreshSummaryAndDetails()` builds the Summary and Details tabs using
   `TightTwoColLayout` and `certs.Format*()` helpers
4. `buildAndRenderChain()` walks AIA CA Issuers URLs up to 5 hops, checking each
   intermediate's SKI against the local trust store then CCADB

**Data flow — CCADB integration:**
1. On startup, `resources.EnsureCCADBCSV()` spawns a goroutine that checks file age
   and fetches the CSV from Salesforce if stale (>30 days by default)
2. CSV is written atomically (`.tmp` → `os.Rename()`) to `~/.cache/cert_viewer/`
3. `resources.LoadCCADBSKISet()` / `LoadCCADBSummary()` read the cached CSV and
   return maps keyed by normalized uppercase-hex SKI

**Data flow — local trust store (Linux):**
1. `resources.EnsureLocalRootsJSON()` is called lazily (only when "Compare Local vs
   CCADB" is triggered) to keep startup fast
2. Parses `/etc/ssl/certs/ca-certificates.crt` (Debian/Ubuntu PEM bundle)
3. Serializes per-cert metadata (Subject, SKI, serial, fingerprint, validity) to
   `~/.cache/cert_viewer/local_roots.json`

---

## Key Files

| File | Lines | Role |
|------|-------|------|
| `cmd/cert_viewer/main.go` | ~723 | Entry point; all UI logic and tab orchestration |
| `internal/certs/parser.go` | 33 | `ParseCertificate([]byte)` — PEM then DER |
| `internal/certs/format.go` | 213 | Formatting: hex, OIDs, key usage, NIST curve names |
| `internal/prefs/prefs.go` | 137 | `Preferences` struct, `Load()`, `Save()`, path helpers |
| `internal/resources/fetcher.go` | 285 | CCADB CSV fetch, cache, SKI/summary loading |
| `internal/resources/localroots.go` | 189 | Linux trust store → `local_roots.json` |
| `internal/ui/tightform.go` | 90 | `TightTwoColLayout` — compact two-column Fyne layout |

---

## Runtime Paths

| Purpose | Path |
|---------|------|
| Preferences | `~/.config/cert_viewer/preferences.json` |
| CCADB CSV cache | `~/.cache/cert_viewer/ccadb_all_certificate_records_v2.csv` |
| Local roots cache | `~/.cache/cert_viewer/local_roots.json` |

### Trust-Store Source Resolution (Linux)

The local-roots cache is built from a configurable source. On Linux, resolution
order matches Go's `crypto/x509` and most other TLS-using tools:

1. `SSL_CERT_FILE` — alternate bundle path (used as-is if it exists and is readable)
2. `SSL_CERT_DIR` — colon-separated list of directories; every `*.pem` / `*.crt`
   / `*.cer` file in any listed directory is parsed and merged
3. `/etc/ssl/certs/ca-certificates.crt` — the Debian/Ubuntu default bundle

The resolved source is recorded in `local_roots.json` as `sourcePath` (the
plain path for a single bundle, or a `DIR:`-prefixed colon-separated list for
the directory case). The cache is regenerated automatically when the source
identifier changes between runs (e.g. `SSL_CERT_FILE` was added/removed) or
when the source's mtime is newer than the cache's mtime (e.g. an admin ran
`update-ca-certificates`). On macOS and Windows the source identifier is a
fixed string and the mtime check is skipped, since neither platform exposes a
single stat-able file for the system trust store.

### Trust Sources & Origin Labels

Each cached root is tagged with one or more `Origins`, recording where the
cert was observed. The Trust Sources tab (Resources → Trust Sources) groups
certs by origin and the Compare Local vs CCADB tab surfaces the origin
labels per cert. Origin constants live in `internal/resources/localroots.go`:

| Constant | Meaning |
|----------|---------|
| `OriginSystemBundle` | Default OS bundle (e.g. `/etc/ssl/certs/ca-certificates.crt`, macOS SystemRoots, Windows `ROOT` store) |
| `OriginEnvOverride` | Bundle resolved from `SSL_CERT_FILE` / `SSL_CERT_DIR` |
| `OriginDistroAnchorDir` | Admin-installed PEMs in the per-distro anchor directory (Debian: `/usr/local/share/ca-certificates`, RHEL: `/etc/pki/ca-trust/source/anchors`, Arch: `/etc/ca-certificates/trust-source/anchors`, SUSE: `/etc/pki/trust/anchors`) |
| `OriginNSSUser` | Per-user NSS DB at `~/.pki/nssdb` (read via `certutil` from `libnss3-tools`) |
| `OriginNSSFirefox` | Each `~/.mozilla/firefox/<profile>/cert9.db` |

A single cert may carry multiple origins — for example, a homelab CA
installed via `update-ca-certificates` shows both `system-bundle` and
`distro-anchor-dir`. NSS sources are read on Linux only and require the
`certutil` CLI; the Trust Sources tab shows a clear note instead of an
error when the tool is missing or a profile DB is absent.

Distro detection uses `/etc/os-release` (`ID`, then `ID_LIKE`) so derived
distros (Mint, Manjaro, Rocky, Alma, Amazon Linux, Pop, etc.) inherit
their parent family's anchor directory automatically.

---

## Code Conventions Used in This Project

- **Error handling:** Always check errors; wrap with context using `fmt.Errorf("context: %w", err)`
- **Formatting:** Run `gofmt` before committing
- **Linting:** `.golangci.yml` at the repo root is the source of truth for the
  enabled linter set; CI runs `golangci-lint v1.64.8` as a blocking job
  (`.github/workflows/ci.yml`). Run `golangci-lint run ./...` locally before
  opening a PR. The config aligns with `~/.claude/languages/go.md`'s required
  linter list (`errcheck`, `staticcheck`, `gosec`, `revive`, `gocritic`,
  `bodyclose`, `errorlint`, `contextcheck`, `noctx`, `nilerr`, plus extras).
  When upgrading the pinned version, update both the GitHub Action and this
  doc together.
- **Vulnerability scanning:** CI runs `govulncheck ./...` as a blocking
  `vuln` job. Run it locally as part of the standard pre-PR workflow
  alongside `golangci-lint run ./...` and `go test -race -count=1 ./...`.
  When `govulncheck` flags a new finding, the right fix is usually a
  dependency or toolchain bump — `go.mod` pins `toolchain go1.25.9` for
  reproducibility, so security patches require updating the pin.
- **Hex normalization:** All SKIs are normalized to uppercase hex with no separator
  for internal comparisons (`NormalizeHexBytesNoSepUpper` in `format.go`)
- **Goroutines for I/O:** Background operations (CCADB fetch, local roots generation)
  use goroutines; UI updates must go through `fyne.Do()` or be called from UI goroutine
- **Atomic writes:** Temporary file + `os.Rename()` for any file that must not be
  partially written (see `fetcher.go`)
- **Preferences:** Access via `prefs.Load()` and `prefs.Save()` — never hard-code paths
- **HTTP client:** Use `internal/httpclient` (`httpclient.Default()` / `httpclient.CCADBDownload()`)
  for all outbound HTTP. `http.DefaultClient` is banned because it has no timeout — a
  misbehaving server that dribbles bytes forever defeats context-only deadlines since
  there is no idle-read timeout. Always thread `context.Context` through to
  `http.NewRequestWithContext`.
- **Naming style:** Standard Go conventions; exported types/functions for anything used
  across packages; unexported for package-internal helpers

---

## Known Technical Debt

These are existing issues to be aware of when making changes. Do not work around them
silently — reference this list and address them as part of related work.

1. **Doc-comment lint coverage is partial** — `.golangci.yml` enables `revive` for
   `var-naming` only; the `exported` and `package-comments` rules are deliberately
   disabled. Roughly 30 missing exported-symbol doc comments and several missing
   package comments would surface if those rules were turned on. Plan to address as
   a follow-up cleanup task in the roadmap (Section 4 area) rather than churning
   the lint-bootstrap PR.

2. **Monolithic `main.go`** — all UI rendering (summary, details, chain, advanced
   comparison, all dialogs) lives in one ~723-line file. Refactoring into
   `internal/ui/` sub-packages is tracked in the roadmap.

3. **Duplicate hex formatting** — `formatHex()` and `formatSerialWithSep()` in
   `main.go` are near-duplicates of `certs.FormatHex()` and `certs.FormatSerialWithSep()`.
   The `main.go` versions accept `prefs.HexSeparator`; the `certs` versions accept
   `string`. Consolidate when touching either.

4. **`escapeMarkdown()` is dead code** — defined at the bottom of `main.go` but never
   called. Remove when refactoring that file.

5. **macOS trust store not yet supported** — `localroots_linux.go` reads
   `/etc/ssl/certs/ca-certificates.crt`; `localroots_windows.go` reads the Windows
   `ROOT` certificate store via `golang.org/x/sys/windows`. macOS (`localroots_unsupported.go`)
   returns an empty result — platform support is tracked in ROADMAP.md Phase 2.

6. **Synchronous chain building** — `buildAndRenderChain()` makes HTTP requests on the
   UI goroutine, which will freeze the UI during chain fetches. Async chain building
   with a progress indicator is in the roadmap.

7. **No PKCS#7 support** — AIA CA Issuers URLs sometimes return PKCS#7 bundles.
   `tryParseSingleCert()` will fail for these. Tracked in roadmap.

---

## Testing Strategy

Follow table-driven tests (idiomatic Go). Use `github.com/stretchr/testify/assert`
(already an indirect dependency via Fyne's dependency graph, but should be added as a
direct dependency when writing tests).

Priority order for new tests:
1. `internal/certs/` — pure functions, no I/O, easiest to test
2. `internal/prefs/` — JSON round-trip, defaults, invalid value handling
3. `internal/resources/` — SKI parsing (including hex vs base64), CSV parsing, date parsing
4. `cmd/cert_viewer/` — integration tests are last; UI testing with Fyne requires
   `fyne.io/fyne/v2/test` package

**Race detection:** Run `go test -race -count=1 ./...` before merging significant
changes. CI runs the same invocation as a blocking job; `-race` catches data
races at test time, `-count=1` defeats the test cache (which interacts poorly
with `-race` in CI). Plain `go test ./...` is fine for the inner edit-loop, but
the `-race` run is the merge gate.

---

## Git Workflow

- **Never commit directly to `main`** — create a feature branch
- **Conventional commits:** `feat:`, `fix:`, `refactor:`, `test:`, `docs:`, `chore:`
- **Squash before merging PRs**
- See global `~/.claude/CLAUDE.md` for full git practices

---

## Roadmap Reference

See [ROADMAP.md](ROADMAP.md) for the full prioritized feature and improvement backlog,
organized into four phases: Foundation → Platform Support → Core Features → Advanced Features.
