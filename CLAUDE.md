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

# Run tests (once test suite exists)
go test ./...
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

---

## Code Conventions Used in This Project

- **Error handling:** Always check errors; wrap with context using `fmt.Errorf("context: %w", err)`
- **Formatting:** Run `gofmt` before committing
- **Hex normalization:** All SKIs are normalized to uppercase hex with no separator
  for internal comparisons (`NormalizeHexBytesNoSepUpper` in `format.go`)
- **Goroutines for I/O:** Background operations (CCADB fetch, local roots generation)
  use goroutines; UI updates must go through `fyne.Do()` or be called from UI goroutine
- **Atomic writes:** Temporary file + `os.Rename()` for any file that must not be
  partially written (see `fetcher.go`)
- **Preferences:** Access via `prefs.Load()` and `prefs.Save()` — never hard-code paths
- **Naming style:** Standard Go conventions; exported types/functions for anything used
  across packages; unexported for package-internal helpers

---

## Known Technical Debt

These are existing issues to be aware of when making changes. Do not work around them
silently — reference this list and address them as part of related work.

1. **Zero test coverage** — no `_test.go` files exist. New code should include tests;
   existing packages (`certs/`, `prefs/`, `resources/`) are the highest priority targets.

2. **Monolithic `main.go`** — all UI rendering (summary, details, chain, advanced
   comparison, all dialogs) lives in one ~723-line file. Refactoring into
   `internal/ui/` sub-packages is tracked in the roadmap.

3. **Duplicate hex formatting** — `formatHex()` and `formatSerialWithSep()` in
   `main.go` are near-duplicates of `certs.FormatHex()` and `certs.FormatSerialWithSep()`.
   The `main.go` versions accept `prefs.HexSeparator`; the `certs` versions accept
   `string`. Consolidate when touching either.

4. **`escapeMarkdown()` is dead code** — defined at the bottom of `main.go` but never
   called. Remove when refactoring that file.

5. **Linux-only trust store** — `localroots.go` is hardcoded to
   `/etc/ssl/certs/ca-certificates.crt`. On Windows and macOS the comparison feature
   will silently produce an empty result. Platform-specific trust store support is in
   the roadmap.

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
