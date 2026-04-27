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

The project uses a layered Go module layout. The UI is now organized into focused
subpackages rather than being rendered entirely from `cmd/cert_viewer/main.go`.

```
cmd/cert_viewer/main.go          ← Application entry point; composes UI from internal/ui/*
internal/
   certs/                         ← Pure certificate parsing and formatting (no UI)
      parser.go                    ← PEM/DER parsing, PKCS#7-aware parsing helpers
      format.go                    ← Hex, OID, key usage, NIST curve name formatting
   prefs/                          ← Preferences types, JSON load/save, OS path helpers
      prefs.go
   resources/                      ← CCADB fetch, local roots, platform trust helpers
      fetcher.go                    ← CCADB CSV download, caching, SKI/summary loading
      localroots_linux.go           ← Linux trust bundle parsing → local_roots.json
      localroots_darwin.go          ← macOS Keychain extraction via `security find-certificate` |
   ui/                             ← Small UI packages used by `main.go`
      tightform.go                  ← Custom Fyne two-column compact layout
      chain/                        ← `internal/ui/chain` — chain building and tabs
      compare/                      ← `internal/ui/compare` — certificate comparison view
      summary/                      ← `internal/ui/summary` — summary/export helpers
      trustsources/                 ← `internal/ui/trustsources` — trust sources view
      advanced/                     ← `internal/ui/advanced` — advanced comparison features
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
| `internal/resources/localroots_linux.go` | 189 | Linux trust store → `local_roots.json` |
| `internal/resources/localroots_darwin.go` | 120 | macOS Keychain extraction via `security find-certificate` |
| `internal/ui/tightform.go` | 90 | `TightTwoColLayout` — compact two-column Fyne layout |
| `internal/ui/chain/chain.go` | 520 | Certificate chain building (async) and tab rendering |
| `internal/certs/parser.go` | 180 | `ParseCertificateOrPKCS7()` — handles PEM/DER and PKCS#7 bundles |

---

## Runtime Paths

| Purpose | Path |
|---------|------|
| Preferences | `~/.config/cert_viewer/preferences.json` |
| CCADB CSV cache | `~/.cache/cert_viewer/ccadb_all_certificate_records_v2.csv` |
| Local roots cache | `~/.cache/cert_viewer/local_roots.json` |
| Log file (Linux) | `$XDG_STATE_HOME/cert_viewer/cert_viewer.log` (default `~/.local/state/cert_viewer/cert_viewer.log`) |
| Log file (macOS) | `~/Library/Logs/cert_viewer/cert_viewer.log` (Console.app reads this directory automatically) |
| Log file (Windows) | `%LOCALAPPDATA%\cert_viewer\Logs\cert_viewer.log` |

### Logging

`cmd/cert_viewer/logging.go` configures `slog.Default()` early in `main()`. Records
fan out through a `teeHandler` to two sinks:

1. **stderr** — visible to terminal-launched runs and dropped under
   `windowsgui` builds (Windows GUI binaries have no console).
2. **A per-OS log file** opened with mode `0o600`. The file is rotated
   to `cert_viewer.log.1` at startup if it exceeds 5 MiB; only one
   rotated slot is retained (next rotation overwrites it).

Set `CERT_VIEWER_LOG=debug` to lower the level to DEBUG; default is INFO.
Logging-setup failures fall back to stderr-only — they never block the
app from launching.

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
- **Logging:** `log/slog` is the project standard. `cmd/cert_viewer/main.go`'s
  `configureLogger()` runs first thing in `main()` and installs a stderr text
  handler at `INFO` (or `DEBUG` when `CERT_VIEWER_LOG=debug`). Use
  `slog.Default()` everywhere — never `log.Printf` / `fmt.Println` /
  `zerolog` / `logrus`. For best-effort cleanup that previously used
  `_ = err`, log at `slog.Warn`. For unexpected failures, `slog.Error`. Keep
  log records free of certificate or PKCS#12 contents — paths and error
  strings only.
- **Update check (opt-in only):** `internal/updates` queries the GitHub tags
  API to discover the latest CalVer release. The check fires *only* when the
  user clicks "Check for Updates" in the About dialog. There is no
  startup-time check, no background polling, and no telemetry — this is a
  deliberate privacy stance for users on air-gapped or metered networks. If
  you add a new caller of `updates.CheckLatestTag`, it must remain
  user-initiated; do not wire it into a timer, startup hook, or autoload
  path without an explicit consent dialog first.
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

2. **macOS trust store historical gap** — older docs noted macOS as unsupported. Platform
   support has been added via `internal/resources/localroots_darwin.go` which extracts
   PEM certificates from the system keychain using `security find-certificate`.

3. **Other active debts** — remain in the roadmap (doc-comments, monolithic `main.go`
   refactor tasks that are intentionally staged, etc.). See ROADMAP.md for priorities.

**Resolved (moved from "Known Technical Debt")**

- **Monolithic `main.go`** — the large UI rendering surface was refactored: UI code
  lives in `internal/ui/*` and `main.go` composes those packages. See `cmd/cert_viewer/main.go` and
  the `internal/ui` subpackages for evidence.
- **Duplicate hex formatting** — canonical hex formatting now lives in `internal/certs/format.go`.
  Callers use `certs.FormatHex(...)` (see `internal/ui/*` usages).
- **`escapeMarkdown()` dead code** — previously present; removed in the refactor.
- **Synchronous chain building** — chain building is performed asynchronously with a spinner
  and cancellation via `context.Context` (see `internal/ui/chain/chain.go`).
- **No PKCS#7 support** — PKCS#7 degenerate SignedData bundles from AIA are parsed by
  `internal/certs/ParseCertificateOrPKCS7()` (see `internal/certs/parser.go`).

If you want, I can move the above resolved items to a `docs/changes.md` changelog entry
with commit links.

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

### Versioning & releases

Merging to `main` automatically tags the merge commit with a CalVer tag of
the form `YYYY.MM.DD.N` (UTC date; `N` increments per merge that day). The
tag push then triggers `.github/workflows/release.yml`, which builds
artifacts for Linux / Windows / macOS amd64 / macOS arm64 with the version
injected via `-ldflags` (see `internal/version/`). The auto-tag logic
lives in `.github/workflows/auto-tag.yml` and is idempotent: if HEAD
already has a CalVer tag, the run skips.

To cut a release: just merge the PR. There is no manual tagging step.
To skip a release for a particular merge: pre-tag HEAD with `git tag -a
<some-other-name> -m "..." && git push origin <some-other-name>` before
merging — but in practice that is rarely needed; every merge is a release
under this convention.

---

## Roadmap Reference

See [ROADMAP.md](ROADMAP.md) for the full prioritized feature and improvement backlog,
organized into four phases: Foundation → Platform Support → Core Features → Advanced Features.
