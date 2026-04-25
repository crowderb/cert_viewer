# cert_viewer

[![CI](https://github.com/crowderb/cert_viewer/actions/workflows/ci.yml/badge.svg)](https://github.com/crowderb/cert_viewer/actions/workflows/ci.yml)

A cross-platform desktop GUI application written in Go for inspecting X.509 digital
certificates. Native alternative to `openssl x509 -text` with chain building, root
trust comparison, CCADB integration, OCSP/CRL revocation checking, and multiple
certificate comparison.

---

## Features

### Opening Certificates

- **PEM or DER encoded certificate files** (`.cer`, `.crt`, `.pem`, `.der`) via
  the File menu or drag-and-drop
- **PKCS#12 / PFX bundles** (`.p12`, `.pfx`) — full chain loaded automatically;
  encrypted bundles prompt for password
- **CSR / Certificate Signing Requests** (`.csr`, `.req`) — Summary and Details views;
  chain not applicable
- **URL or hostname** (File > Open URL…) — connects via TLS and loads the leaf
  certificate along with the server's certificate chain; option to skip TLS verification

### Summary Tab

- Bold field names, monospace values with copy buttons
- Common Name, Subject, Issuer, Serial Number (preserves leading zeros), Validity dates
- Fingerprints: SHA-256 and SHA-1, with configurable separator (None, `:`, or Space)
- **OCSP status** — Check OCSP button shown when the certificate has an OCSP URL;
  reports Good, Revoked, or Unknown
- **CRL revocation** — Fetch CRL and Check CRL buttons shown when CRL Distribution
  Points are present; Fetch CRL opens a searchable revoked-certificate viewer; Check CRL
  reports Good (green) or REVOKED with reason and date (red)
- **Validity color-coding** — Not After / Valid To is shown in warning color when
  ≤ 30 days from expiry and in error color when already expired (threshold configurable)

### Details Tab

- Grouped sections: General, Subject/Issuer Attributes, Subject Public Key Info,
  X.509v3 Extensions, Signature
- Proper word wrapping for long values (SANs, hex, etc.)

### Chain Tab

- Builds a chain up to 5 levels using AIA (CA Issuers) links; runs asynchronously
  to keep the UI responsive
- Detects self-signed certificates (AKI == SKI)
- Resolves the trusted root by checking Subject Key Identifier against:
  1. Local system trust store (preferred)
  2. CCADB CSV cache
- Each chain element shows the same summary info plus SKI/AKI

### Compare Tab

- Load a second certificate alongside the currently open one
- Side-by-side 3-column table: Field name | Certificate A | Certificate B
- Fields that differ between the two certificates are highlighted in warning color
- Certificate B persists when you open a new Certificate A, allowing comparison against
  a fixed reference

### Advanced Comparison (Resources Menu)

- Compares the local system trust store against CCADB
- Three sections:
  - Certificates in Local Store Only (roots on this machine but not in CCADB)
  - Certificates in CCADB Only (optional; disabled by default)
  - Certificates in Both
- CCADB entries filtered to exclude "Not Trusted" (Apple/Chrome/Microsoft/Mozilla)
  and expired certificates
- Preference `showCCADBOnlyCerts` toggles visibility of the CCADB-only section
- Each cert row shows an `Origins:` line listing where it was observed
  (e.g. `system-bundle, distro-anchor-dir`)

### Trust Sources (Resources Menu, Linux)

- Per-origin breakdown of every root the cache has indexed, expandable per cert
- One section per source, each with its own count:
  - **System bundle** — `/etc/ssl/certs/ca-certificates.crt` and equivalents
  - **Env override** — `SSL_CERT_FILE` or `SSL_CERT_DIR`
  - **Distro anchor dir** — `/usr/local/share/ca-certificates` (Debian-family),
    `/etc/pki/ca-trust/source/anchors` (RHEL), `/etc/ca-certificates/trust-source/anchors`
    (Arch), `/etc/pki/trust/anchors` (SUSE) — selected from `/etc/os-release`
  - **NSS — user** — `~/.pki/nssdb` (used by Chrome/Chromium, libnss-based apps)
  - **NSS — Firefox profile** — each `~/.mozilla/firefox/<profile>/cert9.db`
- The same cert can appear under multiple origins (e.g. a homelab CA installed
  via `update-ca-certificates` shows under both system-bundle and distro-anchor-dir)
- NSS sections require `certutil` from `libnss3-tools`; if missing, the section
  shows a clear note instead of failing
- macOS keychain split (System / login / SystemRoots) and Windows CurrentUser /
  GPO additions are deliberate follow-up items under section 3 of the roadmap

### File Management

- **Recent files** (File > Open Recent) — last 10 opened files, persisted in preferences
- **Export Details** (File > Export Details…) — saves all certificate fields to a `.txt`
  file in the same format displayed on screen
- **Copy All to Clipboard** (File menu) — same content as Export Details, direct to
  clipboard

### Preferences

- Attribute name style: OpenSSL (`CN`, `O`, `OU`) or Windows (`Common Name`, `Organization`)
- Hex separator: None, `:`, or Space
- Expiry warning threshold: days before expiry to show warning color (default 30)
- Settings take immediate effect on the open certificate
- Persisted as JSON under the OS config directory

### CCADB CSV Integration

- Background refresh on startup — caches `AllCertificateRecordsCSVFormatv2` to the
  OS cache directory; refreshes if older than 30 days (configurable)
- Resources > CCADB CSV dialog shows the cache file path, last fetch time, and a
  "Fetch Now" button for manual refresh
- Auto-discovers the latest CCADB CSV URL from the CCADB resources page

### Local Trust Store

- **Linux:** Parses the configured bundle (`SSL_CERT_FILE`, `SSL_CERT_DIR`, or
  `/etc/ssl/certs/ca-certificates.crt` by default), then merges in the per-distro
  anchor directory and per-user NSS DBs (Chrome `~/.pki/nssdb`, Firefox profiles)
  via `certutil`
- **Windows:** Reads the Windows `ROOT` certificate store via the Windows API
- **macOS:** Reads `/System/Library/Keychains/SystemRootCertificates.keychain` via
  `security find-certificate`
- Caches per-certificate metadata as `local_roots.json` (Subject, SKI, Not Before,
  Not After, SHA-256, plus an `origins` list recording every source the cert was
  observed in). Cache regenerates automatically when the resolved source path
  changes (e.g. `SSL_CERT_FILE` was set/unset between runs) or when the source's
  mtime is newer than the cache.

---

## Interpreting Results

**Certificates in Local Store Only** — This can indicate a deliberate or managed trust
intervention on this host (e.g., enterprise or MDM adding custom root CAs). Investigate
according to your environment's security policies.

---

## Runtime Paths

| Purpose | Path |
|---------|------|
| Preferences | `~/.config/cert_viewer/preferences.json` |
| CCADB CSV cache | `~/.cache/cert_viewer/ccadb_all_certificate_records_v2.csv` |
| Local roots cache | `~/.cache/cert_viewer/local_roots.json` |

---

## Build

The quick-start commands below get you running from source. For a complete walkthrough
— including fetching a specific release tag, installing all prerequisites, running the
full test suite, and producing the final distributable package — see the per-platform
build guides:

- [BUILD_GUIDE_LINUX.md](BUILD_GUIDE_LINUX.md) — Debian/Ubuntu: apt dependencies, binary, AppImage
- [BUILD_GUIDE_WINDOWS.md](BUILD_GUIDE_WINDOWS.md) — TDM-GCC/MSYS2, binary, NSIS installer
- [BUILD_GUIDE_MACOS.md](BUILD_GUIDE_MACOS.md) — Xcode CLT, binary, `.app` bundle and `.dmg`

```bash
# Install system dependencies (Linux/Debian-Ubuntu)
sudo apt update
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
```

---

## Platform Notes

| Platform | GUI | Certificate parsing | Local trust store |
|----------|-----|--------------------|--------------------|
| Linux (Debian/Ubuntu) | Yes | Yes | Yes |
| Windows | Yes | Yes | Yes (Windows certificate store) |
| macOS | Yes | Yes | Yes (Security framework) |

**Windows:** Requires a C compiler for Fyne's rendering backend. Install
[TDM-GCC](https://jmeubank.github.io/tdm-gcc/) or MSYS2 and set `CGO_ENABLED=1`.

**macOS:** Xcode Command Line Tools provide the required C compiler:
```bash
xcode-select --install
```

---

## Roadmap

See [ROADMAP.md](ROADMAP.md) for the full backlog. Completed work is archived in
[docs/roadmaps/](docs/roadmaps/).

Completed phases include:
1. **Foundation** — test coverage (certs, prefs, resources), refactoring `main.go` into `internal/ui/` sub-packages
2. **Platform Support** — Windows/macOS trust stores, GitHub Actions CI, release binaries
3. **Core Features** — PKCS#7 in AIA, async chain building, PKCS#12, CSR viewing, CCADB auto-discovery
4. **Advanced Features** — URL cert loading, OCSP/CRL status, validity color-coding, recent files, export, CRL viewer, multiple certificate comparison

---

## Repository

**https://github.com/crowderb/cert_viewer/**

Source code, issue tracker, and release downloads are all on GitHub.

---

## Contributing

See [CLAUDE.md](CLAUDE.md) for architecture notes, coding conventions, and known
technical debt. See [TECHNOLOGY.md](TECHNOLOGY.md) for the full technology reference
including package responsibilities and data flow diagrams.

