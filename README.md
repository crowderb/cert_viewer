# cert_viewer

A cross-platform desktop GUI application written in Go for inspecting X.509 digital
certificates. Native alternative to `openssl x509 -text` with chain building, root
trust comparison, and CCADB integration.

---

## Features

- **Open PEM or DER encoded certificate files** (`.cer`, `.crt`, `.pem`, `.der`) via
  the File menu or drag-and-drop

- **Summary tab**
  - Bold field names, monospace values with copy buttons
  - Common Name, Subject, Issuer, Serial Number (preserves leading zeros), Validity
  - Fingerprints: SHA-256 and SHA-1, with configurable separator (None, `:`, or Space)

- **Details tab**
  - Grouped sections: General, Subject/Issuer Attributes, Subject Public Key Info,
    X.509v3 Extensions, Signature
  - Proper word wrapping for long values (SANs, hex, etc.)

- **Chain tab**
  - Builds a chain up to 5 levels using AIA (CA Issuers) links
  - Detects self-signed certificates (AKI == SKI)
  - Resolves the trusted root by checking Subject Key Identifier against:
    1. Local system trust store (preferred)
    2. CCADB CSV cache
  - Each chain element shows the same summary info plus SKI/AKI

- **Advanced comparison** (Resources menu)
  - Compares the local system trust store against CCADB
  - Three sections:
    - Certificates in Local Store Only (roots on this machine but not in CCADB)
    - Certificates in CCADB Only (optional; disabled by default)
    - Certificates in Both
  - CCADB entries filtered to exclude "Not Trusted" (Apple/Chrome/Microsoft/Mozilla)
    and expired certificates
  - Preference `showCCADBOnlyCerts` toggles visibility of the CCADB-only section

- **Preferences**
  - Attribute name style: OpenSSL (`CN`, `O`, `OU`) or Windows (`Common Name`, `Organization`)
  - Hex separator: None, `:`, or Space
  - Settings take immediate effect on the open certificate
  - Persisted as JSON under the OS config directory

- **CCADB CSV integration**
  - Background refresh on startup — caches `AllCertificateRecordsCSVFormatv2` to the
    OS cache directory; refreshes if older than 30 days (configurable)
  - Resources > CCADB CSV dialog shows the cache file path, last fetch time, and a
    "Fetch Now" button for manual refresh

- **Local trust store (Linux)**
  - Parses `/etc/ssl/certs/ca-certificates.crt` on demand (not at startup)
  - Caches per-certificate metadata (Subject, SKI, Not Before, Not After, SHA-256) as
    `local_roots.json` for fast subsequent comparisons

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
| Windows | Yes | Yes | Planned |
| macOS | Yes | Yes | Planned |

**Windows:** Requires a C compiler for Fyne's rendering backend. Install
[TDM-GCC](https://jmeubank.github.io/tdm-gcc/) or MSYS2 and set `CGO_ENABLED=1`.

**macOS:** Xcode Command Line Tools provide the required C compiler:
```bash
xcode-select --install
```

---

## Roadmap

See [ROADMAP.md](ROADMAP.md) for the full backlog, organized into four phases:

1. **Foundation** — test coverage, refactoring `main.go`, eliminating tech debt
2. **Platform Support** — Windows/macOS trust stores, GitHub Actions CI, release binaries
3. **Core Feature Gaps** — PKCS#7 in AIA, async chain building, PKCS#12, CSR viewing
4. **Advanced Features** — URL-based cert loading, OCSP status, recent files, CRL viewer

---

## Contributing

See [CLAUDE.md](CLAUDE.md) for architecture notes, coding conventions, and known
technical debt. See [TECHNOLOGY.md](TECHNOLOGY.md) for the full technology reference
including package responsibilities and data flow diagrams.
