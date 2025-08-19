# cert_viewer

A cross-platform GUI application written in Go using Fyne to inspect X.509 certificates.

## Features
- Open PEM or DER encoded certificate files (.cer/.crt/.pem/.der)
- Summary tab
  - Bold field names, monospace values with copy buttons
  - Common Name, Subject, Issuer, Serial Number (preserves leading zeros), Validity
  - Fingerprints: SHA-256 and SHA-1, with configurable separator (None, ":", or Space)
- Details tab
  - Grouped sections: General, Subject/Issuer Attributes, Subject Public Key Info, X509v3 extensions, Signature
  - Proper word wrapping for long values (SANs, hex, etc.)
- Chain tab
  - Builds a chain up to 5 levels using AIA (CA Issuers) links
  - Detects self-signed certs (AKI == SKI)
  - Resolves a trusted root by checking Subject Key Identifier against:
    1) Local system trust store summary (preferred)
    2) CCADB CSV cache
  - Each chain element shows the same summary info plus SKI/AKI
- Preferences (JSON) under OS config dir
  - UI Settings: attribute name style (OpenSSL vs Windows), hex separator, last opened directory
  - Resources: CCADB CSV URL and refresh interval (days)
- CCADB CSV integration
  - Background refresh on startup to cache `AllCertificateRecordsCSVFormatv2` to the OS cache dir
  - Resources > CCADB CSV dialog shows file path and timestamp, with a "Fetch Now" button
 - Local roots (Linux)
   - On startup, parses `/etc/ssl/certs/ca-certificates.crt` and creates a local summary JSON (if missing)
   - Local summary includes: Subject, SKI, Not Before, Not After, SHA-256

## Paths
- Config: `~/.config/cert_viewer/preferences.json`
- Cache: `~/.cache/cert_viewer/ccadb_all_certificate_records_v2.csv`
 - Local roots summary (generated): `~/.cache/cert_viewer/local_roots.json`

## Build
```bash
# install dependencies
go mod tidy

# run
go run ./cmd/cert_viewer

# build
go build -o bin/cert_viewer ./cmd/cert_viewer
```

## Platform notes
- Linux: requires X11/OpenGL dev packages for Fyne. Example (Debian/Ubuntu):
  ```bash
  sudo apt update
  sudo apt install -y build-essential libgl1-mesa-dev xorg-dev \
    libxcursor-dev libxrandr-dev libxinerama-dev libxi-dev
  ```

## Roadmap
- PKCS#7 parsing in AIA downloads (to extract issuer certs when CA Issuers returns PKCS7)
- Asynchronous chain building with progress indicator
