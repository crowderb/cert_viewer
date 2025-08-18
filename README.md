# cert_viewier

A cross-platform GUI application written in Go using Fyne to inspect X.509 certificates.

## Features (initial)
- Open PEM or DER encoded certificate files
- Summary tab: CN, Subject, Issuer, Validity, Fingerprints
- Details tab: attribute list (with name style preference)
- JSON preferences stored under OS config directory

## Build
```bash
# install dependencies
go mod tidy

# run
go run ./cmd/cert_viewier

# build
go build -o bin/cert_viewier ./cmd/cert_viewier
```
