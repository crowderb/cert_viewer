# Build Guide — macOS

This guide covers fetching the source, installing all prerequisites, running the test
suite, and producing a binary, `.app` bundle, and `.dmg` disk image on macOS.

Supported architectures:
- **Apple Silicon** (M1, M2, M3 — `arm64`)
- **Intel** (`amd64`)

---

## 1. Prerequisites

Fyne's rendering backend requires a C compiler and the macOS SDK headers. The
**Xcode Command Line Tools** provide everything needed:

```bash
xcode-select --install
```

A dialog will appear asking you to install the tools. Click **Install** and accept the
license. This also installs `git`, so no separate git installation is needed.

Verify:
```bash
clang --version
git --version
```

---

## 2. Install Go (1.24 or later)

Check whether Go is already installed:

```bash
go version
```

If not installed or out of date, download the macOS `.pkg` installer from
https://go.dev/dl/ and run it. The installer adds `/usr/local/go/bin` to your `PATH`.

Verify after installation:
```bash
go version   # should print: go version go1.24.x darwin/arm64 (or amd64)
```

---

## 3. Fetch the Source

### Latest code from `main`

```bash
git clone https://github.com/crowderb/cert_viewer.git
cd cert_viewer
```

### Specific release tag

```bash
git clone --branch v1.2.3 https://github.com/crowderb/cert_viewer.git
cd cert_viewer
```

or, inside an existing clone:

```bash
git fetch --tags
git checkout v1.2.3
```

> **Tip:** Release source archives (and pre-built `.dmg` files) are available on the
> [GitHub Releases](https://github.com/crowderb/cert_viewer/releases) page.

---

## 4. Install Module Dependencies

```bash
go mod tidy
```

---

## 5. Run the Test Suite and Linter

```bash
go test ./...
```

Run the linter exactly as CI does (pin matches `.github/workflows/ci.yml` and
`.golangci.yml`):

```bash
go install github.com/golangci/golangci-lint/cmd/golangci-lint@v1.64.8
golangci-lint run ./...
```

Expected output — every package should report `ok` or `[no test files]`, and
`golangci-lint` should exit with status 0:

```
?   	cert_viewer/cmd/cert_viewer	[no test files]
ok  	cert_viewer/internal/certs
ok  	cert_viewer/internal/prefs
ok  	cert_viewer/internal/resources
ok  	cert_viewer/internal/ui/chain
ok  	cert_viewer/internal/ui/compare
ok  	cert_viewer/internal/ui/summary
```

---

## 6. Build the Binary

Build for the **host architecture** (recommended — omit `GOARCH` and Go detects it):

```bash
CGO_ENABLED=1 go build -ldflags="-s -w" -o cert_viewer ./cmd/cert_viewer
```

To build for a **specific architecture** explicitly:

```bash
# Apple Silicon
CGO_ENABLED=1 GOARCH=arm64 go build -ldflags="-s -w" \
  -o cert_viewer-darwin-arm64 ./cmd/cert_viewer

# Intel
CGO_ENABLED=1 GOARCH=amd64 go build -ldflags="-s -w" \
  -o cert_viewer-darwin-amd64 ./cmd/cert_viewer
```

The `-s -w` flags strip debug symbols and DWARF data to reduce binary size.

Run directly:

```bash
./cert_viewer
```

---

## 7. Build the .app Bundle and .dmg

A macOS `.app` bundle wraps the binary in the structure expected by Finder and
Launchpad. The `.dmg` disk image is the standard distribution format.

Set your architecture and version:

```bash
ARCH=arm64    # or amd64
VERSION=1.2.3  # replace with the version being built
```

### Create the .app Bundle

```bash
mkdir -p cert_viewer.app/Contents/MacOS
mkdir -p cert_viewer.app/Contents/Resources

cp cert_viewer-darwin-$ARCH cert_viewer.app/Contents/MacOS/cert_viewer
chmod +x cert_viewer.app/Contents/MacOS/cert_viewer

# Substitute the version into Info.plist
sed "s/VERSION_PLACEHOLDER/$VERSION/" packaging/macos/Info.plist \
  > cert_viewer.app/Contents/Info.plist
```

### Create the .dmg

```bash
# Stage the DMG contents with an Applications symlink for drag-and-drop installation
mkdir dmg_staging
cp -R cert_viewer.app dmg_staging/
ln -s /Applications dmg_staging/Applications

hdiutil create \
  -volname "cert_viewer" \
  -srcfolder dmg_staging \
  -ov -format UDZO \
  cert_viewer-darwin-$ARCH.dmg

rm -rf dmg_staging
```

The resulting `cert_viewer-darwin-arm64.dmg` (or `-amd64.dmg`) can be distributed
directly. Users open the DMG, drag `cert_viewer.app` to the **Applications** folder,
and eject the disk image.

---

## 8. Run

Open the app bundle:

```bash
open cert_viewer.app
```

Or mount the DMG and drag to Applications:

```bash
open cert_viewer-darwin-$ARCH.dmg
```

> **Gatekeeper note:** these builds are **unsigned and unnotarized**. macOS Gatekeeper
> will block the app on first launch with a message that the developer cannot be verified.
>
> To bypass: **right-click** (or Control-click) the `.app` → **Open** → **Open**.
> After the first override the app launches normally.
>
> Full notarization requires an Apple Developer Program membership (USD 99/year) and
> an Apple-issued signing certificate.

---

## See Also

- [BUILD_GUIDE_LINUX.md](BUILD_GUIDE_LINUX.md)
- [BUILD_GUIDE_WINDOWS.md](BUILD_GUIDE_WINDOWS.md)
- [TECHNOLOGY.md](TECHNOLOGY.md) — architecture and package map
- [https://github.com/crowderb/cert_viewer/](https://github.com/crowderb/cert_viewer/) — releases and issue tracker
