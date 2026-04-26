# Build Guide — Linux (Debian/Ubuntu)

This guide covers fetching the source, installing all prerequisites, running the test
suite, and producing a binary and AppImage on Debian/Ubuntu and compatible
distributions.

---

## 1. Prerequisites

Install the system libraries required by Fyne's OpenGL/GLFW rendering backend:

```bash
sudo apt update
sudo apt install -y \
  build-essential \
  libgl1-mesa-dev \
  xorg-dev \
  libxcursor-dev \
  libxrandr-dev \
  libxinerama-dev \
  libxi-dev \
  curl \
  git \
  python3
```

---

## 2. Install Go (1.25.9 or later)

The project pins the Go toolchain in `go.mod` (`toolchain go1.25.9`).
Contributors should install at least Go 1.25.0 — the toolchain directive
will fetch `go1.25.9` automatically on first build if a newer version is
installed locally; on older versions the `go` command refuses to build.

Check whether Go is already installed and at the required version:

```bash
go version
```

If not installed or out of date, download and install from https://go.dev/dl/:

```bash
# Replace 1.25.9 with the latest stable release shown at go.dev/dl
curl -LO https://go.dev/dl/go1.25.9.linux-amd64.tar.gz
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf go1.25.9.linux-amd64.tar.gz
rm go1.25.9.linux-amd64.tar.gz

# Add Go to PATH — add this line to ~/.bashrc or ~/.profile for persistence
export PATH=$PATH:/usr/local/go/bin

go version   # should print: go version go1.25.9 linux/amd64
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
# Clone a specific tag directly
git clone --branch v1.2.3 https://github.com/crowderb/cert_viewer.git
cd cert_viewer
```

or, inside an existing clone:

```bash
git fetch --tags
git checkout v1.2.3
```

> **Tip:** Release source archives are also available on the
> [GitHub Releases](https://github.com/crowderb/cert_viewer/releases) page
> if you prefer not to use git.

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

Optional: install the project's pre-commit hooks (gofmt, goimports,
golangci-lint) so the cheapest issues are caught before push. Requires
`pip install --user pre-commit` (or `pipx install pre-commit`):

```bash
pre-commit install
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

```bash
CGO_ENABLED=1 go build -ldflags="-s -w" -o cert_viewer ./cmd/cert_viewer
```

The `-s -w` flags strip debug symbols and DWARF data, reducing binary size.

Run directly:

```bash
./cert_viewer
```

---

## 7. Build the AppImage

An AppImage bundles the binary into a self-contained, distribution-agnostic executable
that runs on any Linux system without installation.

```bash
# Build the AppDir structure
mkdir -p AppDir/usr/bin
cp cert_viewer AppDir/usr/bin/cert_viewer
chmod +x AppDir/usr/bin/cert_viewer
cp packaging/linux/cert_viewer.desktop AppDir/
cp packaging/linux/AppRun AppDir/
chmod +x AppDir/AppRun

# Generate a placeholder icon (replace with a real 256×256 PNG when available)
python3 -c "
import struct, zlib
def chunk(t, d):
    c = t + d
    return struct.pack('>I', len(d)) + c + struct.pack('>I', zlib.crc32(c) & 0xffffffff)
w, h = 256, 256
rows = b''.join(b'\x00' + bytes([30, 144, 255]) * w for _ in range(h))
open('AppDir/cert_viewer.png', 'wb').write(
    b'\x89PNG\r\n\x1a\n'
    + chunk(b'IHDR', struct.pack('>IIBBBBB', w, h, 8, 2, 0, 0, 0))
    + chunk(b'IDAT', zlib.compress(rows))
    + chunk(b'IEND', b''))
"

# Download appimagetool (stable release 13)
curl -L -o appimagetool \
  https://github.com/AppImage/AppImageKit/releases/download/13/appimagetool-x86_64.AppImage
chmod +x appimagetool

# Build the AppImage (APPIMAGE_EXTRACT_AND_RUN=1 avoids the FUSE requirement)
ARCH=x86_64 APPIMAGE_EXTRACT_AND_RUN=1 ./appimagetool AppDir \
  cert_viewer-linux-x86_64.AppImage
```

Run the AppImage:

```bash
chmod +x cert_viewer-linux-x86_64.AppImage
./cert_viewer-linux-x86_64.AppImage
```

> AppImages require FUSE to run on the user's machine. Most desktop Linux distributions
> include FUSE2 by default. If not: `sudo apt install libfuse2`

---

## See Also

- [BUILD_GUIDE_WINDOWS.md](BUILD_GUIDE_WINDOWS.md)
- [BUILD_GUIDE_MACOS.md](BUILD_GUIDE_MACOS.md)
- [TECHNOLOGY.md](TECHNOLOGY.md) — architecture and package map
- [https://github.com/crowderb/cert_viewer/](https://github.com/crowderb/cert_viewer/) — releases and issue tracker
