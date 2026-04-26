# Build Guide — Windows

This guide covers fetching the source, installing all prerequisites, running the test
suite, and producing a binary and NSIS installer for Windows (64-bit).

Two build paths are available:

- **Option A — Native Windows:** build and package directly on a Windows machine using
  TDM-GCC or MSYS2.
- **Option B — Cross-compile from Linux:** produce the Windows `.exe` and installer on
  a Linux host. Useful for CI pipelines and headless environments.

---

## 1. Prerequisites

### Option A — Native Windows

| Tool | Purpose | Download |
|------|---------|----------|
| **TDM-GCC** or **MSYS2** | C compiler required by Fyne's CGO backend | [TDM-GCC](https://jmeubank.github.io/tdm-gcc/) · [MSYS2](https://www.msys2.org/) |
| **Git for Windows** | Source control | https://git-scm.com/download/win |
| **NSIS** | Windows installer builder | https://nsis.sourceforge.io/Download |

**TDM-GCC setup:** run the installer; it adds `gcc` to `PATH` automatically.

**MSYS2 setup:** after installing MSYS2, open the MSYS2 MinGW 64-bit shell and run:
```bash
pacman -S mingw-w64-x86_64-gcc
```
Add `C:\msys64\mingw64\bin` to your Windows `PATH`.

Set the required environment variable (Command Prompt):
```
set CGO_ENABLED=1
```
or PowerShell:
```powershell
$env:CGO_ENABLED = "1"
```

### Option B — Cross-compile from Linux (Debian/Ubuntu)

```bash
sudo apt update
sudo apt install -y gcc-mingw-w64-x86-64 git nsis
```

---

## 2. Install Go (1.24 or later)

### Native Windows
Download the Windows MSI installer from https://go.dev/dl/ and run it. The installer
adds Go to `PATH` automatically.

Verify:
```
go version
```

### Linux (cross-compile)
Follow the Go installation steps in [BUILD_GUIDE_LINUX.md](BUILD_GUIDE_LINUX.md).

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

> **Tip:** Release source archives are also available on the
> [GitHub Releases](https://github.com/crowderb/cert_viewer/releases) page.

---

## 4. Install Module Dependencies

```bash
go mod tidy
```

---

## 5. Run the Test Suite and Linter

All internal packages are platform-independent, so the test suite can be run on either
Windows or Linux regardless of which build path you chose.

```bash
go test ./...
```

Run the linter exactly as CI does (pin matches `.github/workflows/ci.yml` and
`.golangci.yml`):

```bash
go install github.com/golangci/golangci-lint/cmd/golangci-lint@v1.62.2
golangci-lint run ./...
```

Expected output — every package should report `ok` or `[no test files]`, and
`golangci-lint` should exit with status 0.

---

## 6. Build the Binary

### Option A — Native Windows (Command Prompt)

```
set CGO_ENABLED=1
go build -ldflags="-s -w -H windowsgui" -o cert_viewer.exe .\cmd\cert_viewer
```

PowerShell:
```powershell
$env:CGO_ENABLED = "1"
go build -ldflags="-s -w -H windowsgui" -o cert_viewer.exe .\cmd\cert_viewer
```

The `-H windowsgui` flag prevents a console window from appearing when the app is
launched from Explorer.

### Option B — Cross-compile from Linux

```bash
CC=x86_64-w64-mingw32-gcc CGO_ENABLED=1 GOOS=windows GOARCH=amd64 \
  go build -ldflags="-s -w -H windowsgui" \
  -o cert_viewer-windows-amd64.exe ./cmd/cert_viewer
```

---

## 7. Build the NSIS Installer

The NSIS script at `packaging/windows/installer.nsi` builds a standard Windows
installer that:

- Installs `cert_viewer.exe` to `%ProgramFiles%\cert_viewer\`
- Creates Start Menu and Desktop shortcuts
- Registers an entry in **Add/Remove Programs** (with version number)
- Includes an **Uninstaller**

Run from the **repo root** (where the `.exe` file lives):

### Linux (makensis)

```bash
VERSION=1.2.3   # replace with the version being built
makensis /DVERSION="$VERSION" packaging/windows/installer.nsi
```

### Native Windows (NSIS installed)

```
makensis /DVERSION=1.2.3 packaging\windows\installer.nsi
```

Output: `cert_viewer-windows-installer.exe` in the repo root.

> **Code signing note:** these builds are **unsigned**. Windows SmartScreen may show
> a warning on first run. Users can dismiss it by clicking **More info → Run anyway**.
> To suppress the warning permanently, the binary and installer must be signed with an
> Authenticode certificate from a trusted CA.

---

## 8. Run

Run the binary directly:

```
cert_viewer.exe
```

Or double-click `cert_viewer-windows-installer.exe` to install, then launch from the
Start Menu or Desktop shortcut.

---

## See Also

- [BUILD_GUIDE_LINUX.md](BUILD_GUIDE_LINUX.md)
- [BUILD_GUIDE_MACOS.md](BUILD_GUIDE_MACOS.md)
- [TECHNOLOGY.md](TECHNOLOGY.md) — architecture and package map
- [https://github.com/crowderb/cert_viewer/](https://github.com/crowderb/cert_viewer/) — releases and issue tracker
