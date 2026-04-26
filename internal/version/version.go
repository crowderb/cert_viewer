// Package version exposes build-time identity strings for the cert_viewer
// binary. Values are injected via -ldflags at build time:
//
//	go build -ldflags="\
//	  -X cert_viewer/internal/version.Version=$VERSION \
//	  -X cert_viewer/internal/version.Commit=$COMMIT \
//	  -X cert_viewer/internal/version.BuildDate=$BUILD_DATE" \
//	  ./cmd/cert_viewer
//
// When the binary is built without -ldflags, each value falls back to a
// development sentinel so code can reliably check `if Version == "dev"` to
// detect non-release builds.
package version

// Version is the CalVer release identifier (YYYY.MM.DD.N) for distribution
// builds. Set via -ldflags from the release workflow's GITHUB_REF_NAME or a
// local equivalent. Defaults to "dev" for un-injected builds.
var Version = "dev"

// Commit is the short git SHA the binary was built from. Set via -ldflags
// from `git rev-parse --short HEAD`. Defaults to "unknown".
var Commit = "unknown"

// BuildDate is the UTC build timestamp in RFC 3339 format. Set via -ldflags
// from `date -u +%Y-%m-%dT%H:%M:%SZ`. Defaults to "<unset>".
var BuildDate = "<unset>"

// IsDev reports whether the binary is a non-release build (no -ldflags
// injection happened). Useful for skipping update checks or showing a
// "development build" badge in the UI.
func IsDev() bool { return Version == "dev" }
