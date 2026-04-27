# Recent Implementation Changes (summary)

This file summarizes recent code changes that caused drift from the older
project documentation. Use these notes for release changelogs and to keep
architecture docs in sync.

## Resolved items

- UI refactor: `cmd/cert_viewer/main.go` now composes the UI from
  `internal/ui/*` subpackages instead of containing all rendering logic.
  See: [cmd/cert_viewer/main.go](cmd/cert_viewer/main.go) and the
  `internal/ui` subpackages.

- macOS trust-store support: `internal/resources/localroots_darwin.go`
  extracts PEM-encoded certificates from the system keychain by invoking the
  `security find-certificate -a -p` command and parsing the output. This
  enables the "Compare Local vs CCADB" and Trust Sources features on macOS.
  See: [internal/resources/localroots_darwin.go](internal/resources/localroots_darwin.go).

- Async chain building: `internal/ui/chain/chain.go` performs AIA fetching and
  chain resolution on a background goroutine. The UI shows a spinner and
  chain building can be cancelled with `context.Context`.
  See: [internal/ui/chain/chain.go](internal/ui/chain/chain.go).

- PKCS#7 handling: AIA CA Issuers responses that are PKCS#7 bundles are parsed
  via `internal/certs/ParseCertificateOrPKCS7()` which wraps `go.mozilla.org/pkcs7`.
  See: [internal/certs/parser.go](internal/certs/parser.go).

- Hex formatting consolidation: canonical hex helpers live in
  `internal/certs/format.go` and callers use `certs.FormatHex(...)`.
  See usages in `internal/ui/*`.

## Suggested follow-ups

- Add a short entry to the release notes describing macOS trust-store support
  and the UI refactor (helps users discover the updated Trust Sources tab).

- Consider adding a `docs/changes-YYYY-MM-DD.md` per-release to track these
  transitions with commit links for future auditing.

- Add or expand tests around `localroots_darwin.go` (mock `security` output)
  and `ui/chain` cancellation behavior.


