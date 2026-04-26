// Package httpclient exposes shared *http.Client instances with explicit
// timeouts. Use these instead of http.DefaultClient — the default client has
// no timeout, so a misbehaving server that dribbles bytes forever will defeat
// any context-only deadline because there is no idle-read timeout.
package httpclient

import (
	"net/http"
	"sync"
	"time"
)

// DefaultTimeout is the request timeout used for routine network operations
// (CRL fetches, OCSP queries, AIA CA-Issuers fetches, CCADB resources page
// scrape). Generous enough for slow CDNs but bounded so a hung server cannot
// deadlock the caller.
const DefaultTimeout = 30 * time.Second

// CCADBDownloadTimeout is the timeout for the full CCADB CSV download. The
// CSV is large (tens of MB) and the upstream Salesforce origin can be slow,
// so it gets a longer budget than DefaultTimeout.
const CCADBDownloadTimeout = 120 * time.Second

var (
	defaultOnce   sync.Once
	defaultClient *http.Client

	ccadbOnce   sync.Once
	ccadbClient *http.Client
)

// Default returns the shared client for routine HTTP operations. The returned
// client is safe for concurrent use; do not mutate its fields.
func Default() *http.Client {
	defaultOnce.Do(func() {
		defaultClient = &http.Client{Timeout: DefaultTimeout}
	})
	return defaultClient
}

// CCADBDownload returns the shared client for downloading the CCADB CSV
// bundle. It uses CCADBDownloadTimeout instead of DefaultTimeout because the
// payload is large.
func CCADBDownload() *http.Client {
	ccadbOnce.Do(func() {
		ccadbClient = &http.Client{Timeout: CCADBDownloadTimeout}
	})
	return ccadbClient
}
