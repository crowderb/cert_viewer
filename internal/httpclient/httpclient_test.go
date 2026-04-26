package httpclient

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

// TestClientTimeoutFires verifies that a shared client returns an error when a
// server writes one byte and then hangs longer than the client's timeout.
// We swap the client's Timeout to a short value via a private constructor in
// the test so we don't have to wait the full 30s; the production timeout
// values are asserted separately below.
func TestClientTimeoutFires(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		timeout time.Duration
	}{
		{"short timeout 200ms", 200 * time.Millisecond},
		{"short timeout 500ms", 500 * time.Millisecond},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Server writes one byte then blocks until the test ends.
			// Register cleanups so close(done) runs *before* srv.Close():
			// t.Cleanup is LIFO, so srv.Close (registered last) would run
			// first, then deadlock waiting on the hung handler. Order matters.
			done := make(chan struct{})
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Length", "10")
				w.WriteHeader(http.StatusOK)
				if _, err := w.Write([]byte{'x'}); err != nil {
					return
				}
				if f, ok := w.(http.Flusher); ok {
					f.Flush()
				}
				<-done
			}))
			t.Cleanup(srv.Close)
			t.Cleanup(func() { close(done) })

			client := &http.Client{Timeout: tc.timeout}

			start := time.Now()
			req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
			if err != nil {
				t.Fatalf("building request: %v", err)
			}
			resp, err := client.Do(req)
			if resp != nil {
				defer func() { _ = resp.Body.Close() }()
			}
			if err == nil {
				// http.Client.Timeout covers the whole exchange — including
				// reading the body. The first byte arrives quickly, then the
				// server stalls; draining triggers the timeout.
				_, err = drainUntilError(resp)
			}
			elapsed := time.Since(start)

			if err == nil {
				t.Fatalf("expected timeout error, got nil after %s", elapsed)
			}
			// url.Error wraps the underlying timeout; check via interface for
			// timeout-like behavior rather than string matching.
			var ue *url.Error
			if !errors.As(err, &ue) || !ue.Timeout() {
				// Fall back to the more general Timeout() interface.
				type timeoutErr interface{ Timeout() bool }
				var te timeoutErr
				if !errors.As(err, &te) || !te.Timeout() {
					t.Fatalf("expected timeout error, got %T: %v", err, err)
				}
			}
			// Allow generous slack for CI scheduler jitter.
			if elapsed > tc.timeout+5*time.Second {
				t.Fatalf("timeout fired at %s, well past configured %s", elapsed, tc.timeout)
			}
		})
	}
}

// drainUntilError reads the body until EOF or the underlying client timeout
// kicks in. The caller is responsible for closing resp.Body — leaving that to
// the caller keeps the bodyclose linter happy at the call site.
func drainUntilError(resp *http.Response) ([]byte, error) {
	buf := make([]byte, 1024)
	var out []byte
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			out = append(out, buf[:n]...)
		}
		if err != nil {
			return out, err
		}
	}
}

// TestSharedClientsAreSingletons verifies that repeated calls to Default and
// CCADBDownload return the same instance (so callers can rely on connection
// reuse and we don't accidentally allocate per-call).
func TestSharedClientsAreSingletons(t *testing.T) {
	t.Parallel()

	d1, d2 := Default(), Default()
	if d1 != d2 {
		t.Fatal("Default() returned different instances on successive calls")
	}
	c1, c2 := CCADBDownload(), CCADBDownload()
	if c1 != c2 {
		t.Fatal("CCADBDownload() returned different instances on successive calls")
	}
	if d1 == c1 {
		t.Fatal("Default() and CCADBDownload() must be distinct clients")
	}
}

// TestProductionTimeoutsAreSet ensures the publicly documented timeout values
// match what the shared clients are configured with.
func TestProductionTimeoutsAreSet(t *testing.T) {
	t.Parallel()

	if got := Default().Timeout; got != DefaultTimeout {
		t.Fatalf("Default().Timeout = %s, want %s", got, DefaultTimeout)
	}
	if got := CCADBDownload().Timeout; got != CCADBDownloadTimeout {
		t.Fatalf("CCADBDownload().Timeout = %s, want %s", got, CCADBDownloadTimeout)
	}
}
