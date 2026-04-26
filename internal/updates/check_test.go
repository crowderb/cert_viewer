package updates

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"cert_viewer/internal/version"
)

func TestCheckLatestTagFromURL_HappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Mix of valid CalVer tags, legacy v* tags, and malformed —
		// only the valid CalVer tags should be considered.
		_, _ = w.Write([]byte(`[
			{"name": "2026.04.26.2"},
			{"name": "2026.04.26.1"},
			{"name": "2026.04.25.5"},
			{"name": "v1.2.3"},
			{"name": "random-tag"}
		]`))
	}))
	t.Cleanup(srv.Close)

	saved := version.Version
	t.Cleanup(func() { version.Version = saved })

	// Pretend the binary was built at 2026.04.26.1 — the API offers .2,
	// so we expect isNewer=true.
	version.Version = "2026.04.26.1"

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	latest, isNewer, err := checkLatestTagFromURL(ctx, srv.URL)
	if err != nil {
		t.Fatalf("checkLatestTagFromURL: %v", err)
	}
	if latest != "2026.04.26.2" {
		t.Errorf("latest = %q, want %q", latest, "2026.04.26.2")
	}
	if !isNewer {
		t.Errorf("isNewer = false, want true (running %q vs latest %q)", version.Version, latest)
	}
}

func TestCheckLatestTagFromURL_UpToDate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`[{"name": "2026.04.26.1"}]`))
	}))
	t.Cleanup(srv.Close)

	saved := version.Version
	t.Cleanup(func() { version.Version = saved })
	version.Version = "2026.04.26.1"

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, isNewer, err := checkLatestTagFromURL(ctx, srv.URL)
	if err != nil {
		t.Fatalf("checkLatestTagFromURL: %v", err)
	}
	if isNewer {
		t.Errorf("isNewer = true; expected false when running latest")
	}
}

func TestCheckLatestTagFromURL_DevBuildSeesEverythingAsNewer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`[{"name": "2026.04.26.1"}]`))
	}))
	t.Cleanup(srv.Close)

	saved := version.Version
	t.Cleanup(func() { version.Version = saved })
	version.Version = "dev"

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, isNewer, err := checkLatestTagFromURL(ctx, srv.URL)
	if err != nil {
		t.Fatalf("checkLatestTagFromURL: %v", err)
	}
	if !isNewer {
		t.Errorf("isNewer = false; expected true on a dev build")
	}
}

func TestCheckLatestTagFromURL_NoMatchingTags(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// All legacy / malformed; nothing matches CalVer.
		_, _ = w.Write([]byte(`[{"name": "v1.2.3"}, {"name": "random"}]`))
	}))
	t.Cleanup(srv.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _, err := checkLatestTagFromURL(ctx, srv.URL)
	if !errors.Is(err, ErrNoMatchingTags) {
		t.Fatalf("err = %v, want ErrNoMatchingTags", err)
	}
}

func TestCheckLatestTagFromURL_5xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "GitHub is down", http.StatusServiceUnavailable)
	}))
	t.Cleanup(srv.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _, err := checkLatestTagFromURL(ctx, srv.URL)
	if err == nil {
		t.Fatal("expected error on 5xx response, got nil")
	}
}

func TestCheckLatestTagFromURL_MalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`<html>Not JSON</html>`))
	}))
	t.Cleanup(srv.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _, err := checkLatestTagFromURL(ctx, srv.URL)
	if err == nil {
		t.Fatal("expected error on malformed JSON, got nil")
	}
}
