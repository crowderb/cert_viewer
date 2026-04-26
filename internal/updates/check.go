package updates

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"cert_viewer/internal/httpclient"
	"cert_viewer/internal/version"
)

// DefaultTagsURL points at the GitHub REST API's tags endpoint for the
// project. Hardcoded by design — the update check has no user-controlled
// destination, which keeps the privacy and security analysis trivial.
const DefaultTagsURL = "https://api.github.com/repos/crowderb/cert_viewer/tags"

// ReleasesURL is the user-facing release page; surfaced in the About
// dialog when an update is available so the user can read the notes.
const ReleasesURL = "https://github.com/crowderb/cert_viewer/releases"

// ErrNoMatchingTags is returned when the API responds successfully but
// no tag in the response matches the YYYY.MM.DD.N format. This happens
// before any tag has been pushed by auto-tag.yml on a fresh repo.
var ErrNoMatchingTags = errors.New("no CalVer tags found in repository")

// tagEntry mirrors the subset of the GitHub tags API response we care
// about. Other fields (commit, zipball_url, tarball_url, node_id) are
// ignored.
type tagEntry struct {
	Name string `json:"name"`
}

// CheckLatestTag queries the GitHub tags API, filters to CalVer-shaped
// tags, and returns the highest one along with whether it is newer than
// the locally compiled-in version.Version. Network operations are gated
// by ctx (the caller is expected to set a tight timeout — typically 10s
// — so a hung captive portal cannot lock up the UI).
//
// CheckLatestTag is the only public entry point that touches the
// network. URL is hardcoded — the caller cannot redirect this to a
// different endpoint.
func CheckLatestTag(ctx context.Context) (latest string, isNewer bool, err error) {
	return checkLatestTagFromURL(ctx, DefaultTagsURL)
}

// checkLatestTagFromURL is the test seam: it accepts an arbitrary URL
// so the httptest server in updates_test.go can drive the parsing and
// error paths without touching the live GitHub API. Production code
// should always go through CheckLatestTag.
func checkLatestTagFromURL(ctx context.Context, url string) (latest string, isNewer bool, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", false, fmt.Errorf("building tags request: %w", err)
	}
	// GitHub recommends an explicit Accept header to lock the response
	// schema; "application/vnd.github+json" pins to the current API.
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "cert_viewer-update-check")

	resp, err := httpclient.Default().Do(req)
	if err != nil {
		return "", false, fmt.Errorf("contacting GitHub: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", false, fmt.Errorf("GitHub returned %s", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", false, fmt.Errorf("reading tags response: %w", err)
	}

	var tags []tagEntry
	if jsonErr := json.Unmarshal(body, &tags); jsonErr != nil {
		return "", false, fmt.Errorf("parsing tags JSON: %w", jsonErr)
	}

	highest := ""
	for _, t := range tags {
		if _, _, _, _, ok := ParseCalVer(t.Name); !ok {
			continue
		}
		if highest == "" || CompareCalVer(t.Name, highest) > 0 {
			highest = t.Name
		}
	}
	if highest == "" {
		return "", false, ErrNoMatchingTags
	}

	// Compare against the compiled-in version. The "dev" sentinel is
	// not a CalVer string, so CompareCalVer treats it as older-than
	// any real tag — exactly what we want for development builds.
	isNewer = CompareCalVer(highest, version.Version) > 0
	return highest, isNewer, nil
}
