// Package updates provides the manual "Check for Updates" feature: parse
// and compare CalVer (YYYY.MM.DD.N) version strings, and query the GitHub
// tags API to discover the latest release.
//
// All network operations are strictly opt-in — they only fire when the
// caller invokes CheckLatestTag. There is no background polling, no
// telemetry, no startup-time check.
package updates

import (
	"regexp"
	"strconv"
)

// calverRE matches the canonical CalVer release tag shape used by
// auto-tag.yml: four-digit year, two-digit month, two-digit day, then
// one or more digits for the per-day counter. The anchors ensure we
// reject strings with leading/trailing junk.
var calverRE = regexp.MustCompile(`^(\d{4})\.(\d{2})\.(\d{2})\.(\d+)$`)

// ParseCalVer extracts the four numeric components from a CalVer string.
// On a malformed input it returns zero values and ok=false; callers
// must check ok before using the integers.
func ParseCalVer(s string) (year, month, day, n int, ok bool) {
	m := calverRE.FindStringSubmatch(s)
	if m == nil {
		return 0, 0, 0, 0, false
	}
	year, _ = strconv.Atoi(m[1])
	month, _ = strconv.Atoi(m[2])
	day, _ = strconv.Atoi(m[3])
	n, _ = strconv.Atoi(m[4])
	return year, month, day, n, true
}

// CompareCalVer returns -1 if a < b, 0 if a == b, 1 if a > b. Non-CalVer
// strings sort *after* valid ones (so a valid tag is always considered
// "newer" than an unparseable one — useful when the binary's Version is
// "dev" and we're checking against released tags).
func CompareCalVer(a, b string) int {
	ay, am, ad, an, aok := ParseCalVer(a)
	by, bm, bd, bn, bok := ParseCalVer(b)

	switch {
	case !aok && !bok:
		return 0
	case !aok:
		return -1
	case !bok:
		return 1
	}

	for _, pair := range [4][2]int{{ay, by}, {am, bm}, {ad, bd}, {an, bn}} {
		if pair[0] < pair[1] {
			return -1
		}
		if pair[0] > pair[1] {
			return 1
		}
	}
	return 0
}
