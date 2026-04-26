package updates

import "testing"

func TestParseCalVer(t *testing.T) {
	t.Parallel()

	cases := []struct {
		in           string
		wantY, wantM int
		wantD, wantN int
		ok           bool
	}{
		{"2026.04.26.1", 2026, 4, 26, 1, true},
		{"2026.12.31.99", 2026, 12, 31, 99, true},
		{"2026.04.26.0", 2026, 4, 26, 0, true},
		// Malformed
		{"v1.2.3", 0, 0, 0, 0, false},
		{"2026.4.26.1", 0, 0, 0, 0, false},    // single-digit month rejected
		{"2026.04.26", 0, 0, 0, 0, false},     // missing N
		{"2026.04.26.1.5", 0, 0, 0, 0, false}, // extra component
		{"", 0, 0, 0, 0, false},
		{"dev", 0, 0, 0, 0, false},
		{"unknown", 0, 0, 0, 0, false},
		{"  2026.04.26.1  ", 0, 0, 0, 0, false}, // whitespace not stripped
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			y, m, d, n, ok := ParseCalVer(tc.in)
			if ok != tc.ok {
				t.Fatalf("ParseCalVer(%q) ok = %v, want %v", tc.in, ok, tc.ok)
			}
			if !ok {
				return
			}
			if y != tc.wantY || m != tc.wantM || d != tc.wantD || n != tc.wantN {
				t.Fatalf("ParseCalVer(%q) = (%d, %d, %d, %d), want (%d, %d, %d, %d)",
					tc.in, y, m, d, n, tc.wantY, tc.wantM, tc.wantD, tc.wantN)
			}
		})
	}
}

func TestCompareCalVer(t *testing.T) {
	t.Parallel()

	cases := []struct {
		a, b string
		want int
	}{
		// Equal
		{"2026.04.26.1", "2026.04.26.1", 0},
		// Year
		{"2025.04.26.1", "2026.04.26.1", -1},
		{"2026.04.26.1", "2025.12.31.9", 1},
		// Month
		{"2026.03.31.9", "2026.04.01.1", -1},
		{"2026.04.01.1", "2026.03.31.9", 1},
		// Day
		{"2026.04.25.9", "2026.04.26.1", -1},
		{"2026.04.26.1", "2026.04.25.9", 1},
		// N
		{"2026.04.26.1", "2026.04.26.2", -1},
		{"2026.04.26.10", "2026.04.26.2", 1}, // numeric, not lexicographic
		// Malformed handling
		{"dev", "2026.04.26.1", -1}, // valid > invalid
		{"2026.04.26.1", "dev", 1},
		{"dev", "unknown", 0}, // both invalid
	}
	for _, tc := range cases {
		t.Run(tc.a+" vs "+tc.b, func(t *testing.T) {
			got := CompareCalVer(tc.a, tc.b)
			if got != tc.want {
				t.Fatalf("CompareCalVer(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
			}
		})
	}
}
