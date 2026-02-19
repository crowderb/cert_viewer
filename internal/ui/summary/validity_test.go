package summary

import (
	"testing"
	"time"

	"fyne.io/fyne/v2/theme"
	"github.com/stretchr/testify/assert"
)

func TestValidityColorName(t *testing.T) {
	now := time.Date(2024, 6, 15, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name     string
		notAfter time.Time
		warnDays int
		want     string
	}{
		{
			name:     "expired",
			notAfter: now.Add(-24 * time.Hour), // yesterday
			warnDays: 30,
			want:     string(theme.ColorNameError),
		},
		{
			name:     "expiring in 1 hour",
			notAfter: now.Add(time.Hour),
			warnDays: 30,
			want:     string(theme.ColorNameWarning),
		},
		{
			name:     "expiring in 29 days",
			notAfter: now.Add(29 * 24 * time.Hour),
			warnDays: 30,
			want:     string(theme.ColorNameWarning),
		},
		{
			name:     "expiring exactly at threshold boundary",
			notAfter: now.Add(30 * 24 * time.Hour),
			warnDays: 30,
			want:     string(theme.ColorNameForeground),
		},
		{
			name:     "valid with large margin",
			notAfter: now.Add(60 * 24 * time.Hour),
			warnDays: 30,
			want:     string(theme.ColorNameForeground),
		},
		{
			name:     "custom threshold 7 days - warning",
			notAfter: now.Add(6 * 24 * time.Hour),
			warnDays: 7,
			want:     string(theme.ColorNameWarning),
		},
		{
			name:     "custom threshold 7 days - ok",
			notAfter: now.Add(8 * 24 * time.Hour),
			warnDays: 7,
			want:     string(theme.ColorNameForeground),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ValidityColorName(tc.notAfter, now, tc.warnDays)
			assert.Equal(t, tc.want, string(got))
		})
	}
}
