package summary

import (
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/theme"
)

// ValidityColorName returns the theme color name appropriate for a certificate's
// expiry state relative to now:
//   - theme.ColorNameError    — certificate has expired
//   - theme.ColorNameWarning  — certificate expires within warnDays days
//   - theme.ColorNameForeground — certificate is valid with margin
//
// Pass time.Now() for now in production; use a fixed time in tests.
func ValidityColorName(notAfter, now time.Time, warnDays int) fyne.ThemeColorName {
	if now.After(notAfter) {
		return theme.ColorNameError
	}
	if notAfter.Before(now.Add(time.Duration(warnDays) * 24 * time.Hour)) {
		return theme.ColorNameWarning
	}
	return theme.ColorNameForeground
}
