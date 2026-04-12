package chain

import (
	"image/color"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/theme"
)

// infoNoticeTheme is used with container.ThemeOverride so RichText using ColorNameDisabled
// for chain info notices reads a color halfway between Disabled and Foreground — darker /
// higher-contrast than plain Disabled on light themes, and more legible on dark themes.
type infoNoticeTheme struct{}

func (infoNoticeTheme) Color(n fyne.ThemeColorName, v fyne.ThemeVariant) color.Color {
	b := theme.Current()
	if n == theme.ColorNameDisabled {
		return blendHalf(b.Color(theme.ColorNameDisabled, v), b.Color(theme.ColorNameForeground, v))
	}
	return b.Color(n, v)
}

func (infoNoticeTheme) Font(s fyne.TextStyle) fyne.Resource {
	return theme.Current().Font(s)
}

func (infoNoticeTheme) Icon(n fyne.ThemeIconName) fyne.Resource {
	return theme.Current().Icon(n)
}

func (infoNoticeTheme) Size(n fyne.ThemeSizeName) float32 {
	return theme.Current().Size(n)
}

// blendHalf returns the midpoint of two colors in sRGB (using 16-bit channel space).
func blendHalf(a, b color.Color) color.Color {
	ar, ag, ab, aa := a.RGBA()
	br, bg, bb, ba := b.RGBA()
	return color.NRGBA{
		R: uint8((ar + br) / 2 >> 8),
		G: uint8((ag + bg) / 2 >> 8),
		B: uint8((ab + bb) / 2 >> 8),
		A: uint8((aa + ba) / 2 >> 8),
	}
}
