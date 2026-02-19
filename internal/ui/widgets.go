package ui

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

// BoldLabel returns a *widget.Label with bold text style.
func BoldLabel(text string) *widget.Label {
	lbl := widget.NewLabel(text)
	lbl.TextStyle = fyne.TextStyle{Bold: true}
	return lbl
}

// ColoredCopyRow builds a value widget with monospace colored text and a clipboard
// copy button. Use theme.ColorNameForeground for the default (uncolored) style.
func ColoredCopyRow(win fyne.Window, text string, colorName fyne.ThemeColorName) fyne.CanvasObject {
	value := widget.NewRichText(
		&widget.TextSegment{Text: text, Style: widget.RichTextStyle{
			TextStyle: fyne.TextStyle{Monospace: true},
			ColorName: colorName,
		}},
	)
	value.Wrapping = fyne.TextWrapWord
	copyBtn := widget.NewButtonWithIcon("", theme.ContentCopyIcon(), func() {
		win.Clipboard().SetContent(text)
	})
	copyBtn.Importance = widget.LowImportance
	return container.NewBorder(nil, nil, nil, copyBtn, value)
}

// CopyRow builds a value widget with monospace text and a clipboard copy button.
func CopyRow(win fyne.Window, text string) fyne.CanvasObject {
	value := widget.NewRichTextWithText(text)
	value.Wrapping = fyne.TextWrapWord
	value.Segments = []widget.RichTextSegment{
		&widget.TextSegment{Text: text, Style: widget.RichTextStyle{TextStyle: fyne.TextStyle{Monospace: true}}},
	}
	copyBtn := widget.NewButtonWithIcon("", theme.ContentCopyIcon(), func() {
		win.Clipboard().SetContent(text)
	})
	copyBtn.Importance = widget.LowImportance
	return container.NewBorder(nil, nil, nil, copyBtn, value)
}
