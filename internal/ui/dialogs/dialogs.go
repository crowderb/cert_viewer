package dialogs

import (
	"context"
	"fmt"
	"os"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"

	"cert_viewer/internal/prefs"
	"cert_viewer/internal/resources"
)

// ShowCCADB displays a dialog showing the CCADB CSV cache status and an option
// to fetch a fresh copy immediately.
func ShowCCADB(win fyne.Window, p prefs.Preferences) {
	path, err := resources.CachePath()
	var infoText string
	if err != nil {
		infoText = fmt.Sprintf("Error determining cache path: %v", err)
	} else {
		st, statErr := os.Stat(path)
		if statErr != nil {
			infoText = fmt.Sprintf("File: %s\nStatus: not downloaded", path)
		} else {
			infoText = fmt.Sprintf("File: %s\nModified: %s", path, st.ModTime().Format("2006-01-02 15:04:05 MST"))
		}
	}
	content := container.NewVBox(
		widget.NewLabel("CCADB All Certificate Records CSV"),
		widget.NewRichTextWithText(infoText),
	)
	d := dialog.NewCustomConfirm("CCADB CSV", "Fetch Now", "OK", content, func(fetch bool) {
		if !fetch {
			return
		}
		ctx := context.Background()
		errCh := resources.EnsureCCADBCSV(ctx, p)
		go func() {
			if err := <-errCh; err != nil {
				dialog.ShowError(err, win)
			} else {
				// Refresh dialog to show new timestamp
				ShowCCADB(win, p)
			}
		}()
	}, win)
	d.Resize(fyne.NewSize(520, 220))
	d.Show()
}

// ShowPreferences displays the preferences dialog. onApply is called with the
// updated Preferences if the user clicks Save.
func ShowPreferences(win fyne.Window, p prefs.Preferences, onApply func(prefs.Preferences)) {
	// Name style
	nameOptions := []string{"OpenSSL", "Windows"}
	var nameSelected string
	if p.UI.NameStyle == prefs.Windows {
		nameSelected = nameOptions[1]
	} else {
		nameSelected = nameOptions[0]
	}
	nameRadio := widget.NewRadioGroup(nameOptions, func(string) {})
	nameRadio.Horizontal = false
	nameRadio.SetSelected(nameSelected)

	// Hex separator style
	hexOptions := []string{"None", ":", "Space"}
	var hexSelected string
	switch p.UI.HexSep {
	case prefs.HexNone:
		hexSelected = hexOptions[0]
	case prefs.HexSpace:
		hexSelected = hexOptions[2]
	default:
		hexSelected = hexOptions[1]
	}
	hexRadio := widget.NewRadioGroup(hexOptions, func(string) {})
	hexRadio.Horizontal = true
	hexRadio.SetSelected(hexSelected)

	content := container.NewVBox(
		widget.NewLabel("Attribute name style:"),
		nameRadio,
		widget.NewSeparator(),
		widget.NewLabel("Hex value separator:"),
		hexRadio,
	)
	d := dialog.NewCustomConfirm("Preferences", "Save", "Cancel", content, func(ok bool) {
		if !ok {
			return
		}
		// Name style
		switch nameRadio.Selected {
		case "Windows":
			p.UI.NameStyle = prefs.Windows
		default:
			p.UI.NameStyle = prefs.OpenSSL
		}
		// Hex sep
		switch hexRadio.Selected {
		case "None":
			p.UI.HexSep = prefs.HexNone
		case "Space":
			p.UI.HexSep = prefs.HexSpace
		default:
			p.UI.HexSep = prefs.HexColon
		}
		_ = prefs.Save(p)
		onApply(p)
	}, win)
	d.Resize(fyne.NewSize(420, 260))
	d.Show()
}
