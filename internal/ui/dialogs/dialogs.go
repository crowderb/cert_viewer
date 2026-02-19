package dialogs

import (
	"context"
	"fmt"
	"os"
	"strconv"

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
	path, err := resources.CachePath(p)
	var infoText string
	header := fmt.Sprintf("Discovery: %s\nURL: %s", p.Resources.CCadbResourcesURL, p.Resources.CCADBURL)
	if err != nil {
		infoText = fmt.Sprintf("%s\nError determining cache path: %v", header, err)
	} else {
		st, statErr := os.Stat(path)
		if statErr != nil {
			infoText = fmt.Sprintf("%s\nFile: %s\nStatus: not downloaded", header, path)
		} else {
			infoText = fmt.Sprintf("%s\nFile: %s\nModified: %s", header, path, st.ModTime().Format("2006-01-02 15:04:05 MST"))
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
				// Reload prefs so the refreshed dialog reflects any filename update.
				fresh, _ := prefs.Load()
				ShowCCADB(win, fresh)
			}
		}()
	}, win)
	d.Resize(fyne.NewSize(580, 260))
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

	// CCADB URL
	urlEntry := widget.NewEntry()
	urlEntry.SetText(p.Resources.CCADBURL)

	// Refresh Days
	daysEntry := widget.NewEntry()
	daysEntry.SetText(strconv.Itoa(p.Resources.RefreshDays))

	// Expiry Warning Days
	warnDaysEntry := widget.NewEntry()
	warnDaysEntry.SetText(strconv.Itoa(p.UI.ExpiryWarnDays))

	content := container.NewVBox(
		widget.NewLabel("Attribute name style:"),
		nameRadio,
		widget.NewSeparator(),
		widget.NewLabel("Hex value separator:"),
		hexRadio,
		widget.NewSeparator(),
		widget.NewLabel("Display:"),
		widget.NewLabel("Expiry warning (days):"),
		warnDaysEntry,
		widget.NewSeparator(),
		widget.NewLabel("Resources:"),
		widget.NewLabel("CCADB URL:"),
		urlEntry,
		widget.NewLabel("Refresh Days:"),
		daysEntry,
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
		// CCADB URL — empty resets to default; update CachedFilename to match new URL.
		if u := urlEntry.Text; u != "" {
			p.Resources.CCADBURL = u
		} else {
			p.Resources.CCADBURL = prefs.Default().Resources.CCADBURL
		}
		p.Resources.CachedFilename = prefs.CacheFilenameFromURL(p.Resources.CCADBURL)
		// Expiry Warning Days — non-positive or non-numeric resets to 30
		if n, err := strconv.Atoi(warnDaysEntry.Text); err == nil && n > 0 {
			p.UI.ExpiryWarnDays = n
		} else {
			p.UI.ExpiryWarnDays = 30
		}
		// Refresh Days — non-positive or non-numeric resets to 30
		if n, err := strconv.Atoi(daysEntry.Text); err == nil && n > 0 {
			p.Resources.RefreshDays = n
		} else {
			p.Resources.RefreshDays = 30
		}
		_ = prefs.Save(p)
		onApply(p)
	}, win)
	d.Resize(fyne.NewSize(540, 460))
	d.Show()
}

// ShowOpenURL displays an input dialog for connecting to a TLS server by
// hostname or HTTPS URL. onSubmit is called with the raw input and skipVerify
// flag when the user clicks Connect; nothing is called on Cancel.
func ShowOpenURL(win fyne.Window, onSubmit func(rawInput string, skipVerify bool)) {
	hostEntry := widget.NewEntry()
	hostEntry.SetPlaceHolder("e.g. example.com or https://example.com:8443")
	skipCheck := widget.NewCheck("Skip certificate verification (allows expired/self-signed)", nil)
	content := container.NewVBox(
		widget.NewLabel("Enter hostname or HTTPS URL:"),
		hostEntry,
		skipCheck,
	)
	d := dialog.NewCustomConfirm("Open URL", "Connect", "Cancel", content, func(ok bool) {
		if !ok {
			return
		}
		onSubmit(hostEntry.Text, skipCheck.Checked)
	}, win)
	d.Resize(fyne.NewSize(520, 200))
	d.Show()
}

// ShowPasswordPrompt displays a password entry dialog for opening an encrypted
// PKCS#12 file. onSubmit is called with the entered password when the user
// clicks Open; nothing is called if the user cancels.
func ShowPasswordPrompt(win fyne.Window, filename string, onSubmit func(password string)) {
	entry := widget.NewPasswordEntry()
	entry.SetPlaceHolder("Leave blank if none")
	content := container.NewVBox(
		widget.NewLabel("Enter password for: "+filename),
		entry,
	)
	d := dialog.NewCustomConfirm("Open PKCS#12", "Open", "Cancel", content, func(ok bool) {
		if !ok {
			return
		}
		onSubmit(entry.Text)
	}, win)
	d.Resize(fyne.NewSize(420, 180))
	d.Show()
}
