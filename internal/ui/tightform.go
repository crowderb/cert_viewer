package ui

import (
	"fyne.io/fyne/v2"
)

// TightTwoColLayout arranges objects in two columns (name, value) with
// no vertical spacing between rows. The left column width is sized to the
// maximum minimum width of the name widgets; the right column takes the rest.
// Objects are expected in pairs: [name0, value0, name1, value1, ...].
// If an odd object remains it will be placed in the left column on its own row.
//
// This keeps rows compact and gives more width to the value column.
 type TightTwoColLayout struct{}

func NewTightTwoColLayout() *TightTwoColLayout { return &TightTwoColLayout{} }

func (l *TightTwoColLayout) Layout(objects []fyne.CanvasObject, size fyne.Size) {
	if len(objects) == 0 {
		return
	}
	leftWidth := l.leftColWidth(objects)
	spacingX := float32(8) // small horizontal gap between columns
	xName := float32(0)
	xValue := leftWidth + spacingX
	valueWidth := size.Width - xValue

	y := float32(0)
	for i := 0; i < len(objects); i += 2 {
		name := objects[i]
		var value fyne.CanvasObject
		if i+1 < len(objects) {
			value = objects[i+1]
		}
		nameMS := name.MinSize()
		rowHeight := nameMS.Height
		if value != nil {
			vms := value.MinSize()
			if vms.Height > rowHeight {
				rowHeight = vms.Height
			}
		}
		name.Move(fyne.NewPos(xName, y))
		name.Resize(fyne.NewSize(leftWidth, rowHeight))
		if value != nil {
			value.Move(fyne.NewPos(xValue, y))
			value.Resize(fyne.NewSize(valueWidth, rowHeight))
		}
		y += rowHeight // no vertical spacing
	}
}

func (l *TightTwoColLayout) MinSize(objects []fyne.CanvasObject) fyne.Size {
	if len(objects) == 0 {
		return fyne.NewSize(0, 0)
	}
	leftWidth := l.leftColWidth(objects)
	maxRight := float32(0)
	totalHeight := float32(0)
	for i := 0; i < len(objects); i += 2 {
		name := objects[i]
		nameMS := name.MinSize()
		rowHeight := nameMS.Height
		if i+1 < len(objects) {
			v := objects[i+1]
			vms := v.MinSize()
			if vms.Width > maxRight {
				maxRight = vms.Width
			}
			if vms.Height > rowHeight {
				rowHeight = vms.Height
			}
		}
		totalHeight += rowHeight
	}
	spacingX := float32(8)
	return fyne.NewSize(leftWidth+spacingX+maxRight, totalHeight)
}

func (l *TightTwoColLayout) leftColWidth(objects []fyne.CanvasObject) float32 {
	max := float32(0)
	for i := 0; i < len(objects); i += 2 {
		ms := objects[i].MinSize()
		if ms.Width > max {
			max = ms.Width
		}
	}
	return max
}
