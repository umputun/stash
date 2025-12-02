package enum

// Toggle returns the opposite view mode (grid↔cards).
func (v ViewMode) Toggle() ViewMode {
	if v == ViewModeCards {
		return ViewModeGrid
	}
	return ViewModeCards
}
