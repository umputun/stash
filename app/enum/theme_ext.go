package enum

// Toggle returns the opposite theme (dark↔light). System defaults to dark.
func (t Theme) Toggle() Theme {
	if t == ThemeDark {
		return ThemeLight
	}
	return ThemeDark
}
