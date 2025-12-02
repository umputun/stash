package enum

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTheme_Toggle(t *testing.T) {
	tests := []struct {
		current  Theme
		expected Theme
	}{
		{ThemeSystem, ThemeDark},
		{ThemeLight, ThemeDark},
		{ThemeDark, ThemeLight},
	}

	for _, tc := range tests {
		t.Run(tc.current.String()+"->"+tc.expected.String(), func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.current.Toggle())
		})
	}
}
