package enum

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestViewMode_Toggle(t *testing.T) {
	tests := []struct {
		current  ViewMode
		expected ViewMode
	}{
		{ViewModeGrid, ViewModeCards},
		{ViewModeCards, ViewModeGrid},
	}

	for _, tc := range tests {
		t.Run(tc.current.String()+"->"+tc.expected.String(), func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.current.Toggle())
		})
	}
}
