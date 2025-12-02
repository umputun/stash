package enum

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSortMode_Next(t *testing.T) {
	tests := []struct {
		current  SortMode
		expected SortMode
	}{
		{SortModeUpdated, SortModeKey},
		{SortModeKey, SortModeSize},
		{SortModeSize, SortModeCreated},
		{SortModeCreated, SortModeUpdated}, // wraps around
	}

	for _, tc := range tests {
		t.Run(tc.current.String()+"->"+tc.expected.String(), func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.current.Next())
		})
	}
}
