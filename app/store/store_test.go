package store

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNormalizeKey(t *testing.T) {
	tests := []struct {
		name, input, expected string
	}{
		{"simple key", "foo", "foo"},
		{"key with leading slash", "/foo", "foo"},
		{"key with trailing slash", "foo/", "foo"},
		{"key with both slashes", "/foo/bar/", "foo/bar"},
		{"key with spaces", "foo bar", "foo_bar"},
		{"key with whitespace", "  foo  ", "foo"},
		{"key with spaces and slashes", " /foo bar/ ", "foo_bar"},
		{"nested with spaces", "foo/bar baz/qux", "foo/bar_baz/qux"},
		{"multiple leading slashes", "//foo//bar//", "foo//bar"},
		{"empty key", "", ""},
		{"only slashes", "///", ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, NormalizeKey(tc.input))
		})
	}
}
