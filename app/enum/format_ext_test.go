package enum

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFormat_ContentType(t *testing.T) {
	tests := []struct {
		format   Format
		expected string
	}{
		{FormatJSON, "application/json"},
		{FormatYAML, "application/yaml"},
		{FormatXML, "application/xml"},
		{FormatTOML, "application/toml"},
		{FormatShell, "text/x-shellscript"},
		{FormatText, "text/plain"},
		{FormatINI, "text/plain"},
		{FormatHCL, "text/plain"},
	}

	for _, tc := range tests {
		t.Run(tc.format.String(), func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.format.ContentType())
		})
	}
}
