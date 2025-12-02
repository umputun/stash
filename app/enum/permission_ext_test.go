package enum

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPermission_CanRead(t *testing.T) {
	tests := []struct {
		perm     Permission
		expected bool
	}{
		{PermissionNone, false},
		{PermissionRead, true},
		{PermissionWrite, false},
		{PermissionReadWrite, true},
	}

	for _, tc := range tests {
		t.Run(tc.perm.String(), func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.perm.CanRead())
		})
	}
}

func TestPermission_CanWrite(t *testing.T) {
	tests := []struct {
		perm     Permission
		expected bool
	}{
		{PermissionNone, false},
		{PermissionRead, false},
		{PermissionWrite, true},
		{PermissionReadWrite, true},
	}

	for _, tc := range tests {
		t.Run(tc.perm.String(), func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.perm.CanWrite())
		})
	}
}
