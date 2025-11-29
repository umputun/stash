package server

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVerifyAuthConfig(t *testing.T) {
	tests := []struct {
		name    string
		file    string
		wantErr bool
		errMsg  string
	}{
		{name: "valid config", file: "valid_config.yml", wantErr: false},
		{name: "valid longform access values", file: "valid_longform_access.yml", wantErr: false},
		{name: "invalid access value", file: "invalid_access.yml", wantErr: true, errMsg: "value must be one of"},
		{name: "missing required name", file: "missing_name.yml", wantErr: true, errMsg: "missing properties"},
		{name: "unknown field", file: "unknown_field.yml", wantErr: true, errMsg: "additionalProperties"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join("testdata", tc.file))
			require.NoError(t, err, "failed to read test file")

			err = VerifyAuthConfig(data)
			if tc.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.errMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestVerifyAuthConfig_EmptySchema(t *testing.T) {
	// save original and restore after test
	orig := embeddedSchemaData
	defer func() { embeddedSchemaData = orig }()

	embeddedSchemaData = nil
	err := VerifyAuthConfig([]byte(`users: []`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "embedded auth schema is empty")
}

func TestVerifyAuthConfig_InvalidYAML(t *testing.T) {
	err := VerifyAuthConfig([]byte(`invalid: yaml: content:`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse auth config file")
}
