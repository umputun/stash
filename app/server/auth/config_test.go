package auth

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/umputun/stash/app/enum"
)

func TestLoadConfig(t *testing.T) {
	t.Run("valid config", func(t *testing.T) {
		content := `
users:
  - name: admin
    password: "$2a$10$hash"
    permissions:
      - prefix: "*"
        access: rw
tokens:
  - token: "mytoken"
    permissions:
      - prefix: "*"
        access: r
`
		f := createTempFile(t, content)
		cfg, err := LoadConfig(f, nil)
		require.NoError(t, err)
		require.Len(t, cfg.Users, 1)
		require.Len(t, cfg.Tokens, 1)
		assert.Equal(t, "admin", cfg.Users[0].Name)
		assert.Equal(t, "mytoken", cfg.Tokens[0].Token)
	})

	t.Run("file not found", func(t *testing.T) {
		_, err := LoadConfig("/nonexistent/file.yml", nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to read auth config file")
	})

	t.Run("invalid yaml", func(t *testing.T) {
		f := createTempFile(t, "invalid: yaml: content:")
		_, err := LoadConfig(f, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to parse auth config file")
	})

	t.Run("validator called and error propagates", func(t *testing.T) {
		content := `
users:
  - name: admin
    password: "$2a$10$hash"
    permissions:
      - prefix: "*"
        access: rw
`
		f := createTempFile(t, content)
		validatorCalled := false
		validator := func(data []byte) error {
			validatorCalled = true
			return assert.AnError // return error to test propagation
		}
		_, err := LoadConfig(f, validator)
		require.Error(t, err)
		assert.True(t, validatorCalled, "validator should be called")
		assert.ErrorIs(t, err, assert.AnError, "validator error should propagate")
	})

	t.Run("validator success", func(t *testing.T) {
		content := `
users:
  - name: admin
    password: "$2a$10$hash"
    permissions:
      - prefix: "*"
        access: rw
`
		f := createTempFile(t, content)
		validatorCalled := false
		validator := func(data []byte) error {
			validatorCalled = true
			return nil
		}
		cfg, err := LoadConfig(f, validator)
		require.NoError(t, err)
		assert.True(t, validatorCalled, "validator should be called")
		assert.Len(t, cfg.Users, 1)
	})
}

func TestMatchPrefix(t *testing.T) {
	tests := []struct {
		pattern string
		key     string
		want    bool
	}{
		{"*", "anything", true},
		{"*", "app/config", true},
		{"*", "", true},
		{"app/*", "app/config", true},
		{"app/*", "app/db/host", true},
		{"app/*", "app/", true},
		{"app/*", "application/config", false},
		{"app/*", "other/key", false},
		{"app/config", "app/config", true},
		{"app/config", "app/config/sub", false},
		{"app/config", "app/other", false},
	}

	for _, tt := range tests {
		t.Run(tt.pattern+"_"+tt.key, func(t *testing.T) {
			assert.Equal(t, tt.want, matchPrefix(tt.pattern, tt.key))
		})
	}
}

func TestTokenACL_CheckKeyPermission(t *testing.T) {
	acl := TokenACL{
		Token: "test",
		prefixes: []prefixPerm{
			{prefix: "app/*", permission: enum.PermissionReadWrite},
			{prefix: "*", permission: enum.PermissionRead},
		},
	}

	tests := []struct {
		key       string
		needWrite bool
		want      bool
	}{
		{"app/config", false, true},
		{"app/config", true, true},
		{"other/key", false, true},
		{"other/key", true, false},
	}

	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			assert.Equal(t, tt.want, acl.CheckKeyPermission(tt.key, tt.needWrite))
		})
	}
}

func TestPrefixPerm_GrantsSecrets(t *testing.T) {
	tests := []struct {
		prefix string
		want   bool
	}{
		{"secrets/*", true},
		{"secrets/db", true},
		{"app/secrets/*", true},
		{"app/secrets/key", true},
		{"*", false},
		{"app/*", false},
		{"config/*", false},
		{"mysecrets/*", false}, // "mysecrets" is not a path segment
		{"secretsabc/*", false},
	}

	for _, tt := range tests {
		t.Run(tt.prefix, func(t *testing.T) {
			pp := prefixPerm{prefix: tt.prefix, permission: enum.PermissionRead}
			assert.Equal(t, tt.want, pp.grantsSecrets(), "prefix: %s", tt.prefix)
		})
	}
}

func TestTokenACL_CheckKeyPermission_Secrets(t *testing.T) {
	t.Run("wildcard does not grant secrets", func(t *testing.T) {
		acl := TokenACL{
			Token: "wildcard",
			prefixes: []prefixPerm{
				{prefix: "*", permission: enum.PermissionReadWrite},
			},
		}

		// regular keys work
		assert.True(t, acl.CheckKeyPermission("app/config", false))
		assert.True(t, acl.CheckKeyPermission("app/config", true))

		// secrets are denied
		assert.False(t, acl.CheckKeyPermission("secrets/db", false))
		assert.False(t, acl.CheckKeyPermission("secrets/db", true))
		assert.False(t, acl.CheckKeyPermission("app/secrets/key", false))
	})

	t.Run("app/* does not grant app/secrets/*", func(t *testing.T) {
		acl := TokenACL{
			Token: "scoped",
			prefixes: []prefixPerm{
				{prefix: "app/*", permission: enum.PermissionReadWrite},
			},
		}

		// regular app keys work
		assert.True(t, acl.CheckKeyPermission("app/config", false))
		assert.True(t, acl.CheckKeyPermission("app/config", true))

		// app/secrets/* is denied
		assert.False(t, acl.CheckKeyPermission("app/secrets/db", false))
		assert.False(t, acl.CheckKeyPermission("app/secrets/db", true))
	})

	t.Run("secrets/* grants access to secrets", func(t *testing.T) {
		acl := TokenACL{
			Token: "secrets-reader",
			prefixes: []prefixPerm{
				{prefix: "secrets/*", permission: enum.PermissionRead},
			},
		}

		assert.True(t, acl.CheckKeyPermission("secrets/db", false))
		assert.False(t, acl.CheckKeyPermission("secrets/db", true)) // no write

		// doesn't grant access to non-secrets
		assert.False(t, acl.CheckKeyPermission("app/config", false))
	})

	t.Run("app/secrets/* grants app/secrets/*", func(t *testing.T) {
		acl := TokenACL{
			Token: "app-secrets",
			prefixes: []prefixPerm{
				{prefix: "app/secrets/*", permission: enum.PermissionReadWrite},
			},
		}

		assert.True(t, acl.CheckKeyPermission("app/secrets/db", false))
		assert.True(t, acl.CheckKeyPermission("app/secrets/db", true))

		// doesn't grant other secrets
		assert.False(t, acl.CheckKeyPermission("secrets/db", false))
		assert.False(t, acl.CheckKeyPermission("other/secrets/key", false))
	})

	t.Run("combined permissions with secrets", func(t *testing.T) {
		acl := TokenACL{
			Token: "combined",
			prefixes: []prefixPerm{
				{prefix: "app/secrets/*", permission: enum.PermissionReadWrite},
				{prefix: "app/*", permission: enum.PermissionRead},
				{prefix: "*", permission: enum.PermissionRead},
			},
		}

		// regular keys via app/* or *
		assert.True(t, acl.CheckKeyPermission("app/config", false))
		assert.False(t, acl.CheckKeyPermission("app/config", true)) // app/* is read-only
		assert.True(t, acl.CheckKeyPermission("other/key", false))

		// app/secrets via explicit app/secrets/*
		assert.True(t, acl.CheckKeyPermission("app/secrets/db", false))
		assert.True(t, acl.CheckKeyPermission("app/secrets/db", true))

		// other secrets denied (no matching secrets prefix)
		assert.False(t, acl.CheckKeyPermission("secrets/db", false))
	})
}

func TestParsePermissionString(t *testing.T) {
	tests := []struct {
		input   string
		want    enum.Permission
		wantErr bool
	}{
		{"r", enum.PermissionRead, false},
		{"R", enum.PermissionRead, false},
		{"read", enum.PermissionRead, false},
		{"w", enum.PermissionWrite, false},
		{"write", enum.PermissionWrite, false},
		{"rw", enum.PermissionReadWrite, false},
		{"RW", enum.PermissionReadWrite, false},
		{"readwrite", enum.PermissionReadWrite, false},
		{"read-write", enum.PermissionReadWrite, false},
		{"invalid", enum.PermissionNone, true},
		{"", enum.PermissionNone, true},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := parsePermissionString(tt.input)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestParseTokenConfigs_PublicToken(t *testing.T) {
	t.Run("public token extracted separately", func(t *testing.T) {
		configs := []TokenConfig{
			{Token: "*", Permissions: []PermissionConfig{{Prefix: "public/*", Access: "r"}}},
			{Token: "normal", Permissions: []PermissionConfig{{Prefix: "*", Access: "rw"}}},
		}
		tokens, publicACL, err := parseTokenConfigs(configs)
		require.NoError(t, err)
		require.NotNil(t, publicACL, "public ACL should be extracted")
		assert.Len(t, tokens, 1, "only normal token should be in map")
		_, hasPublic := tokens["*"]
		assert.False(t, hasPublic, "* should not be in tokens map")
		_, hasNormal := tokens["normal"]
		assert.True(t, hasNormal, "normal token should be in map")
	})

	t.Run("only public token", func(t *testing.T) {
		configs := []TokenConfig{
			{Token: "*", Permissions: []PermissionConfig{{Prefix: "*", Access: "r"}}},
		}
		tokens, publicACL, err := parseTokenConfigs(configs)
		require.NoError(t, err)
		require.NotNil(t, publicACL)
		assert.Empty(t, tokens, "tokens map should be empty")
	})

	t.Run("no public token", func(t *testing.T) {
		configs := []TokenConfig{
			{Token: "normal", Permissions: []PermissionConfig{{Prefix: "*", Access: "rw"}}},
		}
		tokens, publicACL, err := parseTokenConfigs(configs)
		require.NoError(t, err)
		assert.Nil(t, publicACL, "public ACL should be nil")
		assert.Len(t, tokens, 1)
	})

	t.Run("duplicate public token rejected", func(t *testing.T) {
		configs := []TokenConfig{
			{Token: "*", Permissions: []PermissionConfig{{Prefix: "public/*", Access: "r"}}},
			{Token: "*", Permissions: []PermissionConfig{{Prefix: "status", Access: "r"}}},
		}
		_, _, err := parseTokenConfigs(configs)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "duplicate public token")
	})
}

// createTempFile creates a temporary file with the given content and returns its path.
func createTempFile(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	f := filepath.Join(dir, "auth.yml")
	err := os.WriteFile(f, []byte(content), 0o600)
	require.NoError(t, err)
	return f
}
