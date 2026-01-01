package auth

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/umputun/stash/app/enum"
	"github.com/umputun/stash/app/store"
)

// Config represents the auth configuration file (stash-auth.yml).
type Config struct {
	Users  []UserConfig  `yaml:"users,omitempty" json:"users,omitempty" jsonschema:"description=users for web UI auth"`
	Tokens []TokenConfig `yaml:"tokens,omitempty" json:"tokens,omitempty" jsonschema:"description=API tokens"`
}

// UserConfig represents a user in the auth config file.
type UserConfig struct {
	Name        string             `yaml:"name" json:"name" jsonschema:"required"`
	Password    string             `yaml:"password" json:"password" jsonschema:"required"` // bcrypt hash
	Admin       bool               `yaml:"admin,omitempty" json:"admin,omitempty" jsonschema:"description=grants admin privileges (audit access)"`
	Permissions []PermissionConfig `yaml:"permissions,omitempty" json:"permissions,omitempty"`
}

// TokenConfig represents an API token in the auth config file.
type TokenConfig struct {
	Token       string             `yaml:"token" json:"token" jsonschema:"required"`
	Admin       bool               `yaml:"admin,omitempty" json:"admin,omitempty" jsonschema:"description=grants admin privileges (audit access)"`
	Permissions []PermissionConfig `yaml:"permissions,omitempty" json:"permissions,omitempty"`
}

// PermissionConfig represents a prefix-permission pair in the config file.
type PermissionConfig struct {
	Prefix string `yaml:"prefix" json:"prefix" jsonschema:"required"`
	Access string `yaml:"access" json:"access" jsonschema:"required,enum=r,enum=read,enum=w,enum=write,enum=rw,enum=readwrite,enum=read-write"`
}

// User represents an authenticated user with ACL.
type User struct {
	Name         string
	PasswordHash string
	Admin        bool     // grants admin privileges (audit access)
	ACL          TokenACL // reuse ACL structure for permissions
}

// TokenACL defines access control for an API token.
type TokenACL struct {
	Token    string
	Admin    bool         // grants admin privileges (audit access)
	prefixes []prefixPerm // sorted by prefix length descending for longest-match-first
}

// SessionStore is the interface for persistent session storage.
type SessionStore interface {
	CreateSession(ctx context.Context, token, username string, expiresAt time.Time) error
	GetSession(ctx context.Context, token string) (username string, expiresAt time.Time, err error)
	DeleteSession(ctx context.Context, token string) error
	DeleteAllSessions(ctx context.Context) error
	DeleteSessionsByUsername(ctx context.Context, username string) error
	DeleteExpiredSessions(ctx context.Context) (int64, error)
}

// ConfigValidator validates auth configuration data against a schema.
type ConfigValidator func(data []byte) error

// prefixPerm represents a single prefix-permission pair, used for ordered matching.
type prefixPerm struct {
	prefix     string
	permission enum.Permission
}

// LoadConfig reads and parses the auth YAML file.
// If validator is provided, the config is validated against the schema.
func LoadConfig(path string, validator ConfigValidator) (*Config, error) {
	data, err := os.ReadFile(path) //nolint:gosec // path is from CLI flag, controlled by admin
	if err != nil {
		return nil, fmt.Errorf("failed to read auth config file: %w", err)
	}

	// validate against embedded JSON schema if validator provided
	if validator != nil {
		if err := validator(data); err != nil {
			return nil, err
		}
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse auth config file: %w", err)
	}

	return &cfg, nil
}

// CheckKeyPermission checks if this ACL grants permission for a key.
// For secret keys (containing "secrets" path segment), the matching prefix
// must also explicitly contain "secrets" - wildcards like "*" or "app/*"
// do not grant access to secrets.
func (acl TokenACL) CheckKeyPermission(key string, needWrite bool) bool {
	isSecretKey := store.IsSecret(key)

	for _, pp := range acl.prefixes {
		if matchPrefix(pp.prefix, key) {
			// if key is a secret, the prefix must explicitly grant secrets access
			if isSecretKey && !pp.grantsSecrets() {
				continue // skip this prefix, try to find one that grants secrets
			}

			if needWrite {
				return pp.permission.CanWrite()
			}
			return pp.permission.CanRead()
		}
	}
	return false
}

// parseUsers converts UserConfig slice to users map.
func parseUsers(configs []UserConfig) (map[string]User, error) {
	users := make(map[string]User)

	for _, uc := range configs {
		if uc.Name == "" {
			return nil, errors.New("user name cannot be empty")
		}
		if uc.Password == "" {
			return nil, fmt.Errorf("password hash cannot be empty for user %q", uc.Name)
		}
		if _, exists := users[uc.Name]; exists {
			return nil, fmt.Errorf("duplicate user name %q", uc.Name)
		}

		acl, err := parsePermissionConfigs(uc.Name, uc.Permissions)
		if err != nil {
			return nil, fmt.Errorf("invalid permissions for user %q: %w", uc.Name, err)
		}

		users[uc.Name] = User{
			Name:         uc.Name,
			PasswordHash: uc.Password,
			Admin:        uc.Admin,
			ACL:          acl,
		}
	}

	return users, nil
}

// parseTokenConfigs converts TokenConfig slice to tokens map and extracts public ACL.
func parseTokenConfigs(configs []TokenConfig) (map[string]TokenACL, *TokenACL, error) {
	tokens := make(map[string]TokenACL)
	var publicACL *TokenACL

	for _, tc := range configs {
		if tc.Token == "" {
			return nil, nil, errors.New("token cannot be empty")
		}
		if _, exists := tokens[tc.Token]; exists {
			return nil, nil, fmt.Errorf("duplicate token %q", MaskToken(tc.Token))
		}

		acl, err := parsePermissionConfigs(tc.Token, tc.Permissions)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid permissions for token %q: %w", MaskToken(tc.Token), err)
		}
		acl.Admin = tc.Admin

		// token "*" is treated as public access (no auth required)
		if tc.Token == "*" {
			if publicACL != nil {
				return nil, nil, errors.New("duplicate public token \"*\"")
			}
			publicACL = &acl
			continue // don't add to regular tokens map
		}

		tokens[tc.Token] = acl
	}

	return tokens, publicACL, nil
}

// parsePermissionConfigs converts PermissionConfig slice to TokenACL.
func parsePermissionConfigs(name string, configs []PermissionConfig) (TokenACL, error) {
	var acl TokenACL
	acl.Token = name
	seen := make(map[string]bool)

	for _, pc := range configs {
		if pc.Prefix == "" {
			return TokenACL{}, errors.New("prefix cannot be empty")
		}
		if seen[pc.Prefix] {
			return TokenACL{}, fmt.Errorf("duplicate prefix %q", pc.Prefix)
		}
		seen[pc.Prefix] = true

		perm, err := parsePermissionString(pc.Access)
		if err != nil {
			return TokenACL{}, fmt.Errorf("invalid access %q for prefix %q: %w", pc.Access, pc.Prefix, err)
		}

		acl.prefixes = append(acl.prefixes, prefixPerm{
			prefix:     pc.Prefix,
			permission: perm,
		})
	}

	// sort prefixes by length descending for longest-match-first
	sort.Slice(acl.prefixes, func(i, j int) bool {
		return len(acl.prefixes[i].prefix) > len(acl.prefixes[j].prefix)
	})

	return acl, nil
}

// parsePermissionString converts a permission string to enum.Permission type.
func parsePermissionString(s string) (enum.Permission, error) {
	perm, err := enum.ParsePermission(strings.TrimSpace(s))
	if err != nil {
		return enum.PermissionNone, errors.New("expected r/w/rw")
	}
	return perm, nil
}

// matchPrefix checks if a key matches a prefix pattern.
// "*" matches everything, "foo/*" matches keys starting with "foo/".
func matchPrefix(pattern, key string) bool {
	if pattern == "*" {
		return true
	}
	// remove trailing * for prefix matching
	if prefix, found := strings.CutSuffix(pattern, "*"); found {
		return strings.HasPrefix(key, prefix)
	}
	// exact match
	return pattern == key
}

// grantsSecrets checks if this prefix pattern explicitly grants access to secrets.
// A prefix grants secrets access if it contains "secrets" as a path segment.
// Examples:
//   - "secrets/*" → true (covers secrets/)
//   - "app/secrets/*" → true (covers app/secrets/)
//   - "*" → false (wildcard doesn't grant secrets)
//   - "app/*" → false (doesn't explicitly include secrets)
func (pp prefixPerm) grantsSecrets() bool {
	// remove trailing * for pattern matching and check if the path is a secret path
	basePrefix := strings.TrimSuffix(pp.prefix, "*")
	return store.IsSecret(basePrefix)
}
