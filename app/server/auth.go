package server

import (
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	log "github.com/go-pkgz/lgr"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/yaml.v3"

	"github.com/umputun/stash/app/store"
)

// sessionCookieNames defines cookie names for session authentication.
// __Host- prefix requires HTTPS, secure, path=/ (preferred for production).
// fallback cookie name works on HTTP for development.
var sessionCookieNames = []string{"__Host-stash-auth", "stash-auth"}

// Permission represents read/write access level.
type Permission int

// Permission constants define access levels.
const (
	PermissionNone      Permission = iota // no access
	PermissionRead                        // read-only access
	PermissionWrite                       // write-only access
	PermissionReadWrite                   // full read-write access
)

// String returns a string representation of the permission.
func (p Permission) String() string {
	switch p {
	case PermissionRead:
		return "r"
	case PermissionWrite:
		return "w"
	case PermissionReadWrite:
		return "rw"
	default:
		return "none"
	}
}

// CanRead returns true if the permission allows reading.
func (p Permission) CanRead() bool {
	return p == PermissionRead || p == PermissionReadWrite
}

// CanWrite returns true if the permission allows writing.
func (p Permission) CanWrite() bool {
	return p == PermissionWrite || p == PermissionReadWrite
}

// AuthConfig represents the auth configuration file (stash-auth.yml).
type AuthConfig struct {
	Users  []UserConfig  `yaml:"users"`
	Tokens []TokenConfig `yaml:"tokens"`
}

// UserConfig represents a user in the auth config file.
type UserConfig struct {
	Name        string             `yaml:"name"`
	Password    string             `yaml:"password"` // bcrypt hash
	Permissions []PermissionConfig `yaml:"permissions"`
}

// TokenConfig represents an API token in the auth config file.
type TokenConfig struct {
	Token       string             `yaml:"token"`
	Permissions []PermissionConfig `yaml:"permissions"`
}

// PermissionConfig represents a prefix-permission pair in the config file.
type PermissionConfig struct {
	Prefix string `yaml:"prefix"`
	Access string `yaml:"access"` // r, w, rw
}

// User represents an authenticated user with ACL.
type User struct {
	Name         string
	PasswordHash string
	ACL          TokenACL // reuse ACL structure for permissions
}

// LoadAuthConfig reads and parses the auth YAML file.
func LoadAuthConfig(path string) (*AuthConfig, error) {
	data, err := os.ReadFile(path) //nolint:gosec // path is from CLI flag, controlled by admin
	if err != nil {
		return nil, fmt.Errorf("failed to read auth config file: %w", err)
	}

	var cfg AuthConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse auth config file: %w", err)
	}

	return &cfg, nil
}

// prefixPerm represents a single prefix-permission pair, used for ordered matching.
type prefixPerm struct {
	prefix     string
	permission Permission
}

// TokenACL defines access control for an API token.
type TokenACL struct {
	Token    string
	prefixes []prefixPerm // sorted by prefix length descending for longest-match-first
}

// session represents an active login session.
type session struct {
	token     string
	username  string // logged-in username (empty for legacy single-password mode)
	createdAt time.Time
}

// Auth handles authentication and authorization.
type Auth struct {
	users      map[string]User     // username -> User (for web UI auth)
	tokens     map[string]TokenACL // token string -> ACL (for API auth)
	publicACL  *TokenACL           // public access ACL (token="*"), nil if not configured
	sessions   map[string]session  // session token -> session
	sessionsMu sync.Mutex
	loginTTL   time.Duration
}

// NewAuth creates a new Auth instance from configuration file.
// Returns nil if authFile is empty (authentication disabled).
func NewAuth(authFile string, loginTTL time.Duration) (*Auth, error) {
	if authFile == "" {
		return nil, nil // auth disabled
	}

	cfg, err := LoadAuthConfig(authFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load auth config: %w", err)
	}

	users, err := parseUsers(cfg.Users)
	if err != nil {
		return nil, fmt.Errorf("failed to parse users: %w", err)
	}

	tokens, publicACL, err := parseTokenConfigs(cfg.Tokens)
	if err != nil {
		return nil, fmt.Errorf("failed to parse tokens: %w", err)
	}

	if len(users) == 0 && len(tokens) == 0 && publicACL == nil {
		return nil, fmt.Errorf("auth config must have at least one user or token")
	}

	if loginTTL == 0 {
		loginTTL = 24 * time.Hour
	}

	return &Auth{
		users:     users,
		tokens:    tokens,
		publicACL: publicACL,
		sessions:  make(map[string]session),
		loginTTL:  loginTTL,
	}, nil
}

// parseUsers converts UserConfig slice to users map.
func parseUsers(configs []UserConfig) (map[string]User, error) {
	users := make(map[string]User)

	for _, uc := range configs {
		if uc.Name == "" {
			return nil, fmt.Errorf("user name cannot be empty")
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
			ACL:          acl,
		}
	}

	return users, nil
}

// parseTokenConfigs converts TokenConfig slice to tokens map and extracts public ACL.
// Returns (tokens map, public ACL or nil, error).
func parseTokenConfigs(configs []TokenConfig) (map[string]TokenACL, *TokenACL, error) {
	tokens := make(map[string]TokenACL)
	var publicACL *TokenACL

	for _, tc := range configs {
		if tc.Token == "" {
			return nil, nil, fmt.Errorf("token cannot be empty")
		}
		if _, exists := tokens[tc.Token]; exists {
			return nil, nil, fmt.Errorf("duplicate token %q", maskToken(tc.Token))
		}

		acl, err := parsePermissionConfigs(tc.Token, tc.Permissions)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid permissions for token %q: %w", maskToken(tc.Token), err)
		}

		// token "*" is treated as public access (no auth required)
		if tc.Token == "*" {
			if publicACL != nil {
				return nil, nil, fmt.Errorf("duplicate public token \"*\"")
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
			return TokenACL{}, fmt.Errorf("prefix cannot be empty")
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

// parsePermissionString converts a permission string to Permission type.
func parsePermissionString(s string) (Permission, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "r", "read":
		return PermissionRead, nil
	case "w", "write":
		return PermissionWrite, nil
	case "rw", "readwrite", "read-write":
		return PermissionReadWrite, nil
	default:
		return PermissionNone, fmt.Errorf("expected r/w/rw")
	}
}

// Enabled returns true if authentication is enabled.
func (a *Auth) Enabled() bool {
	return a != nil && (len(a.users) > 0 || len(a.tokens) > 0 || a.publicACL != nil)
}

// LoginTTL returns the configured login session TTL.
func (a *Auth) LoginTTL() time.Duration {
	if a == nil {
		return 24 * time.Hour // default
	}
	return a.loginTTL
}

// ValidateUser checks if username/password are valid and returns the user.
// Returns nil if credentials are invalid.
// Uses constant-time comparison to prevent username enumeration via timing attacks.
func (a *Auth) ValidateUser(username, password string) *User {
	if a == nil {
		return nil
	}

	// dummy hash for constant-time comparison when user doesn't exist.
	// this is a valid bcrypt hash (cost=10) to ensure comparison takes similar time.
	const dummyHash = "$2a$10$C615A0mfUEFBupj9qcqhiuBEyf60EqrsakB90CozUoSON8d2Dc1uS"

	user, exists := a.users[username]
	hashToCheck := dummyHash
	if exists {
		hashToCheck = user.PasswordHash
	}

	// always run bcrypt comparison to prevent timing-based username enumeration
	if err := bcrypt.CompareHashAndPassword([]byte(hashToCheck), []byte(password)); err != nil || !exists {
		return nil
	}
	return &user
}

// IsValidUser checks if username/password are valid credentials.
// This is the interface-friendly version of ValidateUser.
func (a *Auth) IsValidUser(username, password string) bool {
	return a.ValidateUser(username, password) != nil
}

// GetTokenACL returns the ACL for a token and whether it exists.
func (a *Auth) GetTokenACL(token string) (TokenACL, bool) {
	if a == nil {
		return TokenACL{}, false
	}
	acl, ok := a.tokens[token]
	return acl, ok
}

// HasTokenACL checks if a token exists in the ACL.
func (a *Auth) HasTokenACL(token string) bool {
	_, ok := a.GetTokenACL(token)
	return ok
}

// CheckPermission checks if a token has the required permission for a key.
// Returns true if the token has sufficient permissions.
func (a *Auth) CheckPermission(token, key string, needWrite bool) bool {
	acl, ok := a.GetTokenACL(token)
	if !ok {
		return false
	}
	return acl.CheckKeyPermission(key, needWrite)
}

// matchPrefix checks if a key matches a prefix pattern.
// "*" matches everything, "foo/*" matches keys starting with "foo/".
func matchPrefix(pattern, key string) bool {
	if pattern == "*" {
		return true
	}
	// remove trailing * for prefix matching
	if strings.HasSuffix(pattern, "*") {
		prefix := strings.TrimSuffix(pattern, "*")
		return strings.HasPrefix(key, prefix)
	}
	// exact match
	return pattern == key
}

// CreateSession generates a new session token for the given username.
func (a *Auth) CreateSession(username string) (string, error) {
	if a == nil {
		return "", fmt.Errorf("auth not enabled")
	}

	token := uuid.NewString()

	a.sessionsMu.Lock()
	defer a.sessionsMu.Unlock()

	a.sessions[token] = session{
		token:     token,
		username:  username,
		createdAt: time.Now(),
	}

	// cleanup expired sessions
	a.cleanupExpiredSessions()

	return token, nil
}

// GetSessionUser returns the username for a valid session.
// Returns empty string and false if session is invalid or expired.
func (a *Auth) GetSessionUser(token string) (string, bool) {
	if a == nil {
		return "", false
	}

	a.sessionsMu.Lock()
	defer a.sessionsMu.Unlock()

	sess, exists := a.sessions[token]
	if !exists {
		return "", false
	}

	if time.Since(sess.createdAt) > a.loginTTL {
		delete(a.sessions, token)
		return "", false
	}

	return sess.username, true
}

// CheckUserPermission checks if a user has the required permission for a key.
// Returns true when auth is disabled (permissive by default).
func (a *Auth) CheckUserPermission(username, key string, needWrite bool) bool {
	if a == nil || !a.Enabled() {
		return true // no auth = everything allowed
	}
	user, exists := a.users[username]
	if !exists {
		return false
	}
	return user.ACL.CheckKeyPermission(key, needWrite)
}

// FilterUserKeys filters keys based on user's read permissions.
// Returns all keys when auth is disabled (permissive by default).
func (a *Auth) FilterUserKeys(username string, keys []string) []string {
	if a == nil || !a.Enabled() {
		return keys // no auth = show all keys
	}
	user, exists := a.users[username]
	if !exists {
		return nil
	}

	var filtered []string
	for _, key := range keys {
		if user.ACL.CheckKeyPermission(key, false) {
			filtered = append(filtered, key)
		}
	}
	return filtered
}

// FilterTokenKeys filters keys based on token's read permissions.
// Returns nil if token doesn't exist.
func (a *Auth) FilterTokenKeys(token string, keys []string) []string {
	if a == nil {
		return keys // no auth = show all keys
	}
	acl, ok := a.tokens[token]
	if !ok {
		return nil
	}

	var filtered []string
	for _, key := range keys {
		if acl.CheckKeyPermission(key, false) {
			filtered = append(filtered, key)
		}
	}
	return filtered
}

// FilterPublicKeys filters keys based on public ACL read permissions.
// Returns nil if public access is not configured.
func (a *Auth) FilterPublicKeys(keys []string) []string {
	if a == nil || a.publicACL == nil {
		return nil
	}

	var filtered []string
	for _, key := range keys {
		if a.publicACL.CheckKeyPermission(key, false) {
			filtered = append(filtered, key)
		}
	}
	return filtered
}

// CheckKeyPermission checks if this ACL grants permission for a key.
func (acl TokenACL) CheckKeyPermission(key string, needWrite bool) bool {
	for _, pp := range acl.prefixes {
		if matchPrefix(pp.prefix, key) {
			if needWrite {
				return pp.permission.CanWrite()
			}
			return pp.permission.CanRead()
		}
	}
	return false
}

// UserCanWrite returns true if user has any write permission.
// Returns true when auth is disabled (permissive by default).
func (a *Auth) UserCanWrite(username string) bool {
	if a == nil || !a.Enabled() {
		return true // no auth = write allowed
	}
	user, exists := a.users[username]
	if !exists {
		return false
	}
	for _, pp := range user.ACL.prefixes {
		if pp.permission.CanWrite() {
			return true
		}
	}
	return false
}

// ValidateSession checks if a session token is valid and not expired.
func (a *Auth) ValidateSession(token string) bool {
	if a == nil {
		return false
	}

	a.sessionsMu.Lock()
	defer a.sessionsMu.Unlock()

	sess, exists := a.sessions[token]
	if !exists {
		return false
	}

	if time.Since(sess.createdAt) > a.loginTTL {
		delete(a.sessions, token)
		return false
	}

	return true
}

// InvalidateSession removes a session.
func (a *Auth) InvalidateSession(token string) {
	if a == nil {
		return
	}

	a.sessionsMu.Lock()
	defer a.sessionsMu.Unlock()
	delete(a.sessions, token)
}

// cleanupExpiredSessions removes expired sessions. Must be called with lock held.
func (a *Auth) cleanupExpiredSessions() {
	now := time.Now()
	for token, sess := range a.sessions {
		if now.Sub(sess.createdAt) > a.loginTTL {
			delete(a.sessions, token)
		}
	}
}

// SessionAuth returns middleware that requires a valid session cookie.
// Used for web UI routes. Redirects to loginURL if not authenticated.
func (a *Auth) SessionAuth(loginURL string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// check session cookie
			for _, cookieName := range sessionCookieNames {
				if cookie, err := r.Cookie(cookieName); err == nil && a.ValidateSession(cookie.Value) {
					next.ServeHTTP(w, r)
					return
				}
			}
			// no valid session, redirect to login
			http.Redirect(w, r, loginURL, http.StatusSeeOther)
		})
	}
}

// TokenAuth returns middleware that requires a valid Bearer token with appropriate permissions.
// Used for API routes. Returns 401/403 if not authorized.
// Public access (token="*") is checked first and allows unauthenticated requests.
// For list operations (empty key), only validates token existence, filtering happens in handler.
func (a *Auth) TokenAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := store.NormalizeKey(strings.TrimPrefix(r.URL.Path, "/kv/"))
		needWrite := r.Method == http.MethodPut || r.Method == http.MethodDelete
		isList := key == "" && r.Method == http.MethodGet // list operation has no key

		// check public access first (token="*" in config)
		// for list operation, public access means pass-through (handler filters results)
		if a.publicACL != nil {
			if isList || a.publicACL.CheckKeyPermission(key, needWrite) {
				next.ServeHTTP(w, r)
				return
			}
		}

		// also accept session cookie for API (allows UI to call API)
		for _, cookieName := range sessionCookieNames {
			cookie, err := r.Cookie(cookieName)
			if err != nil {
				continue
			}
			username, valid := a.GetSessionUser(cookie.Value)
			if !valid {
				continue
			}
			// for list operation, just verify session is valid (handler filters results)
			if isList {
				next.ServeHTTP(w, r)
				return
			}
			// check user permissions for the key
			if !a.CheckUserPermission(username, key, needWrite) {
				log.Printf("[INFO] user %q denied %s access to key %q", username, r.Method, key)
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
			return
		}

		// check Bearer token
		authHeader := r.Header.Get("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		token := strings.TrimPrefix(authHeader, "Bearer ")

		// check if token exists
		if _, ok := a.GetTokenACL(token); !ok {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// for list operation, just verify token exists (handler filters results)
		if isList {
			next.ServeHTTP(w, r)
			return
		}

		if !a.CheckPermission(token, key, needWrite) {
			log.Printf("[INFO] token %q denied %s access to key %q", maskToken(token), r.Method, key)
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// NoopAuth returns a pass-through middleware (used when auth is disabled).
func NoopAuth(next http.Handler) http.Handler {
	return next
}

// maskToken returns a masked version of token for safe logging (shows first 4 chars).
func maskToken(token string) string {
	if len(token) <= 4 {
		return "****"
	}
	return token[:4] + "****"
}
