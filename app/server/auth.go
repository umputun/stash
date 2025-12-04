package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	log "github.com/go-pkgz/lgr"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/yaml.v3"

	"github.com/umputun/stash/app/enum"
	"github.com/umputun/stash/app/store"
)

//go:generate go run internal/schema/main.go schema.json
//go:generate moq -out mocks/sessionstore.go -pkg mocks -skip-ensure -fmt goimports . SessionStore

// defaultSessionCleanupInterval is the default interval for background cleanup of expired sessions.
const defaultSessionCleanupInterval = 1 * time.Hour

// sessionCookieNames defines cookie names for session authentication.
// __Host- prefix requires HTTPS, secure, path=/ (preferred for production).
// fallback cookie name works on HTTP for development.
var sessionCookieNames = []string{"__Host-stash-auth", "stash-auth"}

// AuthConfig represents the auth configuration file (stash-auth.yml).
type AuthConfig struct {
	Users  []UserConfig  `yaml:"users,omitempty" json:"users,omitempty" jsonschema:"description=users for web UI auth"`
	Tokens []TokenConfig `yaml:"tokens,omitempty" json:"tokens,omitempty" jsonschema:"description=API tokens"`
}

// UserConfig represents a user in the auth config file.
type UserConfig struct {
	Name        string             `yaml:"name" json:"name" jsonschema:"required"`
	Password    string             `yaml:"password" json:"password" jsonschema:"required"` // bcrypt hash
	Permissions []PermissionConfig `yaml:"permissions,omitempty" json:"permissions,omitempty"`
}

// TokenConfig represents an API token in the auth config file.
type TokenConfig struct {
	Token       string             `yaml:"token" json:"token" jsonschema:"required"`
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
	ACL          TokenACL // reuse ACL structure for permissions
}

// LoadAuthConfig reads, validates and parses the auth YAML file.
func LoadAuthConfig(path string) (*AuthConfig, error) {
	data, err := os.ReadFile(path) //nolint:gosec // path is from CLI flag, controlled by admin
	if err != nil {
		return nil, fmt.Errorf("failed to read auth config file: %w", err)
	}

	// validate against embedded JSON schema
	if err := VerifyAuthConfig(data); err != nil {
		return nil, err
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
	permission enum.Permission
}

// TokenACL defines access control for an API token.
type TokenACL struct {
	Token    string
	prefixes []prefixPerm // sorted by prefix length descending for longest-match-first
}

// SessionStore is the interface for persistent session storage.
// Defined consumer-side per Go idiom.
type SessionStore interface {
	CreateSession(ctx context.Context, token, username string, expiresAt time.Time) error
	GetSession(ctx context.Context, token string) (username string, expiresAt time.Time, err error)
	DeleteSession(ctx context.Context, token string) error
	DeleteAllSessions(ctx context.Context) error
	DeleteSessionsByUsername(ctx context.Context, username string) error
	DeleteExpiredSessions(ctx context.Context) (int64, error)
}

// Auth handles authentication and authorization.
type Auth struct {
	mu              sync.RWMutex        // protects users, tokens, publicACL (config data)
	authFile        string              // path to auth config file for reloading
	users           map[string]User     // username -> User (for web UI auth)
	tokens          map[string]TokenACL // token string -> ACL (for API auth)
	publicACL       *TokenACL           // public access ACL (token="*"), nil if not configured
	sessionStore    SessionStore        // persistent session storage
	loginTTL        time.Duration
	cleanupInterval time.Duration // interval for session cleanup, defaults to 1h
}

// NewAuth creates a new Auth instance from configuration file.
// Returns nil if authFile is empty (authentication disabled).
// sessionStore is required for persistent session storage.
func NewAuth(authFile string, loginTTL time.Duration, sessionStore SessionStore) (*Auth, error) {
	if authFile == "" {
		return nil, nil //nolint:nilnil // nil auth means disabled, not an error
	}

	if sessionStore == nil {
		return nil, errors.New("session store is required")
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
		return nil, errors.New("auth config must have at least one user or token")
	}

	if loginTTL == 0 {
		loginTTL = 30 * 24 * time.Hour // 30 days
	}

	return &Auth{
		authFile:        authFile,
		users:           users,
		tokens:          tokens,
		publicACL:       publicACL,
		sessionStore:    sessionStore,
		loginTTL:        loginTTL,
		cleanupInterval: defaultSessionCleanupInterval,
	}, nil
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
			return nil, nil, errors.New("token cannot be empty")
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

// Enabled returns true if authentication is enabled.
func (a *Auth) Enabled() bool {
	if a == nil {
		return false
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	return len(a.users) > 0 || len(a.tokens) > 0 || a.publicACL != nil
}

// LoginTTL returns the configured login session TTL.
func (a *Auth) LoginTTL() time.Duration {
	if a == nil {
		return 30 * 24 * time.Hour // 30 days default
	}
	return a.loginTTL
}

// Reload reloads the auth configuration from the file.
// Validates new config before applying. On success, invalidates sessions only for
// users that were removed or had their password changed.
// On error, keeps the existing config and returns the error.
func (a *Auth) Reload(ctx context.Context) error {
	if a == nil {
		return errors.New("auth not enabled")
	}
	if a.authFile == "" {
		return errors.New("auth file path not set")
	}

	// capture old users state for selective session invalidation
	oldUsers := make(map[string]string) // username → passwordHash
	a.mu.RLock()
	for name, user := range a.users {
		oldUsers[name] = user.PasswordHash
	}
	a.mu.RUnlock()

	// load and validate new config before acquiring any locks
	cfg, err := LoadAuthConfig(a.authFile)
	if err != nil {
		return fmt.Errorf("failed to load auth config: %w", err)
	}

	users, err := parseUsers(cfg.Users)
	if err != nil {
		return fmt.Errorf("failed to parse users: %w", err)
	}

	tokens, publicACL, err := parseTokenConfigs(cfg.Tokens)
	if err != nil {
		return fmt.Errorf("failed to parse tokens: %w", err)
	}

	if len(users) == 0 && len(tokens) == 0 && publicACL == nil {
		return errors.New("auth config must have at least one user or token")
	}

	// acquire write lock for config
	a.mu.Lock()
	a.users = users
	a.tokens = tokens
	a.publicACL = publicACL
	a.mu.Unlock()

	// selective session invalidation: only for users removed or with password changes
	var invalidated []string
	a.mu.RLock()
	for username, oldHash := range oldUsers {
		newUser, exists := a.users[username]
		if !exists || newUser.PasswordHash != oldHash {
			invalidated = append(invalidated, username)
		}
	}
	a.mu.RUnlock()

	// delete sessions outside the lock to avoid holding it during I/O
	for _, username := range invalidated {
		if err := a.sessionStore.DeleteSessionsByUsername(ctx, username); err != nil {
			log.Printf("[WARN] failed to delete sessions for user %q: %v", username, err)
		}
	}

	if len(invalidated) > 0 {
		log.Printf("[INFO] auth config reloaded from %s, invalidated sessions for: %v", a.authFile, invalidated)
	} else {
		log.Printf("[INFO] auth config reloaded from %s, no sessions invalidated", a.authFile)
	}
	return nil
}

// StartWatcher starts watching the auth config file for changes.
// When the file changes, it reloads the configuration automatically.
// The watcher stops when the context is canceled.
// Returns an error if the watcher cannot be started.
func (a *Auth) StartWatcher(ctx context.Context) error {
	if a == nil {
		return errors.New("auth not enabled")
	}
	if a.authFile == "" {
		return errors.New("auth file path not set")
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("failed to create file watcher: %w", err)
	}

	// watch the directory containing the auth file (not the file itself)
	// this catches atomic renames used by editors like vim/VSCode
	dir := filepath.Dir(a.authFile)
	filename := filepath.Base(a.authFile)

	if err := watcher.Add(dir); err != nil {
		_ = watcher.Close()
		return fmt.Errorf("failed to watch directory %s: %w", dir, err)
	}

	log.Printf("[INFO] watching auth config file %s for changes", a.authFile)

	go func() {
		defer watcher.Close()

		var debounceTimer *time.Timer
		const debounceDelay = 100 * time.Millisecond

		for {
			select {
			case <-ctx.Done():
				if debounceTimer != nil {
					debounceTimer.Stop()
				}
				log.Printf("[INFO] auth config watcher stopped")
				return

			case event, ok := <-watcher.Events:
				if !ok {
					return
				}

				// only react to events on our auth file
				if filepath.Base(event.Name) != filename {
					continue
				}

				// react to write, create, rename events
				if event.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Rename) == 0 {
					continue
				}

				// debounce rapid changes
				if debounceTimer != nil {
					debounceTimer.Stop()
				}
				debounceTimer = time.AfterFunc(debounceDelay, func() {
					if err := a.Reload(ctx); err != nil {
						log.Printf("[WARN] failed to reload auth config: %v", err)
					}
				})

			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				log.Printf("[WARN] auth config watcher error: %v", err)
			}
		}
	}()

	return nil
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

	a.mu.RLock()
	user, exists := a.users[username]
	hashToCheck := dummyHash
	if exists {
		hashToCheck = user.PasswordHash
	}
	a.mu.RUnlock()

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
	a.mu.RLock()
	acl, ok := a.tokens[token]
	a.mu.RUnlock()
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
	if prefix, found := strings.CutSuffix(pattern, "*"); found {
		return strings.HasPrefix(key, prefix)
	}
	// exact match
	return pattern == key
}

// CreateSession generates a new session token for the given username.
func (a *Auth) CreateSession(ctx context.Context, username string) (string, error) {
	if a == nil {
		return "", errors.New("auth not enabled")
	}

	token := uuid.NewString()
	expiresAt := time.Now().Add(a.loginTTL)

	if err := a.sessionStore.CreateSession(ctx, token, username, expiresAt); err != nil {
		return "", fmt.Errorf("failed to create session: %w", err)
	}
	return token, nil
}

// GetSessionUser returns the username for a valid session.
// Returns empty string and false if session is invalid or expired.
// Note: expiration is checked in store.GetSession, which returns ErrNotFound for expired sessions.
func (a *Auth) GetSessionUser(ctx context.Context, token string) (string, bool) {
	if a == nil {
		return "", false
	}

	username, _, err := a.sessionStore.GetSession(ctx, token)
	if err != nil {
		return "", false
	}
	return username, true
}

// CheckUserPermission checks if a user has the required permission for a key.
// Returns true when auth is disabled (permissive by default).
func (a *Auth) CheckUserPermission(username, key string, needWrite bool) bool {
	if a == nil || !a.Enabled() {
		return true // no auth = everything allowed
	}
	a.mu.RLock()
	user, exists := a.users[username]
	a.mu.RUnlock()
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
	a.mu.RLock()
	user, exists := a.users[username]
	a.mu.RUnlock()
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
	a.mu.RLock()
	acl, ok := a.tokens[token]
	a.mu.RUnlock()
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
	if a == nil {
		return nil
	}
	a.mu.RLock()
	publicACL := a.publicACL
	a.mu.RUnlock()
	if publicACL == nil {
		return nil
	}

	var filtered []string
	for _, key := range keys {
		if publicACL.CheckKeyPermission(key, false) {
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
	a.mu.RLock()
	user, exists := a.users[username]
	a.mu.RUnlock()
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
// Note: expiration is checked in store.GetSession, which returns ErrNotFound for expired sessions.
func (a *Auth) ValidateSession(ctx context.Context, token string) bool {
	if a == nil {
		return false
	}

	_, _, err := a.sessionStore.GetSession(ctx, token)
	return err == nil
}

// InvalidateSession removes a session.
func (a *Auth) InvalidateSession(ctx context.Context, token string) {
	if a == nil {
		return
	}
	_ = a.sessionStore.DeleteSession(ctx, token)
}

// StartCleanup starts background cleanup of expired sessions.
// Runs periodically until context is canceled. Default interval is 1 hour.
func (a *Auth) StartCleanup(ctx context.Context) {
	if a == nil {
		return
	}

	interval := a.cleanupInterval
	if interval == 0 {
		interval = defaultSessionCleanupInterval
	}

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				log.Printf("[INFO] session cleanup stopped")
				return
			case <-ticker.C:
				deleted, err := a.sessionStore.DeleteExpiredSessions(ctx)
				if err != nil {
					log.Printf("[WARN] failed to cleanup expired sessions: %v", err)
					continue
				}
				if deleted > 0 {
					log.Printf("[INFO] cleaned up %d expired sessions", deleted)
				}
			}
		}
	}()

	log.Printf("[INFO] session cleanup started (interval: %s)", interval)
}

// SessionAuth returns middleware that requires a valid session cookie.
// Used for web UI routes. Redirects to loginURL if not authenticated.
// For HTMX requests, uses HX-Redirect header to trigger full page navigation.
func (a *Auth) SessionAuth(loginURL string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// check session cookie
			for _, cookieName := range sessionCookieNames {
				if cookie, err := r.Cookie(cookieName); err == nil && a.ValidateSession(r.Context(), cookie.Value) {
					next.ServeHTTP(w, r)
					return
				}
			}
			// no valid session - handle redirect based on request type
			if r.Header.Get("HX-Request") == "true" {
				// HTMX request: use HX-Redirect header to trigger full page navigation
				// instead of swapping login form into the target element
				w.Header().Set("HX-Redirect", loginURL)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			// regular request: use standard HTTP redirect
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
		a.mu.RLock()
		publicACL := a.publicACL
		a.mu.RUnlock()
		if publicACL != nil {
			if isList || publicACL.CheckKeyPermission(key, needWrite) {
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
			username, valid := a.GetSessionUser(r.Context(), cookie.Value)
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
