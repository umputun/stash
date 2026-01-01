// Package auth provides authentication and authorization for the stash server.
//
// It supports two authentication methods:
//   - Session-based authentication for web UI (username/password login)
//   - Token-based authentication for API (X-Auth-Token header or Authorization: Bearer)
//
// Token types:
//   - Named tokens with specific ACL permissions
//   - Public token (token="*") allowing unauthenticated access with limited permissions
//
// Authorization uses prefix-based ACL where permissions are granted per key prefix
// with access levels: read (r), write (w), or read-write (rw). Wildcards (*) match
// any key, and longest prefix match wins. Secrets paths require explicit grant.
//
// Configuration is loaded from a YAML file with optional hot-reload support.
// Sessions are stored persistently and survive server restarts.
package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	log "github.com/go-pkgz/lgr"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"github.com/umputun/stash/app/server/internal/cookie"
)

//go:generate moq -out mocks/sessionstore.go -pkg mocks -skip-ensure -fmt goimports . SessionStore

const defaultSessionCleanupInterval = 1 * time.Hour

// Service handles authentication and authorization.
type Service struct {
	mu              sync.RWMutex        // protects users, tokens, publicACL (config data)
	authFile        string              // path to auth config file for reloading
	users           map[string]User     // username -> User (for web UI auth)
	tokens          map[string]TokenACL // token string -> ACL (for API auth)
	publicACL       *TokenACL           // public access ACL (token="*"), nil if not configured
	sessionStore    SessionStore        // persistent session storage
	validator       ConfigValidator     // validates auth config, may be nil
	loginTTL        time.Duration
	cleanupInterval time.Duration // interval for session cleanup, defaults to 1h
	hotReload       bool          // watch auth config for changes and reload
}

// New creates a new Service instance from configuration file.
// Returns nil if authFile is empty (authentication disabled).
// sessionStore is required for persistent session storage.
// hotReload enables watching the config file for changes.
func New(authFile string, loginTTL time.Duration, hotReload bool, sessionStore SessionStore, validator ConfigValidator) (*Service, error) {
	if authFile == "" {
		return nil, nil //nolint:nilnil // nil auth means disabled, not an error
	}

	if sessionStore == nil {
		return nil, errors.New("session store is required")
	}

	cfg, err := LoadConfig(authFile, validator)
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

	return &Service{
		authFile:        authFile,
		users:           users,
		tokens:          tokens,
		publicACL:       publicACL,
		sessionStore:    sessionStore,
		validator:       validator,
		loginTTL:        loginTTL,
		cleanupInterval: defaultSessionCleanupInterval,
		hotReload:       hotReload,
	}, nil
}

// Enabled returns true if authentication is enabled.
func (s *Service) Enabled() bool {
	if s == nil {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.users) > 0 || len(s.tokens) > 0 || s.publicACL != nil
}

// Activate starts auth background tasks: file watcher (if hot-reload enabled) and session cleanup.
// Should be called once after New(), typically from main.go.
func (s *Service) Activate(ctx context.Context) error {
	if s == nil {
		return nil
	}

	// start config file watcher if hot-reload is enabled
	if err := s.startWatcher(ctx); err != nil {
		return err
	}

	// start session cleanup goroutine
	s.startCleanup(ctx)
	return nil
}

// LoginTTL returns the configured login session TTL.
func (s *Service) LoginTTL() time.Duration {
	if s == nil {
		return 30 * 24 * time.Hour // 30 days default
	}
	return s.loginTTL
}

// Reload reloads the auth configuration from the file.
// Validates new config before applying. On success, invalidates sessions only for
// users that were removed or had their password changed.
// On error, keeps the existing config and returns the error.
func (s *Service) Reload(ctx context.Context) error {
	if s == nil {
		return errors.New("auth not enabled")
	}
	if s.authFile == "" {
		return errors.New("auth file path not set")
	}

	// capture old users state for selective session invalidation
	oldUsers := make(map[string]string) // username → passwordHash
	s.mu.RLock()
	for name, user := range s.users {
		oldUsers[name] = user.PasswordHash
	}
	s.mu.RUnlock()

	// load and validate new config before acquiring any locks
	cfg, err := LoadConfig(s.authFile, s.validator)
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

	s.mu.Lock()
	s.users = users
	s.tokens = tokens
	s.publicACL = publicACL
	s.mu.Unlock()

	// selective session invalidation: only for users removed or with password changes
	var invalidated []string
	s.mu.RLock()
	for username, oldHash := range oldUsers {
		newUser, exists := s.users[username]
		if !exists || newUser.PasswordHash != oldHash {
			invalidated = append(invalidated, username)
		}
	}
	s.mu.RUnlock()

	// delete sessions outside the lock to avoid holding it during I/O
	for _, username := range invalidated {
		if err := s.sessionStore.DeleteSessionsByUsername(ctx, username); err != nil {
			log.Printf("[WARN] failed to delete sessions for user %q: %v", username, err)
		}
	}

	if len(invalidated) > 0 {
		log.Printf("[INFO] auth config reloaded from %s, invalidated sessions for: %v", s.authFile, invalidated)
	} else {
		log.Printf("[INFO] auth config reloaded from %s, no sessions invalidated", s.authFile)
	}
	return nil
}

// IsValidUser checks if username/password are valid credentials.
// Uses constant-time comparison to prevent username enumeration via timing attacks.
func (s *Service) IsValidUser(username, password string) bool {
	if s == nil {
		return false
	}

	// dummy hash for constant-time comparison when user doesn't exist.
	// this is a valid bcrypt hash (cost=10) to ensure comparison takes similar time.
	const dummyHash = "$2a$10$C615A0mfUEFBupj9qcqhiuBEyf60EqrsakB90CozUoSON8d2Dc1uS"

	s.mu.RLock()
	user, exists := s.users[username]
	hashToCheck := dummyHash
	if exists {
		hashToCheck = user.PasswordHash
	}
	s.mu.RUnlock()

	if err := bcrypt.CompareHashAndPassword([]byte(hashToCheck), []byte(password)); err != nil || !exists {
		return false
	}
	return true
}

// getTokenACL returns the ACL for a token and whether it exists.
func (s *Service) getTokenACL(token string) (TokenACL, bool) {
	if s == nil {
		return TokenACL{}, false
	}
	s.mu.RLock()
	acl, ok := s.tokens[token]
	s.mu.RUnlock()
	return acl, ok
}

// hasTokenACL checks if a token exists in the ACL.
func (s *Service) hasTokenACL(token string) bool {
	_, ok := s.getTokenACL(token)
	return ok
}

// checkPermission checks if a token has the required permission for a key.
// returns true if the token has sufficient permissions.
func (s *Service) checkPermission(token, key string, needWrite bool) bool {
	acl, ok := s.getTokenACL(token)
	if !ok {
		return false
	}
	return acl.CheckKeyPermission(key, needWrite)
}

// CreateSession generates a new session token for the given username.
func (s *Service) CreateSession(ctx context.Context, username string) (string, error) {
	if s == nil {
		return "", errors.New("auth not enabled")
	}

	token := uuid.NewString()
	expiresAt := time.Now().Add(s.loginTTL)

	if err := s.sessionStore.CreateSession(ctx, token, username, expiresAt); err != nil {
		return "", fmt.Errorf("failed to create session: %w", err)
	}
	return token, nil
}

// GetSessionUser returns the username for a valid session.
// Returns empty string and false if session is invalid or expired.
// Note: expiration is checked in store.GetSession, which returns ErrNotFound for expired sessions.
func (s *Service) GetSessionUser(ctx context.Context, token string) (string, bool) {
	if s == nil {
		return "", false
	}

	username, _, err := s.sessionStore.GetSession(ctx, token)
	if err != nil {
		return "", false
	}
	return username, true
}

// CheckUserPermission checks if a user has the required permission for a key.
// Returns true when auth is disabled (permissive by default).
func (s *Service) CheckUserPermission(username, key string, needWrite bool) bool {
	if s == nil || !s.Enabled() {
		return true // no auth = everything allowed
	}
	s.mu.RLock()
	user, exists := s.users[username]
	s.mu.RUnlock()
	if !exists {
		return false
	}
	return user.ACL.CheckKeyPermission(key, needWrite)
}

// FilterUserKeys filters keys based on user's read permissions.
// Returns all keys when auth is disabled (permissive by default).
func (s *Service) FilterUserKeys(username string, keys []string) []string {
	if s == nil || !s.Enabled() {
		return keys // no auth = show all keys
	}
	s.mu.RLock()
	user, exists := s.users[username]
	s.mu.RUnlock()
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

// filterTokenKeys filters keys based on token's read permissions.
// returns nil if token doesn't exist.
func (s *Service) filterTokenKeys(token string, keys []string) []string {
	if s == nil {
		return keys // no auth = show all keys
	}
	s.mu.RLock()
	acl, ok := s.tokens[token]
	s.mu.RUnlock()
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

// filterPublicKeys filters keys based on public ACL read permissions.
// returns nil if public access is not configured.
func (s *Service) filterPublicKeys(keys []string) []string {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	publicACL := s.publicACL
	s.mu.RUnlock()
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

// FilterKeysForRequest filters keys based on the request's authentication.
// Determines actor type (token, session user, or public) and filters accordingly.
// Returns all keys when auth is disabled.
func (s *Service) FilterKeysForRequest(r *http.Request, keys []string) []string {
	if s == nil || !s.Enabled() {
		return keys
	}

	// check for API token first
	if token := ExtractToken(r); token != "" {
		if filtered := s.filterTokenKeys(token, keys); filtered != nil {
			return filtered
		}
	}

	// check for session cookie
	for _, cookieName := range cookie.SessionCookieNames {
		if c, err := r.Cookie(cookieName); err == nil {
			if username, ok := s.GetSessionUser(r.Context(), c.Value); ok {
				return s.FilterUserKeys(username, keys)
			}
		}
	}

	// fall back to public access
	if filtered := s.filterPublicKeys(keys); filtered != nil {
		return filtered
	}
	return nil
}

// IsRequestAdmin checks if the request is from an admin (user or token).
// Returns false when auth is disabled.
func (s *Service) IsRequestAdmin(r *http.Request) bool {
	if s == nil || !s.Enabled() {
		return false
	}

	// check for API token first
	if token := ExtractToken(r); token != "" && s.hasTokenACL(token) {
		return s.isTokenAdmin(token)
	}

	// check for session cookie
	for _, cookieName := range cookie.SessionCookieNames {
		if c, err := r.Cookie(cookieName); err == nil {
			if username, ok := s.GetSessionUser(r.Context(), c.Value); ok {
				return s.IsAdmin(username)
			}
		}
	}

	return false
}

// GetRequestActor returns the actor type and name from the request.
// Returns ("user", username), ("token", masked_token), or ("public", "").
func (s *Service) GetRequestActor(r *http.Request) (actorType, actorName string) {
	if s == nil || !s.Enabled() {
		return "public", ""
	}

	// check for API token first
	if token := ExtractToken(r); token != "" && s.hasTokenACL(token) {
		return "token", "token:" + MaskToken(token)
	}

	// check for session cookie
	for _, cookieName := range cookie.SessionCookieNames {
		if c, err := r.Cookie(cookieName); err == nil {
			if username, ok := s.GetSessionUser(r.Context(), c.Value); ok {
				return "user", username
			}
		}
	}

	return "public", ""
}

// UserCanWrite returns true if user has any write permission.
// Returns true when auth is disabled (permissive by default).
func (s *Service) UserCanWrite(username string) bool {
	if s == nil || !s.Enabled() {
		return true // no auth = write allowed
	}
	s.mu.RLock()
	user, exists := s.users[username]
	s.mu.RUnlock()
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

// IsAdmin returns true if user has admin privileges.
// Returns false when auth is disabled.
func (s *Service) IsAdmin(username string) bool {
	if s == nil || !s.Enabled() {
		return false
	}
	s.mu.RLock()
	user, exists := s.users[username]
	s.mu.RUnlock()
	if !exists {
		return false
	}
	return user.Admin
}

// isTokenAdmin checks if an API token has admin privileges.
func (s *Service) isTokenAdmin(token string) bool {
	if s == nil || !s.Enabled() {
		return false
	}
	s.mu.RLock()
	acl, exists := s.tokens[token]
	s.mu.RUnlock()
	if !exists {
		return false
	}
	return acl.Admin
}

// InvalidateSession removes a session.
func (s *Service) InvalidateSession(ctx context.Context, token string) {
	if s == nil {
		return
	}
	if err := s.sessionStore.DeleteSession(ctx, token); err != nil {
		log.Printf("[WARN] failed to delete session: %v", err)
	}
}

// startWatcher starts watching the auth config file for changes.
// when the file changes, it reloads the configuration automatically.
// the watcher stops when the context is canceled.
func (s *Service) startWatcher(ctx context.Context) error {
	if s == nil {
		return errors.New("auth not enabled")
	}
	if !s.hotReload {
		return nil // hot reload not enabled, nothing to do
	}
	if s.authFile == "" {
		return errors.New("auth file path not set")
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("failed to create file watcher: %w", err)
	}

	// watch the directory containing the auth file (not the file itself)
	// this catches atomic renames used by editors like vim/VSCode
	dir := filepath.Dir(s.authFile)
	filename := filepath.Base(s.authFile)

	if err := watcher.Add(dir); err != nil {
		_ = watcher.Close()
		return fmt.Errorf("failed to watch directory %s: %w", dir, err)
	}

	log.Printf("[INFO] watching auth config file %s for changes", s.authFile)

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
					// check if context was canceled before reload
					if ctx.Err() != nil {
						return
					}
					if err := s.Reload(ctx); err != nil {
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

// startCleanup starts background cleanup of expired sessions.
// runs periodically until context is canceled. default interval is 1 hour.
func (s *Service) startCleanup(ctx context.Context) {
	if s == nil {
		return
	}

	go func() {
		ticker := time.NewTicker(s.cleanupInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				log.Printf("[INFO] session cleanup stopped")
				return
			case <-ticker.C:
				deleted, err := s.sessionStore.DeleteExpiredSessions(ctx)
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

	log.Printf("[INFO] session cleanup started (interval: %s)", s.cleanupInterval)
}
