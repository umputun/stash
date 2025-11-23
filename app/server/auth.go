package server

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	log "github.com/go-pkgz/lgr"
	"golang.org/x/crypto/bcrypt"
)

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
	createdAt time.Time
}

// Auth handles authentication and authorization.
type Auth struct {
	passwordHash string
	tokens       map[string]TokenACL // token string -> ACL
	sessions     map[string]session  // session token -> session
	sessionsMu   sync.Mutex
	loginTTL     time.Duration
}

// NewAuth creates a new Auth instance from configuration.
// Returns nil if authentication is disabled (no password hash).
func NewAuth(passwordHash string, tokenStrings []string, loginTTL time.Duration) (*Auth, error) {
	if passwordHash == "" {
		return nil, nil // auth disabled
	}

	tokens, err := parseTokens(tokenStrings)
	if err != nil {
		return nil, fmt.Errorf("failed to parse auth tokens: %w", err)
	}

	if loginTTL == 0 {
		loginTTL = 24 * time.Hour
	}

	return &Auth{
		passwordHash: passwordHash,
		tokens:       tokens,
		sessions:     make(map[string]session),
		loginTTL:     loginTTL,
	}, nil
}

// parseTokens parses token strings in format "token:prefix:permissions".
func parseTokens(tokenStrings []string) (map[string]TokenACL, error) {
	tokens := make(map[string]TokenACL)
	seen := make(map[string]map[string]bool) // token -> prefix -> exists

	for _, ts := range tokenStrings {
		parts := strings.SplitN(ts, ":", 3)
		if len(parts) != 3 {
			return nil, fmt.Errorf("invalid token format %q, expected token:prefix:permissions", ts)
		}

		tokenName := strings.TrimSpace(parts[0])
		prefix := strings.TrimSpace(parts[1])
		permStr := strings.ToLower(strings.TrimSpace(parts[2]))

		if tokenName == "" {
			return nil, fmt.Errorf("empty token name in %q", ts)
		}
		if prefix == "" {
			return nil, fmt.Errorf("empty prefix in %q", ts)
		}

		// parse permission
		var perm Permission
		switch permStr {
		case "r", "read":
			perm = PermissionRead
		case "w", "write":
			perm = PermissionWrite
		case "rw", "readwrite", "read-write":
			perm = PermissionReadWrite
		default:
			return nil, fmt.Errorf("invalid permission %q in %q, expected r/w/rw", permStr, ts)
		}

		// check for duplicate token+prefix
		if seen[tokenName] == nil {
			seen[tokenName] = make(map[string]bool)
		}
		if seen[tokenName][prefix] {
			return nil, fmt.Errorf("duplicate prefix %q for token %q", prefix, tokenName)
		}
		seen[tokenName][prefix] = true

		// add to token ACL
		acl := tokens[tokenName]
		acl.Token = tokenName
		acl.prefixes = append(acl.prefixes, prefixPerm{
			prefix:     prefix,
			permission: perm,
		})
		tokens[tokenName] = acl
	}

	// sort prefixes by length descending for longest-match-first
	for name, acl := range tokens {
		sort.Slice(acl.prefixes, func(i, j int) bool {
			return len(acl.prefixes[i].prefix) > len(acl.prefixes[j].prefix)
		})
		tokens[name] = acl
	}

	return tokens, nil
}

// Enabled returns true if authentication is enabled.
func (a *Auth) Enabled() bool {
	return a != nil && a.passwordHash != ""
}

// ValidatePassword checks if the password matches the stored hash.
func (a *Auth) ValidatePassword(password string) bool {
	if a == nil {
		return false
	}
	err := bcrypt.CompareHashAndPassword([]byte(a.passwordHash), []byte(password))
	return err == nil
}

// GetTokenACL returns the ACL for a token and whether it exists.
func (a *Auth) GetTokenACL(token string) (TokenACL, bool) {
	if a == nil {
		return TokenACL{}, false
	}
	acl, ok := a.tokens[token]
	return acl, ok
}

// CheckPermission checks if a token has the required permission for a key.
// Returns true if the token has sufficient permissions.
func (a *Auth) CheckPermission(token, key string, needWrite bool) bool {
	acl, ok := a.GetTokenACL(token)
	if !ok {
		return false
	}

	// find the longest matching prefix
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

// CreateSession generates a new session token and stores it.
func (a *Auth) CreateSession() (string, error) {
	if a == nil {
		return "", fmt.Errorf("auth not enabled")
	}

	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate session token: %w", err)
	}
	token := hex.EncodeToString(bytes)

	a.sessionsMu.Lock()
	defer a.sessionsMu.Unlock()

	a.sessions[token] = session{
		token:     token,
		createdAt: time.Now(),
	}

	// cleanup expired sessions
	a.cleanupExpiredSessions()

	return token, nil
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
// Used for web UI routes. Redirects to /login if not authenticated.
func (a *Auth) SessionAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// check session cookie
		for _, cookieName := range []string{"__Host-stash-auth", "stash-auth"} {
			if cookie, err := r.Cookie(cookieName); err == nil && a.ValidateSession(cookie.Value) {
				next.ServeHTTP(w, r)
				return
			}
		}
		// no valid session, redirect to login
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	})
}

// TokenAuth returns middleware that requires a valid Bearer token with appropriate permissions.
// Used for API routes. Returns 401/403 if not authorized.
func (a *Auth) TokenAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// also accept session cookie for API (allows UI to call API)
		for _, cookieName := range []string{"__Host-stash-auth", "stash-auth"} {
			if cookie, err := r.Cookie(cookieName); err == nil && a.ValidateSession(cookie.Value) {
				next.ServeHTTP(w, r)
				return
			}
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

		// extract key from path and check permission
		key := strings.TrimPrefix(r.URL.Path, "/kv/")
		needWrite := r.Method == http.MethodPut || r.Method == http.MethodDelete

		if !a.CheckPermission(token, key, needWrite) {
			log.Printf("[DEBUG] token %q denied %s access to key %q", token, r.Method, key)
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
