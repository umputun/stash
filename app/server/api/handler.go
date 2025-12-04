// Package api provides HTTP handlers for the KV API.
package api

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	log "github.com/go-pkgz/lgr"
	"github.com/go-pkgz/rest"
	"github.com/go-pkgz/routegroup"

	"github.com/umputun/stash/app/enum"
	"github.com/umputun/stash/app/git"
	"github.com/umputun/stash/app/store"
)

//go:generate moq -out mocks/kvstore.go -pkg mocks -skip-ensure -fmt goimports . KVStore
//go:generate moq -out mocks/authprovider.go -pkg mocks -skip-ensure -fmt goimports . AuthProvider
//go:generate moq -out mocks/formatvalidator.go -pkg mocks -skip-ensure -fmt goimports . FormatValidator
//go:generate moq -out mocks/gitservice.go -pkg mocks -skip-ensure -fmt goimports . GitService

// sessionCookieNames defines cookie names for session authentication.
// __Host- prefix requires HTTPS, secure, path=/ (preferred for production).
// fallback cookie name works on HTTP for development.
var sessionCookieNames = []string{"__Host-stash-auth", "stash-auth"}

// GitService defines the interface for git operations.
type GitService interface {
	Commit(req git.CommitRequest) error
	Delete(key string, author git.Author) error
	History(key string, limit int) ([]git.HistoryEntry, error)
	GetRevision(key string, rev string) ([]byte, string, error)
}

// KVStore defines the interface for key-value storage operations.
type KVStore interface {
	Get(ctx context.Context, key string) ([]byte, error)
	GetWithFormat(ctx context.Context, key string) ([]byte, string, error)
	Set(ctx context.Context, key string, value []byte, format string) error
	Delete(ctx context.Context, key string) error
	List(ctx context.Context) ([]store.KeyInfo, error)
}

// AuthProvider defines the interface for authentication operations.
type AuthProvider interface {
	Enabled() bool
	GetSessionUser(ctx context.Context, token string) (string, bool)
	FilterUserKeys(username string, keys []string) []string
	FilterTokenKeys(token string, keys []string) []string
	FilterPublicKeys(keys []string) []string
	HasTokenACL(token string) bool
}

// FormatValidator defines the interface for format validation.
type FormatValidator interface {
	IsValidFormat(format string) bool
}

// Handler handles API requests for /kv/* endpoints.
type Handler struct {
	store           KVStore
	auth            AuthProvider
	formatValidator FormatValidator
	git             GitService
}

// New creates a new API handler.
func New(st KVStore, auth AuthProvider, fv FormatValidator, gs GitService) *Handler {
	return &Handler{
		store:           st,
		auth:            auth,
		formatValidator: fv,
		git:             gs,
	}
}

// Register registers API routes on the given router.
func (h *Handler) Register(r *routegroup.Bundle) {
	r.HandleFunc("GET /{$}", h.handleList)                 // list keys (must be before {key...})
	r.HandleFunc("GET /history/{key...}", h.handleHistory) // get key history (before generic key)
	r.HandleFunc("GET /{key...}", h.handleGet)             // get specific key
	r.HandleFunc("PUT /{key...}", h.handleSet)             // set key
	r.HandleFunc("DELETE /{key...}", h.handleDelete)
}

// handleList returns all keys the caller has read access to.
// GET /kv
// Optional query params: ?prefix=app/config (filter by prefix)
func (h *Handler) handleList(w http.ResponseWriter, r *http.Request) {
	keys, err := h.store.List(r.Context())
	if err != nil {
		rest.SendErrorJSON(w, r, log.Default(), http.StatusInternalServerError, err, "failed to list keys")
		return
	}

	// extract key names for filtering
	keyNames := make([]string, len(keys))
	for i, k := range keys {
		keyNames[i] = k.Key
	}

	// filter by auth permissions
	filteredNames := h.filterKeysByAuth(r, keyNames)
	if filteredNames == nil {
		// no valid auth, but this shouldn't happen since tokenAuth middleware already checked
		rest.SendErrorJSON(w, r, log.Default(), http.StatusUnauthorized, nil, "unauthorized")
		return
	}

	// convert filtered names back to KeyInfo slice
	nameSet := make(map[string]bool, len(filteredNames))
	for _, name := range filteredNames {
		nameSet[name] = true
	}
	filtered := make([]store.KeyInfo, 0, len(filteredNames))
	for _, k := range keys {
		if nameSet[k.Key] {
			filtered = append(filtered, k)
		}
	}

	// filter by prefix if specified
	prefix := r.URL.Query().Get("prefix")
	if prefix != "" {
		var prefixed []store.KeyInfo
		for _, k := range filtered {
			if strings.HasPrefix(k.Key, prefix) {
				prefixed = append(prefixed, k)
			}
		}
		filtered = prefixed
	}

	log.Printf("[DEBUG] list keys: %d found, %d after auth filter", len(keys), len(filtered))
	rest.RenderJSON(w, filtered)
}

// filterKeysByAuth filters keys based on the caller's auth credentials.
// returns nil if auth is required but caller has no valid credentials.
// priority: session cookie > Bearer token > public ACL
func (h *Handler) filterKeysByAuth(r *http.Request, keys []string) []string {
	// no auth = return all keys
	if h.auth == nil || !h.auth.Enabled() {
		return keys
	}

	// check session cookie first (authenticated user has priority over public)
	for _, cookieName := range sessionCookieNames {
		cookie, err := r.Cookie(cookieName)
		if err != nil {
			continue
		}
		username, valid := h.auth.GetSessionUser(r.Context(), cookie.Value)
		if valid {
			return h.auth.FilterUserKeys(username, keys)
		}
	}

	// check Bearer token (authenticated token has priority over public)
	authHeader := r.Header.Get("Authorization")
	if token, found := strings.CutPrefix(authHeader, "Bearer "); found {
		if filtered := h.auth.FilterTokenKeys(token, keys); filtered != nil {
			return filtered
		}
	}

	// fall back to public access for unauthenticated requests
	if filtered := h.auth.FilterPublicKeys(keys); filtered != nil {
		return filtered
	}

	return nil // no valid auth
}

// handleGet retrieves the value for a key.
// GET /kv/{key...}
func (h *Handler) handleGet(w http.ResponseWriter, r *http.Request) {
	key := store.NormalizeKey(r.PathValue("key"))
	if key == "" {
		rest.SendErrorJSON(w, r, log.Default(), http.StatusBadRequest, nil, "key is required")
		return
	}

	value, format, err := h.store.GetWithFormat(r.Context(), key)
	if errors.Is(err, store.ErrNotFound) {
		rest.SendErrorJSON(w, r, log.Default(), http.StatusNotFound, err, "key not found")
		return
	}
	if err != nil {
		rest.SendErrorJSON(w, r, log.Default(), http.StatusInternalServerError, err, "failed to get key")
		return
	}

	log.Printf("[DEBUG] get %s (%d bytes, format=%s)", key, len(value), format)

	w.Header().Set("Content-Type", h.formatToContentType(format))
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(value); err != nil {
		log.Printf("[WARN] failed to write response: %v", err)
	}
}

// formatToContentType maps storage format to HTTP Content-Type.
func (h *Handler) formatToContentType(format string) string {
	if f, err := enum.ParseFormat(format); err == nil {
		return f.ContentType()
	}
	return "application/octet-stream"
}

// handleSet stores a value for a key.
// PUT /kv/{key...}
// Accepts format via X-Stash-Format header or ?format= query param (defaults to "text").
func (h *Handler) handleSet(w http.ResponseWriter, r *http.Request) {
	key := store.NormalizeKey(r.PathValue("key"))
	if key == "" {
		rest.SendErrorJSON(w, r, log.Default(), http.StatusBadRequest, nil, "key is required")
		return
	}

	value, err := io.ReadAll(r.Body)
	if err != nil {
		rest.SendErrorJSON(w, r, log.Default(), http.StatusBadRequest, err, "failed to read body")
		return
	}

	// get format from header or query param, default to "text"
	format := r.Header.Get("X-Stash-Format")
	if format == "" {
		format = r.URL.Query().Get("format")
	}
	if !h.formatValidator.IsValidFormat(format) {
		format = "text"
	}

	if err := h.store.Set(r.Context(), key, value, format); err != nil {
		rest.SendErrorJSON(w, r, log.Default(), http.StatusInternalServerError, err, "failed to set key")
		return
	}

	log.Printf("[INFO] set %q (%d bytes, format=%s) by %s", key, len(value), format, h.getIdentityForLog(r))

	// commit to git if enabled
	if h.git != nil {
		req := git.CommitRequest{Key: key, Value: value, Operation: "set", Format: format, Author: h.getAuthorFromRequest(r)}
		if err := h.git.Commit(req); err != nil {
			log.Printf("[WARN] git commit failed for %s: %v", key, err)
		}
	}

	w.WriteHeader(http.StatusOK)
}

// handleDelete removes a key from the store.
// DELETE /kv/{key...}
func (h *Handler) handleDelete(w http.ResponseWriter, r *http.Request) {
	key := store.NormalizeKey(r.PathValue("key"))
	if key == "" {
		rest.SendErrorJSON(w, r, log.Default(), http.StatusBadRequest, nil, "key is required")
		return
	}

	err := h.store.Delete(r.Context(), key)
	if errors.Is(err, store.ErrNotFound) {
		rest.SendErrorJSON(w, r, log.Default(), http.StatusNotFound, err, "key not found")
		return
	}
	if err != nil {
		rest.SendErrorJSON(w, r, log.Default(), http.StatusInternalServerError, err, "failed to delete key")
		return
	}

	log.Printf("[INFO] delete %q by %s", key, h.getIdentityForLog(r))

	// delete from git if enabled
	if h.git != nil {
		if err := h.git.Delete(key, h.getAuthorFromRequest(r)); err != nil {
			log.Printf("[WARN] git delete failed for %s: %v", key, err)
		}
	}

	w.WriteHeader(http.StatusNoContent)
}

// historyResponse represents a single entry in the history response.
type historyResponse struct {
	Hash      string `json:"hash"`
	Timestamp string `json:"timestamp"`
	Author    string `json:"author"`
	Operation string `json:"operation"`
	Format    string `json:"format"`
	Value     string `json:"value"` // base64 encoded
}

// handleHistory returns the commit history for a key.
// GET /kv/history/{key...}
func (h *Handler) handleHistory(w http.ResponseWriter, r *http.Request) {
	if h.git == nil {
		rest.SendErrorJSON(w, r, log.Default(), http.StatusServiceUnavailable, nil, "git integration not enabled")
		return
	}

	key := store.NormalizeKey(r.PathValue("key"))
	if key == "" {
		rest.SendErrorJSON(w, r, log.Default(), http.StatusBadRequest, nil, "key is required")
		return
	}

	// check read permission
	filtered := h.filterKeysByAuth(r, []string{key})
	if len(filtered) == 0 {
		rest.SendErrorJSON(w, r, log.Default(), http.StatusForbidden, nil, "access denied")
		return
	}

	history, err := h.git.History(key, 50)
	if err != nil {
		rest.SendErrorJSON(w, r, log.Default(), http.StatusInternalServerError, err, "failed to get history")
		return
	}

	// convert to response format with base64-encoded values
	resp := make([]historyResponse, len(history))
	for i, entry := range history {
		resp[i] = historyResponse{
			Hash:      entry.Hash,
			Timestamp: entry.Timestamp.UTC().Format(time.RFC3339),
			Author:    entry.Author,
			Operation: entry.Operation,
			Format:    entry.Format,
			Value:     base64.StdEncoding.EncodeToString(entry.Value),
		}
	}

	rest.RenderJSON(w, resp)
}

// identityType represents the type of identity detected from a request.
type identityType int

const (
	identityAnonymous identityType = iota
	identityUser
	identityToken
)

// identity holds information about who made a request.
type identity struct {
	typ  identityType
	name string // username or token prefix
}

// getIdentity extracts identity from request context.
// returns user identity from session cookie, token identity from Authorization header, or anonymous.
func (h *Handler) getIdentity(r *http.Request) identity {
	if h.auth == nil {
		return identity{typ: identityAnonymous}
	}

	// check session cookie for web UI users
	for _, cookieName := range sessionCookieNames {
		cookie, err := r.Cookie(cookieName)
		if err != nil {
			continue
		}
		if username, valid := h.auth.GetSessionUser(r.Context(), cookie.Value); valid && username != "" {
			return identity{typ: identityUser, name: username}
		}
	}

	// check API token from Authorization header
	if authHeader := r.Header.Get("Authorization"); strings.HasPrefix(authHeader, "Bearer ") {
		token := strings.TrimPrefix(authHeader, "Bearer ")
		if h.auth.HasTokenACL(token) {
			prefix := token
			if len(prefix) > 8 {
				prefix = prefix[:8]
			}
			return identity{typ: identityToken, name: "token:" + prefix}
		}
	}

	return identity{typ: identityAnonymous}
}

// getAuthorFromRequest extracts the git author from request context.
// returns username from session cookie for web UI users, token prefix for API tokens, default author otherwise.
func (h *Handler) getAuthorFromRequest(r *http.Request) git.Author {
	id := h.getIdentity(r)
	switch id.typ {
	case identityUser, identityToken:
		return git.Author{Name: id.name, Email: id.name + "@stash"}
	default:
		return git.DefaultAuthor()
	}
}

// getIdentityForLog returns identity string for audit logging.
// returns "user:xxx" for web UI users, "token:xxx" for API tokens, "anonymous" otherwise.
func (h *Handler) getIdentityForLog(r *http.Request) string {
	id := h.getIdentity(r)
	switch id.typ {
	case identityUser:
		return "user:" + id.name
	case identityToken:
		return id.name // already has "token:" prefix
	default:
		return "anonymous"
	}
}
