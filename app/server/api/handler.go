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
	"github.com/umputun/stash/lib/stash"
)

//go:generate moq -out mocks/kvstore.go -pkg mocks -skip-ensure -fmt goimports . KVStore
//go:generate moq -out mocks/authprovider.go -pkg mocks -skip-ensure -fmt goimports . AuthProvider
//go:generate moq -out mocks/formatvalidator.go -pkg mocks -skip-ensure -fmt goimports . FormatValidator
//go:generate moq -out mocks/gitservice.go -pkg mocks -skip-ensure -fmt goimports . GitService
//go:generate moq -out mocks/eventpublisher.go -pkg mocks -skip-ensure -fmt goimports . EventPublisher

// Handler handles API requests for /kv/* endpoints.
type Handler struct {
	Deps
}

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
	Set(ctx context.Context, key string, value []byte, format string) (created bool, err error)
	Delete(ctx context.Context, key string) error
	List(ctx context.Context, filter enum.SecretsFilter) ([]store.KeyInfo, error)
	SecretsEnabled() bool
}

// AuthProvider defines the interface for authentication operations.
type AuthProvider interface {
	Enabled() bool
	FilterKeysForRequest(r *http.Request, keys []string) []string
	GetRequestActor(r *http.Request) (actorType, actorName string)
}

// FormatValidator defines the interface for format validation.
type FormatValidator interface {
	IsValidFormat(format string) bool
}

// EventPublisher defines the interface for publishing key change events.
type EventPublisher interface {
	Publish(key string, action enum.AuditAction)
}

// Deps holds dependencies for the API handler.
type Deps struct {
	Store     KVStore
	Auth      AuthProvider
	Validator FormatValidator
	Git       GitService     // optional
	Events    EventPublisher // optional
}

// New creates a new API handler.
func New(deps Deps) *Handler {
	return &Handler{Deps: deps}
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
// GET /kv?prefix=app/config (filter by prefix)
// GET /kv?filter=secrets (filter to secrets only)
// GET /kv?filter=keys (filter to non-secrets only)
func (h *Handler) handleList(w http.ResponseWriter, r *http.Request) {
	// parse secrets filter query param
	filter := enum.SecretsFilterAll
	if filterParam := r.URL.Query().Get("filter"); filterParam != "" {
		parsed, err := enum.ParseSecretsFilter(filterParam)
		if err != nil {
			rest.SendErrorJSON(w, r, log.Default(), http.StatusBadRequest, err, "invalid filter parameter")
			return
		}
		filter = parsed
	}

	keys, err := h.Store.List(r.Context(), filter)
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

// filterKeysByAuth filters keys based on the request's authentication.
// Returns nil if auth is required but caller has no valid credentials.
func (h *Handler) filterKeysByAuth(r *http.Request, keys []string) []string {
	if h.Auth == nil || !h.Auth.Enabled() {
		return keys
	}
	return h.Auth.FilterKeysForRequest(r, keys)
}

// handleGet retrieves the value for a key.
// GET /kv/{key...}
func (h *Handler) handleGet(w http.ResponseWriter, r *http.Request) {
	key := store.NormalizeKey(r.PathValue("key"))
	if key == "" {
		rest.SendErrorJSON(w, r, log.Default(), http.StatusBadRequest, nil, "key is required")
		return
	}

	value, format, err := h.Store.GetWithFormat(r.Context(), key)
	if errors.Is(err, store.ErrSecretsNotConfigured) {
		rest.SendErrorJSON(w, r, log.Default(), http.StatusBadRequest, err, "secrets not configured")
		return
	}
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

// formatToContentType maps storage format to HTTP Content-Type
func (h *Handler) formatToContentType(format string) string {
	if f, err := stash.ParseFormat(format); err == nil {
		return f.ContentType()
	}
	return "application/octet-stream"
}

// handleSet stores a value for a key.
// PUT /kv/{key...}
// accepts format via X-Stash-Format header or ?format= query param (defaults to "text")
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
	if !h.Validator.IsValidFormat(format) {
		format = "text"
	}

	created, err := h.Store.Set(r.Context(), key, value, format)
	if err != nil {
		if errors.Is(err, store.ErrSecretsNotConfigured) {
			rest.SendErrorJSON(w, r, log.Default(), http.StatusBadRequest, err, "secrets not configured")
			return
		}
		if errors.Is(err, store.ErrInvalidZKPayload) {
			rest.SendErrorJSON(w, r, log.Default(), http.StatusBadRequest, err, "invalid ZK payload")
			return
		}
		rest.SendErrorJSON(w, r, log.Default(), http.StatusInternalServerError, err, "failed to set key")
		return
	}

	operation := "update"
	if created {
		operation = "create"
	}
	log.Printf("[INFO] %s %q (%d bytes, format=%s) by %s", operation, key, len(value), format, h.getIdentityForLog(r))

	// commit to git if enabled
	if h.Git != nil {
		req := git.CommitRequest{Key: key, Value: value, Operation: operation, Format: format, Author: h.getAuthorFromRequest(r)}
		if err := h.Git.Commit(req); err != nil {
			log.Printf("[WARN] git commit failed for %s: %v", key, err)
		}
	}

	// publish event for SSE subscribers
	if h.Events != nil {
		action := enum.AuditActionUpdate
		if created {
			action = enum.AuditActionCreate
		}
		h.Events.Publish(key, action)
	}

	if created {
		w.WriteHeader(http.StatusCreated)
	} else {
		w.WriteHeader(http.StatusOK)
	}
}

// handleDelete removes a key from the store.
// DELETE /kv/{key...}
func (h *Handler) handleDelete(w http.ResponseWriter, r *http.Request) {
	key := store.NormalizeKey(r.PathValue("key"))
	if key == "" {
		rest.SendErrorJSON(w, r, log.Default(), http.StatusBadRequest, nil, "key is required")
		return
	}

	err := h.Store.Delete(r.Context(), key)
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
	if h.Git != nil {
		if err := h.Git.Delete(key, h.getAuthorFromRequest(r)); err != nil {
			log.Printf("[WARN] git delete failed for %s: %v", key, err)
		}
	}

	// publish event for SSE subscribers
	if h.Events != nil {
		h.Events.Publish(key, enum.AuditActionDelete)
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
	if h.Git == nil {
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

	history, err := h.Git.History(key, 50)
	if err != nil {
		rest.SendErrorJSON(w, r, log.Default(), http.StatusInternalServerError, err, "failed to get history")
		return
	}

	// base64-encode values to safely transmit arbitrary binary data in JSON
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

// getIdentity extracts identity from request.
// Returns user identity, token identity, or anonymous.
func (h *Handler) getIdentity(r *http.Request) identity {
	if h.Auth == nil || !h.Auth.Enabled() {
		return identity{typ: identityAnonymous}
	}

	actorType, actorName := h.Auth.GetRequestActor(r)
	switch actorType {
	case "user":
		return identity{typ: identityUser, name: actorName}
	case "token":
		return identity{typ: identityToken, name: actorName}
	default:
		return identity{typ: identityAnonymous}
	}
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
