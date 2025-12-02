// Package web provides HTTP handlers for the web UI.
package web

import (
	"embed"
	"encoding/base64"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/go-pkgz/routegroup"

	"github.com/umputun/stash/app/enum"
	"github.com/umputun/stash/app/git"
	"github.com/umputun/stash/app/store"
)

//go:generate moq -out mocks/kvstore.go -pkg mocks -skip-ensure -fmt goimports . KVStore
//go:generate moq -out mocks/validator.go -pkg mocks -skip-ensure -fmt goimports . Validator
//go:generate moq -out mocks/authprovider.go -pkg mocks -skip-ensure -fmt goimports . AuthProvider
//go:generate moq -out mocks/gitservice.go -pkg mocks -skip-ensure -fmt goimports . GitService

// sessionCookieNames defines cookie names for session authentication.
// __Host- prefix requires HTTPS, secure, path=/ (preferred for production).
// fallback cookie name works on HTTP for development.
var sessionCookieNames = []string{"__Host-stash-auth", "stash-auth"}

//go:embed static
var staticFS embed.FS

//go:embed templates
var templatesFS embed.FS

// StaticFS returns the embedded static filesystem for external use.
func StaticFS() (fs.FS, error) {
	sub, err := fs.Sub(staticFS, "static")
	if err != nil {
		return nil, fmt.Errorf("failed to get static sub-filesystem: %w", err)
	}
	return sub, nil
}

// KVStore defines the interface for key-value storage operations.
type KVStore interface {
	GetWithFormat(key string) ([]byte, string, error)
	GetInfo(key string) (store.KeyInfo, error)
	Set(key string, value []byte, format string) error
	SetWithVersion(key string, value []byte, format string, expectedVersion time.Time) error
	Delete(key string) error
	List() ([]store.KeyInfo, error)
}

// Validator defines the interface for format validation.
type Validator interface {
	Validate(format string, value []byte) error
	IsValidFormat(format string) bool
	SupportedFormats() []string
}

// AuthProvider defines the interface for authentication operations.
type AuthProvider interface {
	Enabled() bool
	GetSessionUser(token string) (string, bool)
	FilterUserKeys(username string, keys []string) []string
	CheckUserPermission(username, key string, write bool) bool
	UserCanWrite(username string) bool
	// login methods
	IsValidUser(username, password string) bool
	CreateSession(username string) (string, error)
	InvalidateSession(token string)
	LoginTTL() time.Duration
}

// GitService defines the interface for git operations.
type GitService interface {
	Commit(req git.CommitRequest) error
	Delete(key string, author git.Author) error
}

// Config holds web handler configuration.
type Config struct {
	BaseURL  string
	PageSize int
}

// Handler handles web UI requests.
type Handler struct {
	store       KVStore
	validator   Validator
	auth        AuthProvider
	highlighter *Highlighter
	tmpl        *template.Template
	baseURL     string
	pageSize    int
	git         GitService
}

// New creates a new web handler.
func New(st KVStore, auth AuthProvider, val Validator, gs GitService, cfg Config) (*Handler, error) {
	tmpl, err := parseTemplates()
	if err != nil {
		return nil, fmt.Errorf("failed to parse templates: %w", err)
	}

	return &Handler{
		store:       st,
		validator:   val,
		auth:        auth,
		highlighter: NewHighlighter(),
		tmpl:        tmpl,
		baseURL:     cfg.BaseURL,
		pageSize:    cfg.PageSize,
		git:         gs,
	}, nil
}

// Register registers web UI routes on the given router.
func (h *Handler) Register(r *routegroup.Bundle) {
	r.HandleFunc("GET /{$}", h.handleIndex)
	r.HandleFunc("GET /web/keys", h.handleKeyList)
	r.HandleFunc("GET /web/keys/new", h.handleKeyNew)
	r.HandleFunc("GET /web/keys/view/{key...}", h.handleKeyView)
	r.HandleFunc("GET /web/keys/edit/{key...}", h.handleKeyEdit)
	r.HandleFunc("POST /web/keys", h.handleKeyCreate)
	r.HandleFunc("PUT /web/keys/{key...}", h.handleKeyUpdate)
	r.HandleFunc("DELETE /web/keys/{key...}", h.handleKeyDelete)
	r.HandleFunc("POST /web/theme", h.handleThemeToggle)
	r.HandleFunc("POST /web/view-mode", h.handleViewModeToggle)
	r.HandleFunc("POST /web/sort", h.handleSortToggle)
}

// RegisterAuth registers auth routes (login/logout) on the given router.
func (h *Handler) RegisterAuth(r *routegroup.Bundle) {
	r.HandleFunc("GET /login", h.handleLoginForm)
	r.HandleFunc("POST /logout", h.handleLogout)
}

// RegisterLogin registers the login POST handler with custom middleware.
func (h *Handler) RegisterLogin(r *routegroup.Bundle, middleware func(http.Handler) http.Handler) {
	r.Handle("POST /login", middleware(http.HandlerFunc(h.handleLogin)))
}

// templateFuncs returns custom template functions.
func templateFuncs() template.FuncMap {
	return template.FuncMap{
		"formatTime": func(t time.Time) string {
			return t.Format("2006-01-02 15:04")
		},
		"formatSize": func(size int) string {
			if size < 1024 {
				return strconv.Itoa(size) + " B"
			}
			if size < 1024*1024 {
				return strconv.FormatFloat(float64(size)/1024, 'f', 1, 64) + " KB"
			}
			return strconv.FormatFloat(float64(size)/(1024*1024), 'f', 1, 64) + " MB"
		},
		"urlEncode":     url.PathEscape,
		"sortModeLabel": sortModeLabel,
		"add":           func(a, b int) int { return a + b },
		"sub":           func(a, b int) int { return a - b },
	}
}

// parseTemplates parses all templates from embedded filesystem.
func parseTemplates() (*template.Template, error) {
	tmpl := template.New("").Funcs(templateFuncs())

	// parse base template
	baseContent, err := templatesFS.ReadFile("templates/base.html")
	if err != nil {
		return nil, fmt.Errorf("read base.html: %w", err)
	}
	tmpl, err = tmpl.Parse(string(baseContent))
	if err != nil {
		return nil, fmt.Errorf("parse base.html: %w", err)
	}

	// parse login template
	loginContent, err := templatesFS.ReadFile("templates/login.html")
	if err != nil {
		return nil, fmt.Errorf("read login.html: %w", err)
	}
	_, err = tmpl.New("login.html").Parse(string(loginContent))
	if err != nil {
		return nil, fmt.Errorf("parse login.html: %w", err)
	}

	// parse index template
	indexContent, err := templatesFS.ReadFile("templates/index.html")
	if err != nil {
		return nil, fmt.Errorf("read index.html: %w", err)
	}
	_, err = tmpl.New("index.html").Parse(string(indexContent))
	if err != nil {
		return nil, fmt.Errorf("parse index.html: %w", err)
	}

	// parse partials
	partials := []string{"keys-table", "form", "view"}
	for _, name := range partials {
		content, readErr := templatesFS.ReadFile("templates/partials/" + name + ".html")
		if readErr != nil {
			return nil, fmt.Errorf("read partial %s: %w", name, readErr)
		}
		_, parseErr := tmpl.New(name).Parse(string(content))
		if parseErr != nil {
			return nil, fmt.Errorf("parse partial %s: %w", name, parseErr)
		}
	}

	return tmpl, nil
}

// keyWithPermission wraps KeyInfo with per-key write permission.
type keyWithPermission struct {
	store.KeyInfo
	CanWrite bool // user has write permission for this specific key
}

// templateData holds data passed to templates.
type templateData struct {
	Keys           []keyWithPermission
	Key            string
	Value          string
	HighlightedVal template.HTML // syntax-highlighted value for view modal
	Format         string        // format type (text, json, yaml, etc.)
	Formats        []string      // available format options
	IsBinary       bool
	IsNew          bool
	Theme          string
	ViewMode       string
	SortMode       string
	Search         string
	Error          string
	CanForce       bool // allow force submit despite error (for validation errors, not conflicts)
	AuthEnabled    bool
	BaseURL        string
	ModalWidth     int
	TextareaHeight int
	CanWrite       bool   // user has write permission (for showing edit controls)
	Username       string // current logged-in username

	// conflict detection fields
	UpdatedAt       int64  // unix timestamp when key was loaded (for optimistic locking)
	Conflict        bool   // true when a conflict was detected on save
	ServerValue     string // current server value (shown during conflict)
	ServerFormat    string // current server format (shown during conflict)
	ServerUpdatedAt int64  // server's updated_at timestamp (for retry after conflict)

	// pagination fields
	Page       int  // current page (1-based)
	TotalPages int  // total number of pages
	TotalKeys  int  // total keys after filtering (before pagination)
	HasPrev    bool // has previous page
	HasNext    bool // has next page
}

// sortModeLabel returns a human-readable label for the sort mode.
func sortModeLabel(mode string) string {
	switch mode {
	case enum.SortModeKey.String():
		return "Key"
	case enum.SortModeSize.String():
		return "Size"
	case enum.SortModeCreated.String():
		return "Created"
	default:
		return "Updated"
	}
}

// getTheme returns the current theme from cookie.
func (h *Handler) getTheme(r *http.Request) string {
	cookie, err := r.Cookie("theme")
	if err != nil || cookie.Value == "" {
		return enum.ThemeSystem.String() // use system preference
	}
	if cookie.Value == enum.ThemeDark.String() || cookie.Value == enum.ThemeLight.String() {
		return cookie.Value
	}
	return enum.ThemeSystem.String()
}

// getViewMode returns the current view mode from cookie, defaulting to "grid".
func (h *Handler) getViewMode(r *http.Request) string {
	if cookie, err := r.Cookie("view_mode"); err == nil {
		if cookie.Value == enum.ViewModeCards.String() || cookie.Value == enum.ViewModeGrid.String() {
			return cookie.Value
		}
	}
	return enum.ViewModeGrid.String()
}

// getSortMode returns the current sort mode from cookie, defaulting to "updated".
func (h *Handler) getSortMode(r *http.Request) string {
	if cookie, err := r.Cookie("sort_mode"); err == nil {
		if _, err := enum.ParseSortMode(cookie.Value); err == nil {
			return cookie.Value
		}
	}
	return enum.SortModeUpdated.String()
}

// url returns a URL path with the base URL prefix.
func (h *Handler) url(path string) string {
	return h.baseURL + path
}

// cookiePath returns the path for cookies (base URL with trailing slash or "/").
func (h *Handler) cookiePath() string {
	if h.baseURL == "" {
		return "/"
	}
	return h.baseURL + "/"
}

// getCurrentUser returns the username from the session cookie, or empty string if not logged in.
func (h *Handler) getCurrentUser(r *http.Request) string {
	for _, cookieName := range sessionCookieNames {
		if cookie, err := r.Cookie(cookieName); err == nil {
			if username, ok := h.auth.GetSessionUser(cookie.Value); ok {
				return username
			}
		}
	}
	return ""
}

// getAuthor returns git author for the given username.
func (h *Handler) getAuthor(username string) git.Author {
	if username == "" {
		return git.DefaultAuthor()
	}
	return git.Author{Name: username, Email: username + "@stash"}
}

// sortByMode sorts a slice by the given mode using a key accessor.
func (h *Handler) sortByMode(keys []keyWithPermission, mode string) {
	switch mode {
	case "key":
		sort.Slice(keys, func(i, j int) bool {
			return strings.ToLower(keys[i].Key) < strings.ToLower(keys[j].Key)
		})
	case "size":
		sort.Slice(keys, func(i, j int) bool {
			return keys[i].Size > keys[j].Size // largest first
		})
	case "created":
		sort.Slice(keys, func(i, j int) bool {
			return keys[i].CreatedAt.After(keys[j].CreatedAt) // newest first
		})
	default: // "updated"
		sort.Slice(keys, func(i, j int) bool {
			return keys[i].UpdatedAt.After(keys[j].UpdatedAt) // newest first
		})
	}
}

// valueForDisplay converts a byte slice to a display string, detecting binary content.
func (h *Handler) valueForDisplay(value []byte) (string, bool) {
	if !utf8.Valid(value) {
		return base64.StdEncoding.EncodeToString(value), true
	}
	return string(value), false
}

// valueFromForm converts form input back to bytes, handling binary encoding.
func (h *Handler) valueFromForm(value string, isBinary bool) ([]byte, error) {
	if isBinary {
		decoded, err := base64.StdEncoding.DecodeString(value)
		if err != nil {
			return nil, fmt.Errorf("decode base64: %w", err)
		}
		return decoded, nil
	}
	return []byte(value), nil
}

// filterBySearch filters keys by search term.
func (h *Handler) filterBySearch(keys []keyWithPermission, search string) []keyWithPermission {
	if search == "" {
		return keys
	}
	search = strings.ToLower(search)
	var filtered []keyWithPermission
	for _, k := range keys {
		if strings.Contains(strings.ToLower(k.Key), search) {
			filtered = append(filtered, k)
		}
	}
	return filtered
}

// paginate applies pagination to a slice of keys and returns pagination info.
// page is 1-based, pageSize is the max keys per page.
func (h *Handler) paginate(keys []keyWithPermission, page, pageSize int) ([]keyWithPermission, int, int, bool, bool) {
	total := len(keys)
	if pageSize <= 0 {
		return keys, 1, 1, false, false
	}

	totalPages := (total + pageSize - 1) / pageSize
	if totalPages == 0 {
		totalPages = 1
	}
	if page < 1 {
		page = 1
	}
	if page > totalPages {
		page = totalPages
	}

	start := (page - 1) * pageSize
	end := start + pageSize
	if start >= total {
		return nil, page, totalPages, page > 1, false
	}
	if end > total {
		end = total
	}
	return keys[start:end], page, totalPages, page > 1, page < totalPages
}

// filterKeysByPermission filters keys based on user permissions and wraps with write permission info.
func (h *Handler) filterKeysByPermission(username string, keys []store.KeyInfo) []keyWithPermission {
	keyNames := make([]string, len(keys))
	for i, k := range keys {
		keyNames[i] = k.Key
	}
	allowedKeys := h.auth.FilterUserKeys(username, keyNames)
	allowedSet := make(map[string]bool, len(allowedKeys))
	for _, k := range allowedKeys {
		allowedSet[k] = true
	}
	var filtered []keyWithPermission
	for _, k := range keys {
		if allowedSet[k.Key] {
			filtered = append(filtered, keyWithPermission{
				KeyInfo:  k,
				CanWrite: h.auth.CheckUserPermission(username, k.Key, true),
			})
		}
	}
	return filtered
}
