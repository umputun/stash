package server

import (
	"embed"
	"encoding/base64"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	log "github.com/go-pkgz/lgr"

	"github.com/umputun/stash/app/store"
)

//go:embed static
var staticFS embed.FS

//go:embed templates
var templatesFS embed.FS

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

// getTheme returns the current theme from cookie.
func (s *Server) getTheme(r *http.Request) string {
	cookie, err := r.Cookie("theme")
	if err != nil || cookie.Value == "" {
		return "" // use system preference
	}
	if cookie.Value == "dark" || cookie.Value == "light" {
		return cookie.Value
	}
	return ""
}

// getViewMode returns the current view mode from cookie, defaulting to "grid".
func (s *Server) getViewMode(r *http.Request) string {
	if cookie, err := r.Cookie("view_mode"); err == nil {
		if cookie.Value == "cards" || cookie.Value == "grid" {
			return cookie.Value
		}
	}
	return "grid"
}

// getSortMode returns the current sort mode from cookie, defaulting to "updated".
func (s *Server) getSortMode(r *http.Request) string {
	if cookie, err := r.Cookie("sort_mode"); err == nil {
		switch cookie.Value {
		case "key", "size", "created", "updated":
			return cookie.Value
		}
	}
	return "updated"
}

// sortModeLabel returns a human-readable label for the sort mode.
func sortModeLabel(mode string) string {
	switch mode {
	case "key":
		return "Key"
	case "size":
		return "Size"
	case "created":
		return "Created"
	default:
		return "Updated"
	}
}

// url returns a URL path with the base URL prefix.
func (s *Server) url(path string) string {
	return s.baseURL + path
}

// cookiePath returns the path for cookies (base URL with trailing slash or "/").
func (s *Server) cookiePath() string {
	if s.baseURL == "" {
		return "/"
	}
	return s.baseURL + "/"
}

// getCurrentUser returns the username from the session cookie, or empty string if not logged in.
func (s *Server) getCurrentUser(r *http.Request) string {
	for _, cookieName := range sessionCookieNames {
		if cookie, err := r.Cookie(cookieName); err == nil {
			if username, ok := s.auth.GetSessionUser(cookie.Value); ok {
				return username
			}
		}
	}
	return ""
}

// sortByMode sorts a slice by the given mode using a key accessor.
func (s *Server) sortByMode(keys []keyWithPermission, mode string) {
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
func (s *Server) valueForDisplay(value []byte) (string, bool) {
	if !utf8.Valid(value) {
		return base64.StdEncoding.EncodeToString(value), true
	}
	return string(value), false
}

// valueFromForm converts form input back to bytes, handling binary encoding.
func (s *Server) valueFromForm(value string, isBinary bool) ([]byte, error) {
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
func (s *Server) filterBySearch(keys []keyWithPermission, search string) []keyWithPermission {
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

// filterKeysByPermission filters keys based on user permissions and wraps with write permission info.
func (s *Server) filterKeysByPermission(username string, keys []store.KeyInfo) []keyWithPermission {
	keyNames := make([]string, len(keys))
	for i, k := range keys {
		keyNames[i] = k.Key
	}
	allowedKeys := s.auth.FilterUserKeys(username, keyNames)
	allowedSet := make(map[string]bool, len(allowedKeys))
	for _, k := range allowedKeys {
		allowedSet[k] = true
	}
	var filtered []keyWithPermission
	for _, k := range keys {
		if allowedSet[k.Key] {
			filtered = append(filtered, keyWithPermission{
				KeyInfo:  k,
				CanWrite: s.auth.CheckUserPermission(username, k.Key, true),
			})
		}
	}
	return filtered
}

// handleIndex renders the main page.
func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	keys, err := s.store.List()
	if err != nil {
		log.Printf("[ERROR] failed to list keys: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	username := s.getCurrentUser(r)
	filteredKeys := s.filterKeysByPermission(username, keys)

	sortMode := s.getSortMode(r)
	s.sortByMode(filteredKeys, sortMode)

	data := templateData{
		Keys:        filteredKeys,
		Theme:       s.getTheme(r),
		ViewMode:    s.getViewMode(r),
		SortMode:    sortMode,
		AuthEnabled: s.auth.Enabled(),
		BaseURL:     s.baseURL,
		CanWrite:    s.auth.UserCanWrite(username),
		Username:    username,
	}

	if err := s.tmpl.ExecuteTemplate(w, "base.html", data); err != nil {
		log.Printf("[ERROR] failed to execute template: %v", err)
	}
}

// handleThemeToggle toggles the theme between light and dark.
func (s *Server) handleThemeToggle(w http.ResponseWriter, r *http.Request) {
	currentTheme := s.getTheme(r)
	newTheme := "dark"
	if currentTheme == "dark" {
		newTheme = "light"
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "theme",
		Value:    newTheme,
		Path:     s.cookiePath(),
		MaxAge:   365 * 24 * 60 * 60, // 1 year
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	// trigger full page refresh
	w.Header().Set("HX-Refresh", "true")
	w.WriteHeader(http.StatusOK)
}

// handleViewModeToggle toggles the view mode between grid and cards.
func (s *Server) handleViewModeToggle(w http.ResponseWriter, r *http.Request) {
	currentMode := s.getViewMode(r)
	newMode := "cards"
	if currentMode == "cards" {
		newMode = "grid"
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "view_mode",
		Value:    newMode,
		Path:     s.cookiePath(),
		MaxAge:   365 * 24 * 60 * 60, // 1 year
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	// return updated keys table with new view mode
	s.handleKeyList(w, r)
}

// handleSortToggle cycles through sort modes: updated -> key -> size -> created -> updated.
func (s *Server) handleSortToggle(w http.ResponseWriter, r *http.Request) {
	currentMode := s.getSortMode(r)
	var newMode string
	switch currentMode {
	case "updated":
		newMode = "key"
	case "key":
		newMode = "size"
	case "size":
		newMode = "created"
	default:
		newMode = "updated"
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "sort_mode",
		Value:    newMode,
		Path:     s.cookiePath(),
		MaxAge:   365 * 24 * 60 * 60, // 1 year
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	// return updated keys table with new sort mode
	s.handleKeyList(w, r)
}
