package server

import (
	"embed"
	"encoding/base64"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"net/url"
	"sort"
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

// templateData holds data passed to templates.
type templateData struct {
	Keys     []store.KeyInfo
	Key      string
	Value    string
	IsBinary bool
	IsNew    bool
	Theme    string
	ViewMode string
	SortMode string
	Search   string
	Error    string
}

// templateFuncs returns custom template functions.
func templateFuncs() template.FuncMap {
	return template.FuncMap{
		"formatTime": func(t time.Time) string {
			return t.Format("2006-01-02 15:04")
		},
		"formatSize": func(size int) string {
			if size < 1024 {
				return formatInt(size) + " B"
			}
			if size < 1024*1024 {
				return formatFloat(float64(size)/1024) + " KB"
			}
			return formatFloat(float64(size)/(1024*1024)) + " MB"
		},
		"urlEncode":     url.PathEscape,
		"sortModeLabel": sortModeLabel,
	}
}

func formatInt(n int) string {
	if n < 0 {
		return "-" + formatInt(-n)
	}
	if n < 10 {
		return string(rune('0' + n))
	}
	return formatInt(n/10) + string(rune('0'+n%10))
}

func formatFloat(f float64) string {
	i := int(f * 10)
	return formatInt(i/10) + "." + formatInt(i%10)
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

	// parse index template
	indexContent, err := templatesFS.ReadFile("templates/index.html")
	if err != nil {
		return nil, fmt.Errorf("read index.html: %w", err)
	}
	tmpl, err = tmpl.Parse(string(indexContent))
	if err != nil {
		return nil, fmt.Errorf("parse index.html: %w", err)
	}

	// parse partials
	partials := []string{
		"templates/partials/keys-table.html",
		"templates/partials/view.html",
		"templates/partials/form.html",
	}
	for _, p := range partials {
		content, err := templatesFS.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", p, err)
		}
		tmpl, err = tmpl.Parse(string(content))
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", p, err)
		}
	}

	return tmpl, nil
}

// staticHandler returns a handler for static files.
func staticHandler() http.Handler {
	staticContent, err := fs.Sub(staticFS, "static")
	if err != nil {
		log.Printf("[ERROR] failed to create static sub filesystem: %v", err)
		return http.NotFoundHandler()
	}
	return http.StripPrefix("/static/", http.FileServer(http.FS(staticContent)))
}

// getTheme reads theme from cookie, returns "light" or "dark".
func getTheme(r *http.Request) string {
	cookie, err := r.Cookie("theme")
	if err != nil || cookie.Value == "" {
		return "" // use system preference
	}
	if cookie.Value == "dark" || cookie.Value == "light" {
		return cookie.Value
	}
	return ""
}

// getViewMode reads view mode from cookie, returns "grid" or "cards".
func getViewMode(r *http.Request) string {
	cookie, err := r.Cookie("view_mode")
	if err != nil || cookie.Value == "" {
		return "grid" // default to grid
	}
	if cookie.Value == "cards" || cookie.Value == "grid" {
		return cookie.Value
	}
	return "grid"
}

// getSortMode reads sort mode from cookie, returns "updated", "key", "size", or "created".
func getSortMode(r *http.Request) string {
	cookie, err := r.Cookie("sort_mode")
	if err != nil || cookie.Value == "" {
		return "updated" // default to updated (newest first)
	}
	switch cookie.Value {
	case "updated", "key", "size", "created":
		return cookie.Value
	}
	return "updated"
}

// sortModeLabel returns human-readable label for sort mode.
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

// sortKeys sorts keys by the given mode.
func sortKeys(keys []store.KeyInfo, mode string) {
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

// valueForDisplay converts a byte slice to display string.
// Returns the string and whether it's binary (base64 encoded).
func valueForDisplay(value []byte) (string, bool) {
	if utf8.Valid(value) {
		return string(value), false
	}
	return base64.StdEncoding.EncodeToString(value), true
}

// valueFromForm converts form value back to bytes.
// If isBinary is true, decodes from base64.
func valueFromForm(value string, isBinary bool) ([]byte, error) {
	if isBinary {
		decoded, err := base64.StdEncoding.DecodeString(value)
		if err != nil {
			return nil, fmt.Errorf("decode base64: %w", err)
		}
		return decoded, nil
	}
	return []byte(value), nil
}

// filterKeys filters keys by search term (case-insensitive substring match).
func filterKeys(keys []store.KeyInfo, search string) []store.KeyInfo {
	if search == "" {
		return keys
	}
	search = strings.ToLower(search)
	var filtered []store.KeyInfo
	for _, k := range keys {
		if strings.Contains(strings.ToLower(k.Key), search) {
			filtered = append(filtered, k)
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

	sortMode := getSortMode(r)
	sortKeys(keys, sortMode)

	data := templateData{
		Keys:     keys,
		Theme:    getTheme(r),
		ViewMode: getViewMode(r),
		SortMode: sortMode,
	}

	if err := s.tmpl.ExecuteTemplate(w, "base.html", data); err != nil {
		log.Printf("[ERROR] failed to execute template: %v", err)
	}
}

// handleKeyList renders the keys table partial (for HTMX).
func (s *Server) handleKeyList(w http.ResponseWriter, r *http.Request) {
	keys, err := s.store.List()
	if err != nil {
		log.Printf("[ERROR] failed to list keys: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// check URL query first, then form values (for POST requests with hx-include)
	search := r.URL.Query().Get("search")
	if search == "" {
		search = r.FormValue("search")
	}
	keys = filterKeys(keys, search)

	// check if view_mode was just set via Set-Cookie header (from toggle handler)
	viewMode := getViewMode(r)
	for _, c := range w.Header()["Set-Cookie"] {
		if strings.Contains(c, "view_mode=cards") {
			viewMode = "cards"
		} else if strings.Contains(c, "view_mode=grid") {
			viewMode = "grid"
		}
	}

	// check if sort_mode was just set via Set-Cookie header (from toggle handler)
	sortMode := getSortMode(r)
	for _, c := range w.Header()["Set-Cookie"] {
		switch {
		case strings.Contains(c, "sort_mode=key"):
			sortMode = "key"
		case strings.Contains(c, "sort_mode=size"):
			sortMode = "size"
		case strings.Contains(c, "sort_mode=created"):
			sortMode = "created"
		case strings.Contains(c, "sort_mode=updated"):
			sortMode = "updated"
		}
	}
	sortKeys(keys, sortMode)

	data := templateData{
		Keys:     keys,
		Search:   search,
		Theme:    getTheme(r),
		ViewMode: viewMode,
		SortMode: sortMode,
	}

	if err := s.tmpl.ExecuteTemplate(w, "keys-table", data); err != nil {
		log.Printf("[ERROR] failed to execute template: %v", err)
	}
}

// handleKeyNew renders the new key form.
func (s *Server) handleKeyNew(w http.ResponseWriter, r *http.Request) {
	data := templateData{
		IsNew: true,
		Theme: getTheme(r),
	}
	if err := s.tmpl.ExecuteTemplate(w, "form", data); err != nil {
		log.Printf("[ERROR] failed to execute template: %v", err)
	}
}

// handleKeyView renders the key view modal.
func (s *Server) handleKeyView(w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("key")
	value, err := s.store.Get(key)
	if err != nil {
		if err == store.ErrNotFound {
			http.Error(w, "key not found", http.StatusNotFound)
			return
		}
		log.Printf("[ERROR] failed to get key: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	displayValue, isBinary := valueForDisplay(value)
	data := templateData{
		Key:      key,
		Value:    displayValue,
		IsBinary: isBinary,
		Theme:    getTheme(r),
	}

	if err := s.tmpl.ExecuteTemplate(w, "view", data); err != nil {
		log.Printf("[ERROR] failed to execute template: %v", err)
	}
}

// handleKeyEdit renders the key edit form.
func (s *Server) handleKeyEdit(w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("key")
	value, err := s.store.Get(key)
	if err != nil {
		if err == store.ErrNotFound {
			http.Error(w, "key not found", http.StatusNotFound)
			return
		}
		log.Printf("[ERROR] failed to get key: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	displayValue, isBinary := valueForDisplay(value)
	data := templateData{
		Key:      key,
		Value:    displayValue,
		IsBinary: isBinary,
		Theme:    getTheme(r),
	}

	if err := s.tmpl.ExecuteTemplate(w, "form", data); err != nil {
		log.Printf("[ERROR] failed to execute template: %v", err)
	}
}

// handleKeyCreate creates a new key.
func (s *Server) handleKeyCreate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}

	key := r.FormValue("key")
	valueStr := r.FormValue("value")
	isBinary := r.FormValue("is_binary") == "true"

	if key == "" {
		http.Error(w, "key is required", http.StatusBadRequest)
		return
	}

	value, err := valueFromForm(valueStr, isBinary)
	if err != nil {
		http.Error(w, "invalid value encoding", http.StatusBadRequest)
		return
	}

	if err := s.store.Set(key, value); err != nil {
		log.Printf("[ERROR] failed to set key: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// return updated keys table
	s.handleKeyList(w, r)
}

// handleKeyUpdate updates an existing key.
func (s *Server) handleKeyUpdate(w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("key")
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}

	valueStr := r.FormValue("value")
	isBinary := r.FormValue("is_binary") == "true"

	value, err := valueFromForm(valueStr, isBinary)
	if err != nil {
		http.Error(w, "invalid value encoding", http.StatusBadRequest)
		return
	}

	if err := s.store.Set(key, value); err != nil {
		log.Printf("[ERROR] failed to set key: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// return updated keys table
	s.handleKeyList(w, r)
}

// handleKeyDelete deletes a key.
func (s *Server) handleKeyDelete(w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("key")
	if err := s.store.Delete(key); err != nil {
		if err == store.ErrNotFound {
			http.Error(w, "key not found", http.StatusNotFound)
			return
		}
		log.Printf("[ERROR] failed to delete key: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// return updated keys table
	s.handleKeyList(w, r)
}

// handleThemeToggle toggles the theme between light and dark.
func (s *Server) handleThemeToggle(w http.ResponseWriter, r *http.Request) {
	currentTheme := getTheme(r)
	newTheme := "dark"
	if currentTheme == "dark" {
		newTheme = "light"
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "theme",
		Value:    newTheme,
		Path:     "/",
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
	currentMode := getViewMode(r)
	newMode := "cards"
	if currentMode == "cards" {
		newMode = "grid"
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "view_mode",
		Value:    newMode,
		Path:     "/",
		MaxAge:   365 * 24 * 60 * 60, // 1 year
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	// return updated keys table with new view mode
	s.handleKeyList(w, r)
}

// handleSortToggle cycles through sort modes: updated -> key -> size -> created -> updated.
func (s *Server) handleSortToggle(w http.ResponseWriter, r *http.Request) {
	currentMode := getSortMode(r)
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
		Path:     "/",
		MaxAge:   365 * 24 * 60 * 60, // 1 year
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	// return updated keys table with new sort mode
	s.handleKeyList(w, r)
}
