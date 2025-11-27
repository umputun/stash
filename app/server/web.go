package server

import (
	"embed"
	"encoding/base64"
	"errors"
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

	// parse index template
	indexContent, err := templatesFS.ReadFile("templates/index.html")
	if err != nil {
		return nil, fmt.Errorf("read index.html: %w", err)
	}
	tmpl, err = tmpl.Parse(string(indexContent))
	if err != nil {
		return nil, fmt.Errorf("parse index.html: %w", err)
	}

	// parse login template
	loginContent, err := templatesFS.ReadFile("templates/login.html")
	if err != nil {
		return nil, fmt.Errorf("read login.html: %w", err)
	}
	tmpl, err = tmpl.Parse(string(loginContent))
	if err != nil {
		return nil, fmt.Errorf("parse login.html: %w", err)
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

// url returns the full URL path with the base URL prefix.
func (s *Server) url(path string) string {
	return s.baseURL + path
}

// cookiePath returns the appropriate cookie path based on base URL.
func (s *Server) cookiePath() string {
	if s.baseURL == "" {
		return "/"
	}
	return s.baseURL + "/"
}

// getCurrentUser returns the username from the session cookie, or empty if not logged in.
func (s *Server) getCurrentUser(r *http.Request) string {
	for _, cookieName := range sessionCookieNames {
		cookie, err := r.Cookie(cookieName)
		if err == nil && cookie.Value != "" {
			if username, ok := s.auth.GetSessionUser(cookie.Value); ok {
				return username
			}
		}
	}
	return ""
}

// sortByMode sorts a slice by the given mode using a key accessor.
func sortByMode[T any](keys []T, mode string, getInfo func(*T) store.KeyInfo) {
	switch mode {
	case "key":
		sort.Slice(keys, func(i, j int) bool {
			return strings.ToLower(getInfo(&keys[i]).Key) < strings.ToLower(getInfo(&keys[j]).Key)
		})
	case "size":
		sort.Slice(keys, func(i, j int) bool {
			return getInfo(&keys[i]).Size > getInfo(&keys[j]).Size // largest first
		})
	case "created":
		sort.Slice(keys, func(i, j int) bool {
			return getInfo(&keys[i]).CreatedAt.After(getInfo(&keys[j]).CreatedAt) // newest first
		})
	default: // "updated"
		sort.Slice(keys, func(i, j int) bool {
			return getInfo(&keys[i]).UpdatedAt.After(getInfo(&keys[j]).UpdatedAt) // newest first
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

// filterBySearch filters a slice by search term using a key accessor.
func filterBySearch[T any](keys []T, search string, getKey func(T) string) []T {
	if search == "" {
		return keys
	}
	search = strings.ToLower(search)
	var filtered []T
	for _, k := range keys {
		if strings.Contains(strings.ToLower(getKey(k)), search) {
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

// calculateModalDimensions estimates modal width and textarea height based on content.
// returns width and textarea height in pixels.
func (s *Server) calculateModalDimensions(value string) (width, textareaHeight int) {
	const minWidth, maxWidth = 600, 1200
	const charWidth = 8        // approximate width in pixels for monospace 13px font
	const padding = 100        // approximate padding, margins, and scrollbar
	const lineHeight = 20      // approximate line height in pixels
	const minLines = 4         // minimum 4 lines for textarea/value display
	const maxLines = 18        // maximum lines before scrolling (fits within 400px max-height)
	const textareaPadding = 24 // textarea padding (12px top + 12px bottom)

	// find longest line and count lines
	lines := strings.Split(value, "\n")
	maxLen := 0
	for _, line := range lines {
		if runeLen := utf8.RuneCountInString(line); runeLen > maxLen {
			maxLen = runeLen
		}
	}
	lineCount := len(lines)

	// calculate width with constraints
	width = maxLen*charWidth + padding
	if width < minWidth {
		width = minWidth
	}
	if width > maxWidth {
		width = maxWidth
	}

	// calculate textarea height based on line count (min 4, max 18 lines)
	if lineCount < minLines {
		lineCount = minLines
	}
	if lineCount > maxLines {
		lineCount = maxLines
	}
	textareaHeight = lineCount*lineHeight + textareaPadding

	return width, textareaHeight
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

	sortMode := getSortMode(r)
	sortByMode(filteredKeys, sortMode, func(k *keyWithPermission) store.KeyInfo { return k.KeyInfo })

	data := templateData{
		Keys:        filteredKeys,
		Theme:       getTheme(r),
		ViewMode:    getViewMode(r),
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

// handleKeyList renders the keys table partial (for HTMX).
func (s *Server) handleKeyList(w http.ResponseWriter, r *http.Request) {
	keys, err := s.store.List()
	if err != nil {
		log.Printf("[ERROR] failed to list keys: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	username := s.getCurrentUser(r)
	filteredKeys := s.filterKeysByPermission(username, keys)

	// check URL query first, then form values (for POST requests with hx-include)
	search := r.URL.Query().Get("search")
	if search == "" {
		search = r.FormValue("search")
	}
	filteredKeys = filterBySearch(filteredKeys, search, func(k keyWithPermission) string { return k.Key })

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
	sortByMode(filteredKeys, sortMode, func(k *keyWithPermission) store.KeyInfo { return k.KeyInfo })

	data := templateData{
		Keys:     filteredKeys,
		Search:   search,
		Theme:    getTheme(r),
		ViewMode: viewMode,
		SortMode: sortMode,
		BaseURL:  s.baseURL,
		CanWrite: s.auth.UserCanWrite(username),
		Username: username,
	}

	if err := s.tmpl.ExecuteTemplate(w, "keys-table", data); err != nil {
		log.Printf("[ERROR] failed to execute template: %v", err)
	}
}

// handleKeyNew renders the new key form.
func (s *Server) handleKeyNew(w http.ResponseWriter, r *http.Request) {
	// check if user can write at all
	username := s.getCurrentUser(r)
	if !s.auth.UserCanWrite(username) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	data := templateData{
		IsNew:    true,
		Format:   "text",
		Formats:  s.highlighter.SupportedFormats(),
		Theme:    getTheme(r),
		BaseURL:  s.baseURL,
		CanWrite: true,
		Username: username,
	}
	if err := s.tmpl.ExecuteTemplate(w, "form", data); err != nil {
		log.Printf("[ERROR] failed to execute template: %v", err)
	}
}

// handleKeyView renders the key view modal.
func (s *Server) handleKeyView(w http.ResponseWriter, r *http.Request) {
	key := normalizeKey(r.PathValue("key"))

	// check read permission
	username := s.getCurrentUser(r)
	if !s.auth.CheckUserPermission(username, key, false) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	value, format, err := s.store.GetWithFormat(key)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			http.Error(w, "key not found", http.StatusNotFound)
			return
		}
		log.Printf("[ERROR] failed to get key: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	displayValue, isBinary := valueForDisplay(value)
	modalWidth, textareaHeight := s.calculateModalDimensions(displayValue)

	// generate highlighted HTML if not binary
	var highlightedVal template.HTML
	if !isBinary {
		highlightedVal = s.highlighter.Code(displayValue, format)
	}

	data := templateData{
		Key:            key,
		Value:          displayValue,
		HighlightedVal: highlightedVal,
		Format:         format,
		IsBinary:       isBinary,
		Theme:          getTheme(r),
		BaseURL:        s.baseURL,
		ModalWidth:     modalWidth,
		TextareaHeight: textareaHeight,
		CanWrite:       s.auth.CheckUserPermission(username, key, true),
		Username:       username,
	}

	if err := s.tmpl.ExecuteTemplate(w, "view", data); err != nil {
		log.Printf("[ERROR] failed to execute template: %v", err)
	}
}

// handleKeyEdit renders the key edit form.
func (s *Server) handleKeyEdit(w http.ResponseWriter, r *http.Request) {
	key := normalizeKey(r.PathValue("key"))

	// check write permission
	username := s.getCurrentUser(r)
	if !s.auth.CheckUserPermission(username, key, true) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	value, format, err := s.store.GetWithFormat(key)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			http.Error(w, "key not found", http.StatusNotFound)
			return
		}
		log.Printf("[ERROR] failed to get key: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	displayValue, isBinary := valueForDisplay(value)
	modalWidth, textareaHeight := s.calculateModalDimensions(displayValue)
	data := templateData{
		Key:            key,
		Value:          displayValue,
		Format:         format,
		Formats:        s.highlighter.SupportedFormats(),
		IsBinary:       isBinary,
		Theme:          getTheme(r),
		BaseURL:        s.baseURL,
		ModalWidth:     modalWidth,
		TextareaHeight: textareaHeight,
		CanWrite:       true,
		Username:       username,
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

	key := normalizeKey(r.FormValue("key"))
	valueStr := r.FormValue("value")
	isBinary := r.FormValue("is_binary") == "true"
	format := r.FormValue("format")
	if !s.highlighter.IsValidFormat(format) {
		format = "text"
	}

	if key == "" {
		http.Error(w, "key is required", http.StatusBadRequest)
		return
	}

	// check write permission for this specific key
	username := s.getCurrentUser(r)
	if !s.auth.CheckUserPermission(username, key, true) {
		// re-render form with error message, retarget to modal content
		w.Header().Set("HX-Retarget", "#modal-content")
		w.Header().Set("HX-Reswap", "innerHTML")
		data := templateData{
			Key:     key,
			Value:   valueStr,
			IsNew:   true,
			Error:   "Access denied: you don't have write permission for this key prefix",
			BaseURL: s.baseURL,
		}
		if err := s.tmpl.ExecuteTemplate(w, "form", data); err != nil {
			log.Printf("[ERROR] failed to execute template: %v", err)
		}
		return
	}

	// check if key already exists
	_, _, getErr := s.store.GetWithFormat(key)
	if getErr != nil && !errors.Is(getErr, store.ErrNotFound) {
		// unexpected store error
		log.Printf("[ERROR] failed to check key existence: %v", getErr)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if getErr == nil {
		// key exists - return error
		w.Header().Set("HX-Retarget", "#modal-content")
		w.Header().Set("HX-Reswap", "innerHTML")
		data := templateData{
			Key:      key,
			Value:    valueStr,
			Format:   format,
			Formats:  s.highlighter.SupportedFormats(),
			IsNew:    true,
			Error:    fmt.Sprintf("key %q already exists", key),
			BaseURL:  s.baseURL,
			CanWrite: true,
			Username: username,
		}
		if err := s.tmpl.ExecuteTemplate(w, "form", data); err != nil {
			log.Printf("[ERROR] failed to execute template: %v", err)
		}
		return
	}

	value, err := valueFromForm(valueStr, isBinary)
	if err != nil {
		http.Error(w, "invalid value encoding", http.StatusBadRequest)
		return
	}

	// validate value unless force flag is set or value is binary
	force := r.FormValue("force") == "true"
	if !force && !isBinary {
		if err := s.validator.Validate(format, value); err != nil {
			// re-render form with validation error
			w.Header().Set("HX-Retarget", "#modal-content")
			w.Header().Set("HX-Reswap", "innerHTML")
			data := templateData{
				Key:      key,
				Value:    valueStr,
				Format:   format,
				Formats:  s.highlighter.SupportedFormats(),
				IsNew:    true,
				Error:    err.Error(),
				CanForce: true,
				BaseURL:  s.baseURL,
				CanWrite: true,
				Username: username,
			}
			if err := s.tmpl.ExecuteTemplate(w, "form", data); err != nil {
				log.Printf("[ERROR] failed to execute template: %v", err)
			}
			return
		}
	}

	if err := s.store.Set(key, value, format); err != nil {
		log.Printf("[ERROR] failed to set key: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	log.Printf("[INFO] create %q (%d bytes, format=%s) by user:%s", key, len(value), format, username)

	// commit to git if enabled
	s.gitCommit(r, key, value, "set", format)

	// return updated keys table
	s.handleKeyList(w, r)
}

// handleKeyUpdate updates an existing key.
func (s *Server) handleKeyUpdate(w http.ResponseWriter, r *http.Request) {
	key := normalizeKey(r.PathValue("key"))

	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}

	valueStr := r.FormValue("value")
	isBinary := r.FormValue("is_binary") == "true"
	format := r.FormValue("format")
	if !s.highlighter.IsValidFormat(format) {
		format = "text"
	}

	// check write permission
	username := s.getCurrentUser(r)
	if !s.auth.CheckUserPermission(username, key, true) {
		// re-render form with error message, retarget to modal content
		w.Header().Set("HX-Retarget", "#modal-content")
		w.Header().Set("HX-Reswap", "innerHTML")
		modalWidth, textareaHeight := s.calculateModalDimensions(valueStr)
		data := templateData{
			Key:            key,
			Value:          valueStr,
			IsBinary:       isBinary,
			IsNew:          false,
			Error:          "Access denied: you don't have write permission for this key",
			BaseURL:        s.baseURL,
			ModalWidth:     modalWidth,
			TextareaHeight: textareaHeight,
		}
		if err := s.tmpl.ExecuteTemplate(w, "form", data); err != nil {
			log.Printf("[ERROR] failed to execute template: %v", err)
		}
		return
	}

	value, err := valueFromForm(valueStr, isBinary)
	if err != nil {
		http.Error(w, "invalid value encoding", http.StatusBadRequest)
		return
	}

	// validate value unless force flag is set or value is binary
	force := r.FormValue("force") == "true"
	if !force && !isBinary {
		if err := s.validator.Validate(format, value); err != nil {
			// re-render form with validation error
			w.Header().Set("HX-Retarget", "#modal-content")
			w.Header().Set("HX-Reswap", "innerHTML")
			modalWidth, textareaHeight := s.calculateModalDimensions(valueStr)
			data := templateData{
				Key:            key,
				Value:          valueStr,
				Format:         format,
				Formats:        s.highlighter.SupportedFormats(),
				IsBinary:       isBinary,
				IsNew:          false,
				Error:          err.Error(),
				CanForce:       true,
				BaseURL:        s.baseURL,
				ModalWidth:     modalWidth,
				TextareaHeight: textareaHeight,
				CanWrite:       true,
				Username:       username,
			}
			if err := s.tmpl.ExecuteTemplate(w, "form", data); err != nil {
				log.Printf("[ERROR] failed to execute template: %v", err)
			}
			return
		}
	}

	if err := s.store.Set(key, value, format); err != nil {
		log.Printf("[ERROR] failed to set key: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	log.Printf("[INFO] update %q (%d bytes, format=%s) by user:%s", key, len(value), format, username)

	// commit to git if enabled
	s.gitCommit(r, key, value, "set", format)

	// return updated keys table
	s.handleKeyList(w, r)
}

// handleKeyDelete deletes a key.
func (s *Server) handleKeyDelete(w http.ResponseWriter, r *http.Request) {
	key := normalizeKey(r.PathValue("key"))

	// check write permission
	username := s.getCurrentUser(r)
	if !s.auth.CheckUserPermission(username, key, true) {
		http.Error(w, "access denied", http.StatusForbidden)
		return
	}

	if err := s.store.Delete(key); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			http.Error(w, "key not found", http.StatusNotFound)
			return
		}
		log.Printf("[ERROR] failed to delete key: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	log.Printf("[INFO] delete %q by user:%s", key, username)

	// delete from git if enabled
	s.gitDelete(r, key)

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
	currentMode := getViewMode(r)
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
		Path:     s.cookiePath(),
		MaxAge:   365 * 24 * 60 * 60, // 1 year
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	// return updated keys table with new sort mode
	s.handleKeyList(w, r)
}

// handleLoginForm renders the login page.
func (s *Server) handleLoginForm(w http.ResponseWriter, r *http.Request) {
	data := templateData{
		Theme:   getTheme(r),
		BaseURL: s.baseURL,
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpl.ExecuteTemplate(w, "login.html", data); err != nil {
		log.Printf("[ERROR] failed to execute login template: %v", err)
	}
}

// handleLogin processes the login form submission.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form data", http.StatusBadRequest)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")
	if username == "" || password == "" {
		s.renderLoginError(w, r, "Username and password are required")
		return
	}

	user := s.auth.ValidateUser(username, password)
	if user == nil {
		s.renderLoginError(w, r, "Invalid username or password")
		return
	}

	// create session
	token, err := s.auth.CreateSession(username)
	if err != nil {
		log.Printf("[ERROR] failed to create session: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// set cookie - use __Host- prefix for enhanced security over HTTPS (only when no base URL)
	// __Host- prefix requires Path="/" which doesn't work with base URL
	cookieName := "stash-auth"
	secure := r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"
	if secure && s.baseURL == "" {
		cookieName = "__Host-stash-auth"
	}

	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    token,
		Path:     s.cookiePath(),
		MaxAge:   int(s.auth.LoginTTL().Seconds()),
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   secure,
	})

	http.Redirect(w, r, s.url("/"), http.StatusSeeOther)
}

// handleLogout logs the user out by clearing the session.
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	// invalidate session
	for _, cookieName := range sessionCookieNames {
		if cookie, err := r.Cookie(cookieName); err == nil {
			s.auth.InvalidateSession(cookie.Value)
		}
	}

	secure := r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"

	// clear both cookies - need both paths for compatibility
	http.SetCookie(w, &http.Cookie{
		Name:     "stash-auth",
		Value:    "",
		Path:     s.cookiePath(),
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   secure,
	})

	// clear __Host- cookie if baseURL is empty (it requires Path="/")
	if s.baseURL == "" {
		http.SetCookie(w, &http.Cookie{
			Name:     "__Host-stash-auth",
			Value:    "",
			Path:     "/",
			MaxAge:   -1,
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
			Secure:   true,
		})
	}

	// tell HTMX to perform a full page refresh
	w.Header().Set("HX-Refresh", "true")
	http.Redirect(w, r, s.url("/login"), http.StatusSeeOther)
}

// renderLoginError renders the login page with an error message.
func (s *Server) renderLoginError(w http.ResponseWriter, r *http.Request, errMsg string) {
	data := templateData{
		Theme:   getTheme(r),
		Error:   errMsg,
		BaseURL: s.baseURL,
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusUnauthorized)
	if err := s.tmpl.ExecuteTemplate(w, "login.html", data); err != nil {
		log.Printf("[ERROR] failed to execute login template: %v", err)
	}
}
