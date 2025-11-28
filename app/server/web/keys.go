package web

import (
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"strconv"
	"strings"
	"unicode/utf8"

	log "github.com/go-pkgz/lgr"

	"github.com/umputun/stash/app/git"
	"github.com/umputun/stash/app/store"
)

// conflictInfo holds data about a detected conflict.
type conflictInfo struct {
	ServerValue     string
	ServerFormat    string
	ServerUpdatedAt int64
}

// checkConflict checks if the key was modified since the form was loaded.
// Returns (nil, nil) if no conflict, (conflictInfo, nil) if conflict detected,
// or (nil, error) if unable to verify due to store error.
func (h *Handler) checkConflict(key string, formUpdatedAt int64) (*conflictInfo, error) {
	if formUpdatedAt <= 0 {
		return nil, nil // no timestamp to compare, skip conflict check
	}

	info, err := h.store.GetInfo(key)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, nil // new key, no conflict possible
		}
		return nil, fmt.Errorf("unable to verify: %w", err) // real DB error
	}

	serverUpdatedAt := info.UpdatedAt.Unix()
	if serverUpdatedAt == formUpdatedAt {
		return nil, nil // no conflict
	}

	// conflict detected - get current server value
	serverValue, serverFormat, err := h.store.GetWithFormat(key)
	if err != nil {
		log.Printf("[WARN] failed to get server value for conflict display: %v", err)
		serverValue = []byte("(unable to retrieve)")
		serverFormat = "text"
	}
	serverDisplayValue, _ := h.valueForDisplay(serverValue)

	return &conflictInfo{
		ServerValue:     serverDisplayValue,
		ServerFormat:    serverFormat,
		ServerUpdatedAt: serverUpdatedAt,
	}, nil
}

// validationErrorParams holds parameters for rendering a validation error form.
type validationErrorParams struct {
	Key       string
	Value     string
	Format    string
	IsBinary  bool
	Username  string
	Error     string
	UpdatedAt int64 // original timestamp from form (preserve for conflict detection on retry)
}

// renderValidationError re-renders the form with a validation error message.
// preserves original updated_at timestamp for conflict detection on retry.
func (h *Handler) renderValidationError(w http.ResponseWriter, p validationErrorParams) {
	w.Header().Set("HX-Retarget", "#modal-content")
	w.Header().Set("HX-Reswap", "innerHTML")
	modalWidth, textareaHeight := h.calculateModalDimensions(p.Value)
	data := templateData{
		Key:            p.Key,
		Value:          p.Value,
		Format:         p.Format,
		Formats:        h.validator.SupportedFormats(),
		IsBinary:       p.IsBinary,
		IsNew:          false,
		Error:          p.Error,
		CanForce:       true,
		BaseURL:        h.baseURL,
		ModalWidth:     modalWidth,
		TextareaHeight: textareaHeight,
		CanWrite:       true,
		Username:       p.Username,
		UpdatedAt:      p.UpdatedAt,
	}
	if err := h.tmpl.ExecuteTemplate(w, "form", data); err != nil {
		log.Printf("[ERROR] failed to execute template: %v", err)
	}
}

// calculateModalDimensions estimates modal width and textarea height based on content.
// returns width and textarea height in pixels.
func (h *Handler) calculateModalDimensions(value string) (width, textareaHeight int) {
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

// handleKeyList renders the keys table partial (for HTMX).
func (h *Handler) handleKeyList(w http.ResponseWriter, r *http.Request) {
	keys, err := h.store.List()
	if err != nil {
		log.Printf("[ERROR] failed to list keys: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	username := h.getCurrentUser(r)
	filteredKeys := h.filterKeysByPermission(username, keys)

	// check URL query first, then form values (for POST requests with hx-include)
	search := r.URL.Query().Get("search")
	if search == "" {
		search = r.FormValue("search")
	}
	filteredKeys = h.filterBySearch(filteredKeys, search)

	// check if view_mode was just set via Set-Cookie header (from toggle handler)
	viewMode := h.getViewMode(r)
	for _, c := range w.Header()["Set-Cookie"] {
		if strings.Contains(c, "view_mode=cards") {
			viewMode = "cards"
		} else if strings.Contains(c, "view_mode=grid") {
			viewMode = "grid"
		}
	}

	// check if sort_mode was just set via Set-Cookie header (from toggle handler)
	sortMode := h.getSortMode(r)
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
	h.sortByMode(filteredKeys, sortMode)

	// pagination
	totalKeys := len(filteredKeys)
	page := 1
	if p := r.URL.Query().Get("page"); p != "" {
		if parsed, parseErr := strconv.Atoi(p); parseErr == nil && parsed > 0 {
			page = parsed
		}
	}
	// also check form value (for POST requests like sort/view toggle)
	if p := r.FormValue("page"); p != "" {
		if parsed, parseErr := strconv.Atoi(p); parseErr == nil && parsed > 0 {
			page = parsed
		}
	}
	pagedKeys, page, totalPages, hasPrev, hasNext := h.paginate(filteredKeys, page, h.pageSize)

	data := templateData{
		Keys:       pagedKeys,
		Search:     search,
		Theme:      h.getTheme(r),
		ViewMode:   viewMode,
		SortMode:   sortMode,
		BaseURL:    h.baseURL,
		CanWrite:   h.auth.UserCanWrite(username),
		Username:   username,
		Page:       page,
		TotalPages: totalPages,
		TotalKeys:  totalKeys,
		HasPrev:    hasPrev,
		HasNext:    hasNext,
	}

	if err := h.tmpl.ExecuteTemplate(w, "keys-table", data); err != nil {
		log.Printf("[ERROR] failed to execute template: %v", err)
	}
}

// handleKeyNew renders the new key form.
func (h *Handler) handleKeyNew(w http.ResponseWriter, r *http.Request) {
	// check if user can write at all
	username := h.getCurrentUser(r)
	if !h.auth.UserCanWrite(username) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	data := templateData{
		IsNew:    true,
		Format:   "text",
		Formats:  h.validator.SupportedFormats(),
		Theme:    h.getTheme(r),
		BaseURL:  h.baseURL,
		CanWrite: true,
		Username: username,
	}
	if err := h.tmpl.ExecuteTemplate(w, "form", data); err != nil {
		log.Printf("[ERROR] failed to execute template: %v", err)
	}
}

// handleKeyView renders the key view modal.
func (h *Handler) handleKeyView(w http.ResponseWriter, r *http.Request) {
	key := store.NormalizeKey(r.PathValue("key"))

	// check read permission
	username := h.getCurrentUser(r)
	if !h.auth.CheckUserPermission(username, key, false) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	value, format, err := h.store.GetWithFormat(key)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			http.Error(w, "key not found", http.StatusNotFound)
			return
		}
		log.Printf("[ERROR] failed to get key: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	displayValue, isBinary := h.valueForDisplay(value)
	modalWidth, textareaHeight := h.calculateModalDimensions(displayValue)

	// generate highlighted HTML if not binary
	var highlightedVal template.HTML
	if !isBinary {
		highlightedVal = h.highlighter.Code(displayValue, format)
	}

	data := templateData{
		Key:            key,
		Value:          displayValue,
		HighlightedVal: highlightedVal,
		Format:         format,
		IsBinary:       isBinary,
		Theme:          h.getTheme(r),
		BaseURL:        h.baseURL,
		ModalWidth:     modalWidth,
		TextareaHeight: textareaHeight,
		CanWrite:       h.auth.CheckUserPermission(username, key, true),
		Username:       username,
	}

	if err := h.tmpl.ExecuteTemplate(w, "view", data); err != nil {
		log.Printf("[ERROR] failed to execute template: %v", err)
	}
}

// handleKeyEdit renders the key edit form.
func (h *Handler) handleKeyEdit(w http.ResponseWriter, r *http.Request) {
	key := store.NormalizeKey(r.PathValue("key"))

	// check write permission
	username := h.getCurrentUser(r)
	if !h.auth.CheckUserPermission(username, key, true) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	value, format, err := h.store.GetWithFormat(key)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			http.Error(w, "key not found", http.StatusNotFound)
			return
		}
		log.Printf("[ERROR] failed to get key: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// get key info for conflict detection (updated_at timestamp)
	var updatedAt int64
	if info, infoErr := h.store.GetInfo(key); infoErr == nil {
		updatedAt = info.UpdatedAt.Unix()
	}

	displayValue, isBinary := h.valueForDisplay(value)
	modalWidth, textareaHeight := h.calculateModalDimensions(displayValue)
	data := templateData{
		Key:            key,
		Value:          displayValue,
		Format:         format,
		Formats:        h.validator.SupportedFormats(),
		IsBinary:       isBinary,
		Theme:          h.getTheme(r),
		BaseURL:        h.baseURL,
		ModalWidth:     modalWidth,
		TextareaHeight: textareaHeight,
		CanWrite:       true,
		Username:       username,
		UpdatedAt:      updatedAt,
	}

	if err := h.tmpl.ExecuteTemplate(w, "form", data); err != nil {
		log.Printf("[ERROR] failed to execute template: %v", err)
	}
}

// handleKeyCreate creates a new key.
func (h *Handler) handleKeyCreate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}

	key := store.NormalizeKey(r.FormValue("key"))
	valueStr := r.FormValue("value")
	isBinary := r.FormValue("is_binary") == "true"
	format := r.FormValue("format")
	if !h.validator.IsValidFormat(format) {
		format = "text"
	}

	if key == "" {
		http.Error(w, "key is required", http.StatusBadRequest)
		return
	}

	// check write permission for this specific key
	username := h.getCurrentUser(r)
	if !h.auth.CheckUserPermission(username, key, true) {
		// re-render form with error message, retarget to modal content
		w.Header().Set("HX-Retarget", "#modal-content")
		w.Header().Set("HX-Reswap", "innerHTML")
		data := templateData{
			Key:     key,
			Value:   valueStr,
			IsNew:   true,
			Error:   "Access denied: you don't have write permission for this key prefix",
			BaseURL: h.baseURL,
		}
		if err := h.tmpl.ExecuteTemplate(w, "form", data); err != nil {
			log.Printf("[ERROR] failed to execute template: %v", err)
		}
		return
	}

	// check if key already exists
	_, _, getErr := h.store.GetWithFormat(key)
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
			Formats:  h.validator.SupportedFormats(),
			IsNew:    true,
			Error:    fmt.Sprintf("key %q already exists", key),
			BaseURL:  h.baseURL,
			CanWrite: true,
			Username: username,
		}
		if err := h.tmpl.ExecuteTemplate(w, "form", data); err != nil {
			log.Printf("[ERROR] failed to execute template: %v", err)
		}
		return
	}

	value, err := h.valueFromForm(valueStr, isBinary)
	if err != nil {
		http.Error(w, "invalid value encoding", http.StatusBadRequest)
		return
	}

	// validate value unless force flag is set or value is binary
	force := r.FormValue("force") == "true"
	if !force && !isBinary {
		if err := h.validator.Validate(format, value); err != nil {
			// re-render form with validation error
			w.Header().Set("HX-Retarget", "#modal-content")
			w.Header().Set("HX-Reswap", "innerHTML")
			data := templateData{
				Key:      key,
				Value:    valueStr,
				Format:   format,
				Formats:  h.validator.SupportedFormats(),
				IsNew:    true,
				Error:    err.Error(),
				CanForce: true,
				BaseURL:  h.baseURL,
				CanWrite: true,
				Username: username,
			}
			if err := h.tmpl.ExecuteTemplate(w, "form", data); err != nil {
				log.Printf("[ERROR] failed to execute template: %v", err)
			}
			return
		}
	}

	if err := h.store.Set(key, value, format); err != nil {
		log.Printf("[ERROR] failed to set key: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	log.Printf("[INFO] create %q (%d bytes, format=%s) by user:%s", key, len(value), format, username)

	// commit to git if enabled
	if h.git != nil {
		req := git.CommitRequest{Key: key, Value: value, Operation: "set", Format: format, Author: h.getAuthor(username)}
		if err := h.git.Commit(req); err != nil {
			log.Printf("[WARN] git commit failed for %s: %v", key, err)
		}
	}

	// return updated keys table
	h.handleKeyList(w, r)
}

// handleKeyUpdate updates an existing key.
func (h *Handler) handleKeyUpdate(w http.ResponseWriter, r *http.Request) {
	key := store.NormalizeKey(r.PathValue("key"))

	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}

	valueStr := r.FormValue("value")
	isBinary := r.FormValue("is_binary") == "true"
	format := r.FormValue("format")
	if !h.validator.IsValidFormat(format) {
		format = "text"
	}

	// check write permission
	username := h.getCurrentUser(r)
	if !h.auth.CheckUserPermission(username, key, true) {
		// re-render form with error message, retarget to modal content
		w.Header().Set("HX-Retarget", "#modal-content")
		w.Header().Set("HX-Reswap", "innerHTML")
		modalWidth, textareaHeight := h.calculateModalDimensions(valueStr)
		data := templateData{
			Key:            key,
			Value:          valueStr,
			IsBinary:       isBinary,
			IsNew:          false,
			Error:          "Access denied: you don't have write permission for this key",
			BaseURL:        h.baseURL,
			ModalWidth:     modalWidth,
			TextareaHeight: textareaHeight,
		}
		if err := h.tmpl.ExecuteTemplate(w, "form", data); err != nil {
			log.Printf("[ERROR] failed to execute template: %v", err)
		}
		return
	}

	value, err := h.valueFromForm(valueStr, isBinary)
	if err != nil {
		http.Error(w, "invalid value encoding", http.StatusBadRequest)
		return
	}

	// check for conflicts (optimistic locking) unless force_overwrite is set
	forceOverwrite := r.FormValue("force_overwrite") == "true"
	formUpdatedAt, _ := strconv.ParseInt(r.FormValue("updated_at"), 10, 64)
	if !forceOverwrite {
		conflict, checkErr := h.checkConflict(key, formUpdatedAt)
		if checkErr != nil {
			log.Printf("[ERROR] conflict check failed for key %q: %v", key, checkErr)
			http.Error(w, "unable to verify, please retry", http.StatusInternalServerError)
			return
		}
		if conflict != nil {
			w.Header().Set("HX-Retarget", "#modal-content")
			w.Header().Set("HX-Reswap", "innerHTML")
			modalWidth, textareaHeight := h.calculateModalDimensions(valueStr)
			data := templateData{
				Key:             key,
				Value:           valueStr,
				Format:          format,
				Formats:         h.validator.SupportedFormats(),
				IsBinary:        isBinary,
				IsNew:           false,
				BaseURL:         h.baseURL,
				ModalWidth:      modalWidth,
				TextareaHeight:  textareaHeight,
				CanWrite:        true,
				Username:        username,
				Conflict:        true,
				ServerValue:     conflict.ServerValue,
				ServerFormat:    conflict.ServerFormat,
				ServerUpdatedAt: conflict.ServerUpdatedAt,
				UpdatedAt:       formUpdatedAt,
			}
			if err := h.tmpl.ExecuteTemplate(w, "form", data); err != nil {
				log.Printf("[ERROR] failed to execute template: %v", err)
			}
			log.Printf("[WARN] conflict detected for key %q: form=%d, server=%d", key, formUpdatedAt, conflict.ServerUpdatedAt)
			return
		}
	}

	// validate value unless force flag is set or value is binary
	force := r.FormValue("force") == "true"
	if !force && !isBinary {
		if validationErr := h.validator.Validate(format, value); validationErr != nil {
			h.renderValidationError(w, validationErrorParams{
				Key: key, Value: valueStr, Format: format, IsBinary: isBinary, Username: username, Error: validationErr.Error(), UpdatedAt: formUpdatedAt,
			})
			return
		}
	}

	if err := h.store.Set(key, value, format); err != nil {
		log.Printf("[ERROR] failed to set key: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	log.Printf("[INFO] update %q (%d bytes, format=%s) by user:%s", key, len(value), format, username)

	// commit to git if enabled
	if h.git != nil {
		req := git.CommitRequest{Key: key, Value: value, Operation: "set", Format: format, Author: h.getAuthor(username)}
		if err := h.git.Commit(req); err != nil {
			log.Printf("[WARN] git commit failed for %s: %v", key, err)
		}
	}

	// return updated keys table
	h.handleKeyList(w, r)
}

// handleKeyDelete deletes a key.
func (h *Handler) handleKeyDelete(w http.ResponseWriter, r *http.Request) {
	key := store.NormalizeKey(r.PathValue("key"))

	// check write permission
	username := h.getCurrentUser(r)
	if !h.auth.CheckUserPermission(username, key, true) {
		http.Error(w, "access denied", http.StatusForbidden)
		return
	}

	if err := h.store.Delete(key); err != nil {
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
	if h.git != nil {
		if err := h.git.Delete(key, h.getAuthor(username)); err != nil {
			log.Printf("[WARN] git delete failed for %s: %v", key, err)
		}
	}

	// return updated keys table
	h.handleKeyList(w, r)
}
