package web

import (
	"net/http"
	"strconv"

	log "github.com/go-pkgz/lgr"
)

// handleIndex renders the main page.
func (h *Handler) handleIndex(w http.ResponseWriter, r *http.Request) {
	keys, err := h.store.List()
	if err != nil {
		log.Printf("[ERROR] failed to list keys: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	username := h.getCurrentUser(r)
	filteredKeys := h.filterKeysByPermission(username, keys)

	sortMode := h.getSortMode(r)
	h.sortByMode(filteredKeys, sortMode)

	// pagination
	totalKeys := len(filteredKeys)
	page := 1
	if p := r.URL.Query().Get("page"); p != "" {
		if parsed, parseErr := strconv.Atoi(p); parseErr == nil && parsed > 0 {
			page = parsed
		}
	}
	pagedKeys, page, totalPages, hasPrev, hasNext := h.paginate(filteredKeys, page, h.pageSize)

	data := templateData{
		Keys:        pagedKeys,
		Theme:       h.getTheme(r),
		ViewMode:    h.getViewMode(r),
		SortMode:    sortMode,
		AuthEnabled: h.auth.Enabled(),
		BaseURL:     h.baseURL,
		CanWrite:    h.auth.UserCanWrite(username),
		Username:    username,
		Page:        page,
		TotalPages:  totalPages,
		TotalKeys:   totalKeys,
		HasPrev:     hasPrev,
		HasNext:     hasNext,
	}

	if err := h.tmpl.ExecuteTemplate(w, "base.html", data); err != nil {
		log.Printf("[ERROR] failed to execute template: %v", err)
	}
}

// handleThemeToggle toggles the theme between light and dark.
func (h *Handler) handleThemeToggle(w http.ResponseWriter, r *http.Request) {
	newTheme := h.getTheme(r).Toggle()
	http.SetCookie(w, &http.Cookie{
		Name:     "theme",
		Value:    newTheme.String(),
		Path:     h.cookiePath(),
		MaxAge:   365 * 24 * 60 * 60, // 1 year
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	// trigger full page refresh
	w.Header().Set("HX-Refresh", "true")
	w.WriteHeader(http.StatusOK)
}

// handleViewModeToggle toggles the view mode between grid and cards.
func (h *Handler) handleViewModeToggle(w http.ResponseWriter, r *http.Request) {
	newMode := h.getViewMode(r).Toggle()
	http.SetCookie(w, &http.Cookie{
		Name:     "view_mode",
		Value:    newMode.String(),
		Path:     h.cookiePath(),
		MaxAge:   365 * 24 * 60 * 60, // 1 year
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	// return updated keys table with new view mode
	h.handleKeyList(w, r)
}

// handleSortToggle cycles through sort modes: updated -> key -> size -> created -> updated.
func (h *Handler) handleSortToggle(w http.ResponseWriter, r *http.Request) {
	newMode := h.getSortMode(r).Next()
	http.SetCookie(w, &http.Cookie{
		Name:     "sort_mode",
		Value:    newMode.String(),
		Path:     h.cookiePath(),
		MaxAge:   365 * 24 * 60 * 60, // 1 year
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	// return updated keys table with new sort mode
	h.handleKeyList(w, r)
}
