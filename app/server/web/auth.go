package web

import (
	"net/http"

	log "github.com/go-pkgz/lgr"
)

// handleLoginForm renders the login page.
func (h *Handler) handleLoginForm(w http.ResponseWriter, r *http.Request) {
	data := templateData{
		Theme:   h.getTheme(r),
		BaseURL: h.baseURL,
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.tmpl.ExecuteTemplate(w, "login.html", data); err != nil {
		log.Printf("[ERROR] failed to execute login template: %v", err)
	}
}

// handleLogin processes the login form submission.
func (h *Handler) handleLogin(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form data", http.StatusBadRequest)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")
	if username == "" || password == "" {
		h.renderLoginError(w, r, "Username and password are required")
		return
	}

	if !h.auth.IsValidUser(username, password) {
		h.renderLoginError(w, r, "Invalid username or password")
		return
	}

	// create session
	token, err := h.auth.CreateSession(r.Context(), username)
	if err != nil {
		log.Printf("[ERROR] failed to create session: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// set cookie - use __Host- prefix for enhanced security over HTTPS (only when no base URL)
	// __Host- prefix requires Path="/" which doesn't work with base URL
	cookieName := "stash-auth"
	secure := r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"
	if secure && h.baseURL == "" {
		cookieName = "__Host-stash-auth"
	}

	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    token,
		Path:     h.cookiePath(),
		MaxAge:   int(h.auth.LoginTTL().Seconds()),
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   secure,
	})

	http.Redirect(w, r, h.url("/"), http.StatusSeeOther)
}

// handleLogout logs the user out by clearing the session.
func (h *Handler) handleLogout(w http.ResponseWriter, r *http.Request) {
	// invalidate session
	for _, cookieName := range sessionCookieNames {
		if cookie, err := r.Cookie(cookieName); err == nil {
			h.auth.InvalidateSession(r.Context(), cookie.Value)
		}
	}

	secure := r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"

	// clear both cookies - need both paths for compatibility
	http.SetCookie(w, &http.Cookie{
		Name:     "stash-auth",
		Value:    "",
		Path:     h.cookiePath(),
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   secure,
	})

	// clear __Host- cookie if baseURL is empty (it requires Path="/")
	if h.baseURL == "" {
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
	http.Redirect(w, r, h.url("/login"), http.StatusSeeOther)
}

// renderLoginError renders the login page with an error message.
func (h *Handler) renderLoginError(w http.ResponseWriter, r *http.Request, errMsg string) {
	data := templateData{
		Theme:   h.getTheme(r),
		Error:   errMsg,
		BaseURL: h.baseURL,
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusUnauthorized)
	if err := h.tmpl.ExecuteTemplate(w, "login.html", data); err != nil {
		log.Printf("[ERROR] failed to execute login template: %v", err)
	}
}
