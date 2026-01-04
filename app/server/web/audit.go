package web

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/umputun/stash/app/enum"
	"github.com/umputun/stash/app/store"
)

//go:generate moq -out mocks/auditstore.go -pkg mocks -skip-ensure -fmt goimports . AuditStore

// AuditStore defines the interface for audit log queries.
type AuditStore interface {
	QueryAudit(ctx context.Context, q store.AuditQuery) ([]store.AuditEntry, int, error)
}

// AuditHandler handles audit log web UI requests.
type AuditHandler struct {
	store    AuditStore
	auth     AuthProvider
	parent   *Handler
	pageSize int // audit-specific: defaults to 100 even if parent.pageSize is 0
}

// NewAuditHandler creates a new audit handler.
func NewAuditHandler(auditStore AuditStore, auth AuthProvider, h *Handler) *AuditHandler {
	pageSize := h.PageSize
	if pageSize == 0 {
		pageSize = 100 // audit log always paginates (unlike keys which can disable with 0)
	}
	return &AuditHandler{
		store:    auditStore,
		auth:     auth,
		parent:   h,
		pageSize: pageSize,
	}
}

// auditTemplateData holds data passed to audit templates.
type auditTemplateData struct {
	Entries []store.AuditEntry
	Total   int
	Page    int

	// filter values for form state
	Key       string
	Actor     string
	Action    string
	Result    string
	ActorType string
	From      string
	To        string

	// pagination
	TotalPages int
	HasPrev    bool
	HasNext    bool

	// UI state
	Theme       enum.Theme
	AuthEnabled bool
	BaseURL     string
	Error       string
}

// HandleAuditPage handles GET /audit - renders full audit page.
func (h *AuditHandler) HandleAuditPage(w http.ResponseWriter, r *http.Request) {
	username := h.parent.getCurrentUser(r)
	if username == "" {
		http.Redirect(w, r, h.parent.BaseURL+"/login?return="+url.QueryEscape(h.parent.BaseURL+"/audit"), http.StatusFound)
		return
	}

	if !h.auth.IsAdmin(username) {
		w.WriteHeader(http.StatusForbidden)
		_ = h.parent.tmpl.ExecuteTemplate(w, "error", map[string]any{
			"Error":   "Admin access required",
			"BaseURL": h.parent.BaseURL,
		})
		return
	}

	data := h.buildAuditData(r)
	if err := h.parent.tmpl.ExecuteTemplate(w, "audit.html", data); err != nil {
		http.Error(w, "template error", http.StatusInternalServerError)
	}
}

// HandleAuditTable handles GET /web/audit - returns audit table partial for HTMX.
func (h *AuditHandler) HandleAuditTable(w http.ResponseWriter, r *http.Request) {
	username := h.parent.getCurrentUser(r)
	if username == "" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if !h.auth.IsAdmin(username) {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	data := h.buildAuditData(r)
	if err := h.parent.tmpl.ExecuteTemplate(w, "audit-table", data); err != nil {
		http.Error(w, "template error", http.StatusInternalServerError)
	}
}

// buildAuditData builds template data from request parameters.
func (h *AuditHandler) buildAuditData(r *http.Request) auditTemplateData {
	q := r.URL.Query()

	// parse filter params
	key := q.Get("key")
	actor := q.Get("actor")
	action := q.Get("action")
	result := q.Get("result")
	actorType := q.Get("actor_type")
	from := q.Get("from")
	to := q.Get("to")
	page, _ := strconv.Atoi(q.Get("page"))
	if page < 1 {
		page = 1
	}

	// build query
	query := store.AuditQuery{
		Key:    key,
		Actor:  actor,
		Limit:  h.pageSize,
		Offset: (page - 1) * h.pageSize,
	}

	// parse enums
	if action != "" && action != "all" {
		if a, err := enum.ParseAuditAction(action); err == nil {
			query.Action = a
		}
	}
	if result != "" && result != "all" {
		if res, err := enum.ParseAuditResult(result); err == nil {
			query.Result = res
		}
	}
	if actorType != "" && actorType != "all" {
		if at, err := enum.ParseActorType(actorType); err == nil {
			query.ActorType = at
		}
	}

	// parse timestamps
	if from != "" {
		if t, err := time.Parse("2006-01-02T15:04", from); err == nil {
			query.From = t
		}
	}
	if to != "" {
		if t, err := time.Parse("2006-01-02T15:04", to); err == nil {
			query.To = t
		}
	}

	// execute query
	entries, total, err := h.store.QueryAudit(r.Context(), query)
	if err != nil {
		return auditTemplateData{
			Error:       "Failed to query audit log",
			Theme:       h.parent.getTheme(r),
			AuthEnabled: h.auth.Enabled(),
			BaseURL:     h.parent.BaseURL,
		}
	}

	// pagination - calculate total pages
	totalPages := (total + h.pageSize - 1) / h.pageSize
	if totalPages == 0 {
		totalPages = 1
	}

	// if page exceeds total pages, clamp and re-query
	if page > totalPages {
		page = totalPages
		query.Offset = (page - 1) * h.pageSize
		entries, _, err = h.store.QueryAudit(r.Context(), query)
		if err != nil {
			return auditTemplateData{
				Error:       "Failed to query audit log",
				Theme:       h.parent.getTheme(r),
				AuthEnabled: h.auth.Enabled(),
				BaseURL:     h.parent.BaseURL,
			}
		}
	}

	if entries == nil {
		entries = []store.AuditEntry{}
	}

	return auditTemplateData{
		Entries:     entries,
		Total:       total,
		Page:        page,
		Key:         key,
		Actor:       actor,
		Action:      action,
		Result:      result,
		ActorType:   actorType,
		From:        from,
		To:          to,
		TotalPages:  totalPages,
		HasPrev:     page > 1,
		HasNext:     page < totalPages,
		Theme:       h.parent.getTheme(r),
		AuthEnabled: h.auth.Enabled(),
		BaseURL:     h.parent.BaseURL,
	}
}

// actionClass returns CSS class for action badge.
func actionClass(action enum.AuditAction) string {
	switch action {
	case enum.AuditActionCreate:
		return "action-create"
	case enum.AuditActionRead:
		return "action-read"
	case enum.AuditActionUpdate:
		return "action-update"
	case enum.AuditActionDelete:
		return "action-delete"
	default:
		return ""
	}
}

// resultClass returns CSS class for result badge.
func resultClass(result enum.AuditResult) string {
	switch result {
	case enum.AuditResultSuccess:
		return "result-success"
	case enum.AuditResultDenied:
		return "result-denied"
	case enum.AuditResultNotFound:
		return "result-not_found"
	default:
		return ""
	}
}

// AuditTemplateFuncs returns template functions for audit templates.
func AuditTemplateFuncs() map[string]any {
	return map[string]any{
		"actionClass": actionClass,
		"resultClass": resultClass,
		"upper":       strings.ToUpper,
	}
}
