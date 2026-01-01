package audit

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	log "github.com/go-pkgz/lgr"
	"github.com/go-pkgz/rest"

	"github.com/umputun/stash/app/enum"
	"github.com/umputun/stash/app/store"
)

// Handler handles audit query requests.
type Handler struct {
	store    Store
	auth     Auth
	maxLimit int
}

// NewHandler creates a new audit handler.
func NewHandler(auditStore Store, authSvc Auth, maxLimit int) *Handler {
	if maxLimit <= 0 {
		maxLimit = 10000
	}
	return &Handler{store: auditStore, auth: authSvc, maxLimit: maxLimit}
}

// QueryRequest represents the JSON request for audit query.
type QueryRequest struct {
	Key       string `json:"key,omitempty"`        // prefix match with * suffix
	Actor     string `json:"actor,omitempty"`      // exact match
	ActorType string `json:"actor_type,omitempty"` // user, token, public
	Action    string `json:"action,omitempty"`     // read, create, update, delete
	Result    string `json:"result,omitempty"`     // success, denied, not_found
	From      string `json:"from,omitempty"`       // RFC3339 timestamp
	To        string `json:"to,omitempty"`         // RFC3339 timestamp
	Limit     int    `json:"limit,omitempty"`      // max entries to return
}

// QueryResponse represents the JSON response for audit query.
type QueryResponse struct {
	Entries []store.AuditEntry `json:"entries"`
	Total   int                `json:"total"`
	Limit   int                `json:"limit"`
}

// HandleQuery handles POST /audit/query requests.
// Requires admin privileges via session cookie or API token with admin flag.
func (h *Handler) HandleQuery(w http.ResponseWriter, r *http.Request) {
	if h.auth == nil {
		rest.SendErrorJSON(w, r, log.Default(), http.StatusUnauthorized, nil, "unauthorized")
		return
	}

	if h.auth.IsRequestAdmin(r) {
		h.handleQueryInternal(w, r)
		return
	}

	// check if authenticated but not admin (403) vs not authenticated at all (401)
	actorType, _ := h.auth.GetRequestActor(r)
	if actorType == enum.ActorTypeUser.String() || actorType == enum.ActorTypeToken.String() {
		rest.SendErrorJSON(w, r, log.Default(), http.StatusForbidden, nil, "admin access required")
		return
	}

	rest.SendErrorJSON(w, r, log.Default(), http.StatusUnauthorized, nil, "unauthorized")
}

// handleQueryInternal performs the actual audit query after auth is verified.
func (h *Handler) handleQueryInternal(w http.ResponseWriter, r *http.Request) {
	// parse request body
	var req QueryRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		rest.SendErrorJSON(w, r, log.Default(), http.StatusBadRequest, err, "invalid request body")
		return
	}

	// build query
	query, err := h.buildQuery(req)
	if err != nil {
		rest.SendErrorJSON(w, r, log.Default(), http.StatusBadRequest, err, "invalid query parameters")
		return
	}

	// execute query
	entries, total, err := h.store.QueryAudit(r.Context(), query)
	if err != nil {
		rest.SendErrorJSON(w, r, log.Default(), http.StatusInternalServerError, err, "failed to query audit log")
		return
	}

	// ensure entries is never nil in response
	if entries == nil {
		entries = []store.AuditEntry{}
	}

	rest.RenderJSON(w, QueryResponse{
		Entries: entries,
		Total:   total,
		Limit:   query.Limit,
	})
}

// buildQuery converts request to store.AuditQuery.
func (h *Handler) buildQuery(req QueryRequest) (store.AuditQuery, error) {
	q := store.AuditQuery{
		Key:   req.Key,
		Actor: req.Actor,
		Limit: req.Limit,
	}

	// apply max limit
	if q.Limit <= 0 || q.Limit > h.maxLimit {
		q.Limit = h.maxLimit
	}

	// parse actor type
	if req.ActorType != "" {
		actorType, err := enum.ParseActorType(req.ActorType)
		if err != nil {
			return store.AuditQuery{}, fmt.Errorf("invalid actor_type: %w", err)
		}
		q.ActorType = actorType
	}

	// parse action
	if req.Action != "" {
		action, err := enum.ParseAuditAction(req.Action)
		if err != nil {
			return store.AuditQuery{}, fmt.Errorf("invalid action: %w", err)
		}
		q.Action = action
	}

	// parse result
	if req.Result != "" {
		result, err := enum.ParseAuditResult(req.Result)
		if err != nil {
			return store.AuditQuery{}, fmt.Errorf("invalid result: %w", err)
		}
		q.Result = result
	}

	// parse from timestamp
	if req.From != "" {
		from, err := time.Parse(time.RFC3339, req.From)
		if err != nil {
			return store.AuditQuery{}, fmt.Errorf("invalid from timestamp: %w", err)
		}
		q.From = from
	}

	// parse to timestamp
	if req.To != "" {
		to, err := time.Parse(time.RFC3339, req.To)
		if err != nil {
			return store.AuditQuery{}, fmt.Errorf("invalid to timestamp: %w", err)
		}
		q.To = to
	}

	return q, nil
}
