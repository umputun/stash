package server

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	log "github.com/go-pkgz/lgr"
	"github.com/go-pkgz/rest"
	"github.com/go-pkgz/rest/realip"

	"github.com/umputun/stash/app/enum"
	"github.com/umputun/stash/app/store"
)

//go:generate moq -out mocks/auditstore.go -pkg mocks -skip-ensure -fmt goimports . AuditStore
//go:generate moq -out mocks/auditauth.go -pkg mocks -skip-ensure -fmt goimports . AuditAuth

// AuditStore defines the interface for audit log storage.
type AuditStore interface {
	LogAudit(ctx context.Context, entry store.AuditEntry) error
	QueryAudit(ctx context.Context, q store.AuditQuery) ([]store.AuditEntry, int, error)
}

// AuditAuth defines the interface for auth operations needed by audit.
type AuditAuth interface {
	GetRequestActor(r *http.Request) (actorType, actorName string)
	IsRequestAdmin(r *http.Request) bool
}

// responseCapture wraps http.ResponseWriter to capture status code and bytes written.
type responseCapture struct {
	http.ResponseWriter
	status       int
	bytesWritten int
}

// newResponseCapture creates a responseCapture wrapper.
func newResponseCapture(w http.ResponseWriter) *responseCapture {
	return &responseCapture{ResponseWriter: w, status: http.StatusOK}
}

// WriteHeader captures the status code and delegates to wrapped writer.
func (rc *responseCapture) WriteHeader(code int) {
	rc.status = code
	rc.ResponseWriter.WriteHeader(code)
}

// Write captures bytes written and delegates to wrapped writer.
func (rc *responseCapture) Write(b []byte) (int, error) {
	n, err := rc.ResponseWriter.Write(b)
	rc.bytesWritten += n
	if err != nil {
		return n, fmt.Errorf("write failed: %w", err)
	}
	return n, nil
}

// Unwrap returns the underlying ResponseWriter (for http.ResponseController).
func (rc *responseCapture) Unwrap() http.ResponseWriter {
	return rc.ResponseWriter
}

// Flush implements http.Flusher.
func (rc *responseCapture) Flush() {
	if f, ok := rc.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Hijack implements http.Hijacker.
func (rc *responseCapture) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hj, ok := rc.ResponseWriter.(http.Hijacker); ok {
		conn, rw, err := hj.Hijack()
		if err != nil {
			return nil, nil, fmt.Errorf("hijack failed: %w", err)
		}
		return conn, rw, nil
	}
	return nil, nil, errors.New("ResponseWriter does not implement http.Hijacker")
}

// auditor handles building and logging audit entries.
type auditor struct {
	store AuditStore
	auth  AuditAuth
}

// newAuditor creates a new auditor.
func newAuditor(auditStore AuditStore, authSvc AuditAuth) *auditor {
	return &auditor{store: auditStore, auth: authSvc}
}

// Middleware returns HTTP middleware that logs audit entries after handler completes.
// Applies only to /kv/* routes. Logs read, create, update, delete actions based on method.
func (a *auditor) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// only audit /kv/* routes (not /kv or /kv/ list operations)
		path := r.URL.Path
		if !strings.HasPrefix(path, "/kv/") && path != "/kv" {
			next.ServeHTTP(w, r)
			return
		}

		// skip list operation (GET /kv or GET /kv/)
		if (path == "/kv" || path == "/kv/") && r.Method == http.MethodGet {
			next.ServeHTTP(w, r)
			return
		}

		// extract key from path
		key := store.NormalizeKey(strings.TrimPrefix(path, "/kv/"))

		// wrap response to capture status and size
		rc := newResponseCapture(w)
		next.ServeHTTP(rc, r)

		// log audit entry after handler completes
		entry := a.buildEntry(r, rc, key)
		if err := a.store.LogAudit(r.Context(), entry); err != nil {
			log.Printf("[WARN] failed to log audit entry: %v", err)
		}
	})
}

// buildEntry creates an audit entry from request and response data.
func (a *auditor) buildEntry(r *http.Request, rc *responseCapture, key string) store.AuditEntry {
	actor, actorType := a.extractActor(r)
	action := a.mapAction(r.Method, rc.status)
	result := a.mapStatus(rc.status)

	ip, _ := realip.Get(r) // ignore error, fallback to empty string

	entry := store.AuditEntry{
		Timestamp: time.Now(),
		Action:    action,
		Key:       key,
		Actor:     actor,
		ActorType: actorType,
		Result:    result,
		IP:        ip,
		UserAgent: r.UserAgent(),
		RequestID: r.Header.Get("X-Request-ID"),
	}

	// set value size for successful read/create/update operations
	if result == enum.AuditResultSuccess && action != enum.AuditActionDelete {
		size := rc.bytesWritten
		entry.ValueSize = &size
	}

	return entry
}

// extractActor extracts actor identity from request.
// returns (actor name, actor type) - delegates to auth service.
func (a *auditor) extractActor(r *http.Request) (string, enum.ActorType) {
	if a.auth == nil {
		return "anonymous", enum.ActorTypePublic
	}

	actorType, actorName := a.auth.GetRequestActor(r)
	switch actorType {
	case enum.ActorTypeUser.String():
		return actorName, enum.ActorTypeUser
	case enum.ActorTypeToken.String():
		return actorName, enum.ActorTypeToken
	default:
		return "anonymous", enum.ActorTypePublic
	}
}

// mapAction maps HTTP method and response status to audit action.
// for PUT requests, distinguishes between create (201) and update (200).
func (a *auditor) mapAction(method string, status int) enum.AuditAction {
	switch method {
	case http.MethodGet:
		return enum.AuditActionRead
	case http.MethodPut:
		if status == http.StatusCreated {
			return enum.AuditActionCreate
		}
		return enum.AuditActionUpdate
	case http.MethodDelete:
		return enum.AuditActionDelete
	default:
		return enum.AuditActionRead // fallback
	}
}

// mapStatus maps HTTP status code to audit result.
func (a *auditor) mapStatus(status int) enum.AuditResult {
	switch {
	case status >= 200 && status < 300:
		return enum.AuditResultSuccess
	case status == http.StatusForbidden:
		return enum.AuditResultDenied
	case status == http.StatusNotFound:
		return enum.AuditResultNotFound
	case status == http.StatusUnauthorized:
		return enum.AuditResultDenied
	default:
		return enum.AuditResultNotFound
	}
}

// AuditMiddleware creates middleware that logs audit entries after handler completes.
// This is a convenience function that creates an auditor and returns its middleware.
func AuditMiddleware(auditStore AuditStore, authProvider AuditAuth) func(http.Handler) http.Handler {
	aud := newAuditor(auditStore, authProvider)
	return aud.Middleware
}

// NoopAuditMiddleware returns a pass-through middleware (used when audit is disabled).
func NoopAuditMiddleware(next http.Handler) http.Handler {
	return next
}

// AuditHandler handles audit query requests.
type AuditHandler struct {
	store    AuditStore
	auth     AuditAuth
	maxLimit int
}

// NewAuditHandler creates a new audit handler.
func NewAuditHandler(auditStore AuditStore, authSvc AuditAuth, maxLimit int) *AuditHandler {
	if maxLimit <= 0 {
		maxLimit = 10000
	}
	return &AuditHandler{store: auditStore, auth: authSvc, maxLimit: maxLimit}
}

// AuditQueryRequest represents the JSON request for audit query.
type AuditQueryRequest struct {
	Key       string `json:"key,omitempty"`        // prefix match with * suffix
	Actor     string `json:"actor,omitempty"`      // exact match
	ActorType string `json:"actor_type,omitempty"` // user, token, public
	Action    string `json:"action,omitempty"`     // read, create, update, delete
	Result    string `json:"result,omitempty"`     // success, denied, not_found
	From      string `json:"from,omitempty"`       // RFC3339 timestamp
	To        string `json:"to,omitempty"`         // RFC3339 timestamp
	Limit     int    `json:"limit,omitempty"`      // max entries to return
}

// AuditQueryResponse represents the JSON response for audit query.
type AuditQueryResponse struct {
	Entries []store.AuditEntry `json:"entries"`
	Total   int                `json:"total"`
	Limit   int                `json:"limit"`
}

// HandleQuery handles POST /audit/query requests.
// Requires admin privileges via session cookie or API token with admin flag.
func (h *AuditHandler) HandleQuery(w http.ResponseWriter, r *http.Request) {
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
func (h *AuditHandler) handleQueryInternal(w http.ResponseWriter, r *http.Request) {
	// parse request body
	var req AuditQueryRequest
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

	rest.RenderJSON(w, AuditQueryResponse{
		Entries: entries,
		Total:   total,
		Limit:   query.Limit,
	})
}

// buildQuery converts request to store.AuditQuery.
func (h *AuditHandler) buildQuery(req AuditQueryRequest) (store.AuditQuery, error) {
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
