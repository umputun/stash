// Package audit provides HTTP middleware for audit logging and query handler for audit log access.
package audit

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	log "github.com/go-pkgz/lgr"
	"github.com/go-pkgz/rest/realip"

	"github.com/umputun/stash/app/enum"
	"github.com/umputun/stash/app/store"
)

//go:generate moq -out mocks/store.go -pkg mocks -skip-ensure -fmt goimports . Store
//go:generate moq -out mocks/auth.go -pkg mocks -skip-ensure -fmt goimports . Auth

// Store defines the interface for audit log storage.
type Store interface {
	LogAudit(ctx context.Context, entry store.AuditEntry) error
	QueryAudit(ctx context.Context, q store.AuditQuery) ([]store.AuditEntry, int, error)
}

// Auth defines the interface for auth operations needed by audit.
type Auth interface {
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
		return n, fmt.Errorf("write: %w", err)
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
			return nil, nil, fmt.Errorf("hijack: %w", err)
		}
		return conn, rw, nil
	}
	return nil, nil, errors.New("ResponseWriter does not implement http.Hijacker")
}

// logger handles building and logging audit entries.
type logger struct {
	store Store
	auth  Auth
}

// newLogger creates a new audit logger.
func newLogger(auditStore Store, authSvc Auth) *logger {
	return &logger{store: auditStore, auth: authSvc}
}

// middleware returns HTTP middleware that logs audit entries after handler completes.
// Applies only to /kv/* routes. Logs read, create, update, delete actions based on method.
func (a *logger) middleware(next http.Handler) http.Handler {
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
func (a *logger) buildEntry(r *http.Request, rc *responseCapture, key string) store.AuditEntry {
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
func (a *logger) extractActor(r *http.Request) (string, enum.ActorType) {
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
func (a *logger) mapAction(method string, status int) enum.AuditAction {
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
func (a *logger) mapStatus(status int) enum.AuditResult {
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

// Middleware creates middleware that logs audit entries after handler completes.
// This is a convenience function that creates a logger and returns its middleware.
func Middleware(auditStore Store, authProvider Auth) func(http.Handler) http.Handler {
	l := newLogger(auditStore, authProvider)
	return l.middleware
}

// NoopMiddleware returns a pass-through middleware (used when audit is disabled).
func NoopMiddleware(next http.Handler) http.Handler {
	return next
}
