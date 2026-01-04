package audit

import (
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/go-pkgz/rest/realip"
	"github.com/umputun/stash/app/enum"
	"github.com/umputun/stash/app/store"
)

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

		// skip SSE subscription endpoints (long-lived streaming connections)
		if strings.HasPrefix(path, "/kv/subscribe/") {
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
