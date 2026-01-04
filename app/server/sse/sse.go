// Package sse provides Server-Sent Events support for real-time key change notifications.
package sse

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	log "github.com/go-pkgz/lgr"
	"github.com/tmaxmax/go-sse"

	"github.com/umputun/stash/app/enum"
)

//go:generate moq -out mocks/auth.go -pkg mocks -skip-ensure -fmt goimports . AuthProvider

// AuthProvider defines the interface for auth operations needed by SSE.
type AuthProvider interface {
	Enabled() bool
	FilterKeysForRequest(r *http.Request, keys []string) []string
}

// Event represents a key change event sent to subscribers.
type Event struct {
	Key       string           `json:"key"`
	Action    enum.AuditAction `json:"action"`
	Timestamp string           `json:"timestamp"`
}

// Service handles SSE subscriptions for key change events.
type Service struct {
	server *sse.Server
	auth   AuthProvider
}

// New creates a new SSE service.
func New(auth AuthProvider) *Service {
	s := &Service{auth: auth}
	s.server = &sse.Server{
		OnSession: s.onSession,
	}
	return s
}

// ServeHTTP implements http.Handler for SSE subscriptions.
// Extends write deadline to allow long-lived streaming connections.
func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// extend write deadline for SSE - this connection will be long-lived
	// http.ResponseController (Go 1.20+) allows extending the deadline
	rc := http.NewResponseController(w)
	if err := rc.SetWriteDeadline(time.Time{}); err != nil {
		// if we can't disable timeout, set a very long one (24 hours)
		if err2 := rc.SetWriteDeadline(time.Now().Add(24 * time.Hour)); err2 != nil {
			log.Printf("[DEBUG] sse: could not set write deadline: %v, %v", err, err2)
		}
	}

	s.server.ServeHTTP(w, r)
}

// onSession handles new SSE connections - validates params and auth, returns topics.
func (s *Service) onSession(w http.ResponseWriter, r *http.Request) ([]string, bool) {
	rawPath := r.PathValue("key")
	path := normalizeKey(rawPath)
	if path == "" && rawPath != "*" {
		http.Error(w, "key path required", http.StatusBadRequest)
		return nil, false
	}

	// check if this is a prefix subscription:
	// - ends with /* (e.g., /subscribe/app/*)
	// - ends with / (e.g., /subscribe/app/)
	// - just * (e.g., /subscribe/*)
	var topic string
	var checkKey string
	isPrefix := rawPath == "*" || strings.HasSuffix(rawPath, "/*") || strings.HasSuffix(rawPath, "/")
	if isPrefix {
		// prefix subscription: /subscribe/* or /subscribe/ → "" (root), /subscribe/app/* or /subscribe/app/ → "app/"
		prefix := strings.TrimSuffix(path, "*")
		prefix = strings.TrimSuffix(prefix, "/") // remove trailing slash from /* pattern
		if prefix != "" {
			prefix += "/"
		}
		checkKey = prefix + "test" // dummy key to check permission
		topic = prefix
	} else {
		// exact key subscription
		checkKey = path
		topic = path
	}

	// check auth permission
	if s.auth != nil && s.auth.Enabled() {
		allowed := s.auth.FilterKeysForRequest(r, []string{checkKey})
		if len(allowed) == 0 {
			http.Error(w, "access denied", http.StatusForbidden)
			return nil, false
		}
	}

	log.Printf("[DEBUG] sse subscription: topic=%q", topic)
	return []string{topic}, true
}

// Publish sends a key change event to all matching subscribers.
// It publishes to the exact key topic and all prefix topics.
func (s *Service) Publish(key string, action enum.AuditAction) {
	event := Event{
		Key:       key,
		Action:    action,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}

	data, err := json.Marshal(event)
	if err != nil {
		log.Printf("[WARN] sse: failed to marshal event: %v", err)
		return
	}

	msg := &sse.Message{}
	msg.AppendData(string(data))
	msg.Type = sse.Type("change")

	// publish to exact key topic and all prefix topics
	topics := keyToTopics(key)
	for _, topic := range topics {
		if err := s.server.Publish(msg, topic); err != nil {
			log.Printf("[WARN] sse: failed to publish to topic %q: %v", topic, err)
		}
	}
	log.Printf("[DEBUG] sse: published %s event for %q to %d topics", action.String(), key, len(topics))
}

// Shutdown gracefully shuts down the SSE server.
func (s *Service) Shutdown(ctx context.Context) error {
	if err := s.server.Shutdown(ctx); err != nil {
		return fmt.Errorf("shutdown sse server: %w", err)
	}
	return nil
}

// keyToTopics returns all topics a key event should be published to.
// For key "app/config/db", returns: ["app/config/db", "app/config/", "app/", ""]
// The empty string topic is for wildcard subscribers.
func keyToTopics(key string) []string {
	key = normalizeKey(key)
	topics := []string{key} // exact key topic

	// add prefix topics (skip if key is empty to avoid duplicate)
	if key == "" {
		return topics
	}

	parts := strings.Split(key, "/")
	for i := len(parts) - 1; i >= 0; i-- {
		prefix := strings.Join(parts[:i], "/")
		if prefix != "" {
			prefix += "/"
		}
		topics = append(topics, prefix)
	}

	return topics
}

// normalizeKey removes leading/trailing slashes from key.
func normalizeKey(key string) string {
	return strings.Trim(key, "/")
}
