// Package sse provides Server-Sent Events support for real-time key change notifications.
package sse

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	log "github.com/go-pkgz/lgr"
	"github.com/google/uuid"
	"github.com/tmaxmax/go-sse"

	"github.com/umputun/stash/app/enum"
	"github.com/umputun/stash/app/store"
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
// Every connection gets its own topic and each published key is checked against that
// connection's credentials, so a prefix subscriber never learns about keys it cannot read.
type Service struct {
	provider *sse.Joe
	auth     AuthProvider
	mu       sync.RWMutex
	subs     map[string]subscriber // topic -> subscriber

	shutdownOnce sync.Once
	shuttingDown chan struct{} // closed when Shutdown starts
	shutdownDone chan struct{} // closed only once the dispatcher has stopped
}

// subscriber is one open connection: an exact key or a prefix (trailing slash, empty for all keys).
type subscriber struct {
	req      *http.Request
	key      string
	isPrefix bool
}

// matches reports whether an event for key belongs to this subscription.
func (sub subscriber) matches(key string) bool {
	if sub.isPrefix {
		return strings.HasPrefix(key, sub.key)
	}
	return key == sub.key
}

// New creates a new SSE service.
func New(auth AuthProvider) *Service {
	return &Service{
		provider:     &sse.Joe{},
		auth:         auth,
		subs:         make(map[string]subscriber),
		shuttingDown: make(chan struct{}),
		shutdownDone: make(chan struct{}),
	}
}

// ServeHTTP implements http.Handler for SSE subscriptions.
// Extends write deadline to allow long-lived streaming connections.
// The session is driven here rather than through sse.Server: go-sse writes events from its
// dispatcher goroutine and lets a session return on the shutdown signal before that goroutine
// has stopped, so this handler must not write to or release the connection until it has.
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

	session, err := sse.Upgrade(w, r)
	if err != nil {
		http.Error(w, "Server-sent events unsupported", http.StatusInternalServerError)
		return
	}

	topic, ok := s.onSession(w, r)
	if !ok {
		return
	}

	sub := sse.Subscription{Client: session, LastEventID: session.LastEventID, Topics: []string{topic}}
	if err := s.provider.Subscribe(r.Context(), sub); err != nil {
		log.Printf("[DEBUG] sse: session ended: %v", err)
	}

	select {
	case <-s.shuttingDown:
		<-s.shutdownDone
	default:
	}
}

// onSession validates params and auth and registers the subscriber, returning its topic.
// An exact-key subscription the caller cannot read is refused; a prefix subscription is
// accepted and filtered per event, since a prefix may cover keys with different permissions.
func (s *Service) onSession(w http.ResponseWriter, r *http.Request) (topic string, ok bool) {
	rawPath := r.PathValue("key")
	path := store.NormalizeKey(rawPath)
	if path == "" && rawPath != "*" {
		http.Error(w, "key path required", http.StatusBadRequest)
		return "", false
	}

	// prefix subscription forms: /subscribe/*, /subscribe/app/* and /subscribe/app/
	sub := subscriber{req: r, key: path}
	if rawPath == "*" || strings.HasSuffix(rawPath, "/*") || strings.HasSuffix(rawPath, "/") {
		prefix := strings.TrimSuffix(strings.TrimSuffix(path, "*"), "/")
		if prefix != "" {
			prefix += "/"
		}
		sub = subscriber{req: r, key: prefix, isPrefix: true}
	}

	if !sub.isPrefix && !s.allowed(r, sub.key) {
		http.Error(w, "access denied", http.StatusForbidden)
		return "", false
	}

	topic = uuid.NewString()
	s.mu.Lock()
	s.subs[topic] = sub
	s.mu.Unlock()
	context.AfterFunc(r.Context(), func() {
		s.mu.Lock()
		delete(s.subs, topic)
		s.mu.Unlock()
	})

	log.Printf("[DEBUG] sse subscription: key=%q prefix=%v", sub.key, sub.isPrefix)
	return topic, true
}

// allowed reports whether the request's credentials grant read access to key.
func (s *Service) allowed(r *http.Request, key string) bool {
	if s.auth == nil || !s.auth.Enabled() {
		return true
	}
	return len(s.auth.FilterKeysForRequest(r, []string{key})) > 0
}

// Publish sends a key change event to every subscriber whose subscription covers the key
// and whose credentials allow reading it.
func (s *Service) Publish(key string, action enum.AuditAction) {
	key = store.NormalizeKey(key)
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

	// permission checks may hit the session store, so they run outside the lock
	type candidate struct {
		topic string
		req   *http.Request
	}
	var candidates []candidate
	s.mu.RLock()
	for topic, sub := range s.subs {
		if sub.matches(key) {
			candidates = append(candidates, candidate{topic: topic, req: sub.req})
		}
	}
	s.mu.RUnlock()

	var topics []string
	for _, c := range candidates {
		if s.allowed(c.req, key) {
			topics = append(topics, c.topic)
		}
	}
	if len(topics) == 0 {
		log.Printf("[DEBUG] sse: no subscribers for %s event on %q", action.String(), key)
		return
	}

	if err := s.provider.Publish(msg, topics); err != nil {
		log.Printf("[WARN] sse: failed to publish event for %q: %v", key, err)
		return
	}
	log.Printf("[DEBUG] sse: published %s event for %q to %d subscribers", action.String(), key, len(topics))
}

// Shutdown stops the dispatcher and returns once it has stopped or ctx expires.
// The stop itself keeps running past a ctx timeout, so a later call can wait for it again;
// handlers stay parked until it completes and are never released on the timeout alone.
func (s *Service) Shutdown(ctx context.Context) error {
	s.shutdownOnce.Do(func() {
		close(s.shuttingDown)
		go func() {
			if err := s.provider.Shutdown(context.Background()); err != nil {
				log.Printf("[WARN] sse: dispatcher shutdown: %v", err)
			}
			close(s.shutdownDone)
		}()
	})
	select {
	case <-s.shutdownDone:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("shutdown sse server: %w", ctx.Err())
	}
}
