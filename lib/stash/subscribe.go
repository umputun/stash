package stash

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/tmaxmax/go-sse"
)

// Event represents a key change event from the server.
type Event struct {
	Key       string `json:"key"`
	Action    string `json:"action"` // create, update, delete
	Timestamp string `json:"timestamp"`
}

// Subscription manages an SSE connection for key change events.
type Subscription struct {
	events chan Event
	errors chan error
	cancel context.CancelFunc
}

// Events returns the channel for receiving events.
func (s *Subscription) Events() <-chan Event {
	return s.events
}

// Errors returns the channel for receiving connection errors.
func (s *Subscription) Errors() <-chan error {
	return s.errors
}

// Close terminates the subscription and releases resources.
func (s *Subscription) Close() {
	s.cancel()
}

// Subscribe creates a subscription for exact key changes.
// The subscription remains active until context is canceled or Close is called.
func (c *Client) Subscribe(ctx context.Context, key string) (*Subscription, error) {
	if key == "" {
		return nil, errors.New("key is required")
	}
	return c.subscribe(ctx, key)
}

// SubscribePrefix creates a subscription for all keys matching the prefix.
// The subscription remains active until context is canceled or Close is called.
func (c *Client) SubscribePrefix(ctx context.Context, prefix string) (*Subscription, error) {
	if prefix == "" {
		return nil, errors.New("prefix is required")
	}
	// append /* for wildcard subscription
	path := prefix + "/*"
	return c.subscribe(ctx, path)
}

// SubscribeAll creates a subscription for all key changes.
// The subscription remains active until context is canceled or Close is called.
func (c *Client) SubscribeAll(ctx context.Context) (*Subscription, error) {
	return c.subscribe(ctx, "*")
}

// subscribe creates an SSE subscription for the given path.
func (c *Client) subscribe(ctx context.Context, path string) (*Subscription, error) {
	u, err := url.JoinPath(c.baseURL, "kv", "subscribe", path)
	if err != nil {
		return nil, fmt.Errorf("build URL: %w", err)
	}

	// create cancellable context so Close() can terminate the connection
	ctx, cancel := context.WithCancel(ctx)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, http.NoBody)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("create request: %w", err)
	}

	sub := &Subscription{
		events: make(chan Event, 16), // buffered to prevent blocking on slow consumers
		errors: make(chan error, 1),  // single buffer for connection errors
		cancel: cancel,
	}

	// create SSE client with the same HTTP client (to inherit auth headers via requester)
	sseClient := &sse.Client{
		HTTPClient: c.requester.Client(),
		Backoff: sse.Backoff{
			InitialInterval: time.Second,
			MaxInterval:     30 * time.Second,
			Multiplier:      2,
		},
	}

	conn := sseClient.NewConnection(req)
	conn.SubscribeEvent("change", func(e sse.Event) {
		var ev Event
		if err := json.Unmarshal([]byte(e.Data), &ev); err != nil {
			select {
			case sub.errors <- fmt.Errorf("parse event: %w", err):
			default:
			}
			return
		}
		select {
		case sub.events <- ev:
		case <-ctx.Done():
		}
	})

	// start connection in background
	go func() {
		defer close(sub.events)
		defer close(sub.errors)

		if err := conn.Connect(); err != nil && ctx.Err() == nil {
			// only send error if not canceled (normal Close)
			select {
			case sub.errors <- err:
			default:
			}
		}
	}()

	return sub, nil
}
