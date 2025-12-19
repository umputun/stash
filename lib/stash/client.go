package stash

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-pkgz/requester"
	"github.com/go-pkgz/requester/middleware"
)

// defaults for client configuration
const (
	defaultTimeout    = 30 * time.Second
	defaultRetryCount = 3
	defaultRetryDelay = 100 * time.Millisecond
)

// Client is a Stash KV service client.
type Client struct {
	baseURL   string
	requester *requester.Requester
}

// clientConfig holds configuration options during client construction.
type clientConfig struct {
	token      string
	timeout    time.Duration
	retryCount int
	retryDelay time.Duration
	httpClient *http.Client
}

// Option is a functional option for configuring the client.
type Option func(*clientConfig)

// WithToken sets the Bearer token for authentication.
func WithToken(token string) Option {
	return func(cfg *clientConfig) {
		cfg.token = token
	}
}

// WithTimeout sets the HTTP request timeout.
func WithTimeout(timeout time.Duration) Option {
	return func(cfg *clientConfig) {
		cfg.timeout = timeout
	}
}

// WithRetry configures retry behavior.
func WithRetry(count int, delay time.Duration) Option {
	return func(cfg *clientConfig) {
		cfg.retryCount = count
		cfg.retryDelay = delay
	}
}

// WithHTTPClient sets a custom http.Client.
// Note: when using WithHTTPClient, the WithTimeout option has no effect
// since timeout is configured on the http.Client directly.
func WithHTTPClient(client *http.Client) Option {
	return func(cfg *clientConfig) {
		cfg.httpClient = client
	}
}

// KeyInfo contains metadata about a stored key.
type KeyInfo struct {
	Key       string    `json:"key"`
	Size      int       `json:"size"`
	Format    string    `json:"format"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// New creates a new Stash client with the given base URL and options.
func New(baseURL string, opts ...Option) (*Client, error) {
	if baseURL == "" {
		return nil, errors.New("base URL is required")
	}

	// normalize base URL
	baseURL = strings.TrimSuffix(baseURL, "/")

	cfg := &clientConfig{
		timeout:    defaultTimeout,
		retryCount: defaultRetryCount,
		retryDelay: defaultRetryDelay,
	}

	// apply options
	for _, opt := range opts {
		opt(cfg)
	}

	// build requester with middleware
	var middlewares []middleware.RoundTripperHandler
	if cfg.retryCount > 0 {
		middlewares = append(middlewares, middleware.Retry(cfg.retryCount, cfg.retryDelay))
	}
	if cfg.token != "" {
		middlewares = append(middlewares, middleware.Header("Authorization", "Bearer "+cfg.token))
	}

	httpClient := cfg.httpClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: cfg.timeout}
	}

	return &Client{
		baseURL:   baseURL,
		requester: requester.New(*httpClient, middlewares...),
	}, nil
}

// Get retrieves a value by key as a string.
func (c *Client) Get(ctx context.Context, key string) (string, error) {
	data, err := c.GetBytes(ctx, key)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// GetOrDefault retrieves a value by key, returning defaultValue if the key doesn't exist.
func (c *Client) GetOrDefault(ctx context.Context, key, defaultValue string) (string, error) {
	val, err := c.Get(ctx, key)
	if errors.Is(err, ErrNotFound) {
		return defaultValue, nil
	}
	return val, err
}

// GetBytes retrieves a value by key as raw bytes.
func (c *Client) GetBytes(ctx context.Context, key string) ([]byte, error) {
	if key == "" {
		return nil, errors.New("key is required")
	}

	u, err := url.JoinPath(c.baseURL, "kv", key)
	if err != nil {
		return nil, fmt.Errorf("failed to build URL: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.requester.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if errResp := c.checkResponse(resp); errResp != nil {
		return nil, errResp
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	return body, nil
}

// Info retrieves metadata for a key.
// Note: this method uses List with prefix filtering, which may be inefficient
// for large keyspaces with many keys sharing the same prefix.
func (c *Client) Info(ctx context.Context, key string) (KeyInfo, error) {
	if key == "" {
		return KeyInfo{}, errors.New("key is required")
	}

	// use list with exact key as prefix and find exact match
	keys, err := c.List(ctx, key)
	if err != nil {
		return KeyInfo{}, err
	}

	for _, k := range keys {
		if k.Key == key {
			return k, nil
		}
	}

	return KeyInfo{}, ErrNotFound
}

// Set stores a value with default text format.
func (c *Client) Set(ctx context.Context, key, value string) error {
	return c.SetWithFormat(ctx, key, value, FormatText)
}

// SetWithFormat stores a value with explicit format.
func (c *Client) SetWithFormat(ctx context.Context, key, value string, format Format) error {
	if key == "" {
		return errors.New("key is required")
	}

	u, err := url.JoinPath(c.baseURL, "kv", key)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, u, strings.NewReader(value))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("X-Stash-Format", format.String())

	resp, err := c.requester.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	return c.checkResponse(resp)
}

// Delete removes a key.
func (c *Client) Delete(ctx context.Context, key string) error {
	if key == "" {
		return errors.New("key is required")
	}

	u, err := url.JoinPath(c.baseURL, "kv", key)
	if err != nil {
		return fmt.Errorf("failed to build URL: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, u, http.NoBody)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.requester.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	return c.checkResponse(resp)
}

// List returns all keys, optionally filtered by prefix.
// Pass empty string to list all keys.
func (c *Client) List(ctx context.Context, prefix string) ([]KeyInfo, error) {
	u := c.baseURL + "/kv/"
	if prefix != "" {
		u += "?prefix=" + url.QueryEscape(prefix)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.requester.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if err := c.checkResponse(resp); err != nil {
		return nil, err
	}

	var keys []KeyInfo
	if err := json.NewDecoder(resp.Body).Decode(&keys); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return keys, nil
}

// Ping checks server connectivity.
func (c *Client) Ping(ctx context.Context) error {
	u := c.baseURL + "/ping"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, http.NoBody)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.requester.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	return c.checkResponse(resp)
}

// checkResponse handles HTTP response status codes and returns appropriate errors.
func (c *Client) checkResponse(resp *http.Response) error {
	switch resp.StatusCode {
	case http.StatusOK, http.StatusNoContent:
		return nil
	case http.StatusNotFound:
		return ErrNotFound
	case http.StatusUnauthorized:
		return ErrUnauthorized
	case http.StatusForbidden:
		return ErrForbidden
	default:
		return &ResponseError{StatusCode: resp.StatusCode}
	}
}
