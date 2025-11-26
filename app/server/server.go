// Package server provides HTTP server for the key-value store API.
package server

import (
	"context"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"time"

	log "github.com/go-pkgz/lgr"
	"github.com/go-pkgz/rest"
	"github.com/go-pkgz/routegroup"

	"github.com/umputun/stash/app/git"
	"github.com/umputun/stash/app/store"
)

//go:generate moq -out mocks/kvstore.go -pkg mocks -skip-ensure -fmt goimports . KVStore
//go:generate moq -out mocks/gitstore.go -pkg mocks -skip-ensure -fmt goimports . GitStore
//go:generate moq -out mocks/validator.go -pkg mocks -skip-ensure -fmt goimports . Validator

// loginConcurrencyLimit is the maximum number of concurrent login attempts.
// Low limit helps mitigate brute-force attacks (combined with bcrypt's ~50ms delay).
const loginConcurrencyLimit = 5

// Server represents the HTTP server.
type Server struct {
	store       KVStore
	gitStore    GitStore  // optional git store for versioning
	validator   Validator // format validator
	cfg         Config
	version     string
	baseURL     string
	tmpl        *template.Template
	auth        *Auth
	highlighter *Highlighter
}

// KVStore defines the interface for key-value storage operations.
// Defined here (consumer side) to allow different store implementations.
type KVStore interface {
	Get(key string) ([]byte, error)
	GetWithFormat(key string) ([]byte, string, error)
	Set(key string, value []byte, format string) error
	Delete(key string) error
	List() ([]store.KeyInfo, error)
}

// GitStore defines the interface for git-based versioning operations.
// Defined here (consumer side) to allow different git implementations.
type GitStore interface {
	Commit(key string, value []byte, operation string, author git.Author) error
	Delete(key string, author git.Author) error
	Pull() error
	Push() error
}

// Validator defines the interface for format validation.
// Defined here (consumer side) to allow different validator implementations.
type Validator interface {
	Validate(format string, value []byte) error
}

// Config holds server configuration.
type Config struct {
	Address     string
	ReadTimeout time.Duration
	Version     string
	AuthFile    string        // path to auth config file (empty = auth disabled)
	LoginTTL    time.Duration // session duration
	BaseURL     string        // base URL path for reverse proxy (e.g., /stash)
	GitPush     bool          // auto-push git commits
}

// New creates a new Server instance.
func New(st KVStore, val Validator, cfg Config) (*Server, error) {
	tmpl, err := parseTemplates()
	if err != nil {
		return nil, fmt.Errorf("failed to parse templates: %w", err)
	}

	auth, err := NewAuth(cfg.AuthFile, cfg.LoginTTL)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize auth: %w", err)
	}

	return &Server{
		store:       st,
		validator:   val,
		cfg:         cfg,
		version:     cfg.Version,
		baseURL:     cfg.BaseURL,
		tmpl:        tmpl,
		auth:        auth,
		highlighter: NewHighlighter(),
	}, nil
}

// SetGitStore sets the git store for versioning.
func (s *Server) SetGitStore(gs GitStore) {
	s.gitStore = gs
}

// Run starts the HTTP server and blocks until context is canceled.
func (s *Server) Run(ctx context.Context) error {
	httpServer := &http.Server{
		Addr:              s.cfg.Address,
		Handler:           s.handler(),
		ReadHeaderTimeout: s.cfg.ReadTimeout,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       30 * time.Second,
	}

	// graceful shutdown
	go func() {
		<-ctx.Done()
		log.Printf("[INFO] shutting down server")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := httpServer.Shutdown(shutdownCtx); err != nil {
			log.Printf("[WARN] shutdown error: %v", err)
		}
	}()

	log.Printf("[DEBUG] started server on %s", s.cfg.Address)
	if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("server error: %w", err)
	}
	return nil
}

// handler returns the HTTP handler, wrapping routes with base URL support if configured.
func (s *Server) handler() http.Handler {
	routes := s.routes()
	if s.baseURL == "" {
		return routes
	}
	mux := http.NewServeMux()
	// redirect /base to /base/
	mux.HandleFunc(s.baseURL, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, s.baseURL+"/", http.StatusMovedPermanently)
	})
	// strip prefix for all routes under base URL
	mux.Handle(s.baseURL+"/", http.StripPrefix(s.baseURL, routes))
	return mux
}

// routes configures and returns the HTTP handler with all routes and middleware.
func (s *Server) routes() http.Handler {
	router := routegroup.New(http.NewServeMux())

	// global middleware (applies to all routes)
	router.Use(
		rest.Recoverer(log.Default()),
		rest.RealIP, // must be before Throttle to rate-limit by real client IP
		rest.Throttle(1000),
		rest.Trace,
		rest.SizeLimit(1024*1024), // 1MB
		rest.AppInfo("stash", "umputun", s.version),
		rest.Ping,
	)

	// determine auth middleware for protected routes
	sessionAuth, tokenAuth := NoopAuth, NoopAuth
	if s.auth.Enabled() {
		sessionAuth = s.auth.SessionAuth(s.url("/login"))
		tokenAuth = s.auth.TokenAuth
	}

	// public routes (no auth required)
	router.Handle("GET /static/", staticHandler())
	if s.auth.Enabled() {
		router.HandleFunc("GET /login", s.handleLoginForm)
		// stricter throttle on login to prevent brute-force (5 concurrent attempts max)
		router.Handle("POST /login", rest.Throttle(loginConcurrencyLimit)(http.HandlerFunc(s.handleLogin)))
		router.HandleFunc("POST /logout", s.handleLogout)
	}

	// web UI routes (session auth)
	router.Group().Route(func(web *routegroup.Bundle) {
		web.Use(sessionAuth)
		web.HandleFunc("GET /{$}", s.handleIndex)
		web.HandleFunc("GET /web/keys", s.handleKeyList)
		web.HandleFunc("GET /web/keys/new", s.handleKeyNew)
		web.HandleFunc("GET /web/keys/view/{key...}", s.handleKeyView)
		web.HandleFunc("GET /web/keys/edit/{key...}", s.handleKeyEdit)
		web.HandleFunc("POST /web/keys", s.handleKeyCreate)
		web.HandleFunc("PUT /web/keys/{key...}", s.handleKeyUpdate)
		web.HandleFunc("DELETE /web/keys/{key...}", s.handleKeyDelete)
		web.HandleFunc("POST /web/theme", s.handleThemeToggle)
		web.HandleFunc("POST /web/view-mode", s.handleViewModeToggle)
		web.HandleFunc("POST /web/sort", s.handleSortToggle)
	})

	// kv API routes (token auth)
	router.Mount("/kv").Route(func(kv *routegroup.Bundle) {
		kv.Use(tokenAuth)
		kv.HandleFunc("GET /{key...}", s.handleGet)
		kv.HandleFunc("PUT /{key...}", s.handleSet)
		kv.HandleFunc("DELETE /{key...}", s.handleDelete)
	})

	return router
}
