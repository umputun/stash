// Package server provides HTTP server for the key-value store API.
package server

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"time"

	"github.com/didip/tollbooth/v8"
	"github.com/didip/tollbooth/v8/limiter"
	log "github.com/go-pkgz/lgr"
	"github.com/go-pkgz/rest"
	"github.com/go-pkgz/routegroup"

	"github.com/umputun/stash/app/git"
	"github.com/umputun/stash/app/server/api"
	"github.com/umputun/stash/app/server/web"
	"github.com/umputun/stash/app/store"
)

//go:generate moq -out mocks/kvstore.go -pkg mocks -skip-ensure -fmt goimports . KVStore
//go:generate moq -out mocks/validator.go -pkg mocks -skip-ensure -fmt goimports . Validator

// Server represents the HTTP server.
type Server struct {
	store      KVStore
	validator  Validator // format validator
	cfg        Config
	version    string
	baseURL    string
	auth       *Auth
	apiHandler *api.Handler
	webHandler *web.Handler
	staticFS   fs.FS // embedded static files
}

// KVStore defines the interface for key-value storage operations.
// Defined here (consumer side) to allow different store implementations.
type KVStore interface {
	Get(ctx context.Context, key string) ([]byte, error)
	GetWithFormat(ctx context.Context, key string) ([]byte, string, error)
	GetInfo(ctx context.Context, key string) (store.KeyInfo, error)
	Set(ctx context.Context, key string, value []byte, format string) error
	SetWithVersion(ctx context.Context, key string, value []byte, format string, expectedVersion time.Time) error
	Delete(ctx context.Context, key string) error
	List(ctx context.Context) ([]store.KeyInfo, error)
}

// GitService defines the interface for git operations.
// Defined here (consumer side) to allow different implementations.
type GitService interface {
	Commit(req git.CommitRequest) error
	Delete(key string, author git.Author) error
	History(key string, limit int) ([]git.HistoryEntry, error)
	GetRevision(key string, rev string) ([]byte, string, error)
}

// Validator defines the interface for format validation.
// Defined here (consumer side) to allow different validator implementations.
type Validator interface {
	Validate(format string, value []byte) error
	IsValidFormat(format string) bool
	SupportedFormats() []string
}

// Config holds server configuration.
type Config struct {
	Address         string
	ReadTimeout     time.Duration
	WriteTimeout    time.Duration
	IdleTimeout     time.Duration
	ShutdownTimeout time.Duration
	Version         string
	AuthFile        string        // path to auth config file (empty = auth disabled)
	AuthHotReload   bool          // watch auth config for changes and reload
	LoginTTL        time.Duration // session duration
	BaseURL         string        // base URL path for reverse proxy (e.g., /stash)
	PageSize        int           // keys per page in web UI (0 = unlimited)

	// limits
	BodySizeLimit    int64   // max request body size in bytes
	RequestsPerSec   float64 // max requests per second (rate limit)
	MaxConcurrent    int64   // max concurrent in-flight requests
	LoginConcurrency int64   // max concurrent login attempts
}

// New creates a new Server instance.
// gs is optional git service, pass nil to disable git versioning.
// ss is the session store for persistent sessions.
func New(st KVStore, val Validator, gs GitService, ss SessionStore, cfg Config) (*Server, error) {
	auth, err := NewAuth(cfg.AuthFile, cfg.LoginTTL, ss)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize auth: %w", err)
	}

	staticContent, err := web.StaticFS()
	if err != nil {
		return nil, fmt.Errorf("failed to load static files: %w", err)
	}

	s := &Server{
		store:     st,
		validator: val,
		cfg:       cfg,
		version:   cfg.Version,
		baseURL:   cfg.BaseURL,
		auth:      auth,
		staticFS:  staticContent,
	}

	// create web handler
	webHandler, err := web.New(st, auth, val, gs, web.Config{
		BaseURL:  cfg.BaseURL,
		PageSize: cfg.PageSize,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create web handler: %w", err)
	}
	s.webHandler = webHandler

	// create api handler
	s.apiHandler = api.New(st, auth, val, gs)

	return s, nil
}

// Run starts the HTTP server and blocks until context is canceled.
func (s *Server) Run(ctx context.Context) error {
	httpServer := &http.Server{
		Addr:              s.cfg.Address,
		Handler:           s.handler(),
		ReadHeaderTimeout: s.cfg.ReadTimeout,
		WriteTimeout:      s.cfg.WriteTimeout,
		IdleTimeout:       s.cfg.IdleTimeout,
	}

	// start auth config file watcher if enabled
	if s.auth.Enabled() && s.cfg.AuthHotReload {
		if err := s.auth.StartWatcher(ctx); err != nil {
			return fmt.Errorf("failed to start auth config watcher: %w", err)
		}
		log.Printf("[INFO] auth config hot-reload enabled")
	}

	// start session cleanup goroutine if auth is enabled
	if s.auth.Enabled() {
		s.auth.StartCleanup(ctx)
	}

	// graceful shutdown
	go func() {
		<-ctx.Done()
		log.Printf("[INFO] shutting down server")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), s.cfg.ShutdownTimeout)
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

// AuthReload reloads auth configuration from file. Returns nil if auth is not enabled.
func (s *Server) AuthReload(ctx context.Context) error {
	if s.auth == nil || !s.auth.Enabled() {
		return nil
	}
	return s.auth.Reload(ctx)
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
		rest.RealIP, // must be before rate limiting to limit by real client IP
		s.rateLimiter(),
		rest.Throttle(s.maxConcurrent()),
		rest.Trace,
		rest.SizeLimit(s.bodySizeLimit()),
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
	router.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.FS(s.staticFS))))
	if s.auth.Enabled() {
		s.webHandler.RegisterAuth(router)
		// stricter throttle on login to prevent brute-force
		s.webHandler.RegisterLogin(router, rest.Throttle(s.loginConcurrency()))
	}

	// web UI routes (session auth)
	router.Group().Route(func(webRouter *routegroup.Bundle) {
		webRouter.Use(sessionAuth)
		s.webHandler.Register(webRouter)
	})

	// kv API routes (token auth)
	router.Mount("/kv").Route(func(kv *routegroup.Bundle) {
		kv.Use(tokenAuth)
		s.apiHandler.Register(kv)
	})

	return router
}

// bodySizeLimit returns the configured body size limit, or default 1MB if not set.
func (s *Server) bodySizeLimit() int64 {
	if s.cfg.BodySizeLimit > 0 {
		return s.cfg.BodySizeLimit
	}
	return 1024 * 1024 // 1MB default
}

// requestsPerSec returns the configured rate limit (requests per second), or default 100 if not set.
func (s *Server) requestsPerSec() float64 {
	if s.cfg.RequestsPerSec > 0 {
		return s.cfg.RequestsPerSec
	}
	return 100 // default
}

// maxConcurrent returns the configured max concurrent in-flight requests, or default 1000 if not set.
func (s *Server) maxConcurrent() int64 {
	if s.cfg.MaxConcurrent > 0 {
		return s.cfg.MaxConcurrent
	}
	return 1000 // default
}

// loginConcurrency returns the configured login concurrency limit, or default 5 if not set.
func (s *Server) loginConcurrency() int64 {
	if s.cfg.LoginConcurrency > 0 {
		return s.cfg.LoginConcurrency
	}
	return 5 // default
}

// rateLimiter returns middleware that limits requests per second using tollbooth.
func (s *Server) rateLimiter() func(http.Handler) http.Handler {
	lmt := tollbooth.NewLimiter(s.requestsPerSec(), &limiter.ExpirableOptions{DefaultExpirationTTL: time.Hour})
	lmt.SetIPLookup(limiter.IPLookup{Name: "RemoteAddr", IndexFromRight: 0}) // use RemoteAddr (RealIP middleware sets it)
	lmt.SetBurst(int(s.requestsPerSec()))                                    // burst equals rate limit
	return func(next http.Handler) http.Handler {
		return tollbooth.LimitHandler(lmt, next)
	}
}

// url returns a URL path with the base URL prefix.
func (s *Server) url(path string) string {
	return s.baseURL + path
}
