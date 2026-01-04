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

	"github.com/umputun/stash/app/enum"
	"github.com/umputun/stash/app/git"
	"github.com/umputun/stash/app/server/api"
	"github.com/umputun/stash/app/server/audit"
	"github.com/umputun/stash/app/server/auth"
	"github.com/umputun/stash/app/server/sse"
	"github.com/umputun/stash/app/server/web"
	"github.com/umputun/stash/app/store"
)

//go:generate moq -out mocks/kvstore.go -pkg mocks -skip-ensure -fmt goimports . KVStore
//go:generate moq -out mocks/validator.go -pkg mocks -skip-ensure -fmt goimports . Validator

// Server represents the HTTP server.
type Server struct {
	Deps
	Config
	apiHandler      *api.Handler
	webHandler      *web.Handler
	auditHandler    *audit.Handler
	webAuditHandler *web.AuditHandler
	staticFS        fs.FS // embedded static files
}

// KVStore defines the interface for key-value storage operations.
type KVStore interface {
	Get(ctx context.Context, key string) ([]byte, error)
	GetWithFormat(ctx context.Context, key string) ([]byte, string, error)
	GetInfo(ctx context.Context, key string) (store.KeyInfo, error)
	Set(ctx context.Context, key string, value []byte, format string) (created bool, err error)
	SetWithVersion(ctx context.Context, key string, value []byte, format string, expectedVersion time.Time) error
	Delete(ctx context.Context, key string) error
	List(ctx context.Context, filter enum.SecretsFilter) ([]store.KeyInfo, error)
	SecretsEnabled() bool
}

// GitService defines the interface for git operations.
type GitService interface {
	Commit(req git.CommitRequest) error
	Delete(key string, author git.Author) error
	History(key string, limit int) ([]git.HistoryEntry, error)
	GetRevision(key string, rev string) ([]byte, string, error)
}

// Validator defines the interface for format validation.
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
	BaseURL         string // base URL path for reverse proxy (e.g., /stash)
	PageSize        int    // keys per page in web UI (0 = unlimited)

	BodySizeLimit    int64   // max request body size in bytes
	RequestsPerSec   float64 // max requests per second (rate limit)
	MaxConcurrent    int64   // max concurrent in-flight requests
	LoginConcurrency int64   // max concurrent login attempts

	AuditEnabled    bool // enable audit logging
	AuditQueryLimit int  // max entries per audit query (default 10000)
}

// Deps holds server dependencies.
type Deps struct {
	Store      KVStore
	Validator  Validator
	Git        GitService    // optional, nil to disable git versioning
	Auth       *auth.Service // optional, nil to disable authentication
	AuditStore *store.Store  // optional, nil to disable audit logging
	SSE        *sse.Service  // optional, nil to disable key change subscriptions
}

// New creates a new Server instance.
func New(deps Deps, cfg Config) (*Server, error) {
	staticContent, err := web.StaticFS()
	if err != nil {
		return nil, fmt.Errorf("failed to load static files: %w", err)
	}

	s := &Server{
		Deps:     deps,
		Config:   cfg,
		staticFS: staticContent,
	}

	// create web handler with optional audit logger and events
	webDeps := web.Deps{Store: deps.Store, Auth: deps.Auth, Validator: deps.Validator, Git: deps.Git}
	if cfg.AuditEnabled && deps.AuditStore != nil {
		webDeps.Audit = deps.AuditStore
	}
	if deps.SSE != nil {
		webDeps.Events = deps.SSE
	}
	webHandler, err := web.New(webDeps, web.Config{
		BaseURL:      cfg.BaseURL,
		PageSize:     cfg.PageSize,
		AuditEnabled: cfg.AuditEnabled && deps.AuditStore != nil,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create web handler: %w", err)
	}
	s.webHandler = webHandler

	// create api handler
	// note: only set Events if SSE is not nil to avoid nil interface issue
	apiDeps := api.Deps{Store: deps.Store, Auth: deps.Auth, Validator: deps.Validator, Git: deps.Git}
	if deps.SSE != nil {
		apiDeps.Events = deps.SSE
	}
	s.apiHandler = api.New(apiDeps)

	// create audit handlers if audit is enabled
	if cfg.AuditEnabled && deps.AuditStore != nil {
		s.auditHandler = audit.NewHandler(deps.AuditStore, deps.Auth, cfg.AuditQueryLimit)
		s.webAuditHandler = web.NewAuditHandler(deps.AuditStore, deps.Auth, webHandler)
	}

	return s, nil
}

// Run starts the HTTP server and blocks until context is canceled.
func (s *Server) Run(ctx context.Context) error {
	httpServer := &http.Server{
		Addr:              s.Address,
		Handler:           s.handler(),
		ReadHeaderTimeout: s.ReadTimeout,
		WriteTimeout:      s.WriteTimeout,
		IdleTimeout:       s.IdleTimeout,
	}

	// graceful shutdown
	go func() {
		<-ctx.Done()
		log.Printf("[INFO] shutting down server")

		// shutdown SSE first to close active connections (half the timeout budget)
		if s.SSE != nil {
			sseCtx, sseCancel := context.WithTimeout(context.Background(), s.ShutdownTimeout/2)
			if err := s.SSE.Shutdown(sseCtx); err != nil {
				log.Printf("[WARN] SSE shutdown error: %v", err)
			}
			sseCancel()
		}

		// shutdown HTTP server with remaining timeout budget
		httpCtx, httpCancel := context.WithTimeout(context.Background(), s.ShutdownTimeout/2)
		defer httpCancel()
		if err := httpServer.Shutdown(httpCtx); err != nil {
			log.Printf("[WARN] shutdown error: %v", err)
		}
	}()

	log.Printf("[DEBUG] started server on %s", s.Address)
	if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("server error: %w", err)
	}
	return nil
}

// handler returns the HTTP handler, wrapping routes with base URL support if configured.
func (s *Server) handler() http.Handler {
	routes := s.routes()
	if s.BaseURL == "" {
		return routes
	}
	mux := http.NewServeMux()
	// redirect /base to /base/
	mux.HandleFunc(s.BaseURL, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, s.BaseURL+"/", http.StatusMovedPermanently)
	})
	// strip prefix for all routes under base URL
	mux.Handle(s.BaseURL+"/", http.StripPrefix(s.BaseURL, routes))
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
		rest.AppInfo("stash", "umputun", s.Version),
		rest.Ping,
	)

	// determine auth middleware for protected routes
	sessionAuth, tokenAuth := noopMiddleware, noopMiddleware
	if s.Auth != nil && s.Auth.Enabled() {
		sessionAuth = s.Auth.SessionMiddleware(s.url("/login"))
		tokenAuth = s.Auth.TokenMiddleware
	}

	// public routes (no auth required)
	router.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.FS(s.staticFS))))
	if s.Auth != nil && s.Auth.Enabled() {
		s.webHandler.RegisterAuth(router)
		// stricter throttle on login to prevent brute-force
		s.webHandler.RegisterLogin(router, rest.Throttle(s.loginConcurrency()))
	}

	// web UI routes (session auth)
	router.Group().Route(func(webRouter *routegroup.Bundle) {
		webRouter.Use(sessionAuth)
		s.webHandler.Register(webRouter)

		// audit web UI routes (admin only, handled inside handler)
		if s.webAuditHandler != nil {
			webRouter.HandleFunc("GET /audit", s.webAuditHandler.HandleAuditPage)
			webRouter.HandleFunc("GET /web/audit", s.webAuditHandler.HandleAuditTable)
		}
	})

	// kv API routes (audit wraps auth to capture denied requests)
	router.Mount("/kv").Route(func(kv *routegroup.Bundle) {
		kv.Use(s.auditMiddleware())
		kv.Use(tokenAuth)
		s.apiHandler.Register(kv)

		// SSE subscription endpoint (if enabled)
		// GET /subscribe/{key...} for exact key, GET /subscribe/{prefix...}/* for prefix
		if s.SSE != nil {
			kv.Handle("GET /subscribe/{key...}", s.SSE)
		}
	})

	// audit query route (admin only, requires auth)
	if s.auditHandler != nil {
		router.HandleFunc("POST /audit/query", s.auditHandler.HandleQuery)
	}

	return router
}

// bodySizeLimit returns the configured body size limit, or default 1MB if not set.
func (s *Server) bodySizeLimit() int64 {
	if s.BodySizeLimit > 0 {
		return s.BodySizeLimit
	}
	return 1024 * 1024
}

// requestsPerSec returns the configured rate limit (requests per second), or default 100 if not set.
func (s *Server) requestsPerSec() float64 {
	if s.RequestsPerSec > 0 {
		return s.RequestsPerSec
	}
	return 100
}

// maxConcurrent returns the configured max concurrent in-flight requests, or default 1000 if not set.
func (s *Server) maxConcurrent() int64 {
	if s.MaxConcurrent > 0 {
		return s.MaxConcurrent
	}
	return 1000
}

// loginConcurrency returns the configured login concurrency limit, or default 5 if not set.
func (s *Server) loginConcurrency() int64 {
	if s.LoginConcurrency > 0 {
		return s.LoginConcurrency
	}
	return 5
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
	return s.BaseURL + path
}

// noopMiddleware is a pass-through middleware (used when auth is disabled).
func noopMiddleware(next http.Handler) http.Handler {
	return next
}

// auditMiddleware returns the audit middleware or noop if audit is disabled.
func (s *Server) auditMiddleware() func(http.Handler) http.Handler {
	if !s.AuditEnabled || s.AuditStore == nil {
		return audit.NoopMiddleware
	}
	return audit.Middleware(s.AuditStore, s.Auth)
}
