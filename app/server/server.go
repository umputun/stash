// Package server provides HTTP server for the key-value store API.
package server

import (
	"context"
	"fmt"
	"net/http"
	"time"

	log "github.com/go-pkgz/lgr"
	"github.com/go-pkgz/rest"
	"github.com/go-pkgz/routegroup"
)

// KVStore defines the interface for key-value storage operations.
// Defined here (consumer side) to allow different store implementations.
type KVStore interface {
	Get(key string) ([]byte, error)
	Set(key string, value []byte) error
	Delete(key string) error
}

// Config holds server configuration.
type Config struct {
	Address     string
	ReadTimeout time.Duration
	Version     string
}

// Server represents the HTTP server.
type Server struct {
	store   KVStore
	cfg     Config
	version string
}

// New creates a new Server instance.
func New(store KVStore, cfg Config) *Server {
	return &Server{
		store:   store,
		cfg:     cfg,
		version: cfg.Version,
	}
}

// Run starts the HTTP server and blocks until context is canceled.
func (s *Server) Run(ctx context.Context) error {
	httpServer := &http.Server{
		Addr:              s.cfg.Address,
		Handler:           s.routes(),
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

	log.Printf("[INFO] starting server on %s", s.cfg.Address)
	if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("server error: %w", err)
	}
	return nil
}

// routes configures and returns the HTTP handler with all routes and middleware.
func (s *Server) routes() http.Handler {
	router := routegroup.New(http.NewServeMux())

	// global middleware
	router.Use(
		rest.Recoverer(log.Default()),
		rest.Throttle(1000),
		rest.RealIP,
		rest.Trace,
		rest.SizeLimit(1024*1024), // 1MB
		rest.AppInfo("stash", "umputun", s.version),
		rest.Ping,
	)

	// kv routes
	router.Mount("/kv").Route(func(kv *routegroup.Bundle) {
		kv.HandleFunc("GET /{key...}", s.handleGet)
		kv.HandleFunc("PUT /{key...}", s.handleSet)
		kv.HandleFunc("DELETE /{key...}", s.handleDelete)
	})

	return router
}
