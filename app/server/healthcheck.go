package server

import (
	"context"
	"net/http"
	"sync"
	"time"

	log "github.com/go-pkgz/lgr"

	"github.com/umputun/stash/app/store"
)

// HealthCheckerConfig holds configuration for the health checker.
type HealthCheckerConfig struct {
	TTLCheckInterval  time.Duration // how often to check for expired TTL services
	HTTPCheckInterval time.Duration // default interval for HTTP health checks
	HTTPCheckTimeout  time.Duration // timeout for HTTP health check requests
}

// HealthChecker runs background health checks for registered services.
type HealthChecker struct {
	store      ServiceStore
	cfg        HealthCheckerConfig
	httpClient *http.Client
	wg         sync.WaitGroup

	// per-service tracking for HTTP checks
	lastChecked   map[string]time.Time
	lastCheckedMu sync.RWMutex
}

// NewHealthChecker creates a new HealthChecker instance.
func NewHealthChecker(st ServiceStore, cfg HealthCheckerConfig) *HealthChecker {
	return &HealthChecker{
		store: st,
		cfg:   cfg,
		httpClient: &http.Client{
			Timeout: cfg.HTTPCheckTimeout,
			Transport: &http.Transport{
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 10,
				IdleConnTimeout:     90 * time.Second,
			},
		},
		lastChecked: make(map[string]time.Time),
	}
}

// Run starts the health checker and blocks until context is canceled.
func (h *HealthChecker) Run(ctx context.Context) {
	log.Printf("[INFO] starting health checker, ttl interval=%v, http interval=%v",
		h.cfg.TTLCheckInterval, h.cfg.HTTPCheckInterval)

	h.wg.Add(2)
	go h.runTTLChecker(ctx)
	go h.runHTTPChecker(ctx)

	<-ctx.Done()
	h.wg.Wait()
	log.Printf("[INFO] health checker stopped")
}

// runTTLChecker periodically marks services with expired TTL as unhealthy.
func (h *HealthChecker) runTTLChecker(ctx context.Context) {
	defer h.wg.Done()

	ticker := time.NewTicker(h.cfg.TTLCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			h.checkTTLServices()
		}
	}
}

// checkTTLServices marks expired TTL services as unhealthy.
func (h *HealthChecker) checkTTLServices() {
	services, err := h.store.GetServicesForHealthCheck(store.HealthCheckTTL)
	if err != nil {
		log.Printf("[WARN] failed to get TTL services: %v", err)
		return
	}

	now := time.Now()
	for _, svc := range services {
		// check if service TTL has expired
		expiry := svc.LastSeen.Add(time.Duration(svc.TTL) * time.Second)
		if now.After(expiry) && svc.Healthy {
			if err := h.store.SetServiceHealthStatus(svc.Name, svc.ID, false); err != nil {
				log.Printf("[WARN] failed to mark service %s/%s unhealthy: %v", svc.Name, svc.ID, err)
				continue
			}
			log.Printf("[DEBUG] marked service %s/%s as unhealthy (TTL expired)", svc.Name, svc.ID)
		}
	}
}

// runHTTPChecker periodically polls HTTP endpoints for services with HTTP checks.
// uses 1-second granularity to support per-service check intervals.
func (h *HealthChecker) runHTTPChecker(ctx context.Context) {
	defer h.wg.Done()

	// use 1-second tick for granular per-service interval support
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			h.checkHTTPServices(ctx)
		}
	}
}

// checkHTTPServices polls HTTP health endpoints for services whose check interval has elapsed.
func (h *HealthChecker) checkHTTPServices(ctx context.Context) {
	services, err := h.store.GetServicesForHealthCheck(store.HealthCheckHTTP)
	if err != nil {
		log.Printf("[WARN] failed to get HTTP services: %v", err)
		return
	}

	for _, svc := range services {
		// determine effective interval: per-service if set, otherwise global default
		interval := h.cfg.HTTPCheckInterval
		if svc.CheckInterval > 0 {
			interval = time.Duration(svc.CheckInterval) * time.Second
		}

		// check if enough time has passed since last check
		h.lastCheckedMu.RLock()
		lastCheck, exists := h.lastChecked[svc.ID]
		h.lastCheckedMu.RUnlock()

		now := time.Now()
		if exists && now.Sub(lastCheck) < interval {
			continue // skip, not time yet
		}

		// perform the check
		healthy := h.checkHTTPEndpoint(ctx, svc.CheckURL)

		// update last checked time
		h.lastCheckedMu.Lock()
		h.lastChecked[svc.ID] = time.Now()
		h.lastCheckedMu.Unlock()

		if healthy != svc.Healthy {
			if err := h.store.SetServiceHealthStatus(svc.Name, svc.ID, healthy); err != nil {
				log.Printf("[WARN] failed to update health for %s/%s: %v", svc.Name, svc.ID, err)
				continue
			}
			status := "healthy"
			if !healthy {
				status = "unhealthy"
			}
			log.Printf("[DEBUG] service %s/%s is now %s (HTTP check)", svc.Name, svc.ID, status)
		}
	}
}

// checkHTTPEndpoint performs an HTTP GET request and returns true if healthy.
func (h *HealthChecker) checkHTTPEndpoint(ctx context.Context, url string) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		log.Printf("[DEBUG] failed to create request for %s: %v", url, err)
		return false
	}

	resp, err := h.httpClient.Do(req)
	if err != nil {
		log.Printf("[DEBUG] health check failed for %s: %v", url, err)
		return false
	}
	defer resp.Body.Close()

	// any 2xx status is considered healthy
	return resp.StatusCode >= 200 && resp.StatusCode < 300
}
