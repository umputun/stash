package server

import (
	"encoding/json"
	"errors"
	"net/http"

	log "github.com/go-pkgz/lgr"
	"github.com/go-pkgz/rest"
	"github.com/google/uuid"

	"github.com/umputun/stash/app/store"
)

// serviceRegisterRequest is the request body for service registration.
type serviceRegisterRequest struct {
	ID      string   `json:"id,omitempty"`
	Address string   `json:"address"`
	Port    int      `json:"port"`
	Tags    []string `json:"tags,omitempty"`
	Check   *struct {
		Type     store.HealthCheckType `json:"type"`
		TTL      int                   `json:"ttl,omitempty"`      // for TTL checks
		URL      string                `json:"url,omitempty"`      // for HTTP checks
		Interval int                   `json:"interval,omitempty"` // for HTTP checks
	} `json:"check,omitempty"`
}

// serviceRegisterResponse is the response for service registration.
type serviceRegisterResponse struct {
	ID string `json:"id"`
}

// handleServiceRegister registers a new service instance.
// PUT /service/{name}
func (s *Server) handleServiceRegister(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if name == "" {
		rest.SendErrorJSON(w, r, log.Default(), http.StatusBadRequest, nil, "service name is required")
		return
	}

	var req serviceRegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		rest.SendErrorJSON(w, r, log.Default(), http.StatusBadRequest, err, "invalid request body")
		return
	}

	if req.Address == "" {
		rest.SendErrorJSON(w, r, log.Default(), http.StatusBadRequest, nil, "address is required")
		return
	}
	if req.Port <= 0 || req.Port > 65535 {
		rest.SendErrorJSON(w, r, log.Default(), http.StatusBadRequest, nil, "valid port is required")
		return
	}

	// generate ID if not provided
	id := req.ID
	if id == "" {
		id = generateServiceID()
	}

	// default check settings
	checkType := store.HealthCheckTTL
	ttl := 30
	checkURL := ""
	checkInterval := 0

	if req.Check != nil {
		checkType = req.Check.Type
		switch checkType {
		case store.HealthCheckTTL:
			if req.Check.TTL > 0 {
				ttl = req.Check.TTL
			}
		case store.HealthCheckHTTP:
			checkURL = req.Check.URL
			if checkURL == "" {
				rest.SendErrorJSON(w, r, log.Default(), http.StatusBadRequest, nil, "check url required for http checks")
				return
			}
			checkInterval = req.Check.Interval
		}
	}

	svc := store.ServiceInstance{
		ID:            id,
		Name:          name,
		Address:       req.Address,
		Port:          req.Port,
		Tags:          req.Tags,
		CheckType:     checkType,
		CheckURL:      checkURL,
		CheckInterval: checkInterval,
		TTL:           ttl,
	}

	if err := s.svcStore.RegisterService(svc); err != nil {
		rest.SendErrorJSON(w, r, log.Default(), http.StatusInternalServerError, err, "failed to register service")
		return
	}

	rest.RenderJSON(w, serviceRegisterResponse{ID: id})
}

// handleServiceDeregister removes a service instance.
// DELETE /service/{name}/{id}
func (s *Server) handleServiceDeregister(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	id := r.PathValue("id")

	if name == "" || id == "" {
		rest.SendErrorJSON(w, r, log.Default(), http.StatusBadRequest, nil, "service name and id are required")
		return
	}

	if err := s.svcStore.DeregisterService(name, id); err != nil {
		if errors.Is(err, store.ErrServiceNotFound) {
			rest.SendErrorJSON(w, r, log.Default(), http.StatusNotFound, err, "service not found")
			return
		}
		rest.SendErrorJSON(w, r, log.Default(), http.StatusInternalServerError, err, "failed to deregister service")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// handleServiceHealth sends a heartbeat for a TTL-based service.
// PUT /service/{name}/{id}/health
func (s *Server) handleServiceHealth(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	id := r.PathValue("id")

	if name == "" || id == "" {
		rest.SendErrorJSON(w, r, log.Default(), http.StatusBadRequest, nil, "service name and id are required")
		return
	}

	if err := s.svcStore.UpdateServiceHealth(name, id); err != nil {
		if errors.Is(err, store.ErrServiceNotFound) {
			rest.SendErrorJSON(w, r, log.Default(), http.StatusNotFound, err, "service not found")
			return
		}
		rest.SendErrorJSON(w, r, log.Default(), http.StatusInternalServerError, err, "failed to update service health")
		return
	}

	w.WriteHeader(http.StatusOK)
}

// handleServiceDiscover returns service instances for a given name.
// GET /service/{name}
// Query params: healthy=true|all, tag=value (multiple allowed)
func (s *Server) handleServiceDiscover(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if name == "" {
		rest.SendErrorJSON(w, r, log.Default(), http.StatusBadRequest, nil, "service name is required")
		return
	}

	// parse healthy filter (default: true)
	healthyOnly := r.URL.Query().Get("healthy") != "all"

	services, err := s.svcStore.GetServices(name, healthyOnly)
	if err != nil {
		rest.SendErrorJSON(w, r, log.Default(), http.StatusInternalServerError, err, "failed to get services")
		return
	}

	// filter by tags if specified
	tags := r.URL.Query()["tag"]
	if len(tags) > 0 {
		services = filterByTags(services, tags)
	}

	rest.RenderJSON(w, services)
}

// handleServiceList returns a summary of all registered services.
// GET /services
func (s *Server) handleServiceList(w http.ResponseWriter, r *http.Request) {
	summaries, err := s.svcStore.ListServicesSummary()
	if err != nil {
		rest.SendErrorJSON(w, r, log.Default(), http.StatusInternalServerError, err, "failed to list services")
		return
	}
	rest.RenderJSON(w, summaries)
}

// filterByTags returns services that have all the specified tags.
func filterByTags(services []store.ServiceInstance, tags []string) []store.ServiceInstance {
	result := make([]store.ServiceInstance, 0, len(services))
	for _, svc := range services {
		if hasAllTags(svc.Tags, tags) {
			result = append(result, svc)
		}
	}
	return result
}

// hasAllTags returns true if svcTags contains all of requiredTags.
func hasAllTags(svcTags, requiredTags []string) bool {
	tagSet := make(map[string]struct{}, len(svcTags))
	for _, t := range svcTags {
		tagSet[t] = struct{}{}
	}
	for _, t := range requiredTags {
		if _, ok := tagSet[t]; !ok {
			return false
		}
	}
	return true
}

// generateServiceID creates a unique service instance ID.
func generateServiceID() string {
	return "svc-" + uuid.New().String()
}
