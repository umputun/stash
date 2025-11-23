# Service Discovery

## Overview

Add simple service discovery to stash, providing a minimal alternative to Consul's service registration and health checking. Services register themselves, send heartbeats or respond to HTTP checks, and clients can discover healthy instances.

**Key features:**
- Service registration with metadata (address, port, tags)
- TTL-based health (heartbeat) and HTTP health checks
- Automatic cleanup of stale services
- Service lookup with optional tag filtering
- Web UI for viewing registered services

## Data Model

```go
// HealthCheckType defines how service health is verified
type HealthCheckType string

const (
    HealthCheckTTL  HealthCheckType = "ttl"  // service sends heartbeats
    HealthCheckHTTP HealthCheckType = "http" // stash polls HTTP endpoint
)

// ServiceInstance represents a registered service instance
type ServiceInstance struct {
    ID            string          `json:"id" db:"id"`
    Name          string          `json:"name" db:"name"`
    Address       string          `json:"address" db:"address"`
    Port          int             `json:"port" db:"port"`
    Tags          []string        `json:"tags,omitempty"` // stored as JSON in DB
    CheckType     HealthCheckType `json:"check_type" db:"check_type"`
    CheckURL      string          `json:"check_url,omitempty" db:"check_url"`       // for HTTP checks
    CheckInterval int             `json:"check_interval" db:"check_interval"`       // seconds, 0 = use global
    TTL           int             `json:"ttl" db:"ttl"`                             // seconds for TTL checks
    Healthy       bool            `json:"healthy" db:"healthy"`
    LastSeen      time.Time       `json:"last_seen" db:"last_seen"`
    RegisteredAt  time.Time       `json:"registered_at" db:"registered_at"`
}
```

## Database Schema

```sql
-- SQLite
CREATE TABLE IF NOT EXISTS services (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    address TEXT NOT NULL,
    port INTEGER NOT NULL,
    tags TEXT DEFAULT '[]',           -- JSON array
    check_type TEXT DEFAULT 'ttl',
    check_url TEXT DEFAULT '',
    check_interval INTEGER DEFAULT 0, -- 0 = use global default
    ttl INTEGER DEFAULT 30,
    healthy INTEGER DEFAULT 1,
    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
    registered_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_services_name ON services(name);
CREATE INDEX idx_services_healthy ON services(healthy);

-- PostgreSQL
CREATE TABLE IF NOT EXISTS services (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    address TEXT NOT NULL,
    port INTEGER NOT NULL,
    tags JSONB DEFAULT '[]',
    check_type TEXT DEFAULT 'ttl',
    check_url TEXT DEFAULT '',
    check_interval INTEGER DEFAULT 0,
    ttl INTEGER DEFAULT 30,
    healthy BOOLEAN DEFAULT true,
    last_seen TIMESTAMP DEFAULT NOW(),
    registered_at TIMESTAMP DEFAULT NOW()
);
CREATE INDEX idx_services_name ON services(name);
CREATE INDEX idx_services_healthy ON services(healthy);
```

## API Endpoints

### Service Registration

```
PUT /service/{name}
```

Register a new service instance. Returns instance ID.

**Request body:**
```json
{
    "id": "optional-custom-id",
    "address": "10.0.0.5",
    "port": 8080,
    "tags": ["primary", "zone-a"],
    "check": {
        "type": "ttl",
        "ttl": 30
    }
}
```

Or with HTTP check:
```json
{
    "address": "10.0.0.5",
    "port": 8080,
    "check": {
        "type": "http",
        "url": "http://10.0.0.5:8080/health",
        "interval": 10
    }
}
```

**Response:** `{"id": "abc123"}`

### Service Deregistration

```
DELETE /service/{name}/{id}
```

Remove a service instance. Returns 204 on success, 404 if not found.

### Health Heartbeat (TTL)

```
PUT /service/{name}/{id}/health
```

Send heartbeat for TTL-based health check. Resets the TTL timer.
Returns 200 on success, 404 if instance not found.

### Service Discovery

```
GET /service/{name}
GET /service/{name}?tag=primary&tag=zone-a
GET /service/{name}?healthy=true  (default)
GET /service/{name}?healthy=all
```

Returns list of service instances, optionally filtered by tags.
By default returns only healthy instances.

**Response:**
```json
[
    {
        "id": "abc123",
        "name": "api",
        "address": "10.0.0.5",
        "port": 8080,
        "tags": ["primary"],
        "healthy": true,
        "last_seen": "2024-01-15T10:30:00Z"
    }
]
```

### List All Services

```
GET /services
```

Returns summary of all registered services.

**Response:**
```json
[
    {
        "name": "api",
        "instances": 3,
        "healthy": 2
    },
    {
        "name": "db",
        "instances": 1,
        "healthy": 1
    }
]
```

## Iterative Development

### Iteration 1: Store Layer

- [ ] Add `ServiceInstance` struct to `app/store/store.go`
- [ ] Add service methods to Store interface:
  - `RegisterService(svc ServiceInstance) error`
  - `DeregisterService(name, id string) error`
  - `UpdateHealth(name, id string) error` - heartbeat, updates last_seen
  - `SetHealthStatus(name, id string, healthy bool) error` - set health state
  - `GetService(name string, tags []string, healthyOnly bool) ([]ServiceInstance, error)`
  - `GetServicesForHealthCheck(checkType HealthCheckType) ([]ServiceInstance, error)` - for background checker
  - `ListServices() ([]ServiceSummary, error)`
  - `CleanupStaleServices(threshold time.Duration) (int, error)` - remove long-dead services
- [ ] Implement SQLite/PostgreSQL schema creation
- [ ] Implement service CRUD operations
- [ ] Add tests for store layer

### Iteration 2: HTTP Handlers

- [ ] Create `app/server/discovery.go` for service handlers
- [ ] Implement `PUT /service/{name}` - register
- [ ] Implement `DELETE /service/{name}/{id}` - deregister
- [ ] Implement `PUT /service/{name}/{id}/health` - heartbeat
- [ ] Implement `GET /service/{name}` - discover with filters
- [ ] Implement `GET /services` - list all
- [ ] Add routes to server
- [ ] Integrate with existing auth middleware
- [ ] Add handler tests

### Iteration 3: Background Health Checker

- [ ] Create `app/server/healthcheck.go`
- [ ] Implement TTL expiration checker (runs periodically)
- [ ] Implement HTTP health checker for services with HTTP checks
- [ ] Add graceful shutdown for background goroutines
- [ ] Configure check intervals via CLI flags
- [ ] Add tests for health checker

### Iteration 4: Web UI

- [ ] Add services list page/tab to web UI
- [ ] Show service name, instance count, health status
- [ ] Add service detail view (list instances)
- [ ] Add manual deregister button
- [ ] Add health status indicators (green/red)
- [ ] HTMX partials for dynamic updates

### Iteration 5: Documentation & Polish

- [ ] Update README.md with discovery API docs
- [ ] Update CLAUDE.md with discovery architecture
- [ ] Add usage examples
- [ ] Add integration tests
- [ ] Run linter and fix issues

## CLI Flags

```
--discovery.ttl-check-interval    Check interval for TTL expiration (default: 5s)
--discovery.http-check-interval   Default interval for HTTP health checks (default: 10s)
--discovery.http-check-timeout    Timeout for HTTP health check requests (default: 5s)
--discovery.cleanup-interval      Interval to remove long-dead services (default: 1h)
--discovery.cleanup-threshold     Remove services dead longer than this (default: 24h)
```

## HTTP Health Check Defaults

| Parameter | Default | Description |
|-----------|---------|-------------|
| Method | GET | HTTP method for health check |
| Success codes | 200-299 | Any 2xx status considered healthy |
| Timeout | 5s | Request timeout (configurable via CLI) |
| Interval | 10s | Check frequency (per-service override via `check_interval`) |
| Failure threshold | 1 | Mark unhealthy after 1 failed check (keep simple) |

**Note**: No backoff/retry logic for MVP. Failed check = immediately unhealthy.
Next successful check = immediately healthy. This keeps implementation simple.

## Authentication Integration

Discovery endpoints use the same auth as KV:
- API tokens work with prefix matching on service names
- Token `mytoken:api/*:rw` can register/deregister services named `api/*`
- Token `monitor:*:r` can read all services but not modify
- Web UI uses session auth (full access)

## Example Usage

### Register a service with TTL health
```bash
curl -X PUT -H "Authorization: Bearer mytoken" \
  -d '{"address":"10.0.0.5","port":8080,"check":{"type":"ttl","ttl":30}}' \
  http://localhost:8484/service/api
# {"id":"svc-abc123"}

# Send heartbeat every <30 seconds
while true; do
  curl -X PUT http://localhost:8484/service/api/svc-abc123/health
  sleep 15
done
```

### Register a service with HTTP health check
```bash
curl -X PUT -H "Authorization: Bearer mytoken" \
  -d '{"address":"10.0.0.5","port":8080,"check":{"type":"http","url":"http://10.0.0.5:8080/health","interval":10}}' \
  http://localhost:8484/service/api
```

### Discover services
```bash
# Get all healthy instances
curl http://localhost:8484/service/api

# Filter by tags
curl "http://localhost:8484/service/api?tag=primary"

# Include unhealthy
curl "http://localhost:8484/service/api?healthy=all"
```

### List all services
```bash
curl http://localhost:8484/services
```

## Files to Create/Modify

**New files:**
- `app/server/discovery.go` - HTTP handlers
- `app/server/discovery_test.go` - handler tests
- `app/server/healthcheck.go` - background health checker
- `app/server/healthcheck_test.go` - health checker tests
- `app/server/templates/services.html` - services list template
- `app/server/templates/partials/service-list.html` - HTMX partial

**Modified files:**
- `app/store/store.go` - add ServiceInstance type, ServiceSummary
- `app/store/sqlite.go` - add service methods, schema
- `app/store/sqlite_test.go` - service store tests
- `app/server/server.go` - add discovery routes, start health checker
- `app/server/handlers.go` - extend KVStore interface
- `app/main.go` - add discovery CLI flags
- `app/server/templates/base.html` - add services nav link
- `README.md` - document discovery API
- `CLAUDE.md` - update architecture notes
