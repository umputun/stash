# Key Subscription (SSE) Implementation Plan

## Overview

Add real-time key change notifications via Server-Sent Events (SSE). Clients subscribe to a specific key or prefix pattern and receive events when matching keys are created, updated, or deleted. Designed for config reloading use cases.

## Context

- **Mutation points:** `app/server/api/handler.go` (API), `app/server/web/handler.go` (Web UI)
- **Auth patterns:** Prefix-based ACL with `FilterKeysForRequest` method
- **SSE library:** `github.com/tmaxmax/go-sse` for both server and client

## API Design

**Endpoint:** `GET /kv/subscribe/{key...}`

**Path patterns:**
- `/kv/subscribe/app/config` - subscribe to exact key "app/config"
- `/kv/subscribe/app/*` - subscribe to all keys with prefix "app/"
- `/kv/subscribe/*` - subscribe to all keys (root wildcard)

**Response:** `text/event-stream`
```
event: change
data: {"key":"app/config","action":"update","timestamp":"2025-01-03T10:30:00Z"}

event: change
data: {"key":"app/db","action":"delete","timestamp":"2025-01-03T10:31:00Z"}
```

**Actions:** `create`, `update`, `delete` (using `enum.AuditAction`)

**Auth:** Token header (`X-Auth-Token` or `Authorization: Bearer`) - same as other `/kv/*` routes

**Multiple subscriptions:** Open multiple connections (stateless, simple)

## Architecture

```
┌─────────────┐     Publish()      ┌─────────────┐
│ API Handler │───────────────────▶│             │
│ (Set/Delete)│                    │  sse.Server │──▶ SSE stream to clients
├─────────────┤     Publish()      │  (Joe)      │
│ Web Handler │───────────────────▶│             │
│ (CRUD ops)  │                    └─────────────┘
└─────────────┘                          │
                                         │ OnSession callback
                                         ▼
                                   ┌─────────────┐
                                   │ Auth check  │
                                   │ Topic setup │
                                   └─────────────┘
```

- `sse.Server` with built-in `Joe` provider handles pub-sub
- `OnSession` callback extracts key from path, validates auth, returns topic
- Path patterns: `/subscribe/{key}` for exact, `/subscribe/{prefix}/*` for prefix
- API/Web handlers call `sseServer.Publish(key, action)` after mutations
- Topics: exact keys (`app/config`) and prefix topics (`app/`, `""` for root)
- Events published to exact key topic + all parent prefix topics

## Tasks

*Mark each checkbox `[x]` as tasks are completed during implementation.*

### 1. Add go-sse Dependency

- [x] Run `go get github.com/tmaxmax/go-sse`
- [x] Verify builds

### 2. SSE Server Setup

**Files:**
- Create: `app/server/sse/sse.go`
- Create: `app/server/sse/sse_test.go`

- [x] Create `Service` struct wrapping `sse.Server`
- [x] Implement `OnSession` callback: parse query params, validate auth, return topic
- [x] Implement `Publish(key, action string)` method to publish events
- [x] Implement `Shutdown()` for graceful shutdown
- [x] Add helper for matching prefix subscriptions to key events
- [x] Add tests for subscription validation, auth filtering
- [x] Verify tests pass

### 3. Wire SSE to Server

**Files:**
- Modify: `app/server/server.go`
- Modify: `app/main.go`

- [x] Create SSE service in `main.go` and inject via Deps struct
- [x] Refactored server.New() to use Deps struct for dependencies
- [x] Add route: `GET /kv/subscribe/{key...}` with tokenAuth middleware
- [x] Call `sseService.Shutdown()` in graceful shutdown
- [x] Verify existing tests pass

### 4. Publish from API Handlers

**Files:**
- Modify: `app/server/api/handler.go`
- Modify: `app/server/api/handler_test.go`

- [x] Refactored API handler to use Deps struct (embeds Deps)
- [x] Add `Events EventPublisher` field to api.Deps
- [x] Uses `enum.AuditAction` for type-safe action values
- [x] Publish event in `handleSet` after successful store.Set
- [x] Publish event in `handleDelete` after successful store.Delete
- [x] Fixed nil interface issue when SSE is disabled
- [x] Verify tests pass

### 5. Publish from Web Handlers

**Files:**
- Modify: `app/server/web/handler.go`
- Modify: `app/server/web/keys.go`

- [x] Added `Events EventPublisher` field to web.Deps
- [x] Updated `New()` to accept events via Deps struct
- [x] Added `publishEvent` helper method to Handler
- [x] Publish event in `handleKeyCreate`
- [x] Publish event in `handleKeyUpdate`
- [x] Publish event in `handleKeyDelete`
- [x] Publish event in `handleKeyRestore`
- [x] Verify tests pass

### 6. Go Client Library

**Files:**
- Create: `lib/stash/subscribe.go`
- Create: `lib/stash/subscribe_test.go`

- [x] go-sse already in go.mod (used for server)
- [x] Define `Event` struct (Key, Action, Timestamp)
- [x] Define `Subscription` struct with Events/Errors channels and Close()
- [x] Implement `Subscribe(ctx, key)` - exact key
- [x] Implement `SubscribePrefix(ctx, prefix)` - uses `{prefix}/*` path
- [x] Implement `SubscribeAll(ctx)` - uses `/*` path
- [x] Add tests with httptest server
- [x] Verify tests pass

### 7. Integration Test

**Files:**
- Modify: `app/main_test.go`

- [x] Add `TestIntegration_SSE` with server start, subscribe, mutate, verify event
- [x] Test exact key subscription receives create event
- [x] Test prefix subscription receives events for matching keys
- [x] Test update and delete events received correctly
- [x] Verify tests pass

### 8. Documentation

**Files:**
- Modify: `CLAUDE.md`
- Modify: `README.md`

- [x] Add subscribe endpoint to API section in CLAUDE.md
- [x] Add SSE Subscriptions section with URL patterns and Go client example
- [x] Add "Subscribe to key changes (SSE)" section in README.md API docs

### 9. Final Validation

- [x] Run full test suite (`go test ./...`)
- [x] Run linter (`golangci-lint run`)
- [x] Manual test with curl: subscribe, mutate via API, observe events
- [x] Move plan to `docs/plans/completed/`

## Future Work (Deferred)

Subscribe support for other SDKs - to be implemented separately:

- **Python** (`lib/stash-python/`) - use `httpx-sse` library
- **JavaScript/TypeScript** (`lib/stash-js/`) - use native `EventSource` (GET supported)
- **Java** (`lib/stash-java/`) - use `okhttp-eventsource` or Java 11+ HttpClient
