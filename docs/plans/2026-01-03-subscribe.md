# Key Subscription (SSE) Implementation Plan

## Overview

Add real-time key change notifications via Server-Sent Events (SSE). Clients subscribe to a specific key or prefix pattern and receive events when matching keys are created, updated, or deleted. Designed for config reloading use cases.

## Context

- **Mutation points:** `app/server/api/handler.go` (API), `app/server/web/handler.go` (Web UI)
- **Auth patterns:** Prefix-based ACL with `FilterKeysForRequest` method
- **SSE library:** `github.com/tmaxmax/go-sse` for both server and client

## API Design

**Endpoint:** `GET /kv/subscribe`

**Query params (mutually exclusive):**
- `key=app/config` - subscribe to exact key
- `prefix=app/` - subscribe to all keys with prefix

**Response:** `text/event-stream`
```
event: change
data: {"key":"app/config","action":"updated","timestamp":"2025-01-03T10:30:00Z"}

event: change
data: {"key":"app/db","action":"deleted","timestamp":"2025-01-03T10:31:00Z"}
```

**Actions:** `created`, `updated`, `deleted`

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
- `OnSession` callback validates auth and returns topic (key or prefix)
- API/Web handlers call `sseServer.Publish(msg, topic)` after mutations
- Topics: exact keys (`app/config`) - events published to exact key topic
- Prefix subscribers match via topic hierarchy (TODO: verify go-sse topic matching)

## Tasks

*Mark each checkbox `[x]` as tasks are completed during implementation.*

### 1. Add go-sse Dependency

- [ ] Run `go get github.com/tmaxmax/go-sse`
- [ ] Verify builds

### 2. SSE Server Setup

**Files:**
- Create: `app/server/sse/sse.go`
- Create: `app/server/sse/sse_test.go`

- [ ] Create `Service` struct wrapping `sse.Server`
- [ ] Implement `OnSession` callback: parse query params, validate auth, return topic
- [ ] Implement `Publish(key, action string)` method to publish events
- [ ] Implement `Shutdown()` for graceful shutdown
- [ ] Add helper for matching prefix subscriptions to key events
- [ ] Add tests for subscription validation, auth filtering
- [ ] Verify tests pass

### 3. Wire SSE to Server

**Files:**
- Modify: `app/server/server.go`

- [ ] Create SSE service in `server.New()`
- [ ] Add route: `GET /kv/subscribe` with tokenAuth middleware
- [ ] Call `sseService.Shutdown()` in graceful shutdown
- [ ] Verify existing tests pass

### 4. Publish from API Handlers

**Files:**
- Modify: `app/server/api/handler.go`
- Modify: `app/server/api/handler_test.go`

- [ ] Add `sse *sse.Service` field to Handler
- [ ] Update `New()` to accept SSE service parameter
- [ ] Publish event in `handleSet` after successful store.Set
- [ ] Publish event in `handleDelete` after successful store.Delete
- [ ] Add tests verifying events are published
- [ ] Verify tests pass

### 5. Publish from Web Handlers

**Files:**
- Modify: `app/server/web/handler.go`
- Modify: `app/server/web/handler_test.go`

- [ ] Add `sse *sse.Service` field to Handler
- [ ] Update `New()` to accept SSE service parameter
- [ ] Publish event in `handleCreateKey`
- [ ] Publish event in `handleUpdateKey`
- [ ] Publish event in `handleDeleteKey`
- [ ] Publish event in `handleRestore`
- [ ] Add tests verifying events are published
- [ ] Verify tests pass

### 6. Go Client Library

**Files:**
- Create: `lib/stash/subscribe.go`
- Create: `lib/stash/subscribe_test.go`

- [ ] Add `github.com/tmaxmax/go-sse` to lib/stash dependencies
- [ ] Define `Event` struct (Key, Action, Timestamp)
- [ ] Implement `SubscribeKey(ctx, key) (<-chan Event, error)`
- [ ] Implement `SubscribePrefix(ctx, prefix) (<-chan Event, error)`
- [ ] Add tests with httptest server
- [ ] Verify tests pass

### 7. Integration Test

**Files:**
- Modify: `app/main_test.go`

- [ ] Add integration test: start server, subscribe, mutate key, verify event received
- [ ] Test prefix subscription receives events for matching keys
- [ ] Test permission filtering (subscribe to key without read permission)
- [ ] Verify tests pass

### 8. Documentation

**Files:**
- Modify: `CLAUDE.md`
- Modify: `README.md`

- [ ] Add subscribe endpoint to API section in CLAUDE.md
- [ ] Document subscribe feature in README.md (usage example with curl and Go client)

### 9. Final Validation

- [ ] Run full test suite (`go test ./...`)
- [ ] Run linter (`golangci-lint run`)
- [ ] Manual test with curl: subscribe, mutate via API, observe events
- [ ] Move plan to `docs/plans/completed/`

## Future Work (Deferred)

Subscribe support for other SDKs - to be implemented separately:

- **Python** (`lib/stash-python/`) - use `httpx-sse` library
- **JavaScript/TypeScript** (`lib/stash-js/`) - use native `EventSource` (GET supported)
- **Java** (`lib/stash-java/`) - use `okhttp-eventsource` or Java 11+ HttpClient
