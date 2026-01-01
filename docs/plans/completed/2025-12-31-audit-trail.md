# Audit Trail Implementation Plan

## Overview

Add audit logging to track all KV operations (read, create, update, delete) with admin-only access to query logs.

## Design Decisions

- **Access control**: `admin: true` flag on users grants audit access
- **Actions audited**: All (read, create, update, delete)
- **Storage**: Same database (audit_log table)
- **Retention**: Time-based with `--audit.retention` flag (default 90d)
- **API**: POST /audit/query with JSON body for filtering
- **Implementation**: Middleware approach (handlers unaware of audit)
- **Timestamps**: Server local TZ with offset

## Audit Entry Fields

- timestamp (RFC3339 with local TZ offset)
- action (read, create, update, delete)
- key (path)
- actor (username or "token:xxxx")
- actor_type (user, token, public)
- result (success, denied, not_found)
- ip (client IP)
- user_agent (request User-Agent)
- value_size (bytes, NULL for delete/denied)
- request_id (for correlation)

## CLI Flags

- `--audit.enabled` - Enable audit logging (default: false)
- `--audit.retention=90d` - Retention period (default: 90d, 0=unlimited)
- `--audit.limit=10000` - Max entries per query (default: 10000)

## Tasks

### 1. Add Enums

**Files:**
- Modify: `app/enum/enum.go`

- [x] Add AuditAction enum (read, create, update, delete)
- [x] Add AuditResult enum (success, denied, not_found)
- [x] Add ActorType enum (user, token, public)
- [x] Run go generate for enum code
- [x] Add tests for new enums

### 2. Add Admin Flag to Auth

**Files:**
- Modify: `app/server/auth.go`
- Modify: `app/server/verify.go` (JSON schema)
- Modify: `app/server/auth_test.go`

- [x] Add `Admin bool` field to UserConfig
- [x] Add `Admin bool` field to User struct
- [x] Update parseUsers to copy admin flag
- [x] Add IsAdmin(username) method to Auth
- [x] Update JSON schema in verify.go
- [x] Add tests for admin flag parsing and IsAdmin method

### 3. Create Audit Store

**Files:**
- Create: `app/store/audit.go`
- Modify: `app/store/db.go`
- Modify: `app/store/db_test.go`

- [x] Define AuditEntry struct with all fields
- [x] Define AuditQuery struct for filtering
- [x] Add audit_log table creation in db.go createSchema
- [x] Implement LogAudit method (insert entry)
- [x] Implement QueryAudit method (with filters, limit, ordering)
- [x] Implement DeleteAuditOlderThan method (for cleanup)
- [x] Add tests for all methods

### 4. Create Audit Middleware

**Files:**
- Create: `app/server/audit.go`
- Create: `app/server/audit_test.go`

- [x] Create responseWriter wrapper to capture status code and bytes
- [x] Create AuditMiddleware that logs after handler completes
- [x] Create NoopAuditMiddleware for disabled state
- [x] Extract actor from session cookie or Bearer token
- [x] Map HTTP method to audit action
- [x] Map response status to audit result
- [x] Add tests for middleware

### 5. Create Audit Query Handler

**Files:**
- Modify: `app/server/audit.go`

- [x] Add POST /audit/query handler
- [x] Parse JSON body with filter fields
- [x] Validate admin access (403 if not admin)
- [x] Call auditStore.Query with filters
- [x] Return JSON response with entries, total, limit
- [x] Add tests for query handler

### 6. Wire Up in Server

**Files:**
- Modify: `app/server/server.go`

- [x] Add AuditStore field to Server config
- [x] Add audit CLI flags to Config struct
- [x] Apply audit middleware to /kv/ route group
- [x] Register /audit/query route with admin check
- [x] Add tests for route registration

### 7. Add CLI Flags and Cleanup

**Files:**
- Modify: `app/main.go`

- [x] Add audit.enabled, audit.retention, audit.limit flags
- [x] Create audit store (or noop) based on enabled flag
- [x] Start audit cleanup goroutine (like session cleanup)
- [x] Pass audit config to server

### 8. Final Validation

- [x] Run full test suite
- [x] Run linter
- [ ] Manual testing with auth-private.yml
- [x] Update CLAUDE.md with audit routes
- [x] Update CHANGELOG.md
- [ ] Move plan to `docs/plans/completed/`
