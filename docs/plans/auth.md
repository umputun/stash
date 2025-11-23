# Authentication System

## Overview

Add optional authentication to Stash, inspired by cronn's simple approach. When enabled via `--password-hash`, all routes require authentication. The system supports:

- **UI authentication**: Password-based form login with session cookies
- **API authentication**: Basic auth (full access) or Bearer tokens (prefix-scoped)
- **Backward compatible**: No `--password-hash` = no auth (current behavior)

## Key Features

- Single password for admin access (UI + Basic auth)
- Optional API tokens with prefix-based read/write permissions
- Session management with secure cookies
- Rate limiting on login attempts
- No database changes required (tokens defined via CLI)

## Configuration

```bash
# No auth (dev mode, current behavior)
stash

# Auth enabled with password
stash --password-hash '$2a$10$...'

# Auth with API tokens for scoped access
stash --password-hash '$2a$10$...' \
      --auth-token "apptoken:app/*:rw" \
      --auth-token "monitor:*:r"
```

**Token format**: `token:prefix:permissions` where:
- `token` - the secret token string
- `prefix` - key prefix pattern (`*` = all, `app/*` = app/ prefix)
- `permissions` - `r` (read), `w` (write), or `rw` (both)

## Access Matrix

| Method | Credential | Scope |
|--------|-----------|-------|
| UI form login | password | full access (cookie session) |
| API Bearer token | token | prefix-scoped (or `*:rw` for full) |

---

## Implementation Plan

### Iteration 1: CLI Options & Data Structures

- [ ] Add auth options to `app/main.go`:
  - `--password-hash` / `PASSWORD_HASH` - bcrypt hash for admin password
  - `--auth-token` / `AUTH_TOKEN` - repeatable flag for API tokens
  - `--login-ttl` / `LOGIN_TTL` - session duration (default: 24h)
- [ ] Create `app/server/auth.go` with types:
  - `Permission` type (Read, Write, ReadWrite)
  - `TokenACL` struct (token, prefix -> permission map)
  - `session` struct (token, createdAt)
- [ ] Add auth fields to `Server` struct in `server.go`:
  - `passwordHash string`
  - `authTokens map[string]*TokenACL`
  - `sessions map[string]session`
  - `sessionsMu sync.Mutex`
  - `loginTTL time.Duration`
- [ ] Update `Config` struct and `New()` to accept auth settings
- [ ] Implement token parser: parse `"token:prefix:rw"` format
  - Validate format, error on malformed input
  - Error on duplicate token+prefix combinations
  - Store prefixes sorted by length (longest first) for deterministic matching
- [ ] Write tests for token parser

### Iteration 2: Session Management

- [ ] Implement `createSession()` - generate secure random token
- [ ] Implement `validateSession(token)` - check token exists and not expired
- [ ] Implement `invalidateSession(token)` - remove session
- [ ] Implement `cleanupExpiredSessions()` - periodic cleanup
- [ ] Write tests for session management

### Iteration 3: Auth Middleware

- [ ] Create `authMiddleware(next http.Handler)`:
  - Skip auth for `/login`, `/ping`, `/static/*`
  - Check session cookie -> allow (full access)
  - Check Bearer token -> allow (scoped access)
  - Else redirect to `/login` (browser) or 401 (API)
- [ ] Create helper `checkTokenPermission(token, key, isWrite)`:
  - Match key against token's prefix patterns
  - Check if operation (read/write) is allowed
- [ ] Add middleware to router (conditional on auth enabled)
- [ ] Write tests for middleware logic

### Iteration 4: Login/Logout Handlers

- [ ] Create login template `templates/login.html`:
  - Simple password form
  - Error message display
  - Theme support (consistent with main UI)
- [ ] Implement `handleLoginForm()` - render login page
- [ ] Implement `handleLogin()`:
  - Parse form, validate password with bcrypt
  - Create session, set secure cookie
  - Redirect to `/`
- [ ] Implement `handleLogout()`:
  - Invalidate session, clear cookie
  - Redirect to `/login`
- [ ] Add rate limiting on login endpoint (tollbooth)
- [ ] Register routes: `GET /login`, `POST /login`, `POST /logout`
- [ ] Write tests for login/logout handlers

### Iteration 5: API Token Authorization

- [ ] Update `/kv` handlers to check token permissions:
  - `handleGet` - requires read permission for key prefix
  - `handleSet` - requires write permission for key prefix
  - `handleDelete` - requires write permission for key prefix
- [ ] Return 403 Forbidden when token lacks permission
- [ ] Update `/web` handlers for consistency:
  - Session cookie = full access (already admin)
  - Bearer token = check permissions per operation
- [ ] Write tests for prefix matching and permission checks

### Iteration 6: UI Updates

- [ ] Add logout button to header (when auth enabled)
- [ ] Show current auth status in UI (optional)
- [ ] Hide edit/delete buttons for read-only tokens (if applicable)
- [ ] Test UI flow: login -> use -> logout

### Iteration 7: Documentation & Testing

- [ ] Update README.md:
  - Document `--password-hash` option
  - Document `--auth-token` format
  - Add examples for generating bcrypt hash
  - Document API authentication methods
- [ ] Update CLAUDE.md if needed
- [ ] Integration tests for full auth flow
- [ ] Manual testing checklist:
  - [ ] No auth mode works as before
  - [ ] Password login works
  - [ ] Basic auth works
  - [ ] Bearer token with full access works
  - [ ] Bearer token with read-only works
  - [ ] Bearer token with prefix restriction works
  - [ ] Logout clears session
  - [ ] Rate limiting triggers after failed attempts

---

## Technical Details

### Data Structures

```go
// Permission represents read/write access level
type Permission int

const (
    PermissionNone Permission = iota
    PermissionRead
    PermissionWrite
    PermissionReadWrite
)

// TokenACL defines access control for an API token
type TokenACL struct {
    Token    string
    Prefixes map[string]Permission // "app/*" -> ReadWrite
}

// session represents an active login session
type session struct {
    token     string
    createdAt time.Time
}
```

### Prefix Matching Rules

**Precedence**: Longest prefix wins (most specific match). Prefixes are sorted by length descending before matching.

| Pattern | Key | Match |
|---------|-----|-------|
| `*` | any key | yes |
| `app/*` | `app/config` | yes |
| `app/*` | `app/db/host` | yes |
| `app/*` | `other/key` | no |
| `app/config` | `app/config` | yes (exact) |
| `app/config` | `app/config/sub` | no |

**Multiple prefixes example**: Token with `*:r` and `app/*:rw` accessing `app/config`:
- `app/*` matches (length 5) - wins over `*` (length 1)
- Result: read-write access

**Duplicate handling**: Error at startup if same token+prefix defined twice via multiple `--auth-token` flags.

### Cookie Configuration

```go
http.Cookie{
    Name:     "stash-auth",        // or "__Host-stash-auth" for HTTPS
    Value:    sessionToken,
    Path:     "/",
    MaxAge:   86400,               // 24 hours
    HttpOnly: true,
    SameSite: http.SameSiteStrictMode,
    Secure:   isHTTPS,
}
```

### Error Responses

| Scenario | Browser | API |
|----------|---------|-----|
| No auth | redirect `/login` | 401 Unauthorized |
| Invalid password | re-render form with error | N/A (form only) |
| Invalid token | N/A | 401 Unauthorized |
| No permission for prefix | 403 page | 403 Forbidden |

---

## Files to Create/Modify

**New files:**
- `app/server/auth.go` - auth logic, middleware, session management
- `app/server/auth_test.go` - tests
- `app/server/templates/login.html` - login form template

**Modified files:**
- `app/main.go` - CLI options, pass auth config to server
- `app/server/server.go` - Server struct fields, middleware setup
- `app/server/web.go` - logout button in templates
- `app/server/templates/base.html` - logout link in header
- `README.md` - documentation

---

## Out of Scope (for now)

- Multiple admin users
- Token management UI (create/delete tokens in UI)
- Token storage in database
- Password change UI
- OAuth/OIDC integration
