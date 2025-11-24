# Reverse Proxy Base URL Support

## Overview

Add support for running stash behind a reverse proxy at a subpath (e.g., `/stash`). This enables deployment scenarios where multiple services share a domain with different path prefixes.

**Reference**: Same pattern as cronn issue #53.

## Context

**Files involved:**
- `app/main.go` - CLI flag and validation
- `app/server/server.go` - Config struct, handler wrapping
- `app/server/web.go` - Template data, url/cookiePath helpers
- `app/server/auth.go` - Redirects and cookie paths
- `app/server/templates/*.html` - All hardcoded URLs
- `app/server/static/app.js` - Dynamic delete URL

**Configuration:**
- Flag: `--server.base-url`
- Env: `STASH_SERVER_BASE_URL`
- Example: `/stash` (must start with `/`, no trailing `/`)

## Progress Tracking

- Mark completed items with `[x]`
- Add newly discovered tasks with ➕ prefix
- Document issues/blockers with ⚠️ prefix

## Implementation Steps

### Iteration 1: CLI Flag and Validation
- [x] Add `BaseURL string` to server options in `app/main.go`
- [x] Add `validateBaseURL()` function (ensure starts with `/`, strip trailing `/`)
- [x] Pass to server config
- [x] Run tests

### Iteration 2: Server Config and Handler Wrapping
- [x] Add `BaseURL string` to `Config` struct in `server.go`
- [x] Add `baseURL string` field to `Server` struct
- [x] Create `handler()` method with `http.StripPrefix` wrapping
- [x] Update `Run()` to use `s.handler()` instead of `s.routes()`
- [x] Add `TestServer_Handler_BaseURL` tests
- [x] Add `TestIntegration_WithBaseURL` integration test
- [x] Run tests

### Iteration 3: Template Helpers
- [x] Add `BaseURL string` to `templateData` struct in `web.go`
- [x] Implement `url()` method on Server
- [x] Implement `cookiePath()` method on Server
- [x] Update all template data to include BaseURL
- [x] Add `TestServer_URL` and `TestServer_CookiePath` tests
- [x] Run tests

### Iteration 4: Update Templates
- [x] `base.html`: Change static file URLs to `{{.BaseURL}}/static/...`
- [x] `base.html`: Add `<script>window.BASE_URL = "{{.BaseURL}}";</script>`
- [x] `login.html`: Update static files and form action
- [x] `index.html`: Update all `hx-get`, `hx-post` URLs and logout link
- [x] `partials/keys-table.html`: Update view/edit/delete URLs (using `{{$.BaseURL}}` in range)
- [x] `partials/form.html`: Update form actions
- [x] `partials/view.html`: Update edit link
- [x] Run tests

### Iteration 5: Cookie Paths and Auth Redirects
- [x] Update all `http.Cookie{Path: "/"}` to use `Path: s.cookiePath()` in `web.go`
- [x] Update `auth.go` `SessionAuth` to accept loginURL parameter
- [x] Update `__Host-` cookie prefix logic (only when no baseURL)
- [x] Update `handleLogin` redirect to use `s.url("/")`
- [x] Update `handleLogout` redirect to use `s.url("/login")`
- [x] Add `TestAuth_SessionAuth_WithBaseURL` test
- [x] Run tests

### Iteration 6: JavaScript Updates
- [x] JavaScript already receives URLs from templates (no changes needed)
- [x] `window.BASE_URL` set in base.html for future use
- [x] Run tests

### Iteration 7: Tests and Documentation
- [x] Add tests for `validateBaseURL()` in `main_test.go`
- [x] Add tests for `url()` and `cookiePath()` helpers
- [x] Add test for handler wrapping with base URL
- [x] Update README.md with `--server.base-url` option and "Subpath Deployment" section
- [x] Update `docker-compose-example.yml` with base URL example
- [x] Run full test suite
- [x] Run linter

## Technical Details

### URL Transformation
- Empty base URL: `/web/keys` → `/web/keys`
- Base URL `/stash`: `/web/keys` → `/stash/web/keys`

### Cookie Path Behavior
- Empty base URL: `Path: "/"`
- Base URL `/stash`: `Path: "/stash/"`

### `__Host-` Cookie Prefix
- Only use `__Host-stash-auth` when baseURL is empty (requires `Path="/"`)
- Use `stash-auth` when baseURL is set

### Reproxy Configuration Example

Forward requests with path intact (do NOT strip the prefix):
```yaml
labels:
  - reproxy.server=example.com
  - reproxy.route=^/stash/
  - reproxy.port=8080
```
