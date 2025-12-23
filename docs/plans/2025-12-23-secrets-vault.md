# Secrets Vault Implementation Plan

## Overview

Add encrypted secrets storage to stash - a secure vault for sensitive configuration values. Unlike regular KV storage, secrets are:
- Encrypted at rest using NaCl secretbox + Argon2id key derivation
- Require mandatory authentication (no anonymous access)
- Accessible via separate `/secrets/*` API endpoints
- Controlled by explicit `secrets/*` permission prefixes in auth.yml

This is modeled after the spot project's `pkg/secrets` implementation.

## Context

**Reference implementation:** `../spot/pkg/secrets/spot.go`
- NaCl secretbox encryption
- Argon2id key derivation (memory-hard, resistant to GPU attacks)
- SQLite/PostgreSQL support with parameterized queries

**Stash components affected:**
- `app/store/` - new secrets store
- `app/server/` - handlers, routes, auth middleware
- `app/server/templates/` - web UI for secrets
- `app/main.go` - CLI flags for secrets key
- `auth.yml` - secrets/* permission prefixes

## Design Decisions

1. **Separate storage:** New `secrets` table, not mixed with `kv`
2. **Encryption:** NaCl secretbox + Argon2id (same as spot)
3. **Key management:** `--secrets.key` flag or `STASH_SECRETS_KEY` env
4. **Auth enforcement:** Secrets disabled if auth not configured
5. **Permissions:** Reuse auth.yml with `secrets/*` prefix patterns
6. **Web UI:** Masked values with reveal button

## Iterative Development Approach

- Complete each step fully before moving to the next
- Make small, focused changes
- **CRITICAL: every iteration must end with adding/updating tests**
- **CRITICAL: all tests must pass before starting next iteration**

## Progress Tracking

- Mark completed items with `[x]`
- Add newly discovered tasks with + prefix
- Document issues/blockers with ! prefix

## Implementation Steps

### Iteration 1: Secrets Store Layer

- [ ] Create `app/store/secrets.go` with SecretsStore struct
  - encrypt/decrypt helpers using NaCl secretbox
  - deriveKey using Argon2id
  - Get, Set, Delete, List methods
  - Support for SQLite and PostgreSQL (reuse dbType detection)
- [ ] Create `app/store/secrets_test.go`
  - Test encryption/decryption roundtrip
  - Test CRUD operations
  - Test with empty/invalid keys
  - Test list with prefix filter
- [ ] **Run tests - must pass before iteration 2**

### Iteration 2: CLI and Configuration

- [ ] Add secrets flags to `app/main.go`
  - `--secrets.key` / `STASH_SECRETS_KEY` env
  - Minimum key length validation (16 chars)
- [ ] Initialize SecretsStore in server if key provided
- [ ] Add SecretsStore field to server.Server
- [ ] **Add tests for key validation**
- [ ] **Run tests - must pass before iteration 3**

### Iteration 3: API Handlers

- [ ] Create `app/server/secrets_handlers.go`
  - GET /secrets/ - list keys (no values)
  - GET /secrets/{key...} - get decrypted value
  - PUT /secrets/{key...} - set (encrypts automatically)
  - DELETE /secrets/{key...} - delete
- [ ] Add middleware to enforce auth on all /secrets/* routes
  - Return 404 if secrets not configured (no key or no auth)
  - Return 401 if not authenticated
  - Return 403 if no secrets/* permission
- [ ] Register routes in `app/server/server.go`
- [ ] **Create `app/server/secrets_handlers_test.go`**
  - Test all CRUD endpoints
  - Test auth enforcement (401/403/404 cases)
  - Test permission checking for secrets/* prefixes
- [ ] **Run tests - must pass before iteration 4**

### Iteration 4: Auth Integration

- [ ] Update permission checking to support `secrets/*` prefixes
- [ ] Update `app/server/auth.go` if needed for secrets prefix matching
- [ ] Document auth.yml format for secrets permissions
- [ ] **Add tests for secrets permission patterns**
- [ ] **Run tests - must pass before iteration 5**

### Iteration 5: Web UI

- [ ] Create `app/server/templates/partials/secrets_*.html` templates
  - secrets_list.html - table of secrets (no values shown)
  - secrets_view.html - masked value with reveal button
  - secrets_form.html - create/edit form
- [ ] Add secrets handlers in `app/server/web.go`
  - GET /web/secrets - secrets page
  - GET /web/secrets/keys - HTMX partial
  - GET /web/secrets/view/{key...} - view modal
  - GET /web/secrets/edit/{key...} - edit form
  - POST /web/secrets - create
  - PUT /web/secrets/{key...} - update
  - DELETE /web/secrets/{key...} - delete
- [ ] Add KV/Secrets toggle button in header
  - Only visible when secrets enabled AND user has any secrets/* permission
  - Toggle switches between /web/keys and /web/secrets/keys views
  - Visual indicator showing current mode (e.g., icon change, active state)
  - Persists selection in session/cookie like theme preference
- [ ] Add lock icon (🔒) indicator for secrets in grid/cards view
  - Display lock icon next to key name in table rows
  - Display lock icon on card header
  - Consistent styling across both view modes
- [ ] Add CSS for masked values, reveal button, mode toggle, and lock icons
- [ ] **Add web handler tests**
- [ ] **Run tests - must pass before iteration 6**

### Iteration 6: Documentation & Cleanup

- [ ] Update README.md with secrets feature documentation
- [ ] Update CLAUDE.md with secrets-related info
- [ ] Add example auth.yml with secrets permissions
- [ ] Code cleanup and refactoring if needed
- [ ] **Verify all tests still pass**
- [ ] **Run linter**
- [ ] **Final validation**

## Technical Details

### Database Schema

```sql
CREATE TABLE secrets (
    skey VARCHAR(255) PRIMARY KEY,
    sval TEXT NOT NULL,           -- base64-encoded encrypted value
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

### Encryption Format

Same as spot:
1. Generate random 16-byte salt
2. Derive 32-byte key using Argon2id(master_key, salt)
3. Generate random 24-byte nonce
4. Encrypt with NaCl secretbox
5. Store as base64(nonce || salt || ciphertext)

### API Responses

```
GET /secrets/        → [{"key": "db/password", "created_at": "...", "updated_at": "..."}]
GET /secrets/db/pass → raw decrypted value (Content-Type based on stored format)
PUT /secrets/db/pass → 200 OK
DELETE /secrets/key  → 204 No Content
```

### Auth.yml Example

```yaml
users:
  - name: admin
    password: "$2a$..."
    permissions:
      - prefix: "*"
        access: rw
      - prefix: "secrets/*"    # explicit secrets access
        access: rw

  - name: app-reader
    password: "$2a$..."
    permissions:
      - prefix: "app/*"
        access: r
      - prefix: "secrets/app/*"  # can read only app secrets
        access: r

tokens:
  - token: "deploy-token-xxx"
    permissions:
      - prefix: "secrets/deploy/*"
        access: r
```

### Dependencies

Add to go.mod:
- `golang.org/x/crypto` (for argon2, nacl/secretbox) - already in use via spot pattern
