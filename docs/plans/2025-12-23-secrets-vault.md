# Secrets Vault Implementation Plan

## Overview

Add encrypted secrets support to stash - secure storage for sensitive configuration values. Secrets are:
- Regular keys with `secret=true` flag
- Encrypted at rest using NaCl secretbox + Argon2id key derivation
- Require mandatory authentication (no anonymous access)
- Use same `/kv/*` API with secret flag
- Controlled by `secrets/*` permission prefixes in auth.yml

Unified approach: same API, same table, per-key encryption flag.

## Context

**Reference implementation:** `../spot/pkg/secrets/spot.go`
- NaCl secretbox encryption
- Argon2id key derivation (memory-hard, resistant to GPU attacks)
- SQLite/PostgreSQL support

**Stash components affected:**
- `app/store/` - add encryption, secret flag to existing store
- `app/server/handlers.go` - check secret flag, enforce auth
- `app/server/web.go` - UI changes for secrets
- `app/server/templates/` - lock icons, toggle filter
- `app/main.go` - CLI flag for secrets key

## Design Decisions

1. **Unified storage:** Same `kv` table with `secret` boolean column
2. **Same API:** `/kv/*` endpoints, `?secret=true` query param to mark as secret
3. **Encryption:** NaCl secretbox + Argon2id (same as spot)
4. **Key management:** `--secrets.key` flag or `STASH_SECRETS_KEY` env
5. **Auth enforcement:** Secrets require auth; if no auth configured, secrets feature disabled
6. **Permissions:** `secrets/*` prefix patterns in auth.yml for secret keys
7. **UI:** Lock icon indicator, filter toggle (All/Keys/Secrets)

## API Changes

```
# Create/update regular key
PUT /kv/{key...}                 → plaintext storage

# Create/update secret
PUT /kv/{key...}?secret=true     → encrypted storage, requires auth

# Get key (auto-detects if secret)
GET /kv/{key...}                 → decrypts if secret, requires auth for secrets

# List keys
GET /kv/?secrets=true            → only secrets
GET /kv/?secrets=false           → only regular keys
GET /kv/                         → all keys (default)

# Delete (same for both)
DELETE /kv/{key...}              → requires auth if secret
```

**KeyInfo response includes:**
```json
{
  "key": "db/password",
  "size": 32,
  "format": "text",
  "secret": true,
  "created_at": "...",
  "updated_at": "..."
}
```

## Iterative Development Approach

- Complete each step fully before moving to the next
- **CRITICAL: every iteration must end with adding/updating tests**
- **CRITICAL: all tests must pass before starting next iteration**

## Progress Tracking

- Mark completed items with `[x]`
- Add newly discovered tasks with + prefix
- Document issues/blockers with ! prefix

## Implementation Steps

### Iteration 1: Store Layer - Encryption

- [ ] Add encryption helpers to `app/store/`
  - Create `app/store/crypto.go` with encrypt/decrypt functions
  - deriveKey using Argon2id (same params as spot)
  - encrypt/decrypt using NaCl secretbox
- [ ] Create `app/store/crypto_test.go`
  - Test encryption/decryption roundtrip
  - Test with various value sizes (empty, small, large)
  - Test wrong key returns error
- [ ] **Run tests - must pass before iteration 2**

### Iteration 2: Store Layer - Secret Flag

- [ ] Add `secret` column to database schema
  - SQLite: `ALTER TABLE kv ADD COLUMN secret INTEGER DEFAULT 0`
  - PostgreSQL: `ALTER TABLE kv ADD COLUMN secret BOOLEAN DEFAULT FALSE`
  - Update schema creation in `app/store/sqlite.go`
- [ ] Update `KeyInfo` struct with `Secret bool` field
- [ ] Update Store methods to handle secret flag
  - `Set()` accepts secret flag, encrypts if true
  - `Get()` decrypts if secret flag is set
  - `GetInfo()` returns secret flag
  - `List()` supports filtering by secret flag
- [ ] Add `secretKey []byte` field to Store, set via option
- [ ] **Update `app/store/sqlite_test.go`**
  - Test CRUD with secret=true
  - Test CRUD with secret=false
  - Test list filtering
  - Test secret requires key configured
- [ ] **Run tests - must pass before iteration 3**

### Iteration 3: CLI and Configuration

- [ ] Add secrets key flag to `app/main.go`
  - `--secrets.key` / `STASH_SECRETS_KEY` env
  - Minimum key length validation (16 chars)
- [ ] Pass secrets key to Store initialization
- [ ] Add `SecretsEnabled() bool` method to check if secrets are available
- [ ] **Add tests for key validation**
- [ ] **Run tests - must pass before iteration 4**

### Iteration 4: API Handlers

- [ ] Update `app/server/handlers.go`
  - `handleSet`: check `?secret=true`, enforce auth for secrets
  - `handleGet`: auto-detect secret, enforce auth, decrypt
  - `handleDelete`: enforce auth for secrets
  - `handleList`: support `?secrets=true/false` filter
- [ ] Add middleware/helper to check secrets permission
  - Return 404 if secrets not configured (no key or no auth)
  - Return 401 if not authenticated for secret access
  - Return 403 if no `secrets/*` permission for the key
- [ ] **Update `app/server/handlers_test.go`**
  - Test secret CRUD with auth
  - Test secret access without auth (401)
  - Test secret access without permission (403)
  - Test secrets disabled returns 404
  - Test list filtering
- [ ] **Run tests - must pass before iteration 5**

### Iteration 5: Auth Integration

- [ ] Update permission checking for `secrets/*` prefix patterns
  - Secret keys require matching `secrets/{key}` permission
  - Example: key `db/password` with secret=true needs `secrets/db/*` or `secrets/*`
- [ ] Update `app/server/auth.go` if needed
- [ ] **Add tests for secrets permission patterns**
- [ ] **Run tests - must pass before iteration 6**

### Iteration 6: Web UI

- [ ] Add lock icon (🔒) indicator in templates
  - Update `partials/keys_table.html` - lock icon in key cell
  - Update `partials/keys_cards.html` - lock icon on card header
- [ ] Add filter toggle in header
  - Three states: All / Keys / Secrets
  - Only visible when secrets enabled AND user has any secrets permission
  - HTMX: updates key list with filter param
  - Persists selection in session cookie
- [ ] Update view modal for secrets
  - Masked value by default (••••••••)
  - "Reveal" button to show actual value
  - Visual indicator that it's a secret
- [ ] Update create/edit form
  - Checkbox: "Store as secret" (encrypted)
  - Only visible when secrets enabled AND user has write permission for secrets
- [ ] **Add web handler tests**
- [ ] **Run tests - must pass before iteration 7**

### Iteration 7: Documentation & Cleanup

- [ ] Update README.md with secrets feature documentation
- [ ] Update CLAUDE.md with secrets-related info
- [ ] Add example auth.yml with secrets permissions
- [ ] Code cleanup and refactoring if needed
- [ ] **Verify all tests still pass**
- [ ] **Run linter**
- [ ] **Final validation**

## Technical Details

### Database Schema Change

```sql
-- SQLite
ALTER TABLE kv ADD COLUMN secret INTEGER DEFAULT 0;

-- PostgreSQL
ALTER TABLE kv ADD COLUMN secret BOOLEAN DEFAULT FALSE;
```

### Encryption Format

Same as spot:
1. Generate random 16-byte salt
2. Derive 32-byte key using Argon2id(master_key, salt)
3. Generate random 24-byte nonce
4. Encrypt with NaCl secretbox
5. Store as base64(nonce || salt || ciphertext)

### Permission Model

```yaml
users:
  - name: admin
    password: "$2a$..."
    permissions:
      - prefix: "*"
        access: rw
      - prefix: "secrets/*"    # can access all secrets
        access: rw

  - name: app-user
    password: "$2a$..."
    permissions:
      - prefix: "app/*"
        access: rw
      - prefix: "secrets/app/*"  # can only access app/* secrets
        access: r

tokens:
  - token: "deploy-xxx"
    permissions:
      - prefix: "secrets/deploy/*"
        access: r
```

### Dependencies

Add to go.mod:
- `golang.org/x/crypto` (for argon2, nacl/secretbox)
