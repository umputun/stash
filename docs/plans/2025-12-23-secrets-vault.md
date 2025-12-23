# Secrets Vault Implementation Plan

## Overview

Add encrypted secrets support to stash - secure storage for sensitive configuration values. Secrets are:
- Keys with `secrets` as a path segment (e.g., `secrets/db/pass`, `app/secrets/key`)
- Encrypted at rest using NaCl secretbox + Argon2id key derivation
- Require mandatory authentication (no anonymous access)
- Use same `/kv/*` API - encryption is automatic based on path
- Permissions use standard prefix patterns (e.g., `app/secrets/*`)

Path-based approach: `secrets` in path = encrypted.

## Context

**Reference implementation:** `../spot/pkg/secrets/spot.go`
- NaCl secretbox encryption
- Argon2id key derivation (memory-hard, resistant to GPU attacks)
- SQLite/PostgreSQL support

**Stash components affected:**
- `app/store/` - add encryption, detect secrets by path
- `app/server/handlers.go` - enforce auth for secrets paths
- `app/server/web.go` - UI changes for secrets
- `app/server/templates/` - lock icons, toggle filter
- `app/main.go` - CLI flag for secrets key

## Design Decisions

1. **Path-based detection:** Key contains `/secrets/` or starts with `secrets/` → encrypted
2. **Same API:** `/kv/*` endpoints, encryption automatic based on path
3. **Same table:** No schema change needed, just encrypt value before storage
4. **Encryption:** NaCl secretbox + Argon2id (same as spot)
5. **Key management:** `--secrets.key` flag or `STASH_SECRETS_KEY` env
6. **Auth enforcement:** Secrets paths require auth; if no auth configured, secrets disabled
7. **Permissions:** Secrets require explicit grant - `app/*` does NOT include `app/secrets/*`
8. **UI:** Lock icon indicator, filter toggle (All/Keys/Secrets)

## Secret Detection

A key is a secret if it contains `secrets` as a path segment:

```
secrets/db/password        ✓ encrypted (starts with secrets/)
app/secrets/db             ✓ encrypted (contains /secrets/)
blah/secrets/config/foo    ✓ encrypted (contains /secrets/)
app/secrets                ✓ encrypted (ends with /secrets)
myapp/config               ✗ plaintext
my-secrets/foo             ✗ plaintext (not a path segment)
secretsabc/foo             ✗ plaintext (not a path segment)
```

**Detection function:**
```go
func IsSecret(key string) bool {
    return key == "secrets" ||
           strings.HasPrefix(key, "secrets/") ||
           strings.Contains(key, "/secrets/") ||
           strings.HasSuffix(key, "/secrets")
}
```

## API Behavior

```
# Create/update - encryption automatic based on path
PUT /kv/app/config           → plaintext storage
PUT /kv/app/secrets/db       → encrypted storage, requires auth

# Get - decryption automatic based on path
GET /kv/app/config           → returns plaintext
GET /kv/app/secrets/db       → decrypts, requires auth

# List
GET /kv/                     → all keys
GET /kv/?secrets=true        → only secret keys
GET /kv/?secrets=false       → only regular keys

# Delete
DELETE /kv/app/secrets/db    → requires auth (it's a secret path)
```

**KeyInfo response includes:**
```json
{
  "key": "app/secrets/db",
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
  - `IsSecret(key string) bool` - detect secret paths
  - deriveKey using Argon2id (same params as spot)
  - encrypt/decrypt using NaCl secretbox
- [ ] Create `app/store/crypto_test.go`
  - Test IsSecret() with various paths
  - Test encryption/decryption roundtrip
  - Test with various value sizes (empty, small, large)
  - Test wrong key returns error
- [ ] **Run tests - must pass before iteration 2**

### Iteration 2: Store Layer - Secret Handling

- [ ] Add `secretKey []byte` field to Store, set via option
- [ ] Add `WithSecretKey(key []byte) Option` function
- [ ] Update Store methods to handle secrets
  - `Set()` encrypts if IsSecret(key) and secretKey configured
  - `Get()` decrypts if IsSecret(key)
  - `GetInfo()` sets Secret field based on IsSecret(key)
  - `List()` supports filtering by secret flag
- [ ] Add `Secret bool` field to KeyInfo struct
- [ ] **Update `app/store/sqlite_test.go`**
  - Test CRUD with secret paths
  - Test CRUD with regular paths
  - Test list filtering
  - Test secret path without key configured returns error
- [ ] **Run tests - must pass before iteration 3**

### Iteration 3: CLI and Configuration

- [ ] Add secrets key flag to `app/main.go`
  - `--secrets.key` / `STASH_SECRETS_KEY` env
  - Minimum key length validation (16 chars)
- [ ] Pass secrets key to Store initialization
- [ ] Add `SecretsEnabled() bool` method to Store
- [ ] **Add tests for key validation**
- [ ] **Run tests - must pass before iteration 4**

### Iteration 4: API Handlers

- [ ] Update `app/server/handlers.go`
  - `handleSet`: enforce auth for secret paths
  - `handleGet`: enforce auth for secret paths
  - `handleDelete`: enforce auth for secret paths
  - `handleList`: support `?secrets=true/false` filter
- [ ] Add helper to check secrets access
  - Return 400 if secret path but secrets not configured
  - Return 401 if not authenticated for secret path
  - Return 403 if no permission for secret path
- [ ] **Update `app/server/handlers_test.go`**
  - Test secret path CRUD with auth
  - Test secret path access without auth (401)
  - Test secret path access without permission (403)
  - Test secrets not configured returns 400
  - Test list filtering
- [ ] **Run tests - must pass before iteration 5**

### Iteration 5: Auth Integration

- [ ] Update permission checking in `app/server/auth.go`
  - Secret paths require permission prefix containing "secrets"
  - `app/*` does NOT match `app/secrets/foo` (no implicit secrets access)
  - `app/secrets/*` DOES match `app/secrets/foo`
  - Even `*` wildcard does NOT grant secrets access
- [ ] Ensure secrets paths always require auth even if auth is optional for regular keys
- [ ] **Add tests for secrets permission patterns**
  - Test `app/*` does not grant `app/secrets/db` access
  - Test `app/secrets/*` grants `app/secrets/db` access
  - Test `*` does not grant secrets access
  - Test `*/secrets/*` grants all secrets access
- [ ] **Run tests - must pass before iteration 6**

### Iteration 6: Web UI

- [ ] Add lock icon indicator in templates
  - SVG matching existing style (Feather/Lucide):
    ```svg
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
      <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
      <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
    </svg>
    ```
  - Update `partials/keys_table.html` - lock icon in key cell
  - Update `partials/keys_cards.html` - lock icon on card header
  - Check `KeyInfo.Secret` to decide icon
- [ ] Add filter toggle in header
  - Three states: All / Keys / Secrets
  - Only visible when secrets enabled AND user has any secrets permission
  - HTMX: updates key list with `?secrets=` filter param
  - Persists selection in session cookie
- [ ] Update view modal for secrets
  - Masked value by default (••••••••)
  - "Reveal" button to show actual value
  - Visual indicator that it's a secret
- [ ] Create form handles secret paths naturally
  - If user types `app/secrets/foo` as key name → becomes secret
  - Show hint/warning when path contains "secrets"
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

### No Schema Change Needed

Secrets are detected by path, values are encrypted before storage. Existing `value` column stores encrypted blob (base64).

### Encryption Format

Same as spot:
1. Generate random 16-byte salt
2. Derive 32-byte key using Argon2id(master_key, salt)
3. Generate random 24-byte nonce
4. Encrypt with NaCl secretbox
5. Store as base64(nonce || salt || ciphertext)

### Permission Model - Secrets Require Explicit Grant

**Key principle:** Secrets are NEVER implicitly granted. Regular wildcards do NOT match secret paths.

- `app/*` matches `app/config`, `app/settings` but NOT `app/secrets/db`
- To access secrets, must have explicit permission containing `secrets` in prefix
- Even `*` (full wildcard) does NOT grant secrets access

**Permission matching for secrets:**
```go
// if key is a secret path, permission prefix must also contain "secrets"
if IsSecret(key) && !strings.Contains(permissionPrefix, "secrets") {
    return false  // deny - no implicit secrets access
}
```

### Permission Examples

```yaml
users:
  - name: admin
    password: "$2a$..."
    permissions:
      - prefix: "*"
        access: rw              # all regular keys, NOT secrets
      - prefix: "*/secrets/*"
        access: rw              # explicitly grant all secrets

  - name: app-user
    password: "$2a$..."
    permissions:
      - prefix: "app/*"
        access: rw              # app/config, app/settings - NOT app/secrets/*
      - prefix: "app/secrets/*"
        access: rw              # must explicitly grant app secrets

  - name: app-readonly
    password: "$2a$..."
    permissions:
      - prefix: "app/*"
        access: r               # regular keys only, secrets denied by default

  - name: secrets-reader
    password: "$2a$..."
    permissions:
      - prefix: "*/secrets/*"
        access: r               # read any secrets, no regular keys

tokens:
  - token: "deploy-xxx"
    permissions:
      - prefix: "deploy/*"
        access: r               # regular deploy keys only
      - prefix: "deploy/secrets/*"
        access: r               # explicitly grant deploy secrets
```

### Dependencies

Add to go.mod:
- `golang.org/x/crypto` (for argon2, nacl/secretbox)
