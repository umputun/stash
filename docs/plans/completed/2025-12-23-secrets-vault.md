# Secrets Vault Implementation Plan

**Status: Completed**

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

### Iteration 1: Store Layer - Encryption ✓

- [x] Add encryption helpers to `app/store/`
  - Created `app/store/crypto.go` with encrypt/decrypt functions
  - `IsSecret(key string) bool` - detect secret paths
  - deriveKey using Argon2id (same params as spot)
  - encrypt/decrypt using NaCl secretbox
- [x] Create `app/store/crypto_test.go`
  - Test IsSecret() with various paths
  - Test encryption/decryption roundtrip
  - Test with various value sizes (empty, small, large)
  - Test wrong key returns error
- [x] **All tests pass**

### Iteration 2: Store Layer - Secret Handling ✓

- [x] Add `secretKey []byte` field to Store, set via option
- [x] Add `WithSecretKey(key []byte) Option` function
- [x] Update Store methods to handle secrets
  - `Set()` encrypts if IsSecret(key) and secretKey configured
  - `Get()` decrypts if IsSecret(key)
  - `GetInfo()` sets Secret field based on IsSecret(key)
  - `List()` supports filtering by secret flag (uses `enum.SecretsFilter`)
- [x] Add `Secret bool` field to KeyInfo struct
- [x] **Updated `app/store/db_test.go`** with secret tests
- [x] **All tests pass**

### Iteration 3: CLI and Configuration ✓

- [x] Add secrets key flag to `app/main.go`
  - `--secrets.key` / `STASH_SECRETS_KEY` env
  - Minimum key length validation (16 chars)
- [x] Pass secrets key to Store initialization
- [x] Add `SecretsEnabled() bool` method to Store
- [x] **All tests pass**

### Iteration 4: API Handlers ✓

- [x] Update `app/server/api/handler.go`
  - Added `SecretsEnabled()` to KVStore interface
  - Return 400 if secret path but secrets not configured
  - `handleList` supports `?filter=all/secrets/keys` query param
- [x] Added `app/enum/enum.go` SecretsFilter enum: All, SecretsOnly, KeysOnly
- [x] Updated all test files to use enum.SecretsFilter parameter in List()
- [x] **All tests pass**

### Iteration 5: Auth Integration ✓

- [x] Update permission checking in `app/server/auth.go`
  - Added `prefixPerm.grantsSecrets()` method
  - Secret paths require permission prefix containing "secrets"
  - `app/*` does NOT match `app/secrets/foo` (no implicit secrets access)
  - `app/secrets/*` DOES match `app/secrets/foo`
  - Even `*` wildcard does NOT grant secrets access
- [x] **Added tests for secrets permission patterns**
  - `TestPrefixPerm_GrantsSecrets`
  - `TestTokenACL_CheckKeyPermission_Secrets`
- [x] **All tests pass**

### Iteration 6: Web UI ✓

- [x] Add lock icon indicator in templates
  - SVG matching existing style (Feather/Lucide)
  - Updated `partials/keys-table.html` - lock icon in key cell (table and cards view)
  - Check `KeyInfo.Secret` to decide icon
- [x] Added CSS styling for `.lock-icon` class
- [x] **All tests pass**

### Iteration 7: Documentation & Cleanup ✓

- [x] Update README.md with secrets feature documentation
- [x] Update CLAUDE.md with secrets-related info
- [x] Added `--secrets.key` to options table
- [x] **All tests pass**
- [x] **Linter clean**

### Iteration 8: E2E UI Tests ✓

- [x] Created `e2e/secrets_test.go` with Playwright e2e tests
- [x] Created `e2e/testdata/auth-secrets.yml` for secrets-enabled users
- [x] Tests:
  - `TestSecrets_LockIconDisplayed` - lock icon shown for secrets
  - `TestSecrets_RegularKeyNoLockIcon` - no lock for regular keys
  - `TestSecrets_UserWithoutSecretsPermissionCannotSee` - permission enforcement
  - `TestSecrets_CardViewLockIcon` - lock icon in card view
  - `TestSecrets_ScopedSecretsAccess` - scoped permission verification
- [x] **All 29 e2e tests pass**

### Iteration 9: Secrets Filter Toggle ✓

- [x] Added secrets filter toggle buttons in web UI (All/Secrets/Keys)
- [x] Added `?filter=secrets|keys` query parameter to API list endpoint
- [x] Invalid filter returns 400 Bad Request (not silent fallback)
- [x] Added E2E tests for filter toggle functionality
- [x] **All tests pass**

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
