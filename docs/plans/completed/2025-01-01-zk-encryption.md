# Zero-Knowledge Client-Side Encryption Plan

## Overview

Add optional client-side encryption so server never sees plaintext - encryption/decryption happens entirely in Go client library. Server stores opaque blobs unchanged. UI detects `$ZK$` prefix for visual indication and disables editing.

## Context

- Files involved: `app/store/`, `app/main.go`, `app/server/web/`, `e2e/`
- Related patterns: existing `crypto.go` for server-side encryption
- Dependencies: Go crypto/aes, cipher.AEAD, Argon2id

## Format

```
$ZK$<base64(salt ∥ iv ∥ ciphertext ∥ auth_tag)>
```

- **Prefix**: `$ZK$` (4 bytes) - detection marker
- **Salt**: 16 bytes - for key derivation
- **IV**: 12 bytes - AES-GCM nonce
- **Ciphertext**: variable length
- **Auth tag**: 16 bytes - GCM authentication

Key derivation: Argon2id(passphrase, salt) → 32-byte AES key

## Progress Tracking

- Mark completed items with `[x]`
- Add newly discovered tasks with ➕ prefix
- Document issues/blockers with ⚠️ prefix

---

## Implementation Steps

### Iteration 1: ZK Crypto Core ✅

**Files:**
- Create: `app/store/zkcrypto.go`
- Create: `app/store/zkcrypto_test.go`

**Tasks:**
- [x] Write test for `IsZKEncrypted(value) bool`
- [x] Write test for `ZKEncrypt(key, plaintext) → $ZK$...`
- [x] Write test for `ZKDecrypt(key, $ZK$...) → plaintext`
- [x] Write test for round-trip encrypt/decrypt
- [x] Write test for wrong key returns error
- [x] Implement ZKCrypto struct with Encrypt/Decrypt methods
- [x] Use AES-256-GCM with Argon2id key derivation
- [x] **Run tests - must pass before Iteration 2**

### Iteration 2: Store ZK Detection ✅

**Files:**
- Modify: `app/store/store.go` (add ZKEncrypted to KeyInfo)
- Modify: `app/store/db.go` (detect $ZK$ prefix in List/GetInfo)
- Test: `app/store/db_test.go`

**Tasks:**
- [x] Add `ZKEncrypted bool` field to KeyInfo struct
- [x] Write test: GetInfo returns ZKEncrypted=true for $ZK$ values
- [x] Write test: List returns ZKEncrypted=true for $ZK$ values
- [x] Implement prefix detection in GetInfo
- [x] Implement prefix detection in List
- [x] **Run tests - must pass before Iteration 3**

### Iteration 3: Client Library Integration ✅

**Files:**
- Modify: `lib/stash/client.go` (add ZK encryption options)
- Create: `lib/stash/zk.go` (ZK crypto implementation)
- Modify: `lib/stash/client_test.go` (ZK tests)

**Tasks:**
- [x] Add `WithZKKey(passphrase string)` client option
- [x] Write test: Set with ZK key sends $ZK$... to server
- [x] Write test: Get with ZK key decrypts $ZK$... from server
- [x] Write test: Get without ZK key returns raw $ZK$...
- [x] Implement client-side encrypt on Set when ZK key present
- [x] Implement client-side decrypt on Get when $ZK$ detected + key present
- [x] **Run tests - must pass before Iteration 4**

### Iteration 4: Web UI Detection ✅

**Files:**
- Modify: `app/server/web/templates/partials/keys-table.html`
- Modify: `app/server/web/templates/partials/view.html`
- Modify: `app/server/web/static/style.css`
- Modify: `app/server/web/handler.go` (add ZKEncrypted to templateData)
- Modify: `app/server/web/keys.go` (set ZKEncrypted, block edit form for ZK keys)

**Tasks:**
- [x] Add distinct icon (green shield) for ZK-encrypted keys in table/cards
- [x] Show "Zero-Knowledge Encrypted" badge in view modal
- [x] Hide Edit button for ZK-encrypted keys (table, cards, modal)
- [x] Block edit form for ZK-encrypted keys (renderError with explanation)
- [x] **Run tests - must pass before Iteration 5**

### Iteration 5: Documentation & E2E ✅

**Files:**
- Modify: `README.md`
- Modify: `CLAUDE.md`
- Modify: `e2e/e2e_test.go`

**Tasks:**
- [x] Document ZK encryption in README (client library usage)
- [x] Add usage examples for Go client with ZK
- [x] Update CLAUDE.md with ZK-related notes
- [x] Add e2e test: ZK-encrypted key shows distinct icon
- [x] Add e2e test: ZK-encrypted key edit button hidden
- [x] **Run all tests - must pass before completion**

### Iteration 6: Final Validation ✅

- [x] Run full test suite: `go test ./...`
- [x] Run linter: `golangci-lint run`
- [x] Run e2e tests: `make e2e`
- [x] Manual verification in browser (verified via e2e tests)
- [x] **Move plan to `docs/plans/completed/`**

---

## Out of Scope

- Browser-side decryption (future enhancement)
- Per-user keys / key sharing
- Migration tools for existing secrets
- Key rotation utilities
