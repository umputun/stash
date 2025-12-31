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

### Iteration 1: ZK Crypto Core

**Files:**
- Create: `app/store/zkcrypto.go`
- Create: `app/store/zkcrypto_test.go`

**Tasks:**
- [ ] Write test for `IsZKEncrypted(value) bool`
- [ ] Write test for `ZKEncrypt(key, plaintext) → $ZK$...`
- [ ] Write test for `ZKDecrypt(key, $ZK$...) → plaintext`
- [ ] Write test for round-trip encrypt/decrypt
- [ ] Write test for wrong key returns error
- [ ] Implement ZKCrypto struct with Encrypt/Decrypt methods
- [ ] Use AES-256-GCM with Argon2id key derivation
- [ ] **Run tests - must pass before Iteration 2**

### Iteration 2: Store Integration

**Files:**
- Modify: `app/store/store.go` (add ZK key option)
- Modify: `app/store/db.go` (encrypt on Set, decrypt on Get)
- Test: `app/store/db_test.go`

**Tasks:**
- [ ] Add `WithZKKey(key []byte)` option to store
- [ ] Write test: Set with ZK key stores `$ZK$...` value
- [ ] Write test: Get with ZK key returns decrypted value
- [ ] Write test: Get without ZK key returns raw `$ZK$...`
- [ ] Implement auto-encrypt in Set when ZK key present
- [ ] Implement auto-decrypt in Get when `$ZK$` detected + key present
- [ ] **Run tests - must pass before Iteration 3**

### Iteration 3: CLI Integration

**Files:**
- Modify: `app/main.go` (add --zk-key flag and STASH_ZK_KEY env)

**Tasks:**
- [ ] Add `--zk-key` flag to CLI options
- [ ] Add `STASH_ZK_KEY` env var support
- [ ] Pass ZK key to store via WithZKKey option
- [ ] Manual test: store and retrieve ZK-encrypted value
- [ ] **Run tests - must pass before Iteration 4**

### Iteration 4: Web UI Detection

**Files:**
- Modify: `app/store/store.go` (add ZKEncrypted to KeyInfo)
- Modify: `app/server/web/templates/partials/keys-table.html`
- Modify: `app/server/web/templates/partials/view.html`
- Modify: `app/server/web/static/style.css`

**Tasks:**
- [ ] Add `ZKEncrypted bool` field to KeyInfo struct
- [ ] Populate field by checking value prefix in List/GetInfo
- [ ] Add distinct icon (green lock) for ZK-encrypted keys
- [ ] Show "[Zero-Knowledge Encrypted]" in view modal
- [ ] Hide Edit button for ZK-encrypted keys
- [ ] Return error if PUT attempted on ZK-encrypted key via web
- [ ] **Run tests - must pass before Iteration 5**

### Iteration 5: Documentation & E2E

**Files:**
- Modify: `README.md`
- Modify: `CLAUDE.md`
- Modify: `e2e/e2e_test.go`

**Tasks:**
- [ ] Document --zk-key flag in README
- [ ] Add usage examples for CLI
- [ ] Update CLAUDE.md with ZK-related notes
- [ ] Add e2e test: ZK-encrypted key shows distinct icon
- [ ] Add e2e test: ZK-encrypted key edit button hidden
- [ ] **Run all tests - must pass before completion**

### Iteration 6: Final Validation

- [ ] Run full test suite: `go test ./...`
- [ ] Run linter: `golangci-lint run`
- [ ] Run e2e tests: `make e2e`
- [ ] Manual verification in browser
- [ ] **Move plan to `docs/plans/completed/`**

---

## Out of Scope

- Browser-side decryption (future enhancement)
- Per-user keys / key sharing
- Migration tools for existing secrets
- Key rotation utilities
