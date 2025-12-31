# Python SDK Implementation Plan

## Overview

Add a Python client library for Stash with full feature parity: CRUD operations, authentication, and zero-knowledge encryption compatible with Go implementation.

## Context

- Go SDK location: `lib/stash/`
- ZK crypto params: AES-256-GCM, Argon2id (time=1, memory=64MB, parallelism=4)
- Package name: `stash-client` (PyPI)
- Python version: 3.10+

## Tasks

### 1. Project Setup

**Files:**
- Create: `lib/stash-python/pyproject.toml`
- Create: `lib/stash-python/README.md`
- Create: `lib/stash-python/src/stash/__init__.py`

- [ ] Create directory structure
- [ ] Configure pyproject.toml with uv/pip compatibility
- [ ] Add dependencies: urllib3, cryptography
- [ ] Add dev dependencies: pytest, pytest-cov, ruff
- [ ] Create README with usage examples

### 2. Error Types

**Files:**
- Create: `lib/stash-python/src/stash/errors.py`

- [ ] Implement StashError base exception
- [ ] Implement NotFoundError, UnauthorizedError, ForbiddenError
- [ ] Implement DecryptionError, ConnectionError
- [ ] Add tests for error hierarchy

### 3. Types and Models

**Files:**
- Create: `lib/stash-python/src/stash/types.py`

- [ ] Implement KeyInfo dataclass
- [ ] Add datetime parsing from JSON
- [ ] Add tests for KeyInfo parsing

### 4. ZK Encryption

**Files:**
- Create: `lib/stash-python/src/stash/zk.py`
- Create: `lib/stash-python/tests/test_zk.py`

- [ ] Implement encrypt() with AES-256-GCM + Argon2id
- [ ] Implement decrypt() with proper error handling
- [ ] Implement is_zk_encrypted() check
- [ ] Add unit tests for encrypt/decrypt round-trip
- [ ] Add test for minimum passphrase length (16 chars)

### 5. Generate Go Fixtures

**Files:**
- Modify: `lib/stash/zk_test.go`
- Create: `lib/stash-python/tests/fixtures/go_encrypted.bin`
- Create: `lib/stash-python/tests/fixtures/go_plaintext.txt`

- [ ] Add Go test to generate encrypted fixture
- [ ] Run test to create fixture files
- [ ] Commit fixtures to repo

### 6. Cross-Compatibility Tests

**Files:**
- Create: `lib/stash-python/tests/test_cross_compat.py`
- Modify: `lib/stash/zk_test.go` (add Python fixture test)
- Create: `lib/stash/testdata/python_encrypted.bin`

- [ ] Python test: decrypt Go-generated fixture
- [ ] Python test: generate fixture for Go
- [ ] Go test: decrypt Python-generated fixture
- [ ] Verify round-trip both directions

### 7. HTTP Client

**Files:**
- Create: `lib/stash-python/src/stash/client.py`
- Create: `lib/stash-python/tests/test_client.py`

- [ ] Implement Client class with __init__ (base_url, token, timeout, retries, zk_key)
- [ ] Implement get(), get_bytes()
- [ ] Implement set() with format parameter
- [ ] Implement delete()
- [ ] Implement list() with prefix filter
- [ ] Implement info()
- [ ] Implement ping()
- [ ] Implement close() for ZK passphrase clearing
- [ ] Add context manager (__enter__, __exit__)
- [ ] Add dict-like access (__getitem__, __setitem__, __delitem__, __contains__)
- [ ] Add mocked HTTP tests for all methods
- [ ] Add error handling tests (404, 401, 403)

### 8. Package Exports

**Files:**
- Modify: `lib/stash-python/src/stash/__init__.py`

- [ ] Export Client, KeyInfo
- [ ] Export all error types
- [ ] Add __version__
- [ ] Add __all__ for explicit exports

### 9. CI Integration

**Files:**
- Modify: `.github/workflows/build.yml`

- [ ] Add python-sdk job
- [ ] Setup uv
- [ ] Run pytest with coverage
- [ ] Run ruff linter
- [ ] Verify tests pass

### 10. Final Validation

- [ ] Run full Go test suite
- [ ] Run full Python test suite
- [ ] Run cross-compatibility tests
- [ ] Run linters (Go + Python)
- [ ] Update main README with Python SDK section
- [ ] Move plan to `docs/plans/completed/`
