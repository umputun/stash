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

- [x] Create directory structure
- [x] Configure pyproject.toml with uv/pip compatibility
- [x] Add dependencies: urllib3, cryptography, argon2-cffi
- [x] Add dev dependencies: pytest, pytest-cov, ruff
- [x] Create README with usage examples

### 2. Error Types

**Files:**
- Create: `lib/stash-python/src/stash/errors.py`

- [x] Implement StashError base exception
- [x] Implement NotFoundError, UnauthorizedError, ForbiddenError
- [x] Implement DecryptionError, ConnectionError
- [x] Add tests for error hierarchy

### 3. Types and Models

**Files:**
- Create: `lib/stash-python/src/stash/types.py`

- [x] Implement KeyInfo dataclass
- [x] Add datetime parsing from JSON
- [x] Add tests for KeyInfo parsing

### 4. ZK Encryption

**Files:**
- Create: `lib/stash-python/src/stash/zk.py`
- Create: `lib/stash-python/tests/test_zk.py`

- [x] Implement encrypt() with AES-256-GCM + Argon2id
- [x] Implement decrypt() with proper error handling
- [x] Implement is_zk_encrypted() check
- [x] Add unit tests for encrypt/decrypt round-trip
- [x] Add test for minimum passphrase length (16 chars)

### 5. Generate Go Fixtures

**Files:**
- Modify: `lib/stash/zk_test.go`
- Create: `lib/stash-python/tests/fixtures/go_encrypted.bin`
- Create: `lib/stash-python/tests/fixtures/go_plaintext.txt`

- [x] Add Go test to generate encrypted fixture
- [x] Run test to create fixture files
- [x] Commit fixtures to repo

### 6. Cross-Compatibility Tests

**Files:**
- Create: `lib/stash-python/tests/test_cross_compat.py`
- Modify: `lib/stash/zk_test.go` (add Python fixture test)
- Create: `lib/stash-python/tests/fixtures/python_encrypted.bin`

- [x] Python test: decrypt Go-generated fixture
- [x] Python test: generate fixture for Go
- [x] Go test: decrypt Python-generated fixture
- [x] Verify round-trip both directions

### 7. HTTP Client

**Files:**
- Create: `lib/stash-python/src/stash/client.py`
- Create: `lib/stash-python/tests/test_client.py`

- [x] Implement Client class with __init__ (base_url, token, timeout, retries, zk_key)
- [x] Implement get(), get_bytes(), get_or_default()
- [x] Implement set() with format parameter
- [x] Implement delete()
- [x] Implement list() with prefix filter
- [x] Implement info()
- [x] Implement ping()
- [x] Implement close() for ZK passphrase clearing
- [x] Add context manager (__enter__, __exit__)
- [x] Add dict-like access (__getitem__, __setitem__, __delitem__, __contains__)
- [x] Add mocked HTTP tests for all methods
- [x] Add error handling tests (404, 401, 403)

### 8. Package Exports

**Files:**
- Modify: `lib/stash-python/src/stash/__init__.py`

- [x] Export Client, KeyInfo
- [x] Export all error types
- [x] Add __version__
- [x] Add __all__ for explicit exports

### 9. CI Integration

**Files:**
- Modify: `.github/workflows/ci.yml`

- [x] Add python-sdk job
- [x] Setup uv
- [x] Run pytest with coverage
- [x] Run ruff linter
- [x] Verify tests pass

### 10. Final Validation

- [x] Run full Go test suite
- [x] Run full Python test suite
- [x] Run cross-compatibility tests
- [x] Run linters (Go + Python)
- [ ] Update main README with Python SDK section
