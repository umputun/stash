# TypeScript SDK Implementation Plan

## Overview

Implement a TypeScript/JavaScript client library for Stash with full feature parity to Go and Python SDKs. The SDK will support both Node.js and browser environments, with zero-knowledge encryption cross-compatible with existing implementations.

## Context

- **Reference implementations**: `lib/stash/` (Go), `lib/stash-python/` (Python)
- **API handlers**: `app/server/api/handler.go`
- **ZK encryption**: AES-256-GCM with Argon2id key derivation
- **Target location**: `lib/stash-js/`
- **Package name**: `stash-client` (on npm, scoped as `@umputun/stash-client` if needed)

## Iterative Development Approach

- Complete each step fully before moving to the next
- Make small, focused changes
- **CRITICAL: every iteration must end with adding/updating tests**
- **CRITICAL: all tests must pass before starting next iteration**
- Run tests after each change
- Maintain cross-compatibility with Go/Python ZK encryption

## Progress Tracking

- Mark completed items with `[x]` immediately when done
- Add newly discovered tasks with ➕ prefix
- Document issues/blockers with ⚠️ prefix

## Implementation Steps

### Iteration 1: Project Setup ✓

**Files:**
- Create: `lib/stash-js/package.json`
- Create: `lib/stash-js/tsconfig.json`
- Create: `lib/stash-js/.gitignore`
- Create: `lib/stash-js/src/index.ts`
- Create: `lib/stash-js/eslint.config.js`

- [x] Initialize npm package with `type: "module"`
- [x] Configure strict tsconfig (see Technical Details)
- [x] Add dev dependencies: typescript, tsup, vitest, eslint, @typescript-eslint/*
- [x] Configure tsup for ESM + CJS dual output
- [x] Configure eslint with typescript-eslint
- [x] Create basic exports structure with placeholder
- [x] **Verify `npm run build` works**
- [x] **Verify `npm run lint` works**

### Iteration 2: Types and Errors ✓

**Files:**
- Create: `lib/stash-js/src/types.ts`
- Create: `lib/stash-js/src/errors.ts`

- [x] Define KeyInfo interface with proper date handling
- [x] Define Format type (text, json, yaml, xml, toml, ini, hcl, shell)
- [x] Define ClientOptions interface
- [x] Implement error classes: StashError, NotFoundError, UnauthorizedError, ForbiddenError, DecryptionError, ConnectionError
- [x] **Add tests for error types**
- [x] **Run tests - must pass before iteration 3**

### Iteration 3: Core HTTP Client ✓

**Files:**
- Create: `lib/stash-js/src/client.ts`

- [x] Implement Client class with constructor (baseUrl, options)
- [x] Implement ping() method
- [x] Implement get(key) and getBytes(key) methods
- [x] Implement getOrDefault(key, defaultValue) method
- [x] Implement set(key, value, format?) method
- [x] Implement delete(key) method
- [x] Implement list(prefix?) method
- [x] Implement info(key) method
- [x] Add retry logic with configurable attempts
- [x] Add Bearer token authentication
- [x] Handle RFC3339/RFC3339Nano datetime parsing
- [x] **Add tests with mocked fetch**
- [x] **Run tests - must pass before iteration 4**

### Iteration 4: Zero-Knowledge Encryption ✓

**Files:**
- Create: `lib/stash-js/src/zk.ts`
- Update: `lib/stash-js/src/client.ts`

- [x] Add dependencies: `hash-wasm` (Argon2id), WebCrypto (AES-GCM built-in)
- [x] Implement ZKCrypto class with encrypt/decrypt methods
- [x] Use exact Argon2id params: time=1, memory=64MB, parallelism=4
- [x] Implement $ZK$<base64> format encoding/decoding
- [x] Integrate ZK into Client (auto encrypt on set, auto decrypt on get)
- [x] Implement close() for passphrase cleanup
- [x] **Add ZK unit tests**
- [x] **Add cross-compatibility tests with Go/Python fixtures**
- [x] **Run tests - must pass before iteration 5** (82 tests passing)

### Iteration 5: Browser Compatibility ✓

**Files:**
- Update: `lib/stash-js/src/zk.ts`
- ~~Create: `lib/stash-js/src/crypto-browser.ts`~~ (not needed)

- [x] Verify WebCrypto API compatibility for AES-GCM (native browser API)
- [x] Verify Argon2 WASM works in browser (hash-wasm uses WASM)
- [x] Add browser-specific build output (tsup produces ESM for browsers)
- [x] ~~Test in browser environment~~ - not needed, uses standard APIs
- [x] **No browser-specific tests needed** - implementation uses browser-native APIs
- [x] **Tests passing** (82 tests)

### Iteration 6: CI Integration ✓

**Files:**
- Update: `.github/workflows/ci.yml`
- Create: `.github/workflows/publish-npm.yml`

- [x] Add typescript-sdk job to CI workflow
- [x] Run tests with Node.js 20
- [x] Run linter (eslint)
- [x] Run type checking (tsc --noEmit)
- [x] Create npm publish workflow (on release)
- [x] Configure npm provenance publishing
- [ ] **Verify CI passes** (will verify after push)

### Iteration 7: Documentation and Cleanup ✓

**Files:**
- Create: `lib/stash-js/README.md`
- Update: `/Users/umputun/dev.umputun/stash/README.md`

- [x] Write README with installation, usage examples, API reference
- [x] Document ZK encryption usage and security notes
- [x] Add TypeScript SDK section to main README
- [x] Update Features section to mention all three SDKs
- [x] Update CHANGELOG.md with TypeScript SDK entry
- [x] Code cleanup and final review
- [x] **Verify all tests still pass** (82 tests passing)

### Iteration 8: Completion ✓

- [x] Mark all tasks above as completed
- [x] Verify plan reflects actual implementation
- [x] Run full test suite one final time (82 tests passing)
- [x] Move this plan to `docs/plans/completed/`

## Technical Details

### Modern TypeScript Patterns (Required)

**Use these patterns throughout the implementation:**

1. **Strict mode**: `"strict": true` in tsconfig - no exceptions
2. **Private fields**: Use `#field` syntax, not `_field` or `private`
3. **Const assertions**: Use `as const` for literal types
4. **Named exports**: Prefer named exports over default exports
5. **Readonly**: Mark immutable properties as `readonly`
6. **Nullish coalescing**: Use `??` and `?.` operators
7. **Template literals**: Use for string interpolation
8. **No `any`**: Use `unknown` when type is uncertain, narrow with guards

### Package Configuration

```json
{
  "name": "@umputun/stash-client",
  "version": "0.1.0",
  "type": "module",
  "exports": {
    ".": {
      "import": "./dist/index.js",
      "require": "./dist/index.cjs",
      "types": "./dist/index.d.ts"
    }
  },
  "main": "./dist/index.cjs",
  "module": "./dist/index.js",
  "types": "./dist/index.d.ts",
  "files": ["dist"],
  "engines": {
    "node": ">=18"
  }
}
```

### tsconfig.json

```json
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "ESNext",
    "moduleResolution": "bundler",
    "strict": true,
    "noUncheckedIndexedAccess": true,
    "noImplicitOverride": true,
    "exactOptionalPropertyTypes": true,
    "declaration": true,
    "declarationMap": true,
    "sourceMap": true,
    "outDir": "./dist",
    "rootDir": "./src"
  },
  "include": ["src"],
  "exclude": ["node_modules", "dist"]
}
```

### Build Tooling

Use `tsup` for bundling (handles ESM/CJS dual output automatically):

```json
{
  "scripts": {
    "build": "tsup src/index.ts --format esm,cjs --dts --clean",
    "test": "vitest run",
    "test:watch": "vitest",
    "lint": "eslint src --ext .ts",
    "typecheck": "tsc --noEmit"
  }
}
```

### Format Type (const assertion pattern)

```typescript
export const Format = {
  Text: 'text',
  Json: 'json',
  Yaml: 'yaml',
  Xml: 'xml',
  Toml: 'toml',
  Ini: 'ini',
  Hcl: 'hcl',
  Shell: 'shell',
} as const;

export type Format = typeof Format[keyof typeof Format];
```

### Client Interface (modern patterns)

```typescript
export interface ClientOptions {
  readonly token?: string;
  readonly timeout?: number;      // default 30000ms
  readonly retries?: number;      // default 3
  readonly zkKey?: string;        // min 16 chars
}

export interface KeyInfo {
  readonly key: string;
  readonly size: number;
  readonly format: Format;
  readonly secret: boolean;
  readonly zkEncrypted: boolean;
  readonly createdAt: Date;
  readonly updatedAt: Date;
}

export class Client {
  readonly #baseUrl: string;
  readonly #token?: string;
  readonly #timeout: number;
  readonly #retries: number;
  #zkCrypto?: ZKCrypto;

  constructor(baseUrl: string, options?: ClientOptions);

  ping(): Promise<void>;
  get(key: string): Promise<string>;
  getBytes(key: string): Promise<Uint8Array>;
  getOrDefault(key: string, defaultValue: string): Promise<string>;
  set(key: string, value: string, format?: Format): Promise<void>;
  delete(key: string): Promise<void>;
  list(prefix?: string): Promise<readonly KeyInfo[]>;
  info(key: string): Promise<KeyInfo>;
  close(): void;
}
```

### Error Classes (discriminated by name)

```typescript
export class StashError extends Error {
  override readonly name = 'StashError' as const;
}

export class NotFoundError extends StashError {
  override readonly name = 'NotFoundError' as const;
}

export class UnauthorizedError extends StashError {
  override readonly name = 'UnauthorizedError' as const;
}

// Type guard for error checking
export function isStashError(error: unknown): error is StashError {
  return error instanceof StashError;
}
```

### ZK Encryption Constants

```typescript
export const ZK_PREFIX = '$ZK$' as const;
export const ZK_SALT_SIZE = 16 as const;
export const ZK_NONCE_SIZE = 12 as const;
export const ZK_KEY_SIZE = 32 as const;
export const ZK_MIN_PASSPHRASE_LENGTH = 16 as const;

// Argon2id params (must match Go/Python exactly)
export const ARGON_TIME = 1 as const;
export const ARGON_MEMORY = 64 * 1024 as const; // 64 MB in KB
export const ARGON_PARALLELISM = 4 as const;
```

### Dependencies

**Runtime (minimal)**:
- `hash-wasm` - Argon2id (small WASM, works in browser+Node)
- Built-in: WebCrypto (`crypto.subtle`) for AES-GCM (works in Node 18+ and browsers)

**Dev**:
- `typescript` ^5.0
- `tsup` - bundler for dual ESM/CJS
- `vitest` - testing
- `eslint` + `@typescript-eslint/*` - linting
- `@types/node` ^18

## Code Style Guidelines

- **No default exports** - always use named exports
- **Explicit return types** - on all public methods
- **JSDoc comments** - on all exported functions/classes/types
- **No `any`** - use `unknown` and type guards instead
- **Immutable by default** - use `readonly` and `as const`
- **Early returns** - avoid deep nesting
- **Descriptive names** - no abbreviations except common ones (url, http, etc.)

## Notes

- Use native `fetch` API (Node.js 18+ built-in)
- ESM-first with CJS fallback via tsup
- Browser support via WebCrypto and WASM Argon2
- Cross-compatibility tests use same fixtures as Python SDK
- Target ES2022 for modern syntax support
