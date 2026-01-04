# Stash TypeScript/JavaScript Client

TypeScript/JavaScript client library for [Stash](https://github.com/umputun/stash) - a simple key-value configuration service.

## Installation

```bash
npm install @umputun/stash-client
```

Or with yarn:

```bash
yarn add @umputun/stash-client
```

## Quick Start

```typescript
import { Client, Format } from '@umputun/stash-client';

// basic usage
const client = new Client('http://localhost:8080');
await client.set('app/config', '{"debug": true}', Format.Json);
const value = await client.get('app/config');
console.log(value);  // {"debug": true}

// with authentication
const authClient = new Client('http://localhost:8080', { token: 'your-api-token' });

// with zero-knowledge encryption
const zkClient = new Client('http://localhost:8080', {
  zkKey: 'your-secret-passphrase-min-16-chars'
});
// values are encrypted client-side before sending to server
await zkClient.set('secrets/api-key', 'sk-secret-value');
// automatically decrypted on retrieval
const secret = await zkClient.get('secrets/api-key');  // "sk-secret-value"
```

## Browser Support

This library works in both Node.js (18+) and modern browsers. It uses:
- WebCrypto API for AES-256-GCM encryption (native in all environments)
- hash-wasm for Argon2id key derivation (WASM-based, works everywhere)

## API Reference

### Client

```typescript
new Client(baseUrl: string, options?: ClientOptions)
```

**Options:**
- `token?: string` - Bearer token for authentication
- `timeout?: number` - Request timeout in milliseconds (default: 30000)
- `retries?: number` - Number of retry attempts for failed requests (default: 3)
- `zkKey?: string` - Passphrase for zero-knowledge encryption (min 16 chars)

### Methods

| Method | Description |
|--------|-------------|
| `get(key: string): Promise<string>` | Get value as string |
| `getBytes(key: string): Promise<Uint8Array>` | Get value as bytes |
| `getOrDefault(key: string, defaultValue: string): Promise<string>` | Get value or return default |
| `set(key: string, value: string, format?: Format): Promise<void>` | Set value with format |
| `delete(key: string): Promise<void>` | Delete key |
| `list(prefix?: string): Promise<readonly KeyInfo[]>` | List keys with optional prefix filter |
| `info(key: string): Promise<KeyInfo>` | Get key metadata |
| `ping(): Promise<void>` | Check server connectivity |
| `close(): void` | Clear ZK passphrase from memory |
| `subscribe(key: string): Subscription` | Subscribe to exact key changes |
| `subscribePrefix(prefix: string): Subscription` | Subscribe to prefix changes |
| `subscribeAll(): Subscription` | Subscribe to all key changes |

### Format

```typescript
import { Format } from '@umputun/stash-client';

Format.Text   // 'text' (default)
Format.Json   // 'json'
Format.Yaml   // 'yaml'
Format.Xml    // 'xml'
Format.Toml   // 'toml'
Format.Ini    // 'ini'
Format.Hcl    // 'hcl'
Format.Shell  // 'shell'
```

### KeyInfo

```typescript
interface KeyInfo {
  readonly key: string;
  readonly size: number;
  readonly format: Format;
  readonly secret: boolean;
  readonly zkEncrypted: boolean;
  readonly createdAt: Date;
  readonly updatedAt: Date;
}
```

### Subscriptions

Real-time key change notifications via Server-Sent Events:

```typescript
import { Client } from '@umputun/stash-client';

const client = new Client('http://localhost:8080', { token: 'your-token' });

// subscribe to exact key
const sub = client.subscribe('app/config');
try {
  for await (const event of sub) {
    console.log(`${event.action}: ${event.key} at ${event.timestamp}`);
  }
} finally {
  sub.close();
}

// subscribe to prefix (all keys under app/)
const prefixSub = client.subscribePrefix('app');
try {
  for await (const event of prefixSub) {
    console.log(`${event.action}: ${event.key}`);
  }
} finally {
  prefixSub.close();
}

// subscribe to all keys
const allSub = client.subscribeAll();
try {
  for await (const event of allSub) {
    console.log(`${event.action}: ${event.key}`);
  }
} finally {
  allSub.close();
}
```

**SubscriptionEvent:**
- `key: string` - The key that changed
- `action: 'create' | 'update' | 'delete'` - The action performed
- `timestamp: string` - RFC3339 timestamp

Subscriptions automatically reconnect on connection failure with exponential backoff (1s initial, 30s max).

### Errors

```typescript
import {
  StashError,        // base error
  NotFoundError,     // key not found (404)
  UnauthorizedError, // unauthorized (401)
  ForbiddenError,    // forbidden (403)
  DecryptionError,   // ZK decryption failed
  ConnectionError,   // connection failed
  ResponseError,     // unexpected HTTP response
} from '@umputun/stash-client';

// type guards
import {
  isStashError,
  isNotFoundError,
  isDecryptionError,
  // ... etc
} from '@umputun/stash-client';

try {
  await client.get('missing-key');
} catch (error) {
  if (isNotFoundError(error)) {
    console.log('Key not found:', error.key);
  }
}
```

## Zero-Knowledge Encryption

When `zkKey` is provided, all values are encrypted client-side using AES-256-GCM with Argon2id key derivation. The server only stores encrypted data and cannot decrypt it.

Encryption parameters (compatible with Go and Python clients):
- Algorithm: AES-256-GCM
- Key derivation: Argon2id (time=1, memory=64MB, parallelism=4)
- Encrypted format: `$ZK$<base64(salt || nonce || ciphertext || tag)>`

### Direct ZK Usage

```typescript
import { ZKCrypto, isZkEncrypted } from '@umputun/stash-client';

const zk = new ZKCrypto('your-passphrase-min-16');

// encrypt
const plaintext = new TextEncoder().encode('secret data');
const encrypted = await zk.encrypt(plaintext);

// check if value is ZK-encrypted
console.log(isZkEncrypted(encrypted));  // true

// decrypt
const decrypted = await zk.decrypt(encrypted);
console.log(new TextDecoder().decode(decrypted));  // 'secret data'

// clear passphrase from memory when done
zk.clear();
```

## Development

```bash
# install dependencies
npm install

# run tests
npm test

# run tests in watch mode
npm run test:watch

# run linter
npm run lint

# type check
npm run typecheck

# build
npm run build
```

## License

MIT License - see the main [Stash repository](https://github.com/umputun/stash) for details.
