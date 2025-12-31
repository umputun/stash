import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { Client } from '../client.js';
import { NotFoundError, UnauthorizedError, ForbiddenError, ResponseError } from '../errors.js';
import type { KeyInfoResponse } from '../types.js';

// mock fetch globally
const mockFetch = vi.fn();
vi.stubGlobal('fetch', mockFetch);

describe('Client', () => {
  beforeEach(() => {
    mockFetch.mockReset();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('constructor', () => {
    it('creates client with base URL', () => {
      const client = new Client('http://localhost:8080');
      expect(client).toBeInstanceOf(Client);
    });

    it('normalizes trailing slash in base URL', async () => {
      const client = new Client('http://localhost:8080/');
      mockFetch.mockResolvedValueOnce(new Response('pong', { status: 200 }));
      await client.ping();
      expect(mockFetch).toHaveBeenCalledWith(
        'http://localhost:8080/ping',
        expect.any(Object)
      );
    });

    it('throws if zkKey is too short', () => {
      expect(() => new Client('http://localhost:8080', { zkKey: 'short' })).toThrow(
        'passphrase must be at least 16 bytes'
      );
    });

    it('accepts zkKey of 16+ characters', () => {
      expect(
        () => new Client('http://localhost:8080', { zkKey: '1234567890123456' })
      ).not.toThrow();
    });
  });

  describe('ping', () => {
    it('succeeds when server returns pong', async () => {
      const client = new Client('http://localhost:8080');
      mockFetch.mockResolvedValueOnce(new Response('pong', { status: 200 }));
      await expect(client.ping()).resolves.toBeUndefined();
    });

    it('throws on unexpected response', async () => {
      const client = new Client('http://localhost:8080');
      mockFetch.mockResolvedValueOnce(new Response('wrong', { status: 200 }));
      await expect(client.ping()).rejects.toThrow('unexpected ping response');
    });
  });

  describe('get', () => {
    it('returns value as string', async () => {
      const client = new Client('http://localhost:8080');
      mockFetch.mockResolvedValueOnce(new Response('test value', { status: 200 }));
      const value = await client.get('app/config');
      expect(value).toBe('test value');
    });

    it('throws NotFoundError on 404', async () => {
      const client = new Client('http://localhost:8080');
      mockFetch.mockResolvedValueOnce(new Response('', { status: 404 }));
      await expect(client.get('missing')).rejects.toBeInstanceOf(NotFoundError);
    });

    it('encodes key segments properly', async () => {
      const client = new Client('http://localhost:8080');
      mockFetch.mockResolvedValueOnce(new Response('value', { status: 200 }));
      await client.get('path/with spaces/key');
      expect(mockFetch).toHaveBeenCalledWith(
        'http://localhost:8080/kv/path/with%20spaces/key',
        expect.any(Object)
      );
    });
  });

  describe('getBytes', () => {
    it('returns value as Uint8Array', async () => {
      const client = new Client('http://localhost:8080');
      const data = new Uint8Array([1, 2, 3, 4]);
      mockFetch.mockResolvedValueOnce(new Response(data, { status: 200 }));
      const value = await client.getBytes('binary');
      expect(value).toBeInstanceOf(Uint8Array);
      expect(value).toEqual(data);
    });
  });

  describe('getOrDefault', () => {
    it('returns value when key exists', async () => {
      const client = new Client('http://localhost:8080');
      mockFetch.mockResolvedValueOnce(new Response('exists', { status: 200 }));
      const value = await client.getOrDefault('key', 'default');
      expect(value).toBe('exists');
    });

    it('returns default when key not found', async () => {
      const client = new Client('http://localhost:8080');
      mockFetch.mockResolvedValueOnce(new Response('', { status: 404 }));
      const value = await client.getOrDefault('missing', 'default');
      expect(value).toBe('default');
    });

    it('throws on other errors', async () => {
      const client = new Client('http://localhost:8080');
      mockFetch.mockResolvedValueOnce(new Response('', { status: 500 }));
      await expect(client.getOrDefault('key', 'default')).rejects.toBeInstanceOf(
        ResponseError
      );
    });
  });

  describe('set', () => {
    it('sends PUT request with value', async () => {
      const client = new Client('http://localhost:8080');
      mockFetch.mockResolvedValueOnce(new Response('', { status: 200 }));
      await client.set('app/config', '{"debug": true}', 'json');
      expect(mockFetch).toHaveBeenCalledWith(
        'http://localhost:8080/kv/app/config',
        expect.objectContaining({
          method: 'PUT',
          body: '{"debug": true}',
        })
      );
    });

    it('sends format header', async () => {
      const client = new Client('http://localhost:8080');
      mockFetch.mockResolvedValueOnce(new Response('', { status: 200 }));
      await client.set('key', 'value', 'yaml');
      const call = mockFetch.mock.calls[0] as [string, RequestInit];
      const headers = call[1].headers as Headers;
      expect(headers.get('X-Stash-Format')).toBe('yaml');
    });

    it('defaults to text format', async () => {
      const client = new Client('http://localhost:8080');
      mockFetch.mockResolvedValueOnce(new Response('', { status: 200 }));
      await client.set('key', 'value');
      const call = mockFetch.mock.calls[0] as [string, RequestInit];
      const headers = call[1].headers as Headers;
      expect(headers.get('X-Stash-Format')).toBe('text');
    });
  });

  describe('delete', () => {
    it('sends DELETE request', async () => {
      const client = new Client('http://localhost:8080');
      mockFetch.mockResolvedValueOnce(new Response(null, { status: 200 }));
      await client.delete('app/config');
      expect(mockFetch).toHaveBeenCalledWith(
        'http://localhost:8080/kv/app/config',
        expect.objectContaining({ method: 'DELETE' })
      );
    });

    it('throws NotFoundError on 404', async () => {
      const client = new Client('http://localhost:8080');
      mockFetch.mockResolvedValueOnce(new Response('', { status: 404 }));
      await expect(client.delete('missing')).rejects.toBeInstanceOf(NotFoundError);
    });
  });

  describe('list', () => {
    it('returns array of KeyInfo', async () => {
      const client = new Client('http://localhost:8080');
      const response: KeyInfoResponse[] = [
        {
          key: 'app/config',
          size: 100,
          format: 'json',
          secret: false,
          zk_encrypted: false,
          created_at: '2024-01-15T10:30:00Z',
          updated_at: '2024-01-15T10:30:00Z',
        },
      ];
      mockFetch.mockResolvedValueOnce(
        new Response(JSON.stringify(response), { status: 200 })
      );
      const keys = await client.list();
      expect(keys).toHaveLength(1);
      expect(keys[0]?.key).toBe('app/config');
      expect(keys[0]?.format).toBe('json');
    });

    it('sends prefix query parameter', async () => {
      const client = new Client('http://localhost:8080');
      mockFetch.mockResolvedValueOnce(new Response('[]', { status: 200 }));
      await client.list('app/');
      expect(mockFetch).toHaveBeenCalledWith(
        'http://localhost:8080/kv/?prefix=app%2F',
        expect.any(Object)
      );
    });
  });

  describe('info', () => {
    it('returns KeyInfo for existing key', async () => {
      const client = new Client('http://localhost:8080');
      const response: KeyInfoResponse[] = [
        {
          key: 'app/config',
          size: 100,
          format: 'json',
          secret: false,
          zk_encrypted: true,
          created_at: '2024-01-15T10:30:00Z',
          updated_at: '2024-01-15T10:30:00Z',
        },
      ];
      mockFetch.mockResolvedValueOnce(
        new Response(JSON.stringify(response), { status: 200 })
      );
      const info = await client.info('app/config');
      expect(info.key).toBe('app/config');
      expect(info.zkEncrypted).toBe(true);
    });

    it('throws NotFoundError if key not in list', async () => {
      const client = new Client('http://localhost:8080');
      mockFetch.mockResolvedValueOnce(new Response('[]', { status: 200 }));
      await expect(client.info('missing')).rejects.toBeInstanceOf(NotFoundError);
    });
  });

  describe('authentication', () => {
    it('sends Authorization header when token provided', async () => {
      const client = new Client('http://localhost:8080', { token: 'secret' });
      mockFetch.mockResolvedValueOnce(new Response('pong', { status: 200 }));
      await client.ping();
      const call = mockFetch.mock.calls[0] as [string, RequestInit];
      const headers = call[1].headers as Headers;
      expect(headers.get('Authorization')).toBe('Bearer secret');
    });

    it('throws UnauthorizedError on 401', async () => {
      const client = new Client('http://localhost:8080');
      mockFetch.mockResolvedValueOnce(new Response('', { status: 401 }));
      await expect(client.get('key')).rejects.toBeInstanceOf(UnauthorizedError);
    });

    it('throws ForbiddenError on 403', async () => {
      const client = new Client('http://localhost:8080');
      mockFetch.mockResolvedValueOnce(new Response('', { status: 403 }));
      await expect(client.get('key')).rejects.toBeInstanceOf(ForbiddenError);
    });
  });

  describe('retry logic', () => {
    it('retries on network error', async () => {
      const client = new Client('http://localhost:8080', { retries: 2 });
      mockFetch
        .mockRejectedValueOnce(new Error('network error'))
        .mockRejectedValueOnce(new Error('network error'))
        .mockResolvedValueOnce(new Response('pong', { status: 200 }));
      await expect(client.ping()).resolves.toBeUndefined();
      expect(mockFetch).toHaveBeenCalledTimes(3);
    });

    it('does not retry on HTTP errors', async () => {
      const client = new Client('http://localhost:8080', { retries: 2 });
      mockFetch.mockResolvedValueOnce(new Response('', { status: 404 }));
      await expect(client.get('key')).rejects.toBeInstanceOf(NotFoundError);
      expect(mockFetch).toHaveBeenCalledTimes(1);
    });
  });

  describe('close', () => {
    it('exists for API compatibility', () => {
      const client = new Client('http://localhost:8080');
      expect(() => {
        client.close();
      }).not.toThrow();
    });
  });

  describe('empty key validation', () => {
    it('throws on empty key for get', async () => {
      const client = new Client('http://localhost:8080');
      await expect(client.get('')).rejects.toThrow('key cannot be empty');
    });

    it('throws on empty key for getBytes', async () => {
      const client = new Client('http://localhost:8080');
      await expect(client.getBytes('')).rejects.toThrow('key cannot be empty');
    });

    it('throws on empty key for set', async () => {
      const client = new Client('http://localhost:8080');
      await expect(client.set('', 'value')).rejects.toThrow('key cannot be empty');
    });

    it('throws on empty key for delete', async () => {
      const client = new Client('http://localhost:8080');
      await expect(client.delete('')).rejects.toThrow('key cannot be empty');
    });

    it('throws on empty key for info', async () => {
      const client = new Client('http://localhost:8080');
      await expect(client.info('')).rejects.toThrow('key cannot be empty');
    });
  });
});
