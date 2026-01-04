import { describe, it, expect } from 'vitest';
import { Client } from '../client.js';
import { StashError } from '../errors.js';

describe('Subscription', () => {
  describe('subscribe methods', () => {
    it('subscribe creates subscription', () => {
      const client = new Client('http://localhost:8080');
      const sub = client.subscribe('app/config');
      expect(sub).toBeDefined();
      expect(typeof sub.close).toBe('function');
      expect(typeof sub[Symbol.asyncIterator]).toBe('function');
      sub.close();
    });

    it('subscribe throws on empty key', () => {
      const client = new Client('http://localhost:8080');
      expect(() => client.subscribe('')).toThrow(StashError);
      expect(() => client.subscribe('')).toThrow('key cannot be empty');
    });

    it('subscribe handles nested keys', () => {
      const client = new Client('http://localhost:8080');
      const sub = client.subscribe('app/config/database');
      expect(sub).toBeDefined();
      sub.close();
    });

    it('subscribePrefix creates subscription', () => {
      const client = new Client('http://localhost:8080');
      const sub = client.subscribePrefix('app');
      expect(sub).toBeDefined();
      sub.close();
    });

    it('subscribePrefix throws on empty prefix', () => {
      const client = new Client('http://localhost:8080');
      expect(() => client.subscribePrefix('')).toThrow(StashError);
      expect(() => client.subscribePrefix('')).toThrow('prefix cannot be empty');
    });

    it('subscribeAll creates subscription', () => {
      const client = new Client('http://localhost:8080');
      const sub = client.subscribeAll();
      expect(sub).toBeDefined();
      sub.close();
    });
  });

  describe('close behavior', () => {
    it('close can be called multiple times', () => {
      const client = new Client('http://localhost:8080');
      const sub = client.subscribe('test');
      sub.close();
      sub.close();
      sub.close();
    });

    it('close works on subscribePrefix', () => {
      const client = new Client('http://localhost:8080');
      const sub = client.subscribePrefix('app');
      sub.close();
    });

    it('close works on subscribeAll', () => {
      const client = new Client('http://localhost:8080');
      const sub = client.subscribeAll();
      sub.close();
    });
  });

  describe('subscription interface', () => {
    it('implements Symbol.asyncIterator', () => {
      const client = new Client('http://localhost:8080');
      const sub = client.subscribe('test');
      expect(sub[Symbol.asyncIterator]).toBeDefined();
      expect(typeof sub[Symbol.asyncIterator]).toBe('function');
      sub.close();
    });

    it('asyncIterator returns AsyncIterator with next method', () => {
      const client = new Client('http://localhost:8080');
      const sub = client.subscribe('test');
      const iterator = sub[Symbol.asyncIterator]();
      expect(iterator).toBeDefined();
      expect(typeof iterator.next).toBe('function');
      sub.close();
    });
  });
});
