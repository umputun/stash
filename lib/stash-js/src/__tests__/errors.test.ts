import { describe, it, expect } from 'vitest';
import {
  StashError,
  NotFoundError,
  UnauthorizedError,
  ForbiddenError,
  DecryptionError,
  ConnectionError,
  ResponseError,
  isStashError,
  isNotFoundError,
  isUnauthorizedError,
  isForbiddenError,
  isDecryptionError,
  isConnectionError,
  isResponseError,
} from '../errors.js';

describe('StashError', () => {
  it('creates error with message', () => {
    const error = new StashError('test error');
    expect(error.message).toBe('test error');
    expect(error.name).toBe('StashError');
  });

  it('is instance of Error', () => {
    const error = new StashError('test');
    expect(error).toBeInstanceOf(Error);
    expect(error).toBeInstanceOf(StashError);
  });
});

describe('NotFoundError', () => {
  it('creates error with key in message', () => {
    const error = new NotFoundError('app/config');
    expect(error.message).toBe('key not found: app/config');
    expect(error.name).toBe('NotFoundError');
    expect(error.key).toBe('app/config');
  });

  it('is instance of StashError', () => {
    const error = new NotFoundError('test');
    expect(error).toBeInstanceOf(StashError);
    expect(error).toBeInstanceOf(NotFoundError);
  });
});

describe('UnauthorizedError', () => {
  it('creates error with default message', () => {
    const error = new UnauthorizedError();
    expect(error.message).toBe('unauthorized');
    expect(error.name).toBe('UnauthorizedError');
  });

  it('creates error with custom message', () => {
    const error = new UnauthorizedError('invalid token');
    expect(error.message).toBe('invalid token');
  });
});

describe('ForbiddenError', () => {
  it('creates error with default message', () => {
    const error = new ForbiddenError();
    expect(error.message).toBe('forbidden');
    expect(error.name).toBe('ForbiddenError');
  });

  it('creates error with custom message', () => {
    const error = new ForbiddenError('no access to secrets');
    expect(error.message).toBe('no access to secrets');
  });
});

describe('DecryptionError', () => {
  it('creates error with message', () => {
    const error = new DecryptionError('wrong key');
    expect(error.message).toBe('decryption failed: wrong key');
    expect(error.name).toBe('DecryptionError');
  });
});

describe('ConnectionError', () => {
  it('creates error with message', () => {
    const error = new ConnectionError('network timeout');
    expect(error.message).toBe('connection failed: network timeout');
    expect(error.name).toBe('ConnectionError');
  });
});

describe('ResponseError', () => {
  it('creates error with status code', () => {
    const error = new ResponseError(500);
    expect(error.message).toBe('unexpected response: 500');
    expect(error.name).toBe('ResponseError');
    expect(error.statusCode).toBe(500);
  });

  it('creates error with custom message', () => {
    const error = new ResponseError(503, 'service unavailable');
    expect(error.message).toBe('service unavailable');
    expect(error.statusCode).toBe(503);
  });
});

describe('type guards', () => {
  it('isStashError returns true for StashError', () => {
    expect(isStashError(new StashError('test'))).toBe(true);
    expect(isStashError(new NotFoundError('key'))).toBe(true);
    expect(isStashError(new Error('test'))).toBe(false);
    expect(isStashError('string')).toBe(false);
    expect(isStashError(null)).toBe(false);
  });

  it('isNotFoundError returns true for NotFoundError', () => {
    expect(isNotFoundError(new NotFoundError('key'))).toBe(true);
    expect(isNotFoundError(new StashError('test'))).toBe(false);
    expect(isNotFoundError(new Error('test'))).toBe(false);
  });

  it('isUnauthorizedError returns true for UnauthorizedError', () => {
    expect(isUnauthorizedError(new UnauthorizedError())).toBe(true);
    expect(isUnauthorizedError(new StashError('test'))).toBe(false);
  });

  it('isForbiddenError returns true for ForbiddenError', () => {
    expect(isForbiddenError(new ForbiddenError())).toBe(true);
    expect(isForbiddenError(new StashError('test'))).toBe(false);
  });

  it('isDecryptionError returns true for DecryptionError', () => {
    expect(isDecryptionError(new DecryptionError('bad'))).toBe(true);
    expect(isDecryptionError(new StashError('test'))).toBe(false);
  });

  it('isConnectionError returns true for ConnectionError', () => {
    expect(isConnectionError(new ConnectionError('net'))).toBe(true);
    expect(isConnectionError(new StashError('test'))).toBe(false);
  });

  it('isResponseError returns true for ResponseError', () => {
    expect(isResponseError(new ResponseError(500))).toBe(true);
    expect(isResponseError(new StashError('test'))).toBe(false);
  });
});
