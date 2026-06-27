import { describe, it, expect } from 'vitest';
import {
  HackerOneApiError,
  GraphQLAuthError,
  GraphQLQueryError,
  RestAuthError,
  NotFoundError,
  RateLimitExceededError,
  TimeoutError,
} from '../src/api/errors.js';

describe('error classes', () => {
  it('GraphQLAuthError surfaces X-Auth-Token hint', () => {
    const e = new GraphQLAuthError('Unauthorized');
    expect(e.message).toContain('401');
    expect(e.hint).toContain('X-Auth-Token');
    expect(e.hint).toContain('HACKERONE_SESSION_COOKIE');
  });

  it('RestAuthError surfaces api-identifier hint', () => {
    const e = new RestAuthError('Unauthorized');
    expect(e.hint).toContain('api-identifier');
    expect(e.hint).toContain('HACKERONE_API_USERNAME');
  });

  it('GraphQLQueryError lists the upstream messages', () => {
    const e = new GraphQLQueryError([{ message: 'foo' }, { message: 'bar' }]);
    expect(e.message).toContain('foo');
    expect(e.message).toContain('bar');
    expect(e.errors.length).toBe(2);
  });

  it('NotFoundError names the resource', () => {
    const e = new NotFoundError('program "missing"');
    expect(e.message).toContain('missing');
  });

  it('RateLimitExceededError suggests a 60s wait', () => {
    const e = new RateLimitExceededError();
    expect(e.hint).toContain('60s');
  });

  it('TimeoutError records the duration', () => {
    const e = new TimeoutError('fetch', 30000);
    expect(e.message).toContain('30000');
  });

  it('toString renders hint when present', () => {
    const e = new GraphQLAuthError('Unauthorized');
    const s = e.toString();
    expect(s).toContain('hint:');
  });

  it('toString omits hint when absent', () => {
    const e = new HackerOneApiError('plain error');
    expect(e.toString()).toBe('plain error');
  });

  it('all errors extend the root HackerOneApiError', () => {
    expect(new GraphQLAuthError('x')).toBeInstanceOf(HackerOneApiError);
    expect(new RestAuthError('x')).toBeInstanceOf(HackerOneApiError);
    expect(new NotFoundError('x')).toBeInstanceOf(HackerOneApiError);
    expect(new RateLimitExceededError()).toBeInstanceOf(HackerOneApiError);
    expect(new TimeoutError('x', 1)).toBeInstanceOf(HackerOneApiError);
    expect(new GraphQLQueryError([{ message: 'x' }])).toBeInstanceOf(HackerOneApiError);
  });

  it('no error message echoes a token-shaped string (sanity)', () => {
    const sample = [
      new GraphQLAuthError('Unauthorized'),
      new RestAuthError('Unauthorized'),
      new GraphQLQueryError([{ message: 'undefinedField' }]),
      new NotFoundError('program "test"'),
      new RateLimitExceededError(),
      new TimeoutError('fetch', 30000),
    ];
    for (const e of sample) {
      const text = e.toString();
      expect(text).not.toMatch(/gho_[A-Za-z0-9]{20,}/);
      expect(text).not.toMatch(/AKIA[0-9A-Z]{16}/);
      expect(text).not.toMatch(/Bearer\s+[A-Za-z0-9_.\-]{20,}/i);
    }
  });
});
