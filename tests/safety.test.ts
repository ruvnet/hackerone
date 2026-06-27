import { describe, it, expect } from 'vitest';
import {
  HARD_SAFE_DEFAULTS,
  isWriteAllowed,
  assertNoCredentialLeak,
  SafetyViolationError,
  validateProgramHandle,
  redactPii,
  RateLimiter,
} from '../src/safety.js';

describe('HARD_SAFE_DEFAULTS', () => {
  it('is frozen — cannot be mutated at runtime', () => {
    expect(Object.isFrozen(HARD_SAFE_DEFAULTS)).toBe(true);
    expect(() => {
      // @ts-expect-error mutating frozen
      HARD_SAFE_DEFAULTS.allowWrite = true;
    }).toThrow();
  });
  it('defaults are SAFE', () => {
    expect(HARD_SAFE_DEFAULTS.allowWrite).toBe(false);
    expect(HARD_SAFE_DEFAULTS.mockByDefault).toBe(true);
    expect(HARD_SAFE_DEFAULTS.redactPii).toBe(true);
    expect(HARD_SAFE_DEFAULTS.maxApiCallsPerMin).toBeGreaterThan(0);
  });
});

describe('isWriteAllowed', () => {
  it('both env=1 AND flag=true required', () => {
    expect(isWriteAllowed('1', true)).toBe(true);
    expect(isWriteAllowed('1', false)).toBe(false);
    expect(isWriteAllowed('0', true)).toBe(false);
    expect(isWriteAllowed(undefined, true)).toBe(false);
    expect(isWriteAllowed('true', true)).toBe(false); // strict "1"
  });
});

describe('assertNoCredentialLeak', () => {
  it('passes for clean strings', () => {
    expect(() => assertNoCredentialLeak('hello world')).not.toThrow();
    expect(() => assertNoCredentialLeak({ a: 1, b: 'safe' })).not.toThrow();
    expect(() => assertNoCredentialLeak(null)).not.toThrow();
  });
  it('catches gho_ pattern', () => {
    expect(() => assertNoCredentialLeak('gho_aaaaaaaaaaaaaaaaaaaa1234'))
      .toThrow(SafetyViolationError);
  });
  it('catches AKIA pattern', () => {
    expect(() => assertNoCredentialLeak('AKIAIOSFODNN7EXAMPLE'))
      .toThrow(SafetyViolationError);
  });
  it('catches PEM private-key header', () => {
    expect(() => assertNoCredentialLeak('-----BEGIN RSA PRIVATE KEY-----\nx\n-----END---'))
      .toThrow(SafetyViolationError);
  });
  it('walks objects + arrays', () => {
    expect(() => assertNoCredentialLeak({ x: { y: ['gho_aaaaaaaaaaaaaaaaaaaa1234'] } }))
      .toThrow(SafetyViolationError);
  });
});

describe('validateProgramHandle', () => {
  it('accepts lowercase + dashes + digits', () => {
    expect(() => validateProgramHandle('example-program-1')).not.toThrow();
  });
  it('rejects uppercase', () => {
    expect(() => validateProgramHandle('Example')).toThrow(SafetyViolationError);
  });
  it('rejects path traversal', () => {
    expect(() => validateProgramHandle('../evil')).toThrow(SafetyViolationError);
  });
  it('rejects empty', () => {
    expect(() => validateProgramHandle('')).toThrow(SafetyViolationError);
  });
});

describe('redactPii', () => {
  it('redacts emails', () => {
    expect(redactPii('contact me at hacker@example.com')).toBe('contact me at <email>');
  });
  it('redacts IPs', () => {
    expect(redactPii('host 192.168.1.1 sent the request')).toContain('<ip>');
  });
  it('redacts phone-shaped strings', () => {
    expect(redactPii('call 555-123-4567')).toContain('<phone>');
  });
  it('leaves clean text alone', () => {
    expect(redactPii('hello world')).toBe('hello world');
  });
});

describe('RateLimiter', () => {
  it('starts at max', () => {
    const rl = new RateLimiter(5);
    expect(rl.remaining).toBe(5);
  });
  it('consumes tokens', () => {
    const rl = new RateLimiter(3);
    expect(rl.tryConsume()).toBe(true);
    expect(rl.tryConsume()).toBe(true);
    expect(rl.tryConsume()).toBe(true);
    expect(rl.tryConsume()).toBe(false);
  });
  it('refills after 60s window', () => {
    let now = 1_000_000;
    const rl = new RateLimiter(2, () => now);
    expect(rl.tryConsume()).toBe(true);
    expect(rl.tryConsume()).toBe(true);
    expect(rl.tryConsume()).toBe(false);
    now += 61_000;
    expect(rl.tryConsume()).toBe(true);
  });
});
