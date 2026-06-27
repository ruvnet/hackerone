import { describe, it, expect, vi } from 'vitest';
import { Lru, asyncMemo } from '../src/api/cache.js';

describe('Lru', () => {
  it('returns undefined on miss', () => {
    const lru = new Lru<number>();
    expect(lru.get('x')).toBeUndefined();
    expect(lru.stats().misses).toBe(1);
  });

  it('returns set value on hit', () => {
    const lru = new Lru<number>();
    lru.set('x', 42);
    expect(lru.get('x')).toBe(42);
    expect(lru.stats().hits).toBe(1);
  });

  it('evicts least-recently-used', () => {
    const lru = new Lru<number>({ maxKeys: 2 });
    lru.set('a', 1);
    lru.set('b', 2);
    lru.set('c', 3); // evicts a
    expect(lru.get('a')).toBeUndefined();
    expect(lru.get('b')).toBe(2);
    expect(lru.get('c')).toBe(3);
  });

  it('bumps MRU on access — `a` survives later eviction', () => {
    const lru = new Lru<number>({ maxKeys: 2 });
    lru.set('a', 1);
    lru.set('b', 2);
    expect(lru.get('a')).toBe(1); // bumps a to MRU
    lru.set('c', 3); // now b is LRU, evicted
    expect(lru.get('b')).toBeUndefined();
    expect(lru.get('a')).toBe(1);
  });

  it('respects TTL', () => {
    let now = 1_000_000;
    const lru = new Lru<number>({ ttlMs: 100, now: () => now });
    lru.set('x', 1);
    now += 50;
    expect(lru.get('x')).toBe(1);
    now += 100; // total 150ms — past 100ms TTL
    expect(lru.get('x')).toBeUndefined();
  });

  it('ttlMs=0 disables TTL (LRU-only)', () => {
    let now = 1;
    const lru = new Lru<number>({ ttlMs: 0, now: () => now });
    lru.set('x', 1);
    now += 999_999_999;
    expect(lru.get('x')).toBe(1);
  });

  it('clear resets stats + store', () => {
    const lru = new Lru<number>();
    lru.set('x', 1);
    lru.get('x');
    lru.clear();
    expect(lru.stats().size).toBe(0);
    expect(lru.stats().hits).toBe(0);
    expect(lru.get('x')).toBeUndefined();
  });
});

describe('asyncMemo', () => {
  it('caches by key — second call hits cache, fetcher not re-invoked', async () => {
    const fetcher = vi.fn(async (k: string) => `v:${k}`);
    const cache = new Lru<string>();
    const wrapped = asyncMemo<string, string>(cache, fetcher);
    expect(await wrapped('a')).toBe('v:a');
    expect(await wrapped('a')).toBe('v:a');
    expect(fetcher).toHaveBeenCalledTimes(1);
  });

  it('concurrent calls for the same key share a single in-flight promise', async () => {
    const fetcher = vi.fn(async (k: string) => {
      await new Promise((r) => setTimeout(r, 20));
      return `v:${k}`;
    });
    const cache = new Lru<string>();
    const wrapped = asyncMemo<string, string>(cache, fetcher);
    const [a, b] = await Promise.all([wrapped('x'), wrapped('x')]);
    expect(a).toBe('v:x');
    expect(b).toBe('v:x');
    expect(fetcher).toHaveBeenCalledTimes(1); // thundering-herd prevented
  });

  it('different keys are fetched independently', async () => {
    const fetcher = vi.fn(async (k: string) => `v:${k}`);
    const cache = new Lru<string>();
    const wrapped = asyncMemo<string, string>(cache, fetcher);
    await wrapped('a');
    await wrapped('b');
    expect(fetcher).toHaveBeenCalledTimes(2);
  });

  it('a failed fetch is NOT cached — next call retries', async () => {
    let calls = 0;
    const fetcher = vi.fn(async (k: string) => {
      calls++;
      if (calls === 1) throw new Error('boom');
      return `v:${k}`;
    });
    const cache = new Lru<string>();
    const wrapped = asyncMemo<string, string>(cache, fetcher);
    await expect(wrapped('a')).rejects.toThrow('boom');
    expect(await wrapped('a')).toBe('v:a');
    expect(fetcher).toHaveBeenCalledTimes(2);
  });
});
