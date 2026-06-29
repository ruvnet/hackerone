// Tiny in-memory LRU cache for read-only API responses.
//
// Why: batch workflows (`triage-batch`, repeated `assets` calls in a
// recon pipeline, multi-handle scope sweeps) re-fetch the same program
// dozens of times. The HackerOne API doesn't penalize that, but it
// burns tokens off our rate-limit bucket and adds round-trip latency
// the operator can feel.
//
// Why not memoize globally: a long-running process polling distinct
// programs would grow unbounded. LRU + TTL caps both memory + staleness.
//
// SAFETY:
//   - Cache stays per-process. Never written to disk.
//   - No credential, no session cookie, no API key reaches the cache key.
//   - TTL defaults to 60s — short enough that scope changes during a
//     batch run get picked up on the next outer invocation.

export interface LruOptions {
  /** Max distinct keys to retain. Evicted least-recently-used. */
  maxKeys?: number;
  /** Time-to-live in milliseconds. 0 disables TTL (LRU-only). */
  ttlMs?: number;
  /** Override clock (tests). */
  now?: () => number;
}

interface Entry<V> {
  value: V;
  expiresAt: number;
}

/**
 * Simple LRU with TTL. Map iteration order in JS is insertion-order,
 * so we re-insert on access to bump to the MRU end without an extra
 * linked list. set() and get() are amortized O(1).
 */
export class Lru<V> {
  private readonly maxKeys: number;
  private readonly ttlMs: number;
  private readonly store = new Map<string, Entry<V>>();
  private readonly _now: () => number;
  private _hits = 0;
  private _misses = 0;

  constructor(opts: LruOptions = {}) {
    this.maxKeys = opts.maxKeys ?? 128;
    this.ttlMs = opts.ttlMs ?? 60_000;
    this._now = opts.now ?? Date.now;
  }

  get(key: string): V | undefined {
    const entry = this.store.get(key);
    if (!entry) {
      this._misses += 1;
      return undefined;
    }
    if (this.ttlMs > 0 && this._now() > entry.expiresAt) {
      this.store.delete(key);
      this._misses += 1;
      return undefined;
    }
    // Bump to MRU
    this.store.delete(key);
    this.store.set(key, entry);
    this._hits += 1;
    return entry.value;
  }

  set(key: string, value: V): void {
    if (this.store.has(key)) this.store.delete(key);
    this.store.set(key, {
      value,
      expiresAt: this.ttlMs > 0 ? this._now() + this.ttlMs : Number.POSITIVE_INFINITY,
    });
    if (this.store.size > this.maxKeys) {
      const lru = this.store.keys().next().value;
      if (lru !== undefined) this.store.delete(lru);
    }
  }

  /** Test/diagnostics: hit/miss counters since construction. */
  stats(): { hits: number; misses: number; size: number } {
    return { hits: this._hits, misses: this._misses, size: this.store.size };
  }

  clear(): void {
    this.store.clear();
    this._hits = 0;
    this._misses = 0;
  }
}

/**
 * Async memoization: wrap a fetcher so repeat calls with the same key
 * dedupe + serve from cache. Concurrent calls for the same key share
 * a single in-flight Promise (prevents thundering herd).
 */
export function asyncMemo<K extends string, V>(
  cache: Lru<V>,
  fetcher: (key: K) => Promise<V>,
): (key: K) => Promise<V> {
  const inflight = new Map<K, Promise<V>>();
  return async (key: K): Promise<V> => {
    const hit = cache.get(key);
    if (hit !== undefined) return hit;
    const pending = inflight.get(key);
    if (pending) return pending;
    const p = (async () => {
      try {
        const v = await fetcher(key);
        cache.set(key, v);
        return v;
      } finally {
        inflight.delete(key);
      }
    })();
    inflight.set(key, p);
    return p;
  };
}
