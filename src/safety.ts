// Hard-enforced safety boundary for @metaharness/hackerone.
//
// Mirrors @metaharness/redblue's posture: the harness is defensive and
// capability-contained. The settings below CANNOT be relaxed via config
// or CLI flags — only by setting matching environment variables, and
// even then the boundary stays narrow.
//
// Anyone reviewing this file should be able to answer in one sentence:
// "What's the worst this harness can do?" → "Issue READ-ONLY HackerOne
// API calls scoped to one program, with a hard rate limit, with the key
// fetched transiently and never logged."

export class SafetyViolationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'SafetyViolationError';
  }
}

/** Hard defaults — enforced at load time, never relaxed by config. */
export const HARD_SAFE_DEFAULTS = Object.freeze({
  /** Never set to true. Reads HACKERONE_ALLOW_WRITE=1 + --allow-write flag both required. */
  allowWrite: false,
  /** Soft rate limit — calls per minute against the HackerOne API. */
  maxApiCallsPerMin: 30,
  /** Max bytes per stored report — prevents accidental large dump. */
  maxReportBytes: 256 * 1024,
  /** Whether to redact reporter/researcher PII from logs. */
  redactPii: true,
  /** Whether the in-memory mock client is the default when no key is present. */
  mockByDefault: true,
});

/**
 * Decide whether the harness is allowed to make WRITE API calls.
 *
 * BOTH conditions must be true:
 *   1. HACKERONE_ALLOW_WRITE env var === "1"
 *   2. The caller explicitly passed allowWriteFlag === true at the API boundary
 *
 * Either alone is insufficient. Defaults to read-only. The function is
 * pure — it never reads from process.env directly; the caller passes the
 * env value in. This makes the gate trivially auditable + testable.
 */
export function isWriteAllowed(envValue: string | undefined, allowWriteFlag: boolean): boolean {
  return envValue === '1' && allowWriteFlag === true;
}

/**
 * Assert that a payload doesn't contain credential-shaped strings.
 *
 * Used to catch accidental leakage of HACKERONE_API_KEY or related
 * secrets into log payloads, fixtures, or stored reports.
 *
 * False positives are fine — better to refuse one fixture than ship a leak.
 */
const CRED_RX_LIST: RegExp[] = [
  /\bsk-[A-Za-z0-9_-]{16,}\b/,        // OpenAI / generic
  /\bgho_[A-Za-z0-9]{20,}\b/,         // GitHub OAuth
  /\bghp_[A-Za-z0-9]{20,}\b/,         // GitHub PAT
  /\bAKIA[0-9A-Z]{16}\b/,             // AWS access key
  /\bbearer\s+[A-Za-z0-9_.\-]{20,}\b/i,
  /\bauthorization\s*[:=]\s*['"]?(basic|bearer)\s+[^\s'"]+/i,
  /-----BEGIN [A-Z ]*PRIVATE KEY-----/,
];

export function assertNoCredentialLeak(payload: unknown, path: string = '<root>'): void {
  if (payload == null) return;
  if (typeof payload === 'string') {
    for (const rx of CRED_RX_LIST) {
      if (rx.test(payload)) {
        throw new SafetyViolationError(
          `@metaharness/hackerone: refusing to handle credential-shaped string at ${path} (matched ${rx})`,
        );
      }
    }
    return;
  }
  if (Array.isArray(payload)) {
    payload.forEach((v, i) => assertNoCredentialLeak(v, `${path}[${i}]`));
    return;
  }
  if (typeof payload === 'object') {
    for (const [k, v] of Object.entries(payload as Record<string, unknown>)) {
      assertNoCredentialLeak(v, `${path}.${k}`);
    }
  }
}

/**
 * Validate a HackerOne program handle is well-formed. Used as a scope
 * guard — the harness only operates on a single program at a time, and
 * the handle is bound to the API call URL, so it MUST be lowercase
 * alphanumeric+dashes only. Anything else is rejected.
 */
const HANDLE_RX = /^[a-z0-9][a-z0-9_-]{0,63}$/;
export function validateProgramHandle(handle: string): void {
  if (!HANDLE_RX.test(handle)) {
    throw new SafetyViolationError(
      `@metaharness/hackerone: invalid program handle "${handle}" — must be lowercase alphanumeric + dashes, ≤64 chars`,
    );
  }
}

/**
 * Redact PII from a string. PII patterns matched:
 *   - email addresses
 *   - phone numbers (US format minimal)
 *   - IP addresses (privacy)
 *   - credit-card-like 16-digit sequences
 *
 * Returns the redacted string. Used before any report content is logged
 * or written to disk.
 */
const PII_PATTERNS: Array<[RegExp, string]> = [
  [/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g, '<email>'],
  [/\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b/g, '<phone>'],
  [/\b(?:\d{1,3}\.){3}\d{1,3}\b/g, '<ip>'],
  [/\b(?:\d[ -]*?){13,19}\b/g, '<cc>'],
];

export function redactPii(input: string): string {
  let s = input;
  for (const [rx, tag] of PII_PATTERNS) {
    s = s.replace(rx, tag);
  }
  return s;
}

/**
 * Per-process API call rate limiter. Token-bucket; refills every minute.
 * Mutates internal state, so wrap once at the API client boundary and
 * call from there.
 */
export class RateLimiter {
  private tokens: number;
  private lastRefill: number;
  private readonly maxPerMin: number;

  constructor(maxPerMin: number = HARD_SAFE_DEFAULTS.maxApiCallsPerMin, nowFn: () => number = Date.now) {
    this.maxPerMin = maxPerMin;
    this.tokens = maxPerMin;
    this.lastRefill = nowFn();
    this._now = nowFn;
  }
  private _now: () => number;

  /** Attempt to consume one token. Returns false if the bucket is empty. */
  tryConsume(): boolean {
    const now = this._now();
    const elapsedMs = now - this.lastRefill;
    if (elapsedMs >= 60_000) {
      const refills = Math.floor(elapsedMs / 60_000);
      this.tokens = Math.min(this.maxPerMin, this.tokens + refills * this.maxPerMin);
      this.lastRefill = now;
    }
    if (this.tokens <= 0) return false;
    this.tokens -= 1;
    return true;
  }

  get remaining(): number {
    return this.tokens;
  }
}
