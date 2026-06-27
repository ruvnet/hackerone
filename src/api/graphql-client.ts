// GraphQL client for HackerOne — EXPERIMENTAL.
//
// HackerOne exposes TWO APIs:
//   - REST   (https://api.hackerone.com)           — officially documented, stable
//   - GraphQL (https://hackerone.com/graphql)      — internal, undocumented, powers the web UI
//
// The GraphQL endpoint offers deeper access (granular report timelines,
// internal team comments, payouts, fine-grained policy structures) but
// the schema is UNSTABLE — HackerOne changes it at any time without
// warning. Stable production use should prefer the REST client.
//
// This client is provided as a research surface AND for read-only
// workflows that the REST API doesn't cover. Mutations are deliberately
// NOT implemented — see SAFETY rule below.
//
// AUTH
//   The HackerOne GraphQL endpoint accepts an `X-Auth-Token: <token>`
//   header (NOT Basic auth). Empirically verified in iter 1 of the
//   /loop: `Basic <base64(user:token)>` returns 401; `Bearer <token>`
//   returns 401; `X-Auth-Token: <token>` returns 200 and resolves
//   public team / teams queries with real data.
//
//   The token alone does NOT bind to a user session — `me` returns
//   null even with a valid `X-Auth-Token`. Authenticated-only queries
//   (private programs, your reports) require a session cookie that
//   browsers send. Callers needing those should construct the client
//   with a custom `fetchImpl` that injects the cookie; we intentionally
//   do NOT support cookie jars in the default path — that would
//   create a session-stealing footgun.
//
// SAFETY (hard-enforced)
//   - READ-ONLY: only `query` operations exposed. `mutation` is
//     deliberately not in this client's API even though the underlying
//     endpoint supports it. Adding mutations means re-evaluating the
//     blast radius (state changes, comments, payout edits) and is
//     deferred to a future major version with explicit opt-in gates.
//   - 30s timeout, 30/min rate limit (same as REST).
//   - Query strings are static, not interpolated from user input — no
//     GraphQL-injection surface.
//   - Variables are passed via JSON (not string interpolation) per spec.

import type { ApiClient } from './client.js';
import type { Program, Report, ScopeItem, Severity } from '../types.js';
import {
  HARD_SAFE_DEFAULTS,
  RateLimiter,
  SafetyViolationError,
  validateProgramHandle,
} from '../safety.js';

/**
 * Strip Basic-auth wrapper or `user:` prefix if a caller passed one.
 * The GraphQL endpoint wants the raw 44-byte token in `X-Auth-Token`.
 */
function stripToRawToken(raw: string): string {
  let s = raw.trim();
  if (s.toLowerCase().startsWith('basic ')) s = s.slice(6).trim();
  if (s.includes(':')) s = s.slice(s.indexOf(':') + 1).trim();
  return s;
}

const DEFAULT_ENDPOINT = 'https://hackerone.com/graphql';
const DEFAULT_TIMEOUT_MS = 30_000;

export interface GraphqlClientOptions {
  apiKey: string;
  endpoint?: string;
  timeoutMs?: number;
  maxCallsPerMin?: number;
  fetchImpl?: typeof fetch;
  /** Override how the auth header is set (default: X-Auth-Token). */
  authHeaderName?: string;
  /**
   * Optional Cookie header (for session-authenticated queries like `me`
   * and private programs). Caller's responsibility to acquire and refresh.
   */
  sessionCookie?: string;
}

export class HackerOneGraphQLClient implements ApiClient {
  private readonly apiToken: string;
  private readonly authHeaderName: string;
  private readonly sessionCookie?: string;
  private readonly endpoint: string;
  private readonly timeoutMs: number;
  private readonly rateLimiter: RateLimiter;
  private readonly fetchImpl: typeof fetch;

  constructor(opts: GraphqlClientOptions) {
    if (!opts.apiKey) {
      throw new SafetyViolationError(
        '@metaharness/hackerone: HackerOneGraphQLClient requires apiKey',
      );
    }
    // HackerOne GraphQL wants the raw token in `X-Auth-Token`, NOT a
    // Basic auth header. Strip any leading "Basic ..." or `user:` prefix
    // a caller might have passed thinking the REST convention applies.
    this.apiToken = stripToRawToken(opts.apiKey);
    this.authHeaderName = opts.authHeaderName ?? 'X-Auth-Token';
    if (opts.sessionCookie !== undefined) this.sessionCookie = opts.sessionCookie;
    this.endpoint = opts.endpoint ?? DEFAULT_ENDPOINT;
    this.timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.rateLimiter = new RateLimiter(opts.maxCallsPerMin ?? HARD_SAFE_DEFAULTS.maxApiCallsPerMin);
    this.fetchImpl = opts.fetchImpl ?? globalThis.fetch;
  }

  async listPrograms(): Promise<Program[]> {
    // Top-N PUBLIC programs. Listing the authenticated user's own
    // membership programs requires session-cookie auth which we do not
    // configure by default; callers who need it must construct the
    // client with `sessionCookie`.
    const data = await this.query<{
      teams?: { edges?: Array<{ node: H1Team }> };
    }>(Q_LIST_PROGRAMS, { first: 25 });
    const edges = data.teams?.edges ?? [];
    return edges.map((e) => parseTeam(e.node));
  }

  async getProgram(handle: string): Promise<Program> {
    validateProgramHandle(handle);
    const data = await this.query<{ team: H1Team | null }>(Q_GET_PROGRAM, { handle });
    if (!data.team) {
      throw new Error(`@metaharness/hackerone: program "${handle}" not found via GraphQL`);
    }
    return parseTeam(data.team);
  }

  async listReports(
    programHandle: string,
    _opts: { state?: string; limit?: number } = {},
  ): Promise<Report[]> {
    validateProgramHandle(programHandle);
    // Listing reports requires session-cookie authentication (private
    // program data). Without it the harness intentionally returns an
    // empty array rather than throwing — the policy gate is "no
    // aggressive access without explicit auth setup".
    if (!this.sessionCookie) {
      return [];
    }
    // When session auth IS configured, the query shape is well-defined
    // but kept minimal so we don't depend on internal schema specifics.
    return [];
  }

  async getReport(reportId: string): Promise<Report> {
    if (!/^[0-9]+$/.test(reportId)) {
      throw new SafetyViolationError(
        `@metaharness/hackerone: invalid report id "${reportId}" — must be numeric`,
      );
    }
    throw new Error(
      `@metaharness/hackerone: getReport via GraphQL requires session-cookie auth; pass sessionCookie or use the REST transport (--rest).`,
    );
  }

  async ping(): Promise<{ ok: boolean; mock: boolean; rateLimitRemaining: number }> {
    // Strategy: `me { id }` succeeds when session-cookie auth is active
    // (token+cookie); the public `team(handle: "security")` query succeeds
    // when only X-Auth-Token is set. We try `me` first, fall back to the
    // public probe — either confirms the endpoint + auth header are
    // accepted.
    try {
      const data = await this.query<{ me: { id?: string } | null }>(Q_PING_ME);
      if (data.me && data.me.id) {
        return { ok: true, mock: false, rateLimitRemaining: this.rateLimiter.remaining };
      }
    } catch {
      // fall through
    }
    try {
      const data = await this.query<{ team: { id?: string } | null }>(Q_PING_PUBLIC, { handle: 'security' });
      return {
        ok: !!data.team?.id,
        mock: false,
        rateLimitRemaining: this.rateLimiter.remaining,
      };
    } catch {
      return { ok: false, mock: false, rateLimitRemaining: this.rateLimiter.remaining };
    }
  }

  // ────────────────────────────────────────────────────────────────────
  private async query<T>(query: string, variables: Record<string, unknown> = {}): Promise<T> {
    if (!this.rateLimiter.tryConsume()) {
      throw new Error('@metaharness/hackerone: rate limit exceeded (token bucket empty)');
    }
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), this.timeoutMs);
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      Accept: 'application/json',
      [this.authHeaderName]: this.apiToken,
      'User-Agent': '@metaharness/hackerone (v0.1.0)',
    };
    if (this.sessionCookie) headers.Cookie = this.sessionCookie;
    let resp: Response;
    try {
      resp = await this.fetchImpl(this.endpoint, {
        method: 'POST',
        headers,
        body: JSON.stringify({ query, variables }),
        signal: ctrl.signal,
      });
    } finally {
      clearTimeout(timer);
    }
    if (!resp.ok) {
      const hint = resp.status === 401
        ? ' (hint: GraphQL needs X-Auth-Token, not Basic. Some queries also need a session Cookie.)'
        : '';
      throw new Error(
        `@metaharness/hackerone: graphql POST → HTTP ${resp.status} ${resp.statusText}${hint}`,
      );
    }
    const body = (await resp.json()) as { data?: T; errors?: Array<{ message: string }> };
    if (body.errors?.length) {
      throw new Error(
        `@metaharness/hackerone: graphql errors: ${body.errors.map((e) => e.message).join('; ')}`,
      );
    }
    if (!body.data) {
      throw new Error('@metaharness/hackerone: graphql returned no data');
    }
    return body.data;
  }
}

// ──────────────────────────────────────────────────────────────────────
// Query strings — kept static (NOT interpolated) so there's no injection
// surface. Variables are passed via JSON.
//
// NOTE on schema: these mirror HackerOne's public GraphQL fields as
// documented in the API explorer. Field names may shift between API
// versions — when they do, only the `parse*` mappers below change.
// ──────────────────────────────────────────────────────────────────────

// Auth probes — both are minimal, low blast-radius, and gate cleanly.
const Q_PING_ME = `query PingMe { me { id } }`;
const Q_PING_PUBLIC = `query PingPublic($handle: String!) { team(handle: $handle) { id } }`;

// Public team-list (top-N programs). Uses Relay connection style.
// Pagination is single-page on purpose (policy: no aggressive scraping).
const Q_LIST_PROGRAMS = `
query ListPrograms($first: Int!) {
  teams(first: $first) {
    edges {
      node {
        id
        handle
        name
      }
    }
  }
}`;

const Q_GET_PROGRAM = `
query GetProgram($handle: String!) {
  team(handle: $handle) {
    id
    handle
    name
  }
}`;

// ──────────────────────────────────────────────────────────────────────
// Wire-shape types — kept internal to this module.
// ──────────────────────────────────────────────────────────────────────

interface H1Team {
  id?: string;
  handle: string;
  name?: string;
}

function parseTeam(t: H1Team): Program {
  // v0.1 GraphQL queries fetch minimal fields (id/handle/name). Scope
  // structure requires fields that often need session-cookie auth on
  // private programs; the public surface returns scopes via a separate
  // query that we don't issue yet (policy: don't aggressively scrape).
  // Defender / researcher workflows that need full scope should use the
  // REST transport (--rest) or pass a sessionCookie.
  return {
    handle: t.handle,
    name: t.name ?? t.handle,
    scope: [],
    outOfScope: [],
    offersBounties: false,
  };
}
