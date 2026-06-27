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
//   The internal GraphQL endpoint primarily authenticates with the same
//   session+CSRF tokens the web UI uses, NOT the REST API key. For
//   harness use, we accept the same `HACKERONE_API_KEY` env var and
//   pass it as a Basic-auth header — this works for the subset of
//   GraphQL queries that share REST auth, and gives a clear failure
//   signal (HTTP 401) when a query needs session cookies instead.
//
//   Callers needing session-cookie auth should construct the client
//   with a custom `buildAuthHeader` or `fetchImpl` that injects the
//   needed headers. We intentionally do NOT support cookie jars in the
//   default path — that would create a session-stealing footgun.
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
import { toBasicAuthHeader } from './key-source.js';

const DEFAULT_ENDPOINT = 'https://hackerone.com/graphql';
const DEFAULT_TIMEOUT_MS = 30_000;

export interface GraphqlClientOptions {
  apiKey: string;
  endpoint?: string;
  timeoutMs?: number;
  maxCallsPerMin?: number;
  fetchImpl?: typeof fetch;
  /** Override the auth header builder (e.g., to use Bearer instead of Basic). */
  buildAuthHeader?: (apiKey: string) => string;
}

export class HackerOneGraphQLClient implements ApiClient {
  private readonly authHeader: string;
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
    const headerBuilder = opts.buildAuthHeader ?? toBasicAuthHeader;
    this.authHeader = headerBuilder(opts.apiKey);
    this.endpoint = opts.endpoint ?? DEFAULT_ENDPOINT;
    this.timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.rateLimiter = new RateLimiter(opts.maxCallsPerMin ?? HARD_SAFE_DEFAULTS.maxApiCallsPerMin);
    this.fetchImpl = opts.fetchImpl ?? globalThis.fetch;
  }

  async listPrograms(): Promise<Program[]> {
    const data = await this.query<{ me: { membership_groups?: { nodes: Array<{ team: H1Team }> } } }>(
      Q_LIST_PROGRAMS,
    );
    const nodes = data.me?.membership_groups?.nodes ?? [];
    return nodes.map((n) => parseTeam(n.team));
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
    opts: { state?: string; limit?: number } = {},
  ): Promise<Report[]> {
    validateProgramHandle(programHandle);
    const limit = Math.min(100, Math.max(1, opts.limit ?? 25));
    const states = opts.state ? [opts.state] : null;
    const data = await this.query<{ team: { reports: { nodes: H1Report[] } } | null }>(
      Q_LIST_REPORTS,
      { handle: programHandle, first: limit, states },
    );
    const nodes = data.team?.reports?.nodes ?? [];
    return nodes.map((n) => parseReport(n, programHandle));
  }

  async getReport(reportId: string): Promise<Report> {
    if (!/^[0-9]+$/.test(reportId)) {
      throw new SafetyViolationError(
        `@metaharness/hackerone: invalid report id "${reportId}" — must be numeric`,
      );
    }
    const data = await this.query<{ report: H1Report | null }>(Q_GET_REPORT, { id: reportId });
    if (!data.report) {
      throw new Error(`@metaharness/hackerone: report "${reportId}" not found via GraphQL`);
    }
    const programHandle =
      data.report.team?.handle ?? data.report.program?.handle ?? 'unknown';
    return parseReport(data.report, programHandle);
  }

  async ping(): Promise<{ ok: boolean; mock: boolean; rateLimitRemaining: number }> {
    try {
      await this.query<{ me: { username: string } }>(Q_PING);
      return { ok: true, mock: false, rateLimitRemaining: this.rateLimiter.remaining };
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
    let resp: Response;
    try {
      resp = await this.fetchImpl(this.endpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Accept: 'application/json',
          Authorization: this.authHeader,
          'User-Agent': '@metaharness/hackerone (v0.1.0)',
        },
        body: JSON.stringify({ query, variables }),
        signal: ctrl.signal,
      });
    } finally {
      clearTimeout(timer);
    }
    if (!resp.ok) {
      throw new Error(
        `@metaharness/hackerone: graphql POST → HTTP ${resp.status} ${resp.statusText}`,
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

const Q_PING = `query Ping { me { username } }`;

const Q_LIST_PROGRAMS = `
query ListPrograms {
  me {
    membership_groups {
      nodes {
        team {
          handle
          name
          offers_bounties
          updated_at
          structured_scopes {
            nodes {
              asset_identifier
              asset_type
              eligible_for_bounty
              eligible_for_submission
              max_severity
              instruction
            }
          }
        }
      }
    }
  }
}`;

const Q_GET_PROGRAM = `
query GetProgram($handle: String!) {
  team(handle: $handle) {
    handle
    name
    offers_bounties
    updated_at
    structured_scopes {
      nodes {
        asset_identifier
        asset_type
        eligible_for_bounty
        eligible_for_submission
        max_severity
        instruction
      }
    }
  }
}`;

const Q_LIST_REPORTS = `
query ListReports($handle: String!, $first: Int!, $states: [String!]) {
  team(handle: $handle) {
    reports(first: $first, state: $states) {
      nodes {
        id
        title
        state
        created_at
        vulnerability_information
        bounty_awarded_amount
        severity { rating score }
        weakness { external_id name }
        structured_scope { asset_identifier }
      }
    }
  }
}`;

const Q_GET_REPORT = `
query GetReport($id: ID!) {
  report(id: $id) {
    id
    title
    state
    created_at
    vulnerability_information
    bounty_awarded_amount
    severity { rating score }
    weakness { external_id name }
    structured_scope { asset_identifier }
    team { handle }
    program { handle }
  }
}`;

// ──────────────────────────────────────────────────────────────────────
// Wire-shape types — kept internal to this module.
// ──────────────────────────────────────────────────────────────────────

interface H1Team {
  handle: string;
  name?: string;
  offers_bounties?: boolean;
  updated_at?: string;
  structured_scopes?: { nodes: H1Scope[] };
}

interface H1Scope {
  asset_identifier: string;
  asset_type: string;
  eligible_for_bounty?: boolean;
  eligible_for_submission?: boolean;
  max_severity?: string;
  instruction?: string;
}

interface H1Report {
  id: string;
  title: string;
  state: string;
  created_at?: string;
  vulnerability_information?: string;
  bounty_awarded_amount?: number;
  severity?: { rating?: string; score?: number };
  weakness?: { external_id?: string; name?: string };
  structured_scope?: { asset_identifier?: string };
  team?: { handle?: string };
  program?: { handle?: string };
}

function parseTeam(t: H1Team): Program {
  const scopes = t.structured_scopes?.nodes ?? [];
  const inScope = scopes
    .filter((s) => s.eligible_for_submission !== false)
    .map(parseScope);
  const outOfScope = scopes
    .filter((s) => s.eligible_for_submission === false)
    .map(parseScope);
  const out: Program = {
    handle: t.handle,
    name: t.name ?? t.handle,
    scope: inScope,
    outOfScope,
    offersBounties: t.offers_bounties ?? false,
  };
  if (t.updated_at !== undefined) out.updatedAt = t.updated_at;
  return out;
}

function parseScope(s: H1Scope): ScopeItem {
  const out: ScopeItem = {
    identifier: s.asset_identifier,
    assetType: s.asset_type,
  };
  if (s.eligible_for_bounty !== undefined) out.eligibleForBounty = s.eligible_for_bounty;
  if (s.max_severity) out.maxSeverity = s.max_severity.toLowerCase() as Severity;
  if (s.instruction !== undefined) out.instructions = s.instruction;
  return out;
}

function parseReport(r: H1Report, programHandleFallback: string): Report {
  const asset = r.structured_scope?.asset_identifier ?? 'unknown';
  const severityRaw = r.severity?.rating?.toLowerCase();
  const severity = (
    ['none', 'low', 'medium', 'high', 'critical'].includes(severityRaw ?? '')
      ? severityRaw
      : undefined
  ) as Severity | undefined;
  const finding: Report['finding'] = {
    id: r.id,
    title: r.title,
    description: r.vulnerability_information ?? '',
    asset,
  };
  if (r.severity?.score !== undefined) finding.cvssScore = r.severity.score;
  if (severity !== undefined) finding.severity = severity;
  if (r.weakness?.external_id !== undefined) finding.cwe = r.weakness.external_id;
  if (r.created_at !== undefined) finding.createdAt = r.created_at;
  const out: Report = {
    id: r.id,
    programHandle: r.team?.handle ?? r.program?.handle ?? programHandleFallback,
    state: r.state as Report['state'],
    finding,
  };
  if (r.created_at !== undefined) out.submittedAt = r.created_at;
  if (r.bounty_awarded_amount !== undefined) out.bountyAmount = r.bounty_awarded_amount;
  return out;
}
