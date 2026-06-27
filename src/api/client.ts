// HackerOne API client — read-only, rate-limited, mock-by-default.
//
// Wraps the HackerOne REST/JSON API surface at https://api.hackerone.com.
// Only the endpoints the harness actually needs are exposed here; we add
// more as new triage/research features land.
//
// Safety posture:
//   - All methods are READ-ONLY in v0.1. Writes (state changes, comments,
//     bounties) are NOT implemented and refuse at the API boundary.
//   - RateLimiter caps calls per minute (HARD_SAFE_DEFAULTS.maxApiCallsPerMin).
//   - Every fetch() uses a 30s timeout and AbortController.
//   - Errors are wrapped to never expose the Authorization header in
//     diagnostics.

import type { Program, Report, ScopeItem } from '../types.js';
import {
  HARD_SAFE_DEFAULTS,
  RateLimiter,
  SafetyViolationError,
  validateProgramHandle,
} from '../safety.js';
import { toBasicAuthHeader } from './key-source.js';

const BASE_URL = 'https://api.hackerone.com/v1';
const DEFAULT_TIMEOUT_MS = 30_000;

export interface HackerOneClientOptions {
  apiKey: string;
  baseUrl?: string;
  timeoutMs?: number;
  maxCallsPerMin?: number;
  /** Override fetch (for tests). */
  fetchImpl?: typeof fetch;
}

export interface ApiClient {
  listPrograms(): Promise<Program[]>;
  getProgram(handle: string): Promise<Program>;
  listReports(programHandle: string, opts?: { state?: string; limit?: number }): Promise<Report[]>;
  getReport(reportId: string): Promise<Report>;
  /** Health/diagnostic — never makes real calls in mock mode. */
  ping(): Promise<{ ok: boolean; mock: boolean; rateLimitRemaining: number }>;
}

export class HackerOneClient implements ApiClient {
  private readonly authHeader: string;
  private readonly baseUrl: string;
  private readonly timeoutMs: number;
  private readonly rateLimiter: RateLimiter;
  private readonly fetchImpl: typeof fetch;

  constructor(opts: HackerOneClientOptions) {
    if (!opts.apiKey) {
      throw new SafetyViolationError(
        '@metaharness/hackerone: HackerOneClient requires apiKey — use MockHackerOneClient when no key is available',
      );
    }
    this.authHeader = toBasicAuthHeader(opts.apiKey);
    this.baseUrl = opts.baseUrl ?? BASE_URL;
    this.timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.rateLimiter = new RateLimiter(opts.maxCallsPerMin ?? HARD_SAFE_DEFAULTS.maxApiCallsPerMin);
    this.fetchImpl = opts.fetchImpl ?? globalThis.fetch;
  }

  async listPrograms(): Promise<Program[]> {
    const body = await this.get<{ data: H1Program[] }>('/me/programs');
    return body.data.map(parseProgram);
  }

  async getProgram(handle: string): Promise<Program> {
    validateProgramHandle(handle);
    const body = await this.get<{ data: H1Program }>(`/programs/${encodeURIComponent(handle)}`);
    return parseProgram(body.data);
  }

  async listReports(
    programHandle: string,
    opts: { state?: string; limit?: number } = {},
  ): Promise<Report[]> {
    validateProgramHandle(programHandle);
    const params = new URLSearchParams();
    params.set('filter[program][]', programHandle);
    if (opts.state) params.set('filter[state][]', opts.state);
    if (opts.limit) params.set('page[size]', String(Math.min(100, Math.max(1, opts.limit))));
    const body = await this.get<{ data: H1Report[] }>(`/reports?${params}`);
    return body.data.map(parseReport);
  }

  async getReport(reportId: string): Promise<Report> {
    if (!/^[0-9]+$/.test(reportId)) {
      throw new SafetyViolationError(
        `@metaharness/hackerone: invalid report id "${reportId}" — must be numeric`,
      );
    }
    const body = await this.get<{ data: H1Report }>(`/reports/${reportId}`);
    return parseReport(body.data);
  }

  async ping(): Promise<{ ok: boolean; mock: boolean; rateLimitRemaining: number }> {
    try {
      await this.get<unknown>('/me');
      return { ok: true, mock: false, rateLimitRemaining: this.rateLimiter.remaining };
    } catch {
      return { ok: false, mock: false, rateLimitRemaining: this.rateLimiter.remaining };
    }
  }

  // ────────────────────────────────────────────────────────────────────
  // Internal: rate-limited fetch with timeout.
  // ────────────────────────────────────────────────────────────────────
  private async get<T>(path: string): Promise<T> {
    if (!this.rateLimiter.tryConsume()) {
      throw new Error('@metaharness/hackerone: rate limit exceeded (token bucket empty)');
    }
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), this.timeoutMs);
    let resp: Response;
    try {
      resp = await this.fetchImpl(this.baseUrl + path, {
        method: 'GET',
        headers: {
          Accept: 'application/json',
          Authorization: this.authHeader,
          'User-Agent': '@metaharness/hackerone (v0.1.0)',
        },
        signal: ctrl.signal,
      });
    } finally {
      clearTimeout(timer);
    }
    if (!resp.ok) {
      // Do NOT include headers in the error message — could leak auth state
      throw new Error(
        `@metaharness/hackerone: GET ${path} → HTTP ${resp.status} ${resp.statusText}`,
      );
    }
    return (await resp.json()) as T;
  }
}

// ──────────────────────────────────────────────────────────────────────
// HackerOne JSON-API shape (the wire format, kept internal so consumers
// only see the narrowed shapes from types.ts).
// ──────────────────────────────────────────────────────────────────────

interface H1Program {
  id: string;
  type: string;
  attributes: {
    handle: string;
    name?: string;
    offers_bounties?: boolean;
    updated_at?: string;
  };
  relationships?: {
    structured_scopes?: { data: Array<{ attributes: H1ScopeAttrs }> };
  };
}

interface H1ScopeAttrs {
  asset_identifier: string;
  asset_type: string;
  eligible_for_bounty?: boolean;
  max_severity?: string;
  instruction?: string;
  eligible_for_submission?: boolean;
}

interface H1Report {
  id: string;
  attributes: {
    title: string;
    state: string;
    vulnerability_information?: string;
    severity?: { rating?: string; score?: number };
    cve_ids?: string[];
    created_at?: string;
    bounty_awarded_amount?: number;
  };
  relationships?: {
    program?: { data: { attributes: { handle: string } } };
    structured_scope?: { data: { attributes: { asset_identifier: string } } };
    weakness?: { data: { attributes: { external_id?: string; name?: string } } };
  };
}

function parseProgram(p: H1Program): Program {
  const scopes = p.relationships?.structured_scopes?.data ?? [];
  const inScope = scopes
    .filter((s) => s.attributes.eligible_for_submission !== false)
    .map(parseScopeItem);
  const outOfScope = scopes
    .filter((s) => s.attributes.eligible_for_submission === false)
    .map(parseScopeItem);
  return {
    handle: p.attributes.handle,
    name: p.attributes.name ?? p.attributes.handle,
    scope: inScope,
    outOfScope,
    offersBounties: p.attributes.offers_bounties ?? false,
    updatedAt: p.attributes.updated_at,
  };
}

function parseScopeItem(s: { attributes: H1ScopeAttrs }): ScopeItem {
  return {
    identifier: s.attributes.asset_identifier,
    assetType: s.attributes.asset_type,
    eligibleForBounty: s.attributes.eligible_for_bounty,
    maxSeverity: s.attributes.max_severity?.toLowerCase() as ScopeItem['maxSeverity'],
    instructions: s.attributes.instruction,
  };
}

function parseReport(r: H1Report): Report {
  const programHandle = r.relationships?.program?.data?.attributes?.handle ?? 'unknown';
  const asset = r.relationships?.structured_scope?.data?.attributes?.asset_identifier ?? 'unknown';
  const cwe = r.relationships?.weakness?.data?.attributes?.external_id;
  const severityRaw = r.attributes.severity?.rating?.toLowerCase();
  const severity = (
    ['none', 'low', 'medium', 'high', 'critical'].includes(severityRaw ?? '')
      ? severityRaw
      : undefined
  ) as Report['finding']['severity'];

  return {
    id: r.id,
    programHandle,
    state: r.attributes.state as Report['state'],
    submittedAt: r.attributes.created_at,
    bountyAmount: r.attributes.bounty_awarded_amount,
    finding: {
      id: r.id,
      title: r.attributes.title,
      description: r.attributes.vulnerability_information ?? '',
      cvssScore: r.attributes.severity?.score,
      severity,
      cwe,
      asset,
      createdAt: r.attributes.created_at,
    },
  };
}
