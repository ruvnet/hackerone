// In-memory mock HackerOne client.
//
// This is the default when no API key is found. Lets the entire CLI +
// MCP surface be exercised offline with $0 spend. The fixtures are
// realistic enough to drive triage/research logic but explicitly tagged
// (id prefix `mock-`) so it's never mistaken for real data.

import type { ApiClient } from './client.js';
import type { Program, Report, ScopeItem, Severity } from '../types.js';

const FIXTURE_PROGRAMS: Program[] = [
  {
    handle: 'example-program',
    name: 'Example Corp',
    offersBounties: true,
    updatedAt: '2026-06-01T00:00:00Z',
    scope: [
      mockScope('*.example.com', 'URL', 'critical', true),
      mockScope('api.example.com', 'URL', 'critical', true),
      mockScope('com.example.android', 'ANDROID_PLAY_STORE', 'high', true),
      mockScope('id1234.ios', 'IOS_APP_STORE', 'high', true),
    ],
    outOfScope: [
      mockScope('marketing.example.com', 'URL', undefined, false),
      mockScope('static.example.com', 'URL', undefined, false),
    ],
  },
  {
    handle: 'demo-vdp',
    name: 'Demo VDP (no bounty)',
    offersBounties: false,
    updatedAt: '2026-06-01T00:00:00Z',
    scope: [mockScope('vdp.demo.test', 'URL', 'medium', false)],
    outOfScope: [],
  },
];

const FIXTURE_REPORTS: Report[] = [
  {
    id: 'mock-1001',
    programHandle: 'example-program',
    state: 'new',
    submittedAt: '2026-06-20T10:00:00Z',
    finding: {
      id: 'mock-1001',
      title: 'Reflected XSS in /search?q=',
      description:
        'The `q` query parameter is reflected unescaped into the search results page. Payload: `"><img src=x onerror=alert(1)>`',
      asset: 'api.example.com',
      cwe: 'CWE-79',
      owasp: 'A03:2021',
      severity: 'high',
      cvssScore: 7.4,
      cvssVector: 'AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N',
      reproduction:
        '1. GET https://api.example.com/search?q="><img src=x onerror=alert(1)>\n2. Observe alert fires in the rendered HTML',
      createdAt: '2026-06-20T10:00:00Z',
    },
  },
  {
    id: 'mock-1002',
    programHandle: 'example-program',
    state: 'new',
    submittedAt: '2026-06-21T11:00:00Z',
    finding: {
      id: 'mock-1002',
      title: 'Reflected XSS via search query parameter q',
      description:
        // Intentionally a paraphrase of mock-1001: same bug, same asset,
        // same CWE — different researcher's wording. Shares 60%+ of the
        // language so the fuzzy dedupe stage catches it at default threshold.
        'The q query parameter is reflected unescaped into the search results page. Payload: `<svg/onload=alert(1)>` fires alert in the rendered HTML.',
      asset: 'api.example.com',
      cwe: 'CWE-79',
      severity: 'high',
      cvssScore: 7.1,
      createdAt: '2026-06-21T11:00:00Z',
    },
  },
  {
    id: 'mock-1003',
    programHandle: 'example-program',
    state: 'new',
    submittedAt: '2026-06-22T09:00:00Z',
    finding: {
      id: 'mock-1003',
      title: 'SSRF via /webhooks/test endpoint',
      description:
        'The `url` field in POST /webhooks/test does not validate the destination — server fetches arbitrary internal URLs (169.254.169.254 reaches the AWS IMDS).',
      asset: 'api.example.com',
      cwe: 'CWE-918',
      owasp: 'A10:2021',
      severity: 'critical',
      cvssScore: 9.1,
      cvssVector: 'AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N',
      createdAt: '2026-06-22T09:00:00Z',
    },
  },
  {
    id: 'mock-1004',
    programHandle: 'example-program',
    state: 'new',
    submittedAt: '2026-06-22T15:00:00Z',
    finding: {
      id: 'mock-1004',
      title: 'XSS on out-of-scope marketing page',
      description: 'XSS on https://marketing.example.com/?ref= — this asset is OUT OF SCOPE.',
      asset: 'marketing.example.com',
      cwe: 'CWE-79',
      severity: 'medium',
      cvssScore: 5.4,
      createdAt: '2026-06-22T15:00:00Z',
    },
  },
];

export class MockHackerOneClient implements ApiClient {
  private readonly programs: Program[];
  private readonly reports: Report[];
  private callCount = 0;

  constructor(opts: { programs?: Program[]; reports?: Report[] } = {}) {
    this.programs = opts.programs ?? FIXTURE_PROGRAMS;
    this.reports = opts.reports ?? FIXTURE_REPORTS;
  }

  async listPrograms(): Promise<Program[]> {
    this.callCount++;
    return this.programs;
  }

  async getProgram(handle: string): Promise<Program> {
    this.callCount++;
    const p = this.programs.find((x) => x.handle === handle);
    if (!p) throw new Error(`@metaharness/hackerone: mock program "${handle}" not found`);
    return p;
  }

  async listReports(
    programHandle: string,
    opts: { state?: string; limit?: number } = {},
  ): Promise<Report[]> {
    this.callCount++;
    let r = this.reports.filter((x) => x.programHandle === programHandle);
    if (opts.state) r = r.filter((x) => x.state === opts.state);
    if (opts.limit) r = r.slice(0, opts.limit);
    return r;
  }

  async getReport(reportId: string): Promise<Report> {
    this.callCount++;
    const r = this.reports.find((x) => x.id === reportId);
    if (!r) throw new Error(`@metaharness/hackerone: mock report "${reportId}" not found`);
    return r;
  }

  async ping(): Promise<{ ok: boolean; mock: boolean; rateLimitRemaining: number }> {
    this.callCount++;
    return { ok: true, mock: true, rateLimitRemaining: Number.POSITIVE_INFINITY };
  }

  /** Test-only: read internal call counter. */
  get calls(): number {
    return this.callCount;
  }
}

function mockScope(
  identifier: string,
  assetType: string,
  maxSeverity: Severity | undefined,
  eligibleForBounty: boolean,
): ScopeItem {
  return {
    identifier,
    assetType,
    maxSeverity,
    eligibleForBounty,
  };
}

/** Exposed for tests that want to seed a specific fixture set. */
export const MOCK_FIXTURES = Object.freeze({
  programs: FIXTURE_PROGRAMS,
  reports: FIXTURE_REPORTS,
});
