// Researcher-side scope analysis.
//
// Given a Program, surface the in-scope assets ranked by bounty potential
// (maxSeverity * eligibleForBounty * recency) and suggest a test plan
// per asset based on its assetType.
//
// Output is deterministic and offline — no live API calls, no LLM. The
// goal: give a researcher a "where do I start?" answer that they can
// then verify against the program's actual policy.

import type { Program, ScopeAnalysis, ScopeItem, Severity } from '../types.js';

/** Severity → bounty-potential weight. */
const SEVERITY_WEIGHT: Record<Severity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  none: 0,
};

/** Per-assetType suggested test families. Researcher-tunable per program. */
const TEST_CHECKLIST: Record<string, string[]> = {
  URL: [
    'authentication bypass',
    'authorization (IDOR / privilege escalation)',
    'XSS (reflected, stored, DOM)',
    'CSRF on state-changing endpoints',
    'SSRF on URL/webhook input fields',
    'SQL injection on search/filter parameters',
    'open redirect on auth flows',
    'rate limiting on sensitive endpoints',
  ],
  DOMAIN: [
    'subdomain takeover',
    'DNS misconfiguration',
    'cert transparency log review',
    'wildcard subdomain enumeration',
  ],
  API: [
    'broken authentication',
    'mass assignment / parameter pollution',
    'IDOR via numeric/UUID id',
    'rate limit bypass',
    'insufficient input validation',
    'missing scope/permission check on mutations',
  ],
  IOS_APP_STORE: [
    'hardcoded secrets in plist/binary',
    'insecure data storage (Keychain misuse)',
    'cert pinning bypass',
    'jailbroken device detection bypass',
  ],
  ANDROID_PLAY_STORE: [
    'hardcoded secrets in APK',
    'insecure data storage (SharedPreferences)',
    'exported Activity / Provider / Service',
    'root detection bypass',
    'tapjacking / overlay',
  ],
  GITHUB: [
    'leaked secrets in commit history',
    'CI/CD config exposing tokens',
    'release artifact integrity',
  ],
};

export function analyzeScope(program: Program): ScopeAnalysis {
  const ranked = [...program.scope].sort((a, b) => weightOf(b) - weightOf(a));
  const suggestedChecks = ranked.map((asset) => ({
    asset: asset.identifier,
    checks: TEST_CHECKLIST[asset.assetType] ?? TEST_CHECKLIST['URL'] ?? [],
  }));
  return {
    programHandle: program.handle,
    testableAssets: ranked,
    suggestedChecks,
    forbidden: program.outOfScope,
    offersBounties: program.offersBounties,
  };
}

function weightOf(item: ScopeItem): number {
  const sev = item.maxSeverity ?? 'medium';
  const sevW = SEVERITY_WEIGHT[sev];
  const bountyW = item.eligibleForBounty ? 1.5 : 1;
  return sevW * bountyW;
}
