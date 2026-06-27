// Scope check — does this finding target an in-scope asset?
//
// Matches the finding's `asset` against a program's scope+outOfScope
// arrays. The match rules deliberately mirror HackerOne's:
//
//   - Exact identifier match               → matches
//   - Wildcard scope ("*.example.com")     → matches any subdomain
//   - Mobile bundle id / store id          → exact only (no wildcards)
//
// outOfScope wins ties: if an asset matches BOTH an in-scope wildcard
// AND an out-of-scope exact entry, the report is OUT of scope.

import type { Program, ScopeItem, Report } from '../types.js';

export interface ScopeCheckResult {
  inScope: boolean;
  matchedItem?: ScopeItem;
  /** Which side fired ('in', 'out', 'none'). */
  side: 'in' | 'out' | 'none';
  reasoning: string[];
}

export function checkScope(report: Report, program: Program): ScopeCheckResult {
  const asset = report.finding.asset?.trim();
  const reasoning: string[] = [];
  if (!asset || asset === 'unknown') {
    reasoning.push('report has no asset identifier');
    return { inScope: false, side: 'none', reasoning };
  }

  // Check out-of-scope FIRST — out wins ties (defensive).
  const outHit = matchAny(asset, program.outOfScope);
  if (outHit) {
    reasoning.push(`asset "${asset}" matched OUT-OF-SCOPE: ${outHit.identifier} (${outHit.assetType})`);
    return { inScope: false, side: 'out', matchedItem: outHit, reasoning };
  }
  reasoning.push(`asset "${asset}" did not match any out-of-scope entry`);

  const inHit = matchAny(asset, program.scope);
  if (inHit) {
    reasoning.push(`asset "${asset}" matched IN-SCOPE: ${inHit.identifier} (${inHit.assetType})`);
    return { inScope: true, side: 'in', matchedItem: inHit, reasoning };
  }
  reasoning.push(`asset "${asset}" did not match any in-scope entry`);
  return { inScope: false, side: 'none', reasoning };
}

function matchAny(asset: string, items: ScopeItem[]): ScopeItem | undefined {
  for (const item of items) {
    if (assetMatches(asset, item.identifier, item.assetType)) return item;
  }
  return undefined;
}

/**
 * Match a candidate asset string against a scope identifier.
 *
 *   URL / DOMAIN:
 *     - "*.example.com"      matches "foo.example.com" and "a.b.example.com"
 *                            (does NOT match "example.com" itself unless that's listed separately)
 *     - "api.example.com"    matches exactly
 *     - "example.com"        matches exactly
 *
 *   IOS_APP_STORE / ANDROID_PLAY_STORE / API:
 *     - exact match only
 */
export function assetMatches(candidate: string, scopeId: string, assetType?: string): boolean {
  if (scopeId === candidate) return true;
  if (!isUrlLike(assetType)) return false;

  // Wildcard prefix
  if (scopeId.startsWith('*.')) {
    const suffix = scopeId.slice(2);
    if (candidate.endsWith('.' + suffix)) return true;
    return false;
  }

  // URL with protocol stripped
  const candHost = stripUrl(candidate);
  const scopeHost = stripUrl(scopeId);
  if (candHost === scopeHost) return true;

  return false;
}

function isUrlLike(assetType: string | undefined): boolean {
  if (!assetType) return true; // when unknown, assume URL-like (defensive)
  return assetType === 'URL' || assetType === 'DOMAIN' || assetType === 'API';
}

function stripUrl(s: string): string {
  return s
    .replace(/^https?:\/\//, '')
    .replace(/\/.*$/, '')
    .replace(/:\d+$/, '')
    .toLowerCase();
}
