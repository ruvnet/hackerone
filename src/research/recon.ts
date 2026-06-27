// Researcher-side recon orchestrator.
//
// Wraps scope-analysis + cwe-map + report-format into a single
// "where to look, what to look for, how to write it up" workflow.
//
// Inputs: a Program (from the API or a fixture).
// Outputs: ScopeAnalysis + an opening checklist + (optional) a draft
// report skeleton for a hypothetical finding the researcher describes.

import type { Program } from '../types.js';
import { analyzeScope } from './scope-analysis.js';
import { classifyDescription } from './cwe-map.js';
import { formatFinding } from './report-format.js';

export interface ReconResult {
  programHandle: string;
  offersBounties: boolean;
  topAssets: Array<{ identifier: string; assetType: string; maxSeverity?: string; weight: number }>;
  forbiddenAssets: string[];
  totalChecksSuggested: number;
  topChecks: string[];
}

/**
 * Build a recon plan for a program — what to test first, what to avoid,
 * what families of bugs to look for.
 *
 * Cheap; runs in microseconds; no I/O.
 */
export function buildReconPlan(program: Program): ReconResult {
  const scope = analyzeScope(program);
  const topAssets = scope.testableAssets.slice(0, 5).map((a) => ({
    identifier: a.identifier,
    assetType: a.assetType,
    maxSeverity: a.maxSeverity,
    weight: weightOf(a.maxSeverity),
  }));
  const allChecks = new Set<string>();
  for (const c of scope.suggestedChecks) {
    for (const x of c.checks) allChecks.add(x);
  }
  const result: ReconResult = {
    programHandle: program.handle,
    offersBounties: program.offersBounties,
    topAssets,
    forbiddenAssets: scope.forbidden.map((f) => f.identifier),
    totalChecksSuggested: allChecks.size,
    topChecks: [...allChecks].slice(0, 8),
  };
  return result;
}

function weightOf(sev: string | undefined): number {
  switch (sev) {
    case 'critical': return 4;
    case 'high': return 3;
    case 'medium': return 2;
    case 'low': return 1;
    default: return 2; // assume medium when unknown
  }
}

export { analyzeScope, classifyDescription, formatFinding };
