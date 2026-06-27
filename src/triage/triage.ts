// Defender-side triage orchestrator.
//
// Given an incoming Report + the Program + recent history, emit a
// TriageVerdict by running:
//   1. scope-check         — is the asset in scope?
//   2. cvss                — if a vector is present, recompute the score
//   3. dedupe              — match against history
//   4. classify state      — recommend a new ReportState
//
// All four sub-steps are pure functions; this module is just glue.
// Returns reasoning trails the analyst can read line-by-line.

import type { Program, Report, TriageVerdict, ReportState } from '../types.js';
import { evaluateVector } from './cvss.js';
import { findDuplicate } from './dedupe.js';
import { checkScope } from './scope-check.js';

export interface TriageOptions {
  program: Program;
  history?: Report[];
  /** Override the default dedupe similarity threshold (0..1). */
  dedupeThreshold?: number;
}

export function triageReport(report: Report, opts: TriageOptions): TriageVerdict {
  const reasoning: string[] = [];
  let confidence = 1;

  // ── 1. Scope ─────────────────────────────────────────────────────
  const scope = checkScope(report, opts.program);
  reasoning.push(`[scope] ${scope.side}: ${scope.reasoning.join('; ')}`);
  if (!scope.inScope) {
    return {
      reportId: report.id,
      recommendedState: 'not-applicable',
      severity: report.finding.severity ?? 'none',
      cvssScore: report.finding.cvssScore,
      inScope: false,
      confidence: 0.95,
      reasoning,
    };
  }

  // ── 2. CVSS recompute (only if vector present) ───────────────────
  let cvssScore = report.finding.cvssScore;
  let severity = report.finding.severity ?? 'none';
  if (report.finding.cvssVector) {
    try {
      const ev = evaluateVector(report.finding.cvssVector);
      cvssScore = ev.score;
      severity = ev.severity;
      reasoning.push(`[cvss] vector ${report.finding.cvssVector} → ${ev.score} (${ev.severity})`);
    } catch (e) {
      reasoning.push(`[cvss] parse failed: ${(e as Error).message} — keeping reporter's value`);
      confidence *= 0.85;
    }
  } else if (cvssScore == null) {
    reasoning.push('[cvss] no vector and no score — keeping severity=none');
  } else {
    reasoning.push(`[cvss] no vector; using reporter score ${cvssScore} (${severity})`);
  }

  // ── 3. Dedupe ────────────────────────────────────────────────────
  const dedupe = findDuplicate(report, {
    history: opts.history ?? [],
    similarityThreshold: opts.dedupeThreshold,
  });
  reasoning.push(`[dedupe] ${dedupe.stage}: ${dedupe.reasoning.join('; ')}`);

  // ── 4. Classify state ────────────────────────────────────────────
  let recommendedState: ReportState;
  if (dedupe.isDuplicate) {
    recommendedState = 'duplicate';
    confidence *= dedupe.confidence;
  } else if (severity === 'none' && cvssScore == null) {
    recommendedState = 'needs-more-info';
    confidence *= 0.7;
  } else if (severity === 'none') {
    recommendedState = 'informative';
    confidence *= 0.8;
  } else {
    recommendedState = 'triaged';
    confidence *= 0.9;
  }
  reasoning.push(
    `[verdict] recommendedState=${recommendedState}, severity=${severity}, score=${cvssScore ?? 'n/a'}, conf=${confidence.toFixed(2)}`,
  );

  const result: TriageVerdict = {
    reportId: report.id,
    recommendedState,
    severity,
    inScope: true,
    confidence: Number(confidence.toFixed(3)),
    reasoning,
  };
  if (cvssScore !== undefined) result.cvssScore = cvssScore;
  if (dedupe.duplicateOf !== undefined) result.duplicateOf = dedupe.duplicateOf;
  return result;
}
