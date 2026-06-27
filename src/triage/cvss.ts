// CVSS v3.1 Base score → severity band, plus vector parsing.
//
// Implements the official CVSS v3.1 base score formula from
// https://www.first.org/cvss/v3.1/specification-document. No environmental
// or temporal metrics — those are out of scope for v0.1 triage.

import type { Severity } from '../types.js';

/** CVSS v3.1 base metrics. Each value is the metric string from the vector (e.g., "N", "L"). */
export interface CvssBaseMetrics {
  AV: 'N' | 'A' | 'L' | 'P';
  AC: 'L' | 'H';
  PR: 'N' | 'L' | 'H';
  UI: 'N' | 'R';
  S: 'U' | 'C';
  C: 'N' | 'L' | 'H';
  I: 'N' | 'L' | 'H';
  A: 'N' | 'L' | 'H';
}

/** Numeric weights per metric, per CVSS v3.1 spec. */
const W = {
  AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
  AC: { L: 0.77, H: 0.44 },
  PR_unchanged: { N: 0.85, L: 0.62, H: 0.27 },
  PR_changed: { N: 0.85, L: 0.68, H: 0.5 },
  UI: { N: 0.85, R: 0.62 },
  C: { N: 0.0, L: 0.22, H: 0.56 },
  I: { N: 0.0, L: 0.22, H: 0.56 },
  A: { N: 0.0, L: 0.22, H: 0.56 },
} as const;

/**
 * Parse a CVSS v3.1 vector string into its base metrics.
 *
 * Accepts the bare-vector form ("AV:N/AC:L/...") and the prefixed form
 * ("CVSS:3.1/AV:N/AC:L/..."). Throws on missing or invalid components.
 */
export function parseCvssVector(vector: string): CvssBaseMetrics {
  const stripped = vector.replace(/^CVSS:3\.[01]\//, '');
  const parts = stripped.split('/').filter(Boolean);
  const map = new Map<string, string>();
  for (const p of parts) {
    const [k, v] = p.split(':');
    if (!k || !v) throw new Error(`@metaharness/hackerone: invalid CVSS component "${p}"`);
    map.set(k, v);
  }
  const required = ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A'] as const;
  for (const k of required) {
    if (!map.has(k)) {
      throw new Error(`@metaharness/hackerone: CVSS vector missing required metric "${k}"`);
    }
  }
  // Validate values
  const m = {
    AV: map.get('AV')! as CvssBaseMetrics['AV'],
    AC: map.get('AC')! as CvssBaseMetrics['AC'],
    PR: map.get('PR')! as CvssBaseMetrics['PR'],
    UI: map.get('UI')! as CvssBaseMetrics['UI'],
    S: map.get('S')! as CvssBaseMetrics['S'],
    C: map.get('C')! as CvssBaseMetrics['C'],
    I: map.get('I')! as CvssBaseMetrics['I'],
    A: map.get('A')! as CvssBaseMetrics['A'],
  };
  const valid: Record<keyof CvssBaseMetrics, string[]> = {
    AV: ['N', 'A', 'L', 'P'],
    AC: ['L', 'H'],
    PR: ['N', 'L', 'H'],
    UI: ['N', 'R'],
    S: ['U', 'C'],
    C: ['N', 'L', 'H'],
    I: ['N', 'L', 'H'],
    A: ['N', 'L', 'H'],
  };
  for (const k of required) {
    if (!valid[k].includes(m[k])) {
      throw new Error(`@metaharness/hackerone: CVSS ${k} value "${m[k]}" invalid (expected ${valid[k].join('|')})`);
    }
  }
  return m;
}

/**
 * Compute the CVSS v3.1 base score from base metrics.
 *
 * Returns a number in [0, 10] rounded UP to one decimal per the spec
 * (round-up rule, e.g., 6.01 → 6.1).
 */
export function computeBaseScore(m: CvssBaseMetrics): number {
  const iss = 1 - (1 - W.C[m.C]) * (1 - W.I[m.I]) * (1 - W.A[m.A]);
  const impact = m.S === 'U' ? 6.42 * iss : 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15);
  if (impact <= 0) return 0;
  const pr = m.S === 'U' ? W.PR_unchanged[m.PR] : W.PR_changed[m.PR];
  const exploitability = 8.22 * W.AV[m.AV] * W.AC[m.AC] * pr * W.UI[m.UI];
  const raw = m.S === 'U'
    ? Math.min(impact + exploitability, 10)
    : Math.min(1.08 * (impact + exploitability), 10);
  return roundUpTenth(raw);
}

function roundUpTenth(n: number): number {
  // CVSS spec rounds toward positive infinity at 0.1 precision.
  return Math.ceil(n * 10) / 10;
}

/**
 * Map a numeric CVSS base score to the standard severity band.
 *   0.0      → none
 *   0.1–3.9  → low
 *   4.0–6.9  → medium
 *   7.0–8.9  → high
 *   9.0–10.0 → critical
 */
export function scoreToSeverity(score: number): Severity {
  if (score >= 9.0) return 'critical';
  if (score >= 7.0) return 'high';
  if (score >= 4.0) return 'medium';
  if (score >= 0.1) return 'low';
  return 'none';
}

/** Convenience: parse a vector + return score + severity. */
export function evaluateVector(vector: string): { score: number; severity: Severity; metrics: CvssBaseMetrics } {
  const metrics = parseCvssVector(vector);
  const score = computeBaseScore(metrics);
  const severity = scoreToSeverity(score);
  return { score, severity, metrics };
}
