// Duplicate detection for incoming HackerOne reports.
//
// Two-stage match against a history of prior reports on the same program:
//
//   1. EXACT SIGNATURE  — hash (cwe, asset, normalized-payload-fingerprint).
//      If two reports share this signature, they're almost certainly the
//      same bug. Cheap (O(1) per candidate after the index is built).
//
//   2. FUZZY SIMILARITY — Jaccard over token-shingled finding text. The
//      threshold defaults to 0.5; tunable per-program. Quadratic in the
//      worst case but the candidate set is filtered down by stage 1.
//
// No ML, no embeddings, no external calls — just deterministic string
// math the SOC can audit and reproduce.

import type { Report } from '../types.js';

const DEFAULT_THRESHOLD = 0.5;
const SHINGLE_SIZE = 3;

export interface DedupeOptions {
  /** Similarity threshold [0..1] for a fuzzy match. Default 0.5. */
  similarityThreshold?: number;
  /** History to match against. */
  history: Report[];
}

export interface DedupeResult {
  isDuplicate: boolean;
  duplicateOf?: string;
  /** Match confidence [0..1]. */
  confidence: number;
  /** Why we think this is or isn't a duplicate. */
  reasoning: string[];
  /** Stage that fired ('exact' / 'fuzzy' / 'none'). */
  stage: 'exact' | 'fuzzy' | 'none';
}

/**
 * Build a stable signature for a finding. Two findings with the same
 * signature are treated as exact duplicates.
 *
 * Signature = (cwe || severity, asset, normalized fingerprint of the
 * first 200 chars of description with whitespace collapsed and lowered).
 */
export function signatureOf(report: Report): string {
  const f = report.finding;
  const cwe = f.cwe ?? f.severity ?? 'unknown';
  const asset = f.asset ?? 'unknown';
  const fingerprint = normalize(f.description ?? '').slice(0, 200);
  return `${cwe}|${asset}|${fingerprint}`;
}

/**
 * Check whether `candidate` is a duplicate of anything in `history`.
 */
export function findDuplicate(candidate: Report, opts: DedupeOptions): DedupeResult {
  const threshold = opts.similarityThreshold ?? DEFAULT_THRESHOLD;
  const candSig = signatureOf(candidate);
  const reasoning: string[] = [];

  // Stage 1 — exact signature
  for (const prior of opts.history) {
    if (prior.id === candidate.id) continue;
    if (signatureOf(prior) === candSig) {
      reasoning.push(`exact signature match against ${prior.id}`);
      return {
        isDuplicate: true,
        duplicateOf: prior.id,
        confidence: 0.95,
        reasoning,
        stage: 'exact',
      };
    }
  }
  reasoning.push('no exact signature match');

  // Stage 2 — fuzzy similarity. Only compare candidates with same asset OR same cwe.
  const candTokens = shingle(normalize(candidate.finding.description ?? ''));
  let best: { id: string; sim: number } | null = null;
  for (const prior of opts.history) {
    if (prior.id === candidate.id) continue;
    const sameAsset = prior.finding.asset === candidate.finding.asset;
    const sameCwe = prior.finding.cwe && prior.finding.cwe === candidate.finding.cwe;
    if (!sameAsset && !sameCwe) continue;
    const priorTokens = shingle(normalize(prior.finding.description ?? ''));
    const sim = jaccard(candTokens, priorTokens);
    if (!best || sim > best.sim) best = { id: prior.id, sim };
  }
  if (best) {
    reasoning.push(`best fuzzy match: ${best.id} @ ${best.sim.toFixed(3)} (threshold ${threshold})`);
    if (best.sim >= threshold) {
      return {
        isDuplicate: true,
        duplicateOf: best.id,
        confidence: best.sim,
        reasoning,
        stage: 'fuzzy',
      };
    }
  } else {
    reasoning.push('no candidates shared asset OR cwe');
  }

  return {
    isDuplicate: false,
    confidence: best ? 1 - best.sim : 1,
    reasoning,
    stage: 'none',
  };
}

// ──────────────────────────────────────────────────────────────────────
// internal — text normalization + shingling + jaccard
// ──────────────────────────────────────────────────────────────────────

function normalize(s: string): string {
  return s
    .toLowerCase()
    .replace(/`+/g, ' ')          // code fences
    .replace(/[^a-z0-9\s]/g, ' ') // strip punct
    .replace(/\s+/g, ' ')
    .trim();
}

function shingle(s: string): Set<string> {
  const tokens = s.split(' ').filter((t) => t.length > 1);
  const out = new Set<string>();
  for (let i = 0; i <= tokens.length - SHINGLE_SIZE; i++) {
    out.add(tokens.slice(i, i + SHINGLE_SIZE).join(' '));
  }
  // Also unigrams — catch very short descriptions
  for (const t of tokens) out.add(t);
  return out;
}

function jaccard(a: Set<string>, b: Set<string>): number {
  if (a.size === 0 && b.size === 0) return 0;
  let intersect = 0;
  const [small, large] = a.size <= b.size ? [a, b] : [b, a];
  for (const x of small) {
    if (large.has(x)) intersect++;
  }
  const union = a.size + b.size - intersect;
  return union === 0 ? 0 : intersect / union;
}
