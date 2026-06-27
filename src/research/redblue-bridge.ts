// Bridge: convert a @metaharness/hackerone Finding → an
// @metaharness/redblue HackerOneReportDraft.
//
// redblue@0.1.4 owns the human-gated HackerOne submit verb (4 gates,
// dry-run default, scope-verified live). This module emits the exact
// JSON shape redblue's submit gate consumes, so a hackerone-side draft
// pipes directly:
//
//   npx hackerone export-redblue <finding.json> | npx redblue submit --in - --dry-run
//
// CONTRACT (matches the public type in
// @metaharness/redblue/dist/reports/hackerone.d.ts):
//
//   interface HackerOneReportDraft {
//     draft: true                                      // sentinel
//     title: string
//     weakness: { family, cwe[], owaspLlm }
//     severity: {
//       redblueBand, redblueScore,
//       cvssVector, cvssBaseScore, cvssRating,
//       hackeroneSeverity
//     }
//     impact: string
//     stepsToReproduce: string[]
//     evidence: string[]
//     recommendedFix?: string
//     asset?: string                                   // scope gate matches against this
//     repro: { confirmed: boolean, method?: string }   // verification gate
//     submission: { auto_submit: false, note: string } // hard machine marker
//   }
//
// SAFETY (load-bearing — DO NOT WEAKEN):
//   - `repro.confirmed` DEFAULTS to FALSE. Drafts emitted here trip
//     redblue's verification gate UNLESS the operator explicitly marks
//     them confirmed (`--repro-confirmed --repro-method "<how>"`). This
//     mirrors redblue's own posture: a hand-built / model-generated
//     draft cannot pass by omission.
//   - `submission.auto_submit` is ALWAYS false.
//   - `submission.note` calls out the external origin so a triager sees
//     this didn't come from a redblue run.
//   - There is NO submit path in this file. The bridge produces the
//     draft; redblue (or a human) submits it.

import type { Finding, Severity } from '../types.js';

/** redblue's AttackFamily union. Mirrored as a string-literal type so we
 *  don't need a runtime dep on @metaharness/redblue. */
export type RedblueAttackFamily =
  | 'prompt_injection'
  | 'tool_overreach'
  | 'data_exfiltration'
  | 'role_confusion'
  | 'cost_amplification';

/** Mirror of redblue's CweRef shape. */
export interface CweRef {
  id: string;
  name: string;
}

/** Mirror of redblue's HackerOneReportDraft shape. */
export interface HackerOneReportDraft {
  draft: true;
  title: string;
  weakness: {
    family: RedblueAttackFamily;
    cwe: CweRef[];
    owaspLlm: string;
  };
  severity: {
    redblueBand: 'none' | 'low' | 'medium' | 'high' | 'critical';
    redblueScore: number;
    cvssVector: string;
    cvssBaseScore: number;
    cvssRating: 'None' | 'Low' | 'Medium' | 'High' | 'Critical';
    hackeroneSeverity: 'none' | 'low' | 'medium' | 'high' | 'critical';
  };
  impact: string;
  stepsToReproduce: string[];
  evidence: string[];
  recommendedFix?: string;
  asset?: string;
  repro: { confirmed: boolean; method?: string };
  submission: { auto_submit: false; note: string };
}

export interface BridgeOptions {
  /**
   * Mark the repro as confirmed. ONLY pass true when the operator has
   * manually reproduced the finding. Defaults to false — redblue's
   * verification gate refuses unconfirmed drafts.
   */
  reproConfirmed?: boolean;
  /** Operator's note on how the repro was confirmed. */
  reproMethod?: string;
  /** Override the asset (default: finding.asset). */
  asset?: string;
  /** Override the family classification. */
  family?: RedblueAttackFamily;
  /** Add a recommended-fix line. */
  recommendedFix?: string;
}

/**
 * CWE-id → redblue AttackFamily. Lossy but transparent; the triager
 * sees the CWE in the weakness block and can correct.
 *
 * Heuristic:
 *   injection-class (XSS, SQLi, OS-cmd, code-eval, LLM-prompt) → prompt_injection
 *   authz/IDOR/privesc/CSRF/path-trav                          → tool_overreach
 *   info-disclosure                                            → data_exfiltration
 *   role-confusion / improper-priv-management                  → role_confusion
 *   DoS / cost / rate-limit                                    → cost_amplification
 *   anything else                                              → data_exfiltration (safest default)
 */
function cweToFamily(cwe: string | undefined): RedblueAttackFamily {
  if (!cwe) return 'data_exfiltration';
  const id = cwe.toUpperCase();
  // Injection-class
  if (['CWE-79', 'CWE-89', 'CWE-78', 'CWE-94', 'CWE-77', 'CWE-1427', 'CWE-90', 'CWE-91', 'CWE-502'].includes(id)) {
    return 'prompt_injection';
  }
  // AuthZ / privesc / CSRF / path-traversal / open-redirect / mass assignment
  if (['CWE-285', 'CWE-862', 'CWE-639', 'CWE-22', 'CWE-352', 'CWE-601', 'CWE-732', 'CWE-918', 'CWE-250', 'CWE-287'].includes(id)) {
    return 'tool_overreach';
  }
  // Info disclosure / data exposure / crypto failures
  if (['CWE-200', 'CWE-201', 'CWE-319', 'CWE-327', 'CWE-1104'].includes(id)) {
    return 'data_exfiltration';
  }
  // Role / privilege confusion / session
  if (['CWE-269', 'CWE-1426', 'CWE-384', 'CWE-521', 'CWE-16', 'CWE-778'].includes(id)) {
    return 'role_confusion';
  }
  // DoS / rate-limit / resource exhaustion
  if (['CWE-400', 'CWE-770', 'CWE-799'].includes(id)) {
    return 'cost_amplification';
  }
  return 'data_exfiltration';
}

/**
 * CWE-id → human-readable name. Names match the CWE_RULES set in
 * src/research/cwe-map.ts so a finding that was classified by us round-
 * trips with a consistent label. For unknown CWEs, the id is used as
 * the name too.
 */
function cweName(id: string): string {
  const MAP: Record<string, string> = {
    'CWE-79': 'Cross-site Scripting',
    'CWE-89': 'SQL Injection',
    'CWE-78': 'OS Command Injection',
    'CWE-94': 'Code Injection',
    'CWE-77': 'Command Injection (generic)',
    'CWE-90': 'LDAP Injection',
    'CWE-91': 'XML Injection',
    'CWE-285': 'Authorization Bypass',
    'CWE-639': 'IDOR',
    'CWE-352': 'CSRF',
    'CWE-22': 'Path Traversal',
    'CWE-287': 'Improper Authentication',
    'CWE-384': 'Session Fixation',
    'CWE-521': 'Weak Password Requirements',
    'CWE-327': 'Broken/Risky Crypto',
    'CWE-319': 'Cleartext Transmission',
    'CWE-16': 'Configuration',
    'CWE-200': 'Information Exposure',
    'CWE-918': 'Server-Side Request Forgery',
    'CWE-1104': 'Outdated Component',
    'CWE-502': 'Insecure Deserialization',
    'CWE-778': 'Insufficient Logging',
    'CWE-601': 'Open Redirect',
    'CWE-400': 'Resource Exhaustion / DoS',
    'CWE-732': 'Insecure Permissions',
  };
  return MAP[id.toUpperCase()] ?? id;
}

/** OWASP Top-10 (2021) id → LLM Top-10 anchor. Best-effort for traditional
 *  web vulns. redblue's owaspLlm field is informational for triagers. */
function owaspWebToLlm(owaspTop10: string | undefined, family: RedblueAttackFamily): string {
  // Generic fallback by family
  const FAM: Record<RedblueAttackFamily, string> = {
    prompt_injection: 'LLM01: Prompt Injection (analog: traditional injection)',
    tool_overreach: 'LLM06: Excessive Agency (analog: broken access control)',
    data_exfiltration: 'LLM06: Sensitive Information Disclosure',
    role_confusion: 'LLM02: Insecure Output Handling (analog: identification & auth failures)',
    cost_amplification: 'LLM04: Model Denial of Service',
  };
  return owaspTop10 ? `${owaspTop10} (mapped via ${FAM[family]})` : FAM[family];
}

/** redblue severity band (lowercase) → CVSS Rating (PascalCase). */
function toCvssRating(band: Severity): HackerOneReportDraft['severity']['cvssRating'] {
  const map: Record<Severity, HackerOneReportDraft['severity']['cvssRating']> = {
    none: 'None',
    low: 'Low',
    medium: 'Medium',
    high: 'High',
    critical: 'Critical',
  };
  return map[band];
}

/** Severity band → representative 0..1 redblue score. */
function toRedblueScore(band: Severity): number {
  const map: Record<Severity, number> = {
    none: 0.0,
    low: 0.2,
    medium: 0.5,
    high: 0.75,
    critical: 0.95,
  };
  return map[band];
}

/** Representative CVSS 3.1 vector per band, used when the finding
 *  doesn't carry its own vector. Honest "shape", not over-claimed. */
function fallbackCvssVector(band: Severity): string {
  switch (band) {
    case 'critical': return 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H';
    case 'high':     return 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N';
    case 'medium':   return 'AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N';
    case 'low':      return 'AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N';
    case 'none':     return 'AV:N/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N';
  }
}

/** Build the redblue draft from one Finding. */
export function toRedblueDraft(finding: Finding, opts: BridgeOptions = {}): HackerOneReportDraft {
  const sev: Severity = finding.severity ?? 'medium';
  const family = opts.family ?? cweToFamily(finding.cwe);
  const cwe: CweRef[] = finding.cwe
    ? [{ id: finding.cwe, name: cweName(finding.cwe) }]
    : [{ id: 'CWE-NONE', name: 'Unclassified — pending triage' }];
  const cvssVector = finding.cvssVector ?? fallbackCvssVector(sev);
  const cvssBase = finding.cvssScore ?? severityToScore(sev);

  const draft: HackerOneReportDraft = {
    draft: true,
    title: finding.title,
    weakness: {
      family,
      cwe,
      owaspLlm: owaspWebToLlm(finding.owasp, family),
    },
    severity: {
      redblueBand: sev,
      redblueScore: toRedblueScore(sev),
      cvssVector,
      cvssBaseScore: cvssBase,
      cvssRating: toCvssRating(sev),
      hackeroneSeverity: sev,
    },
    impact: impactNarrative(sev),
    stepsToReproduce: parseSteps(finding.reproduction),
    evidence: [],
    repro: {
      confirmed: opts.reproConfirmed === true,
      ...(opts.reproMethod ? { method: opts.reproMethod } : {}),
    },
    submission: {
      auto_submit: false,
      note: 'External draft from @metaharness/hackerone — operator must run all 4 redblue submit gates before any POST.',
    },
  };
  const asset = opts.asset ?? finding.asset;
  if (asset && asset !== 'unknown') draft.asset = asset;
  if (opts.recommendedFix) draft.recommendedFix = opts.recommendedFix;
  return draft;
}

function severityToScore(sev: Severity): number {
  // Representative CVSS score midpoints per band.
  switch (sev) {
    case 'critical': return 9.5;
    case 'high':     return 8.0;
    case 'medium':   return 5.5;
    case 'low':      return 2.5;
    case 'none':     return 0.0;
  }
}

function impactNarrative(sev: Severity): string {
  switch (sev) {
    case 'critical': return 'Full compromise of confidentiality, integrity, or availability — escalation to admin/root, mass data exfiltration, or service-wide downtime.';
    case 'high':     return 'Significant compromise — privilege escalation, cross-user data access, or material business-impact event.';
    case 'medium':   return 'Partial compromise — limited data exposure, scoped unauthorized access, or moderate availability impact.';
    case 'low':      return 'Minor compromise or hardening gap — limited material impact in most scenarios.';
    case 'none':     return 'Informational — no direct exploitability; defense-in-depth context only.';
  }
}

function parseSteps(reproduction: string | undefined): string[] {
  if (!reproduction) return ['(no reproduction steps provided — operator must add before submit)'];
  // Best-effort split: numbered lines first, then newline split, then a single block.
  const lines = reproduction.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
  if (lines.length === 0) return [reproduction.trim()];
  // Strip leading numbering ("1.", "1)", "1 -")
  return lines.map((l) => l.replace(/^\d+[\.\)\-]\s*/, ''));
}
