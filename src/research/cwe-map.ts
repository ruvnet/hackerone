// Map free-text vulnerability descriptions → CWE + OWASP Top-10 (2021).
//
// Lightweight keyword classifier — no ML, no external calls. Each rule
// is a (regex → CWE → OWASP) tuple. Multiple rules may fire; the result
// is the highest-confidence (most specific) hit.
//
// This is intentionally narrow: only the ~25 most common bug classes
// are covered. Researchers can append rules per program; defenders can
// use this as a hint, not a verdict (every CWE assignment needs human
// review).

export interface CweRule {
  cwe: string;
  /** OWASP Top-10 (2021) category id, e.g. "A03:2021". */
  owasp?: string;
  /** Display name. */
  name: string;
  /** Regex applied case-insensitively to the description. */
  patterns: RegExp[];
  /** Higher = more specific. Ties resolved by rule order. */
  specificity: number;
}

export const CWE_RULES: CweRule[] = [
  // ── A03:2021 Injection ────────────────────────────────────────────
  { cwe: 'CWE-89',  owasp: 'A03:2021', name: 'SQL Injection',  specificity: 9,
    patterns: [/sql\s*injection/i, /\bsqli\b/i, /union\s+select/i] },
  { cwe: 'CWE-78',  owasp: 'A03:2021', name: 'OS Command Injection', specificity: 9,
    patterns: [/command\s*injection/i, /\brce\b/i, /remote\s+code\s+execution/i, /shell\s*injection/i] },
  { cwe: 'CWE-94',  owasp: 'A03:2021', name: 'Code Injection',  specificity: 8,
    patterns: [/code\s*injection/i, /\beval\b/i, /dynamic\s+code\s+execution/i] },
  { cwe: 'CWE-79',  owasp: 'A03:2021', name: 'Cross-site Scripting', specificity: 9,
    patterns: [/\bxss\b/i, /cross[-\s]*site\s*scripting/i, /reflected\s+xss/i, /stored\s+xss/i] },
  { cwe: 'CWE-90',  owasp: 'A03:2021', name: 'LDAP Injection',  specificity: 8,
    patterns: [/ldap\s*injection/i] },
  { cwe: 'CWE-91',  owasp: 'A03:2021', name: 'XML Injection',   specificity: 8,
    patterns: [/xml\s*injection/i, /xxe\b/i, /xml\s+external\s+entity/i] },
  { cwe: 'CWE-77',  owasp: 'A03:2021', name: 'Command Injection (generic)', specificity: 6,
    patterns: [/argument\s+injection/i] },

  // ── A01:2021 Broken Access Control ────────────────────────────────
  { cwe: 'CWE-639', owasp: 'A01:2021', name: 'IDOR',            specificity: 9,
    patterns: [/\bidor\b/i, /insecure\s+direct\s+object\s+reference/i] },
  { cwe: 'CWE-285', owasp: 'A01:2021', name: 'Authorization Bypass', specificity: 8,
    patterns: [/authorization\s+bypass/i, /broken\s+access\s+control/i, /privilege\s+escalation/i] },
  { cwe: 'CWE-352', owasp: 'A01:2021', name: 'CSRF',            specificity: 9,
    patterns: [/\bcsrf\b/i, /cross[-\s]*site\s*request\s+forgery/i] },
  { cwe: 'CWE-22',  owasp: 'A01:2021', name: 'Path Traversal',  specificity: 9,
    patterns: [/path\s+traversal/i, /directory\s+traversal/i, /\.\.[\\/]/] },

  // ── A07:2021 Identification and Authentication Failures ───────────
  { cwe: 'CWE-287', owasp: 'A07:2021', name: 'Improper Authentication', specificity: 7,
    patterns: [/auth(?:entication)?\s+bypass/i, /broken\s+auth(?:entication)?/i] },
  { cwe: 'CWE-384', owasp: 'A07:2021', name: 'Session Fixation', specificity: 8,
    patterns: [/session\s+fixation/i] },
  { cwe: 'CWE-521', owasp: 'A07:2021', name: 'Weak Password Requirements', specificity: 7,
    patterns: [/weak\s+password/i, /no\s+password\s+complexity/i] },

  // ── A02:2021 Cryptographic Failures ───────────────────────────────
  { cwe: 'CWE-327', owasp: 'A02:2021', name: 'Broken/Risky Crypto', specificity: 8,
    patterns: [/\bmd5\b/i, /\bsha[-_]?1\b/i, /weak\s+cipher/i, /broken\s+crypto/i, /\brc4\b/i] },
  { cwe: 'CWE-319', owasp: 'A02:2021', name: 'Cleartext Transmission', specificity: 8,
    patterns: [/cleartext\s+transmission/i, /unencrypted\s+(?:http|transport)/i, /no\s+tls/i] },

  // ── A05:2021 Security Misconfiguration ────────────────────────────
  { cwe: 'CWE-16',  owasp: 'A05:2021', name: 'Configuration',    specificity: 5,
    patterns: [/misconfiguration/i, /default\s+credentials/i, /exposed\s+config/i] },
  { cwe: 'CWE-200', owasp: 'A04:2021', name: 'Information Exposure', specificity: 7,
    patterns: [/information\s+(?:exposure|disclosure|leak)/i, /sensitive\s+data\s+exposure/i] },

  // ── A04:2021 Insecure Design ─────────────────────────────────────
  { cwe: 'CWE-918', owasp: 'A10:2021', name: 'Server-Side Request Forgery', specificity: 9,
    patterns: [/\bssrf\b/i, /server[-\s]*side\s*request\s*forgery/i] },

  // ── A06:2021 Vulnerable & Outdated Components ─────────────────────
  { cwe: 'CWE-1104', owasp: 'A06:2021', name: 'Outdated Component', specificity: 7,
    patterns: [/outdated\s+(?:library|component)/i, /vulnerable\s+dependency/i, /\bcve-\d{4}-\d+/i] },

  // ── A08:2021 Software and Data Integrity Failures ────────────────
  { cwe: 'CWE-502', owasp: 'A08:2021', name: 'Insecure Deserialization', specificity: 9,
    patterns: [/insecure\s+deserialization/i, /unsafe\s+(?:pickle|yaml|deserialize)/i] },

  // ── A09:2021 Security Logging and Monitoring Failures ────────────
  { cwe: 'CWE-778', owasp: 'A09:2021', name: 'Insufficient Logging', specificity: 6,
    patterns: [/insufficient\s+logging/i, /no\s+audit\s+log/i] },

  // ── Misc ──────────────────────────────────────────────────────────
  { cwe: 'CWE-601', owasp: 'A01:2021', name: 'Open Redirect',   specificity: 8,
    patterns: [/open\s+redirect/i, /unvalidated\s+redirect/i] },
  { cwe: 'CWE-400', name: 'Resource Exhaustion / DoS', specificity: 6,
    patterns: [/denial\s+of\s+service/i, /\bdos\b/i, /resource\s+exhaustion/i] },
  { cwe: 'CWE-732', owasp: 'A01:2021', name: 'Insecure Permissions', specificity: 6,
    patterns: [/insecure\s+permissions/i, /world[-\s]*(?:readable|writable)/i] },
];

export interface CweClassification {
  cwe: string;
  owasp?: string;
  name: string;
  /** [0..1]; combination of rule specificity and number of patterns matched. */
  confidence: number;
  /** Alternative classifications that also matched, ranked. */
  alternatives: Array<{ cwe: string; owasp?: string; name: string; confidence: number }>;
}

/**
 * Classify a free-text description into a (CWE, OWASP, name).
 *
 * Returns null if NO rule fires. The classifier is intentionally
 * conservative — better to return null than to mislabel.
 */
export function classifyDescription(description: string): CweClassification | null {
  const hits: Array<{ rule: CweRule; matchCount: number; score: number }> = [];
  for (const rule of CWE_RULES) {
    let matchCount = 0;
    for (const p of rule.patterns) {
      if (p.test(description)) matchCount++;
    }
    if (matchCount > 0) {
      // Score = specificity + bonus for multiple patterns matched
      const score = rule.specificity + Math.min(2, matchCount - 1);
      hits.push({ rule, matchCount, score });
    }
  }
  if (hits.length === 0) return null;
  hits.sort((a, b) => b.score - a.score);
  const best = hits[0]!;
  const top = best.rule;
  const maxScore = 11; // specificity 9 + 2 matches
  const result: CweClassification = {
    cwe: top.cwe,
    name: top.name,
    confidence: Math.min(1, best.score / maxScore),
    alternatives: hits.slice(1, 4).map((h) => {
      const alt: CweClassification['alternatives'][number] = {
        cwe: h.rule.cwe,
        name: h.rule.name,
        confidence: Math.min(1, h.score / maxScore),
      };
      if (h.rule.owasp !== undefined) alt.owasp = h.rule.owasp;
      return alt;
    }),
  };
  if (top.owasp !== undefined) result.owasp = top.owasp;
  return result;
}
