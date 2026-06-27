import { describe, it, expect } from 'vitest';
import { toRedblueDraft } from '../src/research/redblue-bridge.js';
import type { Finding } from '../src/types.js';

const baseFinding: Finding = {
  id: 'f-1',
  title: 'Reflected XSS in /search?q=',
  description: 'q param reflected unescaped',
  asset: 'api.example.com',
  cwe: 'CWE-79',
  owasp: 'A03:2021',
  severity: 'high',
  cvssScore: 7.4,
  cvssVector: 'AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N',
  reproduction: '1. GET https://api.example.com/search?q=<x>\n2. Observe XSS fires',
};

describe('toRedblueDraft — contract shape', () => {
  const d = toRedblueDraft(baseFinding);

  it('draft sentinel + auto_submit=false hard-coded', () => {
    expect(d.draft).toBe(true);
    expect(d.submission.auto_submit).toBe(false);
    expect(d.submission.note).toContain('@metaharness/hackerone');
  });

  it('repro.confirmed DEFAULTS to false (verification gate failsafe)', () => {
    expect(d.repro.confirmed).toBe(false);
  });

  it('weakness has family + cwe[] + owaspLlm', () => {
    expect(d.weakness.family).toBeDefined();
    expect(Array.isArray(d.weakness.cwe)).toBe(true);
    expect(d.weakness.cwe.length).toBeGreaterThan(0);
    expect(d.weakness.cwe[0]!.id).toBe('CWE-79');
    expect(d.weakness.cwe[0]!.name).toBe('Cross-site Scripting');
    expect(typeof d.weakness.owaspLlm).toBe('string');
  });

  it('severity carries BOTH redblue and CVSS bands', () => {
    expect(d.severity.redblueBand).toBe('high');
    expect(d.severity.redblueScore).toBeGreaterThan(0.5);
    expect(d.severity.cvssVector).toBe(baseFinding.cvssVector);
    expect(d.severity.cvssBaseScore).toBe(7.4);
    expect(d.severity.cvssRating).toBe('High');
    expect(d.severity.hackeroneSeverity).toBe('high');
  });

  it('stepsToReproduce parsed from numbered reproduction', () => {
    expect(d.stepsToReproduce.length).toBe(2);
    expect(d.stepsToReproduce[0]).toContain('GET');
    expect(d.stepsToReproduce[1]).toContain('XSS');
    // Numbering should be stripped
    expect(d.stepsToReproduce[0]).not.toMatch(/^\d/);
  });

  it('asset preserved from finding', () => {
    expect(d.asset).toBe('api.example.com');
  });
});

describe('toRedblueDraft — opts', () => {
  it('reproConfirmed:true sets repro.confirmed + method', () => {
    const d = toRedblueDraft(baseFinding, {
      reproConfirmed: true,
      reproMethod: 'Manually reproduced via curl in staging',
    });
    expect(d.repro.confirmed).toBe(true);
    expect(d.repro.method).toBe('Manually reproduced via curl in staging');
  });

  it('asset override wins over finding.asset', () => {
    const d = toRedblueDraft(baseFinding, { asset: 'staging.example.com' });
    expect(d.asset).toBe('staging.example.com');
  });

  it('family override wins over CWE heuristic', () => {
    const d = toRedblueDraft(baseFinding, { family: 'tool_overreach' });
    expect(d.weakness.family).toBe('tool_overreach');
  });

  it('recommendedFix surfaces in output', () => {
    const d = toRedblueDraft(baseFinding, { recommendedFix: 'Escape HTML in search results' });
    expect(d.recommendedFix).toBe('Escape HTML in search results');
  });
});

describe('toRedblueDraft — CWE → family mapping', () => {
  const cases: Array<{ cwe: string; expected: string }> = [
    { cwe: 'CWE-79',  expected: 'prompt_injection' },
    { cwe: 'CWE-89',  expected: 'prompt_injection' },
    { cwe: 'CWE-78',  expected: 'prompt_injection' },
    { cwe: 'CWE-639', expected: 'tool_overreach' },
    { cwe: 'CWE-22',  expected: 'tool_overreach' },
    { cwe: 'CWE-918', expected: 'tool_overreach' },
    { cwe: 'CWE-200', expected: 'data_exfiltration' },
    { cwe: 'CWE-319', expected: 'data_exfiltration' },
    { cwe: 'CWE-384', expected: 'role_confusion' },
    { cwe: 'CWE-400', expected: 'cost_amplification' },
    { cwe: 'CWE-770', expected: 'cost_amplification' },
  ];
  for (const c of cases) {
    it(`${c.cwe} → ${c.expected}`, () => {
      const d = toRedblueDraft({ ...baseFinding, cwe: c.cwe });
      expect(d.weakness.family).toBe(c.expected);
    });
  }

  it('unclassified CWE defaults to data_exfiltration (safest read-class)', () => {
    const d = toRedblueDraft({ ...baseFinding, cwe: 'CWE-99999' });
    expect(d.weakness.family).toBe('data_exfiltration');
  });

  it('missing CWE produces a placeholder cwe[] entry', () => {
    const withoutCwe = { ...baseFinding };
    delete (withoutCwe as Partial<Finding>).cwe;
    const d = toRedblueDraft(withoutCwe);
    expect(d.weakness.cwe[0]!.id).toBe('CWE-NONE');
    expect(d.weakness.cwe[0]!.name).toContain('Unclassified');
  });
});

describe('toRedblueDraft — severity bands without explicit score/vector', () => {
  it('low fills representative CVSS vector + score', () => {
    const d = toRedblueDraft({
      id: 'x', title: 'X', description: '', asset: 'a.test', severity: 'low',
    });
    expect(d.severity.cvssRating).toBe('Low');
    expect(d.severity.cvssVector.length).toBeGreaterThan(10);
    expect(d.severity.cvssBaseScore).toBeGreaterThan(0);
    expect(d.severity.cvssBaseScore).toBeLessThan(4);
  });

  it('critical fills representative vector + score in 9.0..10.0', () => {
    const d = toRedblueDraft({
      id: 'x', title: 'X', description: '', asset: 'a.test', severity: 'critical',
    });
    expect(d.severity.cvssBaseScore).toBeGreaterThanOrEqual(9.0);
  });
});

describe('toRedblueDraft — no reproduction produces a placeholder line', () => {
  it('flags missing repro for the operator to fill in', () => {
    const noRepro = { ...baseFinding };
    delete (noRepro as Partial<Finding>).reproduction;
    const d = toRedblueDraft(noRepro);
    expect(d.stepsToReproduce.length).toBe(1);
    expect(d.stepsToReproduce[0]).toContain('no reproduction');
  });
});
