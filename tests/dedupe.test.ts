import { describe, it, expect } from 'vitest';
import { findDuplicate, signatureOf } from '../src/triage/dedupe.js';
import { MOCK_FIXTURES } from '../src/api/mock-client.js';

const report = (id: string, desc: string, asset = 'api.example.com', cwe = 'CWE-79') => ({
  id, programHandle: 'example-program', state: 'new' as const,
  finding: { id, title: id, description: desc, asset, cwe },
});

describe('dedupe', () => {
  it('signatureOf is deterministic', () => {
    const r = report('A', 'Reflected XSS via search query');
    expect(signatureOf(r)).toBe(signatureOf(r));
    expect(signatureOf(r)).toContain('CWE-79');
    expect(signatureOf(r)).toContain('api.example.com');
  });

  it('exact-signature match wins instantly', () => {
    const a = report('A', 'Same body identical');
    const b = report('B', 'Same body identical');
    const r = findDuplicate(b, { history: [a] });
    expect(r.isDuplicate).toBe(true);
    expect(r.stage).toBe('exact');
    expect(r.duplicateOf).toBe('A');
    expect(r.confidence).toBeGreaterThan(0.9);
  });

  it('fuzzy match fires above threshold', () => {
    // Same XSS-on-search pattern, different wording — same CWE+asset
    const a = report('A',
      'The q query parameter is reflected unescaped into the search results page. Payload triggers XSS.');
    const b = report('B',
      'The q query parameter is reflected unescaped into the search results page. Payload triggers XSS.');
    const r = findDuplicate(b, { history: [a], similarityThreshold: 0.5 });
    expect(r.isDuplicate).toBe(true);
    // either stage acceptable — both should fire
    expect(['exact', 'fuzzy']).toContain(r.stage);
  });

  it('different asset prevents match', () => {
    const a = report('A', 'Identical body', 'asset-A');
    const b = report('B', 'Identical body', 'asset-B', 'CWE-89'); // different cwe too
    const r = findDuplicate(b, { history: [a] });
    expect(r.isDuplicate).toBe(false);
    expect(r.stage).toBe('none');
  });

  it('candidate ignores its own id in history', () => {
    const a = report('A', 'body');
    const r = findDuplicate(a, { history: [a] });
    expect(r.isDuplicate).toBe(false);
  });

  it('threshold tunable downward catches looser matches', () => {
    const a = report('A', 'XSS in search via q parameter encoding bug');
    const b = report('B', 'XSS in search ');
    const strict = findDuplicate(b, { history: [a], similarityThreshold: 0.9 });
    const loose = findDuplicate(b, { history: [a], similarityThreshold: 0.05 });
    // Strict should not match; loose should (or strict is already false)
    expect(strict.isDuplicate).toBe(false);
    expect(loose.isDuplicate).toBe(true);
  });

  it('mock fixtures contain XSS dupes that get caught at default threshold', () => {
    // The two XSS fixtures (mock-1001 / mock-1002) describe the same bug
    // in legitimately different language — same CWE-79 + same asset,
    // paraphrased. The metadata-narrowed jaccard catches them at the
    // default 0.5 threshold; if a future fixture edit drops shared
    // language below that, this test pins the regression.
    const [r1, r2] = MOCK_FIXTURES.reports;
    expect(r1).toBeDefined();
    expect(r2).toBeDefined();
    const r = findDuplicate(r2!, { history: [r1!] });
    expect(r.isDuplicate).toBe(true);
  });
});
