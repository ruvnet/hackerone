import { describe, it, expect } from 'vitest';
import { classifyDescription, CWE_RULES } from '../src/research/cwe-map.js';

describe('cwe-map', () => {
  it('classifies obvious XSS', () => {
    const r = classifyDescription('Reflected XSS via search query parameter');
    expect(r).not.toBeNull();
    expect(r!.cwe).toBe('CWE-79');
    expect(r!.owasp).toBe('A03:2021');
  });

  it('classifies SQL injection', () => {
    const r = classifyDescription('SQL injection on /api/user?id= via UNION SELECT');
    expect(r!.cwe).toBe('CWE-89');
  });

  it('classifies SSRF', () => {
    const r = classifyDescription('SSRF — the webhook endpoint fetches arbitrary URLs including 169.254.169.254');
    expect(r!.cwe).toBe('CWE-918');
  });

  it('classifies command injection', () => {
    const r = classifyDescription('OS command injection in the exec endpoint allows arbitrary RCE');
    expect(r!.cwe).toBe('CWE-78');
  });

  it('classifies path traversal', () => {
    const r = classifyDescription('Path traversal: ../../etc/passwd retrievable via the file param');
    expect(r!.cwe).toBe('CWE-22');
  });

  it('classifies IDOR', () => {
    const r = classifyDescription('IDOR — incrementing the userId param returns other accounts');
    expect(r!.cwe).toBe('CWE-639');
  });

  it('returns null on unclassifiable input', () => {
    expect(classifyDescription('hello world this is just text')).toBeNull();
  });

  it('returns alternatives ordered by confidence', () => {
    // ambiguous wording — both auth bypass + CSRF rules may fire
    const r = classifyDescription('CSRF leads to authentication bypass via state-changing GET');
    expect(r).not.toBeNull();
    expect(r!.alternatives.length).toBeGreaterThanOrEqual(1);
    for (let i = 1; i < r!.alternatives.length; i++) {
      expect(r!.alternatives[i]!.confidence).toBeLessThanOrEqual(r!.alternatives[i - 1]!.confidence);
    }
  });

  it('CWE_RULES exports a non-trivial ruleset', () => {
    expect(CWE_RULES.length).toBeGreaterThanOrEqual(20);
  });
});
