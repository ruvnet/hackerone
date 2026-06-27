import { describe, it, expect } from 'vitest';
import { parseCvssVector, computeBaseScore, scoreToSeverity, evaluateVector } from '../src/triage/cvss.js';

describe('cvss', () => {
  it('parses bare CVSS v3.1 vector', () => {
    const m = parseCvssVector('AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H');
    expect(m.AV).toBe('N');
    expect(m.S).toBe('U');
    expect(m.C).toBe('H');
  });

  it('parses prefixed CVSS:3.1/ vector', () => {
    const m = parseCvssVector('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H');
    expect(m.AV).toBe('N');
  });

  it('rejects missing metric', () => {
    expect(() => parseCvssVector('AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H')).toThrow(/missing/);
  });

  it('rejects invalid metric value', () => {
    expect(() => parseCvssVector('AV:Z/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')).toThrow(/AV value/);
  });

  it('computes CVSS 9.8 for AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', () => {
    // Reference: NVD calculator for that vector reports 9.8 Critical.
    const score = computeBaseScore(parseCvssVector('AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'));
    expect(score).toBeCloseTo(9.8, 1);
  });

  it('computes CVSS 7.5 for AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N (reflected XSS-like)', () => {
    const score = computeBaseScore(parseCvssVector('AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N'));
    expect(score).toBeCloseTo(7.5, 1);
  });

  it('computes 0.0 when all impacts are None', () => {
    const score = computeBaseScore(parseCvssVector('AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N'));
    expect(score).toBe(0);
  });

  it('maps score to severity bands', () => {
    expect(scoreToSeverity(0.0)).toBe('none');
    expect(scoreToSeverity(0.1)).toBe('low');
    expect(scoreToSeverity(3.9)).toBe('low');
    expect(scoreToSeverity(4.0)).toBe('medium');
    expect(scoreToSeverity(6.9)).toBe('medium');
    expect(scoreToSeverity(7.0)).toBe('high');
    expect(scoreToSeverity(8.9)).toBe('high');
    expect(scoreToSeverity(9.0)).toBe('critical');
    expect(scoreToSeverity(10.0)).toBe('critical');
  });

  it('evaluateVector returns score+severity+metrics', () => {
    const r = evaluateVector('AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H');
    expect(r.score).toBeCloseTo(9.8, 1);
    expect(r.severity).toBe('critical');
    expect(r.metrics.AV).toBe('N');
  });
});
