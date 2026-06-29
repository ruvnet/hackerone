import { describe, it, expect } from 'vitest';
import { toGithubIssue, toJiraIssue, toIssue } from '../src/research/issue-bridge.js';
import type { Finding } from '../src/types.js';

const baseFinding: Finding = {
  id: 'f-1',
  title: 'Reflected XSS in /search?q=',
  description: 'q param reflected unescaped. Reporter: hacker@example.com — IP 1.2.3.4',
  asset: 'api.example.com',
  cwe: 'CWE-79',
  owasp: 'A03:2021',
  severity: 'high',
  cvssScore: 7.4,
  cvssVector: 'AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N',
  reproduction: '1. GET https://api.example.com/search?q=<x>\n2. Observe XSS fires',
};

describe('toGithubIssue', () => {
  const g = toGithubIssue(baseFinding);

  it('title carries the [H1] prefix', () => {
    expect(g.title.startsWith('[H1')).toBe(true);
    expect(g.title).toContain(baseFinding.title);
  });

  it('with --report-id title becomes [H1#<id>] …', () => {
    const r = toGithubIssue(baseFinding, { hackeroneReportId: '4242' });
    expect(r.title).toContain('[H1#4242]');
  });

  it('body redacts PII by default', () => {
    expect(g.body).not.toContain('hacker@example.com');
    expect(g.body).not.toContain('1.2.3.4');
    expect(g.body).toContain('<email>');
    expect(g.body).toContain('<ip>');
  });

  it('--skip-pii-redaction surfaces raw PII (operator override)', () => {
    const raw = toGithubIssue(baseFinding, { skipPiiRedaction: true });
    expect(raw.body).toContain('hacker@example.com');
  });

  it('labels include security + severity + cwe', () => {
    expect(g.labels).toContain('security');
    expect(g.labels).toContain('severity/high');
    expect(g.labels).toContain('cwe/cwe-79');
  });

  it('labels are deduplicated', () => {
    const dup = toGithubIssue(baseFinding, { labels: ['security', 'security', 'extra'] });
    const securityCount = dup.labels.filter((l) => l === 'security').length;
    expect(securityCount).toBe(1);
    expect(dup.labels).toContain('extra');
  });

  it('assignees only present when supplied', () => {
    expect(g.assignees).toBeUndefined();
    const withAssign = toGithubIssue(baseFinding, { assignees: ['alice', 'bob'] });
    expect(withAssign.assignees).toEqual(['alice', 'bob']);
  });

  it('body documents asset + CWE + OWASP + CVSS', () => {
    expect(g.body).toContain('api.example.com');
    expect(g.body).toContain('CWE-79');
    expect(g.body).toContain('A03:2021');
    expect(g.body).toContain('7.4');
  });
});

describe('toJiraIssue', () => {
  it('requires --project', () => {
    expect(() => toJiraIssue(baseFinding)).toThrow(/project/);
  });

  const j = toJiraIssue(baseFinding, { project: 'SEC' });

  it('summary carries H1 prefix', () => {
    expect(j.fields.summary.startsWith('[H1')).toBe(true);
  });

  it('priority maps from severity', () => {
    expect(j.fields.priority?.name).toBe('High');
    const crit = toJiraIssue({ ...baseFinding, severity: 'critical' }, { project: 'SEC' });
    expect(crit.fields.priority?.name).toBe('Highest');
    const lowOne = toJiraIssue({ ...baseFinding, severity: 'low' }, { project: 'SEC' });
    expect(lowOne.fields.priority?.name).toBe('Low');
  });

  it('description is valid ADF (Atlassian Document Format)', () => {
    expect(j.fields.description.type).toBe('doc');
    expect(j.fields.description.version).toBe(1);
    expect(Array.isArray(j.fields.description.content)).toBe(true);
    expect(j.fields.description.content.length).toBeGreaterThan(0);
    // Each paragraph must have one text node
    for (const p of j.fields.description.content) {
      expect(p.type).toBe('paragraph');
      expect(p.content[0]!.type).toBe('text');
      expect(typeof p.content[0]!.text).toBe('string');
    }
  });

  it('PII redacted in description ADF', () => {
    const text = j.fields.description.content.map((p) => p.content[0]!.text).join('\n');
    expect(text).not.toContain('hacker@example.com');
    expect(text).toContain('<email>');
  });

  it('labels include severity tag and cwe', () => {
    expect(j.fields.labels).toContain('security');
    expect(j.fields.labels).toContain('severity-high');
    expect(j.fields.labels).toContain('cwe-79');
  });

  it('issue type defaults to Bug; override via opts', () => {
    expect(j.fields.issuetype.name).toBe('Bug');
    const task = toJiraIssue(baseFinding, { project: 'SEC', issueType: 'Task' });
    expect(task.fields.issuetype.name).toBe('Task');
  });
});

describe('toIssue dispatch', () => {
  it('routes to github', () => {
    const g = toIssue('github', baseFinding);
    expect('title' in g).toBe(true);
    expect('labels' in g).toBe(true);
  });
  it('routes to jira', () => {
    const j = toIssue('jira', baseFinding, { project: 'X' });
    expect('fields' in j).toBe(true);
  });
});

describe('safety invariants', () => {
  it('no token / credential strings appear in any emit (sanity grep)', () => {
    const g = toGithubIssue(baseFinding);
    const j = toJiraIssue(baseFinding, { project: 'SEC' });
    const combined = JSON.stringify(g) + JSON.stringify(j);
    expect(combined).not.toMatch(/gho_[A-Za-z0-9]{20,}/);
    expect(combined).not.toMatch(/ghp_[A-Za-z0-9]{20,}/);
    expect(combined).not.toMatch(/AKIA[0-9A-Z]{16}/);
    expect(combined).not.toMatch(/Bearer\s+[A-Za-z0-9_.\-]{20,}/i);
  });
});
