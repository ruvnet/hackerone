import { describe, it, expect } from 'vitest';
import { dispatch } from '../src/cli/dispatch.js';

describe('cli dispatch', () => {
  it('help exits 0 with subcommand list', async () => {
    const r = await dispatch('help', []);
    expect(r.code).toBe(0);
    expect(r.lines.join('\n')).toContain('Subcommands:');
    expect(r.lines.join('\n')).toContain('triage');
  });

  it('--help exits 0', async () => {
    const r = await dispatch('--help', []);
    expect(r.code).toBe(0);
  });

  it('unknown subcommand exits 2', async () => {
    const r = await dispatch('fakecmd', []);
    expect(r.code).toBe(2);
    expect(r.lines.join('\n')).toContain('unknown subcommand');
  });

  it('classify with a clear description picks CWE', async () => {
    const r = await dispatch('classify', ['Reflected XSS via search query']);
    expect(r.code).toBe(0);
    expect(r.lines.join('\n')).toContain('CWE-79');
  });

  it('classify --json emits JSON', async () => {
    const r = await dispatch('classify', ['SQL injection on /api', '--json']);
    expect(r.code).toBe(0);
    const json = JSON.parse(r.lines.join('\n'));
    expect(json.cwe).toBe('CWE-89');
  });

  it('programs (mock) returns the fixture programs', async () => {
    const r = await dispatch('programs', ['--mock-api']);
    expect(r.code).toBe(0);
    expect(r.lines.join('\n')).toContain('example-program');
    expect(r.lines.join('\n')).toContain('demo-vdp');
  });

  it('scope (mock) returns recon plan with assets + forbidden list', async () => {
    const r = await dispatch('scope', ['example-program', '--mock-api']);
    expect(r.code).toBe(0);
    const text = r.lines.join('\n');
    expect(text).toContain('Recon plan');
    expect(text).toContain('Top assets');
    expect(text).toContain('OUT OF SCOPE');
  });

  it('triage-batch (mock) returns one verdict per fixture report', async () => {
    const r = await dispatch('triage-batch', ['example-program', '--mock-api', '--json']);
    expect(r.code).toBe(0);
    const json = JSON.parse(r.lines.join('\n'));
    expect(Array.isArray(json)).toBe(true);
    expect(json.length).toBeGreaterThan(0);
    // Should produce at least one duplicate verdict (mock fixtures include duplicate XSS)
    expect(json.some((v: any) => v.recommendedState === 'duplicate')).toBe(true);
    // Should produce at least one not-applicable verdict (mock-1004 hits out-of-scope)
    expect(json.some((v: any) => v.recommendedState === 'not-applicable')).toBe(true);
  });

  it('ping (mock) reports mock=true', async () => {
    const r = await dispatch('ping', ['--mock-api', '--json']);
    expect(r.code).toBe(0);
    const json = JSON.parse(r.lines.join('\n'));
    expect(json.mock).toBe(true);
    expect(json.ok).toBe(true);
  });

  it('assets (mock) returns newline-delimited in-scope identifiers with banner', async () => {
    const r = await dispatch('assets', ['example-program', '--mock-api']);
    expect(r.code).toBe(0);
    const text = r.lines.join('\n');
    expect(text).toContain('@metaharness/hackerone');
    expect(text).toContain('api.example.com');
    expect(text).toContain('*.example.com');
    // Out-of-scope must NOT leak by default
    expect(text).not.toContain('marketing.example.com');
  });

  it('assets --include-out-of-scope flags out-of-scope as comment', async () => {
    const r = await dispatch('assets', [
      'example-program', '--mock-api', '--include-out-of-scope',
    ]);
    expect(r.code).toBe(0);
    const text = r.lines.join('\n');
    expect(text).toContain('# OUT-OF-SCOPE');
    expect(text).toContain('#   marketing.example.com');
  });

  it('assets --type ANDROID_PLAY_STORE filters to mobile only', async () => {
    const r = await dispatch('assets', [
      'example-program', '--mock-api', '--type', 'ANDROID_PLAY_STORE',
    ]);
    expect(r.code).toBe(0);
    const text = r.lines.join('\n');
    expect(text).toContain('com.example.android');
    expect(text).not.toContain('api.example.com');
  });

  it('assets --json returns structured payload', async () => {
    const r = await dispatch('assets', ['example-program', '--mock-api', '--json']);
    expect(r.code).toBe(0);
    const json = JSON.parse(r.lines.join('\n'));
    expect(json.programHandle).toBe('example-program');
    expect(Array.isArray(json.assets)).toBe(true);
    expect(json.count).toBe(json.assets.length);
  });

  it('scope --format lines produces pipe-friendly output', async () => {
    const r = await dispatch('scope', [
      'example-program', '--mock-api', '--format', 'lines',
    ]);
    expect(r.code).toBe(0);
    const text = r.lines.join('\n');
    expect(text).toContain('# @metaharness/hackerone');
    expect(text).toContain('api.example.com');
  });

  it('export-redblue emits a HackerOneReportDraft JSON', async () => {
    const r = await dispatch('export-redblue', ['fixtures/example-finding.json']);
    expect(r.code).toBe(0);
    const j = JSON.parse(r.lines.join('\n'));
    expect(j.draft).toBe(true);
    expect(j.submission.auto_submit).toBe(false);
    expect(j.repro.confirmed).toBe(false);
    expect(j.weakness.cwe[0].id).toBe('CWE-79');
    expect(j.severity.cvssRating).toBe('High');
    expect(j.asset).toBe('api.example.com');
    expect(Array.isArray(j.stepsToReproduce)).toBe(true);
    expect(j.stepsToReproduce.length).toBeGreaterThanOrEqual(2);
  });

  it('export-redblue --repro-confirmed flips the verification gate (operator-attested)', async () => {
    const r = await dispatch('export-redblue', [
      'fixtures/example-finding.json',
      '--repro-confirmed',
      '--repro-method', 'reproduced via curl in staging at 15:35',
    ]);
    expect(r.code).toBe(0);
    const j = JSON.parse(r.lines.join('\n'));
    expect(j.repro.confirmed).toBe(true);
    expect(j.repro.method).toContain('reproduced via curl');
  });

  it('export-redblue rejects invalid --family', async () => {
    const r = await dispatch('export-redblue', [
      'fixtures/example-finding.json',
      '--family', 'not-a-real-family',
    ]);
    expect(r.code).toBe(2);
    expect(r.lines.join('\n')).toContain('invalid --family');
  });

  it('export-issue (default kind=github) emits a labelled, redacted Issue body', async () => {
    const r = await dispatch('export-issue', [
      'fixtures/example-finding.json',
      '--report-id', '4242',
    ]);
    expect(r.code).toBe(0);
    const body = JSON.parse(r.lines.join('\n'));
    expect(body.title).toContain('[H1#4242]');
    expect(body.labels).toContain('security');
    expect(body.labels).toContain('severity/high');
    expect(body.labels).toContain('cwe/cwe-79');
    // PII guard: the fixture description doesn't have email but the report-format
    // module strips IPs / emails consistently; just ensure no raw IPs leak.
    expect(body.body).not.toMatch(/\b\d+\.\d+\.\d+\.\d+\b/);
  });

  it('export-issue --kind jira --project SEC emits Atlassian Document Format', async () => {
    const r = await dispatch('export-issue', [
      'fixtures/example-finding.json',
      '--kind', 'jira',
      '--project', 'SEC',
    ]);
    expect(r.code).toBe(0);
    const body = JSON.parse(r.lines.join('\n'));
    expect(body.fields.project.key).toBe('SEC');
    expect(body.fields.description.type).toBe('doc');
    expect(body.fields.priority.name).toBe('High');
  });

  it('export-issue --kind jira without --project fails with 2', async () => {
    const r = await dispatch('export-issue', [
      'fixtures/example-finding.json',
      '--kind', 'jira',
    ]);
    expect(r.code).toBe(2);
    expect(r.lines.join('\n')).toContain('project');
  });

  it('export-issue rejects unknown --kind', async () => {
    const r = await dispatch('export-issue', [
      'fixtures/example-finding.json',
      '--kind', 'gitlab',
    ]);
    expect(r.code).toBe(2);
    expect(r.lines.join('\n')).toContain('invalid --kind');
  });
});
