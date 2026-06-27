// Bridge: convert a @metaharness/hackerone Finding → an engineering
// ticket POST body for Jira or GitHub Issues.
//
// This closes the defender-side "fix" workflow: an analyst triages a
// HackerOne report with this harness, then pipes the finding straight
// into their internal tracker:
//
//   npx hackerone export-issue finding.json --kind github --repo owner/name \
//     | curl -X POST https://api.github.com/repos/owner/name/issues \
//         -H "Authorization: Bearer $GITHUB_TOKEN" \
//         -H "Accept: application/vnd.github+json" \
//         -d @-
//
//   npx hackerone export-issue finding.json --kind jira --project SEC \
//     | curl -X POST https://your-org.atlassian.net/rest/api/3/issue \
//         -H "Authorization: Basic $JIRA_TOKEN" \
//         -H "Content-Type: application/json" \
//         -d @-
//
// SAFETY (load-bearing — DO NOT WEAKEN):
//   - Pure transform. No network calls. No tokens read.
//   - PII redaction applied to the description before emit
//     (redactPii from safety.ts) — the engineering tracker may have
//     wider access than the security team.
//   - No automation of the POST itself. The operator pipes to curl;
//     this stays well inside HackerOne's "automation does
//     discovery→validate→draft→scope-check, a human owns each
//     submission" line, applied to engineering-ticket creation.
//   - Title prefix `[H1#<id>]` is hard-coded so engineering can search
//     and dedupe; rejecting an unsigned prefix is a future ticket-side
//     concern.

import type { Finding, Severity } from '../types.js';
import { redactPii } from '../safety.js';

export type IssueKind = 'jira' | 'github';

/** GitHub Issues POST body shape (subset we populate). */
export interface GithubIssueBody {
  title: string;
  body: string;
  labels: string[];
  assignees?: string[];
}

/** Jira issue create body (subset we populate). */
export interface JiraIssueBody {
  fields: {
    project: { key: string };
    summary: string;
    /** Atlassian Document Format (plain doc with paragraphs). */
    description: {
      type: 'doc';
      version: 1;
      content: Array<{
        type: 'paragraph';
        content: Array<{ type: 'text'; text: string }>;
      }>;
    };
    issuetype: { name: string };
    priority?: { name: string };
    labels?: string[];
  };
}

export interface IssueBridgeOptions {
  /** Jira: project key. e.g., "SEC", "PLATFORM" */
  project?: string;
  /** GitHub: "owner/name" (informational only; goes in the title prefix). */
  repo?: string;
  /** Override the default issue-type / labels. */
  issueType?: string;
  /** Additional labels to append. */
  labels?: string[];
  /** GitHub-only: assignees. */
  assignees?: string[];
  /** HackerOne report id, prepended to the title for searchability. */
  hackeroneReportId?: string;
  /** Skip the PII redaction step (operator override; off by default). */
  skipPiiRedaction?: boolean;
}

/** Severity → Jira priority name. Sane defaults; orgs can re-map their own. */
const JIRA_PRIORITY: Record<Severity, string> = {
  critical: 'Highest',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  none: 'Lowest',
};

/** Severity → GitHub label suffix. */
const GH_SEV_LABEL: Record<Severity, string> = {
  critical: 'severity/critical',
  high: 'severity/high',
  medium: 'severity/medium',
  low: 'severity/low',
  none: 'severity/info',
};

/** Build the title: "[H1#1234] Reflected XSS in /search?q=" */
function buildTitle(finding: Finding, hackeroneReportId?: string): string {
  const prefix = hackeroneReportId ? `[H1#${hackeroneReportId}] ` : '[H1] ';
  return prefix + finding.title;
}

/** Markdown body shared between Jira-plain and GitHub. */
function buildMarkdown(finding: Finding, opts: IssueBridgeOptions): string {
  const sev = finding.severity ?? 'medium';
  const redact = opts.skipPiiRedaction ? (s: string) => s : redactPii;
  const lines: string[] = [];
  lines.push('## Summary');
  lines.push(redact(finding.description || '_(no description)_'));
  lines.push('');
  if (finding.reproduction) {
    lines.push('## Steps to Reproduce');
    lines.push(redact(finding.reproduction));
    lines.push('');
  }
  lines.push('## Classification');
  lines.push(`- **Asset:** \`${finding.asset}\``);
  lines.push(`- **Severity:** ${sev}` + (finding.cvssScore !== undefined ? ` (CVSS ${finding.cvssScore})` : ''));
  if (finding.cwe) lines.push(`- **CWE:** ${finding.cwe}`);
  if (finding.owasp) lines.push(`- **OWASP Top-10 (2021):** ${finding.owasp}`);
  if (finding.cvssVector) lines.push(`- **CVSS Vector:** \`${finding.cvssVector}\``);
  lines.push('');
  lines.push('---');
  lines.push(`_Filed via @metaharness/hackerone v0.1.0 — defender triage → engineering sync._`);
  if (opts.hackeroneReportId) lines.push(`_Source: HackerOne report ${opts.hackeroneReportId}_`);
  return lines.join('\n');
}

/** Build a GitHub Issues POST body from a finding. */
export function toGithubIssue(finding: Finding, opts: IssueBridgeOptions = {}): GithubIssueBody {
  const sev = finding.severity ?? 'medium';
  const labels = new Set<string>([
    'security',
    GH_SEV_LABEL[sev],
    ...(finding.cwe ? [`cwe/${finding.cwe.toLowerCase()}`] : []),
    ...(opts.labels ?? []),
  ]);
  const out: GithubIssueBody = {
    title: buildTitle(finding, opts.hackeroneReportId),
    body: buildMarkdown(finding, opts),
    labels: [...labels],
  };
  if (opts.assignees && opts.assignees.length > 0) out.assignees = opts.assignees;
  return out;
}

/** Build a Jira issue-create POST body from a finding. */
export function toJiraIssue(finding: Finding, opts: IssueBridgeOptions = {}): JiraIssueBody {
  if (!opts.project) {
    throw new Error('@metaharness/hackerone: --project <KEY> is required for Jira (e.g., SEC)');
  }
  const sev = finding.severity ?? 'medium';
  const labels: string[] = [
    'security',
    `severity-${sev}`,
    ...(finding.cwe ? [finding.cwe.toLowerCase()] : []),
    ...(opts.labels ?? []),
  ];
  const md = buildMarkdown(finding, opts);
  // Render markdown as ADF — minimal: each newline-separated paragraph
  // becomes a paragraph block. Jira's full ADF supports headings/lists
  // but a flat paragraph block survives every Jira instance + add-on.
  const paragraphs = md
    .split(/\n\n+/)
    .map((p) => p.trim())
    .filter(Boolean)
    .map((text) => ({
      type: 'paragraph' as const,
      content: [{ type: 'text' as const, text }],
    }));

  return {
    fields: {
      project: { key: opts.project },
      summary: buildTitle(finding, opts.hackeroneReportId),
      description: {
        type: 'doc',
        version: 1,
        content: paragraphs,
      },
      issuetype: { name: opts.issueType ?? 'Bug' },
      priority: { name: JIRA_PRIORITY[sev] },
      labels,
    },
  };
}

/** Dispatch: pick the right transform by kind. */
export function toIssue(kind: IssueKind, finding: Finding, opts: IssueBridgeOptions = {}): GithubIssueBody | JiraIssueBody {
  switch (kind) {
    case 'github': return toGithubIssue(finding, opts);
    case 'jira':   return toJiraIssue(finding, opts);
  }
}
