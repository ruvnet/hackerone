#!/usr/bin/env node
// CLI entry point for @metaharness/hackerone.
//
// Subcommands:
//   init                              — write a sample config
//   ping                              — verify the API key resolves + connects
//   programs [--mock-api]             — list programs accessible to the key
//   scope <handle> [--mock-api]       — researcher recon plan for a program
//   classify "<description>"          — classify free-text into CWE/OWASP
//   triage <report-id> [--program H]  — triage a single report against history
//   triage-batch <handle> [--state]   — triage every open report on a program
//   format <fixture-path>             — format a finding fixture as markdown
//
// SAFETY:
//   - All commands run against the in-memory MockHackerOneClient by
//     default unless HACKERONE_API_KEY is set AND --no-mock is passed.
//   - --mock-api forces mock mode even if a key is present.
//   - No write/state-change commands in v0.1.
//
// BIN BOOTSTRAP:
//   We call main() unconditionally rather than gating on
//   `import.meta.url === \`file://${process.argv[1]}\`` because npx's
//   symlinked shim breaks that pattern (silent exit 0 with no output).
//   Bundling consumers who don't want CLI side effects should import
//   from the library entry (../index.js), not ./cli/index.js.

import { resolveApiKey } from '../api/key-source.js';
import { HackerOneClient } from '../api/client.js';
import { HackerOneGraphQLClient } from '../api/graphql-client.js';
import { MockHackerOneClient } from '../api/mock-client.js';
import type { ApiClient } from '../api/client.js';
import { triageReport } from '../triage/triage.js';
import { buildReconPlan, classifyDescription, formatFinding } from '../research/recon.js';
import { extractAssets, formatAssetListWithBanner } from '../research/asset-list.js';
import { readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';

export interface CliResult {
  code: number;
  lines: string[];
}

const VALID_SUBS = new Set([
  'init', 'ping', 'programs', 'scope', 'assets', 'classify', 'triage', 'triage-batch', 'format', 'help',
]);

const SAMPLE_ENV = `# @metaharness/hackerone — sample env file
# Copy to .env (NEVER commit). See README for the full safety boundary.

HACKERONE_API_KEY=username:token-goes-here
GCP_PROJECT=ruv-dev
HACKERONE_ALLOW_WRITE=0
`;

const SAMPLE_CONFIG = `# @metaharness/hackerone engagement config (YAML)
# Set with --config <path> on any command.

program: example-program
dedupe_threshold: 0.5
max_calls_per_min: 30
mock_api: true       # set false once HACKERONE_API_KEY is configured
`;

interface ParsedArgs {
  positional: string[];
  flags: Record<string, string | boolean>;
}

function parseArgs(argv: string[]): ParsedArgs {
  const positional: string[] = [];
  const flags: Record<string, string | boolean> = {};
  for (let i = 0; i < argv.length; i++) {
    const v = argv[i];
    if (!v) continue;
    if (v.startsWith('--')) {
      const next = argv[i + 1];
      if (next === undefined || next.startsWith('--')) {
        flags[v.slice(2)] = true;
      } else {
        flags[v.slice(2)] = next;
        i++;
      }
    } else {
      positional.push(v);
    }
  }
  return { positional, flags };
}

function pickClient(args: ParsedArgs): { client: ApiClient; mock: boolean; keyDiag: string } {
  const forceMock = args.flags['mock-api'] === true || args.flags['mock-api'] === 'true';
  const noMock = args.flags['no-mock'] === true;
  // GraphQL is the DEFAULT transport (iter 1 finding: HackerOne's
  // documented internal API path; X-Auth-Token works for public queries).
  // REST is the opt-in fallback for the documented public REST surface.
  const useRest = args.flags.rest === true;
  if (forceMock) {
    return { client: new MockHackerOneClient(), mock: true, keyDiag: 'mock (forced via --mock-api)' };
  }
  const { key, resolution } = resolveApiKey();
  if (!key) {
    if (noMock) {
      throw new Error('@metaharness/hackerone: no HACKERONE_API_KEY found (env / .env / GCP) and --no-mock was passed');
    }
    return { client: new MockHackerOneClient(), mock: true, keyDiag: 'mock (no key found in env/.env/gcp)' };
  }
  const transport = useRest ? 'rest' : 'graphql';
  const diag = `live ${transport} (source=${resolution.source}, len=${resolution.length}, prefix=${resolution.prefix})`;
  const sessionCookie = process.env['HACKERONE_SESSION_COOKIE'];
  const client: ApiClient = useRest
    ? new HackerOneClient({ apiKey: key })
    : new HackerOneGraphQLClient({
        apiKey: key,
        ...(sessionCookie ? { sessionCookie } : {}),
      });
  return { client, mock: false, keyDiag: diag };
}

/**
 * Dispatch a subcommand and collect its output.
 *
 * Returns `{ lines, code }` so the umbrella forwarder pattern works (the
 * `metaharness` package, when published, can route
 * `metaharness hackerone <...>` here).
 */
export async function dispatch(sub: string | undefined, args: string[]): Promise<CliResult> {
  const parsed = parseArgs(args);
  const lines: string[] = [];
  const out = (s: string) => lines.push(s);

  if (!sub || sub === 'help' || sub === '--help' || sub === '-h') {
    out('Usage: hackerone <subcommand> [options]');
    out('');
    out('Subcommands:');
    out('  init                          Write .env.example to cwd');
    out('  ping                          Verify the API key resolves + connects');
    out('  programs                      List programs accessible to the API key');
    out('  scope <handle>                Researcher recon plan for a program');
    out('  assets <handle>               Print newline-delimited in-scope assets (pipe-friendly)');
    out('  classify "<description>"      Classify free-text into CWE/OWASP (--stdin for batch)');
    out('  triage <report-id> [--program H]   Triage one report against history');
    out('  triage-batch <handle>         Triage every open report on a program');
    out('  format <fixture-path>         Format a finding fixture as markdown');
    out('');
    out('Common options:');
    out('  --mock-api          Force in-memory mock client (no live API)');
    out('  --no-mock           Fail if no live API key is configured');
    out('  --json              Emit JSON instead of human text');
    out('');
    out('SAFETY: read-only by default; no write/state-change commands in v0.1.');
    return { code: 0, lines };
  }

  if (!VALID_SUBS.has(sub)) {
    return { code: 2, lines: [`@metaharness/hackerone: unknown subcommand "${sub}"`] };
  }

  // Subcommand handlers write into the closure's `lines` via `out()` and
  // return JUST a code; this dispatcher then bundles the closure-collected
  // lines with that code. Subcommand-returned `lines` arrays (kept for
  // back-compat with the CliResult shape) are merged in too.
  try {
    let code = 2;
    let r: CliResult;
    switch (sub) {
      case 'init': r = await cmdInit(parsed, out); break;
      case 'ping': r = await cmdPing(parsed, out); break;
      case 'programs': r = await cmdPrograms(parsed, out); break;
      case 'scope': r = await cmdScope(parsed, out); break;
      case 'assets': r = await cmdAssets(parsed, out); break;
      case 'classify': r = await cmdClassify(parsed, out); break;
      case 'triage': r = await cmdTriage(parsed, out); break;
      case 'triage-batch': r = await cmdTriageBatch(parsed, out); break;
      case 'format': r = cmdFormat(parsed, out); break;
      default: r = { code: 2, lines: [] };
    }
    code = r.code;
    // Subcommand may have returned additional lines (e.g., error pre-empt).
    for (const l of r.lines) lines.push(l);
    return { code, lines };
  } catch (e) {
    return { code: 1, lines: [`@metaharness/hackerone: ${e instanceof Error ? e.message : String(e)}`] };
  }
}

// ──────────────────────────────────────────────────────────────────────
// Subcommand implementations
// ──────────────────────────────────────────────────────────────────────

async function cmdInit(args: ParsedArgs, out: (s: string) => void): Promise<CliResult> {
  const envOut = (args.flags['env-out'] as string) ?? '.env.example';
  const cfgOut = (args.flags['config-out'] as string) ?? 'hackerone.yaml';
  writeFileSync(envOut, SAMPLE_ENV);
  writeFileSync(cfgOut, SAMPLE_CONFIG);
  out(`Wrote ${resolve(envOut)} and ${resolve(cfgOut)}`);
  out('Next steps:');
  out('  1. Copy .env.example → .env and fill in HACKERONE_API_KEY');
  out('  2. Or: gcloud secrets versions add HACKERONE_API_KEY --data-file=- --project=ruv-dev');
  out('  3. Run: hackerone ping  (verifies the key resolves)');
  return { code: 0, lines: [] };
}

async function cmdPing(args: ParsedArgs, out: (s: string) => void): Promise<CliResult> {
  const { client, mock, keyDiag } = pickClient(args);
  const result = await client.ping();
  if (args.flags.json) {
    // JSON mode: no human-text preamble — output must be JSON.parse-able as-is.
    out(JSON.stringify({ ...result, keyDiag }, null, 2));
  } else {
    out(`auth: ${keyDiag}`);
    out(`mock: ${mock}`);
    out(`ok: ${result.ok}`);
    out(`rate-limit-remaining: ${result.rateLimitRemaining}`);
  }
  return { code: result.ok ? 0 : 1, lines: [] };
}

async function cmdPrograms(args: ParsedArgs, out: (s: string) => void): Promise<CliResult> {
  const { client } = pickClient(args);
  const programs = await client.listPrograms();
  if (args.flags.json) {
    out(JSON.stringify(programs, null, 2));
  } else {
    out(`Found ${programs.length} program(s):`);
    for (const p of programs) {
      out(`  ${p.handle.padEnd(24)} ${p.offersBounties ? '💰' : '  '} ${p.name}`);
      out(`      ${p.scope.length} in-scope, ${p.outOfScope.length} out-of-scope`);
    }
  }
  return { code: 0, lines: [] };
}

async function cmdScope(args: ParsedArgs, out: (s: string) => void): Promise<CliResult> {
  const handle = args.positional[0];
  if (!handle) return { code: 2, lines: ['scope: missing program handle. Usage: scope <handle>'] };
  const { client } = pickClient(args);
  const program = await client.getProgram(handle);

  // --format lines → newline-delimited identifiers, pipe-friendly for recon tools.
  if (args.flags.format === 'lines') {
    const text = formatAssetListWithBanner(program, {
      includeOutOfScope: args.flags['include-out-of-scope'] === true,
      expandWildcards: args.flags['expand-wildcards'] === true,
      ...(typeof args.flags.type === 'string'
        ? { assetTypes: args.flags.type.split(',') }
        : {}),
    });
    out(text);
    return { code: 0, lines: [] };
  }

  const plan = buildReconPlan(program);
  if (args.flags.json) {
    out(JSON.stringify(plan, null, 2));
  } else {
    out(`# Recon plan: ${plan.programHandle} (${plan.offersBounties ? 'bounty' : 'VDP'})`);
    out('');
    out('## Top assets to test');
    for (const a of plan.topAssets) {
      out(`  - ${a.identifier} (${a.assetType}) maxSev=${a.maxSeverity ?? '?'} weight=${a.weight}`);
    }
    out('');
    out('## Top check families');
    for (const c of plan.topChecks) out(`  - ${c}`);
    out('');
    out('## OUT OF SCOPE (do NOT test)');
    if (plan.forbiddenAssets.length === 0) out('  (none declared)');
    for (const f of plan.forbiddenAssets) out(`  - ${f}`);
  }
  return { code: 0, lines: [] };
}

async function cmdAssets(args: ParsedArgs, out: (s: string) => void): Promise<CliResult> {
  const handle = args.positional[0];
  if (!handle) return { code: 2, lines: ['assets: missing program handle. Usage: assets <handle>'] };
  const { client } = pickClient(args);
  const program = await client.getProgram(handle);
  const includeOutOfScope = args.flags['include-out-of-scope'] === true;
  const expandWildcards = args.flags['expand-wildcards'] === true;
  const assetTypes =
    typeof args.flags.type === 'string' ? args.flags.type.split(',').map((t) => t.trim()) : undefined;

  if (args.flags.json) {
    const items = extractAssets(program, {
      includeOutOfScope,
      expandWildcards,
      ...(assetTypes ? { assetTypes } : {}),
    });
    out(JSON.stringify({ programHandle: program.handle, count: items.length, assets: items }, null, 2));
    return { code: 0, lines: [] };
  }

  // Default: newline-delimited assets with a banner header. The banner is
  // a comment block (lines start with `#`) so it's a no-op for tools like
  // Subfinder / Amass / Nuclei that read targets from stdin.
  const text = formatAssetListWithBanner(program, {
    includeOutOfScope,
    expandWildcards,
    ...(assetTypes ? { assetTypes } : {}),
  });
  out(text);
  return { code: 0, lines: [] };
}

async function cmdClassify(args: ParsedArgs, out: (s: string) => void): Promise<CliResult> {
  // --stdin: read one description per line; classify each, JSON-line out.
  // Useful for piping security scanner alert summaries through batch
  // classification → CWE/OWASP routing.
  if (args.flags.stdin === true) {
    return classifyStdin(args, out);
  }
  const desc = args.positional.join(' ');
  if (!desc) return { code: 2, lines: ['classify: pass a description as a positional argument or --stdin'] };
  const result = classifyDescription(desc);
  if (args.flags.json) {
    out(JSON.stringify(result, null, 2));
  } else if (!result) {
    out('No CWE rule fired. The description may be too short or describe an uncommon bug class.');
  } else {
    out(`CWE: ${result.cwe} — ${result.name}`);
    if (result.owasp) out(`OWASP: ${result.owasp}`);
    out(`confidence: ${result.confidence.toFixed(2)}`);
    if (result.alternatives.length > 0) {
      out('alternatives:');
      for (const a of result.alternatives) {
        out(`  - ${a.cwe} ${a.name}${a.owasp ? ` (${a.owasp})` : ''} @ ${a.confidence.toFixed(2)}`);
      }
    }
  }
  return { code: result ? 0 : 1, lines: [] };
}

/**
 * Read newline-delimited descriptions from stdin; classify each; emit
 * JSON-line output (one object per input line). Skip blank lines and
 * shell comments (lines starting with `#`).
 */
async function classifyStdin(args: ParsedArgs, out: (s: string) => void): Promise<CliResult> {
  const wantJson = args.flags.json !== false; // JSON-line is the default in stdin mode
  // Read all of stdin synchronously — descriptions are short, batches small.
  const raw = await new Promise<string>((resolveStdin) => {
    let buf = '';
    process.stdin.setEncoding('utf-8');
    process.stdin.on('data', (chunk: string) => { buf += chunk; });
    process.stdin.on('end', () => resolveStdin(buf));
  });
  const inputs = raw
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith('#'));
  let anyHit = false;
  for (const line of inputs) {
    const result = classifyDescription(line);
    if (result) anyHit = true;
    if (wantJson) {
      out(JSON.stringify({ input: line, classification: result }));
    } else {
      out(`${line} → ${result ? `${result.cwe} (${result.name}) @ ${result.confidence.toFixed(2)}` : 'unclassified'}`);
    }
  }
  // Return 0 if at least one was classified (lenient for batch use).
  return { code: anyHit ? 0 : 1, lines: [] };
}

async function cmdTriage(args: ParsedArgs, out: (s: string) => void): Promise<CliResult> {
  const reportId = args.positional[0];
  if (!reportId) return { code: 2, lines: ['triage: missing report id. Usage: triage <report-id> --program <handle>'] };
  const programHandle = args.flags.program as string | undefined;
  if (!programHandle) return { code: 2, lines: ['triage: --program <handle> is required'] };
  const { client } = pickClient(args);
  const program = await client.getProgram(programHandle);
  const report = await client.getReport(reportId);
  const history = await client.listReports(programHandle, { limit: 100 });
  const verdict = triageReport(report, { program, history });
  if (args.flags.json) {
    out(JSON.stringify(verdict, null, 2));
  } else {
    out(`# Triage verdict for report ${verdict.reportId}`);
    out(`recommendedState: ${verdict.recommendedState}`);
    out(`severity: ${verdict.severity}` + (verdict.cvssScore !== undefined ? ` (CVSS ${verdict.cvssScore})` : ''));
    out(`inScope: ${verdict.inScope}`);
    if (verdict.duplicateOf) out(`duplicateOf: ${verdict.duplicateOf}`);
    out(`confidence: ${verdict.confidence}`);
    out('');
    out('Reasoning:');
    for (const r of verdict.reasoning) out(`  ${r}`);
  }
  return { code: 0, lines: [] };
}

async function cmdTriageBatch(args: ParsedArgs, out: (s: string) => void): Promise<CliResult> {
  const programHandle = args.positional[0];
  if (!programHandle) return { code: 2, lines: ['triage-batch: missing program handle'] };
  const stateFilter = args.flags.state as string | undefined;
  const { client } = pickClient(args);
  const program = await client.getProgram(programHandle);
  const baseOpts: { state?: string; limit: number } = { limit: 100 };
  if (stateFilter) baseOpts.state = stateFilter;
  const reports = await client.listReports(programHandle, baseOpts);
  const verdicts = reports.map((r) =>
    triageReport(r, { program, history: reports.filter((x) => x.id !== r.id) }),
  );
  if (args.flags.json) {
    out(JSON.stringify(verdicts, null, 2));
  } else {
    out(`# Batch triage: ${verdicts.length} reports`);
    for (const v of verdicts) {
      out(`  ${v.reportId} → ${v.recommendedState.padEnd(18)} sev=${v.severity.padEnd(8)} conf=${v.confidence}`);
    }
  }
  return { code: 0, lines: [] };
}

function cmdFormat(args: ParsedArgs, out: (s: string) => void): CliResult {
  const path = args.positional[0];
  if (!path) return { code: 2, lines: ['format: missing fixture path'] };
  const data = JSON.parse(readFileSync(path, 'utf-8'));
  const finding = (data.finding ?? data) as Parameters<typeof formatFinding>[0];
  const opts: Parameters<typeof formatFinding>[1] = {};
  if (args.flags.researcher) opts.researcher = String(args.flags.researcher);
  const md = formatFinding(finding, opts);
  out(md);
  return { code: 0, lines: [] };
}

// NOTE: this file is library-only — no bin bootstrap here so callers
// importing `@metaharness/hackerone/cli` don't trigger a process.exit.
// The bin shim lives in `src/cli/index.ts` and is what package.json's
// `bin` field points at.
