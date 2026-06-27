# @metaharness/hackerone

> 🛡️ **A meta-harness for HackerOne workflows.** Defender-side triage (dedupe, CVSS scoring, scope-check, classification) AND researcher-side recon (scope analysis, OWASP/CWE mapping, report formatting) — all read-only, safety-contained, with a `$0` mock-mode for CI.

[![npm version](https://img.shields.io/npm/v/@metaharness/hackerone.svg)](https://www.npmjs.com/package/@metaharness/hackerone)
[![license: MIT](https://img.shields.io/npm/l/@metaharness/hackerone.svg)](./LICENSE)
[![node ≥20](https://img.shields.io/node/v/@metaharness/hackerone.svg)](https://nodejs.org)

## What it is

`@metaharness/hackerone` is a **deterministic, offline-first** harness for the two sides of a HackerOne engagement:

| Side | Verb | What it does |
|------|------|--------------|
| **Defender** (program owner) | `triage`, `triage-batch` | Score incoming reports against scope, recompute CVSS, dedupe vs history, recommend a new state |
| **Researcher** (bounty hunter) | `scope`, `classify`, `format` | Build a recon plan from a program's scope, classify free-text into CWE/OWASP, format a finding as a submission-ready report |

No ML, no embeddings, no external calls beyond the HackerOne API itself. Every classification is a transparent rule the SOC/researcher can audit and reproduce.

## ⚠️ Safety boundary (enforced in code)

The harness is **read-only and capability-contained** in v0.1. The defaults below are hard-frozen in `src/safety.ts`; nothing in this codebase relaxes them:

| Boundary | Enforcement |
|---|---|
| **No write API calls** | `HARD_SAFE_DEFAULTS.allowWrite = false` (frozen); write commands not implemented in v0.1 |
| **Mock-by-default** | When no `HACKERONE_API_KEY` is found, the in-memory `MockHackerOneClient` is used |
| **Forced mock** | `--mock-api` flag overrides any configured key |
| **Rate limit** | Token bucket caps API calls at 30/min per process (tunable) |
| **No credential logging** | The API key is fetched transiently; only `length + 4-char prefix` is ever echoed |
| **PII redaction** | Emails, IPs, phone numbers, CC-shaped sequences stripped before logging |
| **Scope validation** | Program handles are regex-validated before they hit any URL builder |
| **Credential-shape guard** | Reports/fixtures scanned for `gho_`, `AKIA`, `Bearer …`, PEM headers before logging |

Anyone reviewing `src/safety.ts` should be able to answer in one sentence: **"What's the worst this harness can do?"** → "Issue read-only HackerOne API calls scoped to one program, with a hard rate limit, with the key fetched transiently and never logged."

## Install

```bash
npm install @metaharness/hackerone
# or
npx @metaharness/hackerone --help
```

## Quick start — researcher side

```bash
# 1. Generate a sample config
npx hackerone init

# 2. Inspect a program's scope and get a test plan (mock-mode — no key needed)
npx hackerone scope example-program --mock-api

# 3. Classify a finding description
npx hackerone classify "Reflected XSS via search query parameter"
# → CWE: CWE-79 — Cross-site Scripting
# → OWASP: A03:2021
# → confidence: 0.91

# 4. Format a fixture as a HackerOne-style submission report
npx hackerone format fixtures/example-finding.json
```

### Recon pipeline (UNIX-style stdin/stdout)

The `assets` subcommand emits newline-delimited in-scope identifiers (with
a `#`-prefixed banner that recon tools ignore), so the harness drops
straight into Subfinder, Amass, Nuclei, httpx, etc.:

```bash
# Subdomain enumeration on in-scope wildcards
npx hackerone assets security --expand-wildcards | subfinder -dL -

# Active enum
npx hackerone assets <handle> --type URL,DOMAIN --expand-wildcards | amass enum -df -

# Nuclei against the live targets (after subdomain enum + httpx probe)
npx hackerone assets <handle> --expand-wildcards \
  | subfinder -dL - \
  | httpx -silent \
  | nuclei -t cves/ -severity high,critical

# Mobile-only — no URL noise
npx hackerone assets <handle> --type IOS_APP_STORE,ANDROID_PLAY_STORE
```

By default the asset list is **in-scope only** — pass
`--include-out-of-scope` to add a flagged `# OUT-OF-SCOPE` block (still
inert for recon tools, but informative for humans). The `--type` filter
accepts a comma-separated list of HackerOne asset types.

### Bridge to `@metaharness/redblue` for submit

`@metaharness/redblue@0.1.4` owns the human-gated HackerOne submit verb
(4 gates: scope / verification / per-report-confirm / no-batch; dry-run
default; scope verified live; CI/non-interactive refused). `@metaharness/
hackerone` does **not** reimplement submit. Instead, the bridge subcommand
emits the exact `HackerOneReportDraft` JSON redblue's submit gate
consumes, so the recon → triage → draft → submit handoff is one pipe:

```bash
# Produce a redblue-shaped draft from a finding JSON
npx hackerone export-redblue fixtures/example-finding.json > draft.json

# Pipe straight into redblue's submit gates (dry-run by default)
npx hackerone export-redblue fixtures/example-finding.json \
  | npx redblue submit --in - --dry-run
```

Defaults are safety-first:
- `draft.repro.confirmed = false` — redblue's verification gate refuses
  the draft unless the operator explicitly attests reproduction via
  `--repro-confirmed --repro-method "<how>"`.
- `submission.auto_submit = false` — hard-coded sentinel; redblue's
  submit gate refuses any draft missing this.
- No submit logic in this package — it just emits the shape.

Flags:
- `--repro-confirmed` — operator attests they reproduced the finding
- `--repro-method "<text>"` — how the repro was confirmed (free text)
- `--asset <id>` — override the asset (must match a live in-scope entry)
- `--family <enum>` — override the family heuristic (`prompt_injection`
  / `tool_overreach` / `data_exfiltration` / `role_confusion` /
  `cost_amplification`); CWE→family heuristic applies otherwise
- `--recommended-fix "<text>"` — surfaces in the draft

### Engineering-tracker sync (defender → Jira / GitHub Issues)

When the defender side wants to file an engineering ticket for a
triaged report, `export-issue` emits the POST body in the right shape;
the operator pipes to `curl` to actually create the ticket. **No
automation of the POST itself, no token handling here, no network
calls** — the harness only produces the payload.

```bash
# GitHub Issues — POST body to /repos/<o>/<n>/issues
npx hackerone export-issue finding.json \
    --kind github \
    --repo myorg/myrepo \
    --report-id 4242 \
    --labels frontend,p1 \
  | curl -X POST https://api.github.com/repos/myorg/myrepo/issues \
      -H "Authorization: Bearer $GITHUB_TOKEN" \
      -H "Accept: application/vnd.github+json" \
      -d @-

# Jira — POST body to /rest/api/3/issue
npx hackerone export-issue finding.json \
    --kind jira \
    --project SEC \
    --report-id 4242 \
  | curl -X POST https://myorg.atlassian.net/rest/api/3/issue \
      -H "Authorization: Basic $JIRA_TOKEN" \
      -H "Content-Type: application/json" \
      -d @-
```

Defaults:
- Title is auto-prefixed `[H1#<report-id>]` for searchability +
  dedup-by-operator.
- Labels for GitHub: `security`, `severity/<band>`, `cwe/<id>`.
- Priority for Jira: severity → `Highest|High|Medium|Low|Lowest`.
- Description is markdown for GitHub, ADF (Atlassian Document Format)
  for Jira.
- **PII redaction is on by default** — emails, IPs, phone numbers,
  CC-shaped digit sequences are stripped before emit. Override with
  `--skip-pii-redaction`.

Flags:
- `--kind jira|github` (default: github)
- `--project KEY` (required for Jira)
- `--repo owner/name` (GitHub informational)
- `--report-id <id>` (prepended to title)
- `--issue-type Bug|Task|…` (Jira)
- `--labels a,b,c` (additive)
- `--assignees a,b` (GitHub)
- `--skip-pii-redaction` (off by default)

### Batch classification from stdin

`classify --stdin` reads one finding description per line, emits one
JSON object per line (`{input, classification}`). Useful for piping
scanner alerts into the CWE/OWASP classifier:

```bash
# From a security log file
cat alerts.txt | npx hackerone classify --stdin > classified.jsonl

# From an inline list
printf "SQL injection on /api\nReflected XSS\n" | npx hackerone classify --stdin
```

Blank lines and `#`-prefixed comments are skipped.

## Quick start — defender side

```bash
# 1. Configure the API key (see "Configuring the API key" below)
export HACKERONE_API_KEY=username:token

# 2. Verify it resolves and connects
npx hackerone ping

# 3. Triage every open report in a program
npx hackerone triage-batch example-program --state new --json

# 4. Triage a single report
npx hackerone triage 1001 --program example-program
```

## Configuring the API key

The harness resolves `HACKERONE_API_KEY` in priority order:

1. **`process.env.HACKERONE_API_KEY`** — preferred for CI/CD
2. **`.env` file** (cwd or any parent up to 6 levels) — local dev
3. **GCP Secret Manager** — `gcloud secrets versions access latest --secret=HACKERONE_API_KEY --project=$GCP_PROJECT`

### Format

`HACKERONE_API_KEY` accepts either:
- `username:token` — encoded as Basic `<base64(username:token)>` automatically
- A pre-encoded base64 token — passed through

Get yours at https://hackerone.com/users/<you>/api_tokens.

### Session-cookie workflow (advanced — GraphQL `me` and private programs)

The HackerOne GraphQL endpoint authenticates **public** queries with just
`X-Auth-Token: <token>` (handled automatically when `HACKERONE_API_KEY`
is set). But user-bound queries (`me`, private program detail, your
submitted reports) need the **session cookie** that the web UI sends.

To use those queries from the harness:

1. Log in to https://hackerone.com in a browser
2. Open DevTools → Application/Storage → Cookies → `hackerone.com`
3. Copy the value of `_hackerone_session` (or the whole `Cookie:` header)
4. Export it transiently, never commit:

    ```bash
    export HACKERONE_SESSION_COOKIE="_hackerone_session=<value>"
    npx hackerone ping --no-mock --json   # should now report ok=true for `me`
    npx hackerone scope <your-private-program>
    ```

The cookie is **never** logged or stored on disk by the harness — same
treatment as the API key. Sessions expire; refresh by re-extracting.

### GCP Secret Manager (recommended for prod)

```bash
# One-time setup
echo -n 'username:token' | gcloud secrets create HACKERONE_API_KEY --data-file=- --project=ruv-dev

# Rotate
echo -n 'new-username:new-token' | gcloud secrets versions add HACKERONE_API_KEY --data-file=- --project=ruv-dev

# Grant CI access (one-time)
gcloud secrets add-iam-policy-binding HACKERONE_API_KEY \
  --member=serviceAccount:ci@ruv-dev.iam.gserviceaccount.com \
  --role=roles/secretmanager.secretAccessor \
  --project=ruv-dev
```

The harness fetches the secret transiently via `gcloud` at startup. It never writes the value to disk.

## CLI surface

| Subcommand | Side | Description |
|---|---|---|
| `init` | both | Write `.env.example` and `hackerone.yaml` to cwd |
| `ping` | both | Verify the API key resolves + connects (or report mock-mode) |
| `programs` | both | List programs accessible to the configured key |
| `scope <handle>` | researcher | Recon plan: top assets ranked by bounty potential, suggested checks per asset, forbidden assets |
| `classify "<description>"` | researcher | Map free-text into CWE + OWASP Top-10 + confidence |
| `format <path>` | researcher | Render a finding JSON as a HackerOne-style submission report |
| `triage <id> --program <handle>` | defender | Triage one report: scope → CVSS → dedupe → recommended state + reasoning |
| `triage-batch <handle>` | defender | Triage every open report on a program (use `--state new` to filter) |

All commands accept:
- `--mock-api` — force the in-memory mock client
- `--no-mock` — fail if no live API key is configured
- `--json` — emit JSON instead of human text

## Library use

```typescript
import {
  HackerOneClient,
  MockHackerOneClient,
  triageReport,
  buildReconPlan,
  classifyDescription,
  formatFinding,
  resolveApiKey,
} from '@metaharness/hackerone';

const { key } = resolveApiKey();
const client = key ? new HackerOneClient({ apiKey: key }) : new MockHackerOneClient();

const program = await client.getProgram('example-program');
const plan = buildReconPlan(program);
console.log(plan.topAssets);
```

Subpath imports for narrower bundles:

```typescript
import { triageReport } from '@metaharness/hackerone/triage';
import { classifyDescription } from '@metaharness/hackerone/research';
import { HARD_SAFE_DEFAULTS } from '@metaharness/hackerone/safety';
```

## Build / Test

```bash
npm install
npm run build           # tsc → dist/
npm test                # vitest run
npm run smoke           # structural smoke (no npm deps required)
```

## License

MIT — see [LICENSE](./LICENSE). Authored by [rUv](https://ruv.io).
