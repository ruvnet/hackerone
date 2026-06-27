#!/usr/bin/env bash
# Structural smoke for @metaharness/hackerone v0.1.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PASS=0
FAIL=0
step() { printf "→ %s ... " "$1"; }
ok()   { printf "PASS\n"; PASS=$((PASS+1)); }
bad()  { printf "FAIL: %s\n" "$1"; FAIL=$((FAIL+1)); }

step "1. package.json declares correct name + bin"
node -e "
const j = JSON.parse(require('fs').readFileSync('$ROOT/package.json'));
if (j.name !== '@metaharness/hackerone') process.exit(1);
if (!j.bin || !j.bin.hackerone || !j.bin['metaharness-hackerone']) process.exit(2);
if (!j.engines || !j.engines.node) process.exit(3);
" 2>/dev/null && ok || bad "package.json invariants"

step "2. tsconfig.json strict + ESNext"
node -e "
const j = JSON.parse(require('fs').readFileSync('$ROOT/tsconfig.json'));
if (!j.compilerOptions.strict) process.exit(1);
if (j.compilerOptions.module !== 'ESNext') process.exit(2);
" 2>/dev/null && ok || bad "tsconfig invariants"

step "3. all src/*.ts parse"
miss=""
for f in $(find "$ROOT/src" -name '*.ts'); do
  node -e "require('typescript').transpileModule(require('fs').readFileSync('$f','utf-8'), {compilerOptions:{module:'ESNext',target:'ES2022'}})" 2>/dev/null \
    || miss="$miss $(basename "$f")"
done
[[ -z "$miss" ]] && ok || bad "ts-transpile failures:$miss"

step "4. cli/index.ts is bin-shim; cli/dispatch.ts is library"
miss=""
grep -q "^#!/usr/bin/env node" "$ROOT/src/cli/index.ts" || miss="$miss no-shebang"
grep -q "dispatch(sub, rest)" "$ROOT/src/cli/index.ts" || miss="$miss no-dispatch-call"
grep -q "export async function dispatch" "$ROOT/src/cli/dispatch.ts" || miss="$miss no-exported-dispatch"
# Comment-mentions of process.exit are fine; what's banned is an actual call.
! grep -qE "^[^/]*\bprocess\.exit\(" "$ROOT/src/cli/dispatch.ts" || miss="$miss dispatch-has-exit-side-effect"
[[ -z "$miss" ]] && ok || bad "$miss"

step "5. safety.ts hard-defaults frozen + write-allow gate present"
F="$ROOT/src/safety.ts"
miss=""
grep -q "Object.freeze" "$F" || miss="$miss no-freeze"
grep -q "isWriteAllowed" "$F" || miss="$miss no-write-gate"
grep -q "assertNoCredentialLeak" "$F" || miss="$miss no-cred-leak-guard"
grep -q "RateLimiter" "$F" || miss="$miss no-rate-limiter"
[[ -z "$miss" ]] && ok || bad "$miss"

step "6. api/key-source.ts implements all 3 sources"
F="$ROOT/src/api/key-source.ts"
miss=""
grep -q "process.env" "$F" || miss="$miss no-env-source"
grep -q "readFromDotenv\|readFromDotenv\|dotenv" "$F" || miss="$miss no-dotenv-source"
grep -q "gcloud" "$F" || miss="$miss no-gcp-source"
grep -q "toBasicAuthHeader" "$F" || miss="$miss no-basic-auth-helper"
# Never logs the key
grep -q "console.log.*key" "$F" && miss="$miss possible-key-log" || true
[[ -z "$miss" ]] && ok || bad "$miss"

step "7. mock client exports MOCK_FIXTURES with both sides covered"
F="$ROOT/src/api/mock-client.ts"
miss=""
grep -q "MOCK_FIXTURES" "$F" || miss="$miss no-fixtures-export"
grep -q "MockHackerOneClient" "$F" || miss="$miss no-mock-class"
grep -q "example-program" "$F" || miss="$miss no-example-program"
grep -q "demo-vdp" "$F" || miss="$miss no-demo-vdp"
grep -q "CWE-918\|SSRF" "$F" || miss="$miss no-ssrf-fixture"
grep -q "marketing.example.com\|out.of.scope" "$F" || miss="$miss no-out-of-scope-fixture"
[[ -z "$miss" ]] && ok || bad "$miss"

step "8. triage modules implement scope+cvss+dedupe+orchestrator"
miss=""
for f in scope-check.ts cvss.ts dedupe.ts triage.ts; do
  [[ -f "$ROOT/src/triage/$f" ]] || miss="$miss missing-$f"
done
grep -q "computeBaseScore" "$ROOT/src/triage/cvss.ts" || miss="$miss no-cvss-compute"
grep -q "scoreToSeverity" "$ROOT/src/triage/cvss.ts" || miss="$miss no-cvss-sev-map"
grep -q "findDuplicate" "$ROOT/src/triage/dedupe.ts" || miss="$miss no-find-duplicate"
grep -q "checkScope" "$ROOT/src/triage/scope-check.ts" || miss="$miss no-check-scope"
grep -q "triageReport" "$ROOT/src/triage/triage.ts" || miss="$miss no-triage-orchestrator"
[[ -z "$miss" ]] && ok || bad "$miss"

step "9. research modules implement cwe-map+scope-analysis+report-format+redblue-bridge"
miss=""
for f in cwe-map.ts scope-analysis.ts report-format.ts recon.ts asset-list.ts redblue-bridge.ts; do
  [[ -f "$ROOT/src/research/$f" ]] || miss="$miss missing-$f"
done
grep -q "classifyDescription" "$ROOT/src/research/cwe-map.ts" || miss="$miss no-classifier"
grep -q "CWE-79\|CWE-89\|CWE-918" "$ROOT/src/research/cwe-map.ts" || miss="$miss missing-cwes"
grep -q "buildReconPlan" "$ROOT/src/research/recon.ts" || miss="$miss no-recon-plan"
grep -q "formatFinding" "$ROOT/src/research/report-format.ts" || miss="$miss no-format-finding"
grep -q "toRedblueDraft" "$ROOT/src/research/redblue-bridge.ts" || miss="$miss no-redblue-bridge"
grep -q "auto_submit: false" "$ROOT/src/research/redblue-bridge.ts" || miss="$miss no-auto-submit-false"
grep -q "confirmed: opts.reproConfirmed === true" "$ROOT/src/research/redblue-bridge.ts" || miss="$miss no-default-false-repro"
[[ -z "$miss" ]] && ok || bad "$miss"

step "10. CLI has both surfaces (triage AND scope) + redblue bridge"
F="$ROOT/src/cli/dispatch.ts"
miss=""
grep -q "'triage'" "$F" || miss="$miss no-triage-cmd"
grep -q "'triage-batch'" "$F" || miss="$miss no-triage-batch-cmd"
grep -q "'scope'" "$F" || miss="$miss no-scope-cmd"
grep -q "'assets'" "$F" || miss="$miss no-assets-cmd"
grep -q "'classify'" "$F" || miss="$miss no-classify-cmd"
grep -q "'format'" "$F" || miss="$miss no-format-cmd"
grep -q "'export-redblue'" "$F" || miss="$miss no-export-redblue-cmd"
grep -q "'programs'" "$F" || miss="$miss no-programs-cmd"
grep -q "'init'" "$F" || miss="$miss no-init-cmd"
grep -q "'ping'" "$F" || miss="$miss no-ping-cmd"
grep -q "mock-api" "$F" || miss="$miss no-mock-flag"
[[ -z "$miss" ]] && ok || bad "$miss"

step "11. .env in .gitignore + .env.example present"
miss=""
[[ -f "$ROOT/.env.example" ]] || miss="$miss no-env-example"
grep -q "^.env$" "$ROOT/.gitignore" || miss="$miss .env-not-gitignored"
grep -q "!.env.example" "$ROOT/.gitignore" || miss="$miss no-env-example-allow"
# .env should NOT be checked in
[[ -f "$ROOT/.env" ]] && miss="$miss .env-was-committed" || true
[[ -z "$miss" ]] && ok || bad "$miss"

step "12. tests/ directory has ≥5 test files"
COUNT=$(find "$ROOT/tests" -name '*.test.ts' 2>/dev/null | wc -l | tr -d ' ')
[[ "$COUNT" -ge 5 ]] && ok || bad "test-file-count:$COUNT"

step "13. README documents the safety boundary"
F="$ROOT/README.md"
miss=""
[[ -f "$F" ]] || miss="$miss no-readme"
grep -qi "safety" "$F" || miss="$miss no-safety-section"
grep -qi "HACKERONE_API_KEY" "$F" || miss="$miss no-key-env-doc"
grep -qi "mock" "$F" || miss="$miss no-mock-doc"
[[ -z "$miss" ]] && ok || bad "$miss"

printf "\n%d passed, %d failed\n" "$PASS" "$FAIL"
exit $FAIL
