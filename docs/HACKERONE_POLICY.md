# HackerOne API policy compliance

`@metaharness/hackerone` is designed to operate within HackerOne's API automation
policies. This document explains exactly what the harness does and does not do,
mapped against the constraints HackerOne publishes (or has publicly stated in
support / disclosure documentation).

## Sources

- HackerOne REST API docs — https://api.hackerone.com
- HackerOne submission policy — https://docs.hackerone.com/en/articles/8473994-submitting-reports
- HackerOne acceptable use & TOS — https://www.hackerone.com/terms
- Public commentary on bulk-automation prohibition — multiple HackerOne reports
  and platform announcements indicate accounts are rate-limited or blocked when
  generating auto-spam submissions

## What HackerOne allows

| Action | Allowed? | Notes |
|---|---|---|
| Programmatic READ of program scopes | ✅ Yes | The documented recon path |
| Programmatic READ of your own report list / details | ✅ Yes | Defender intake automation |
| Sync incoming reports to Jira / GitHub Issues via webhook | ✅ Yes | Designed for this |
| Triage state changes (program owner) | ✅ Yes | But not what this harness does in v0.1 |
| Single, human-authored, well-formed report submission | ✅ Yes | One at a time, manually triggered |
| Bulk automated report submission | ❌ Banned | Account block + report rejection |
| Hooking a scanner directly to the submit endpoint | ❌ Banned | Same |
| Submitting reports without verifiable proof-of-concept steps | ❌ Banned | Spam classification |
| Aggressive scraping of public program data | ⚠️ Discouraged | Respect rate limits |

## What `@metaharness/hackerone` v0.1 does

| Surface | API calls made | Policy compliance rationale |
|---|---|---|
| `ping` | `GET /me` (REST) or `query Ping { me }` (GraphQL) | Read-only, identifies the authenticated user; standard auth probe |
| `programs` | `GET /me/programs` | Read-only, one page (no aggressive pagination) |
| `scope <handle>` | `GET /programs/<handle>` | Read-only, one program, deterministic processing client-side |
| `triage <id>` | `GET /reports/<id>` + `GET /reports?filter[program]=<handle>&page[size]=100` | Read-only; classification is local |
| `triage-batch <handle>` | `GET /reports?filter[program]=<handle>&page[size]=100` | One page; classification is local; no auto-state-change |
| `classify "<text>"` | none | Fully offline; rule-based |
| `format <fixture>` | none | Fully offline; pure formatter |

**All v0.1 commands are READ-ONLY.** The harness does not call any HackerOne
mutation, write endpoint, or submit verb. The GraphQL client at
`src/api/graphql-client.ts` deliberately does not expose `mutation` operations
even though the underlying endpoint supports them.

## How the harness stays within policy at runtime

1. **No write API surface.** `HARD_SAFE_DEFAULTS.allowWrite = false` is frozen
   via `Object.freeze` and never read by the v0.1 client constructors. Adding a
   write surface in a future version requires a major bump + explicit gates
   (see `safety.ts:isWriteAllowed`).
2. **Token-bucket rate limiter.** `RateLimiter` caps API calls at 30/min per
   process by default. HackerOne's documented rate limit headers are not
   universally available across endpoints, so we self-cap below their floor.
3. **One page per call.** No subcommand recursively walks pagination. Batch
   triage caps `page[size]=100` and stops; the operator runs again if they need
   more. This stays well clear of "aggressive scraping" classification.
4. **Static query strings.** GraphQL queries are static literals with parameters
   passed as JSON variables — no user-controlled query interpolation, no
   introspection of the schema (since that's an unstable internal API surface
   we don't want to depend on or stress).
5. **Mock-by-default in CI.** When no key is configured the in-memory
   `MockHackerOneClient` is used, so CI runs make ZERO real API calls. The
   `--mock-api` flag forces this even when a key is present.
6. **User-Agent identifies the tool.** Every request sets
   `User-Agent: @metaharness/hackerone (v0.1.0)` so HackerOne's anti-abuse can
   identify and rate-limit this tooling distinctly from real browser traffic.
7. **No PII echo.** PII (emails, IPs, phones, CC-shaped sequences) is redacted
   before any payload is logged, persisted, or returned from a CLI handler.
8. **No credential echo.** The API key is fetched transiently from env / .env /
   GCP Secret Manager and never logged. Diagnostics return only `length + first
   4 chars`.

## What a future version would need to do for submit

If a future major (`v1.0` or later) adds a `submit` verb, the safety review
will need to cover (at minimum):

- **One report per invocation, never bulk.** No `submit-all`, no
  `--from-fixtures` directory mode.
- **Mandatory proof-of-concept payload check.** Refuse to submit without
  populated `reproduction` field of non-trivial length.
- **Mandatory CWE + asset + severity.** Refuse to submit without all three.
- **Operator confirmation step.** `--confirm` flag AND interactive `--dry-run`
  preview by default.
- **Operator-set rate cap.** Refuse to submit more than 1 report per
  configurable cooldown window (default 1 hour).
- **Audit log.** Every submission attempt logged locally with timestamp + program
  + finding hash, even when refused.
- **HackerOne ToS acknowledgement.** First-run prompt requires explicit ACK of
  https://www.hackerone.com/terms.

The above is documented as Phase 2 in the README. The v0.1 safety boundary in
`src/safety.ts` does not enable any of this.

## Reporting policy concerns

If you observe behavior that may violate HackerOne policy:
1. Open an issue at https://github.com/ruvnet/hackerone/issues
2. Describe the command + flags used + the resulting API call(s)
3. Tag the issue `policy-compliance`

We treat policy compliance as a security boundary — a violation is a bug, not a
feature request.
