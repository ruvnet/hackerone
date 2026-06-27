// Resolve HACKERONE_API_KEY from (in priority order):
//   1. process.env.HACKERONE_API_KEY        — preferred path
//   2. .env file (cwd or repo root)         — local dev
//   3. GCP Secret Manager                   — CI / prod
//
// The resolver NEVER logs the resolved key. Diagnostics return only the
// length + first 4 chars + the source bucket. See KeyResolution in types.ts.
//
// This module shells out to `gcloud secrets versions access` rather than
// adding a heavy SDK dep — the @metaharness/* family keeps deps minimal.
// If gcloud isn't installed, GCP source is skipped silently.

import { readFileSync, existsSync } from 'node:fs';
import { join, resolve, dirname } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

import type { KeyResolution } from '../types.js';

const KEY_NAME = 'HACKERONE_API_KEY';
const GCP_PROJECT_ENV = 'GCP_PROJECT';

export interface KeyResolverOptions {
  /** Override cwd for .env lookup (tests). */
  cwd?: string;
  /** Override gcloud binary path (tests). */
  gcloudBin?: string;
  /** Skip GCP lookup entirely. */
  skipGcp?: boolean;
}

/**
 * Try each source in priority order. Returns the resolved key and a
 * KeyResolution describing where it came from. The key string is the
 * caller's responsibility to handle — DO NOT log it, DO NOT store it on
 * disk, DO NOT include it in error messages.
 */
export function resolveApiKey(opts: KeyResolverOptions = {}): {
  key: string | null;
  resolution: KeyResolution;
} {
  // 1. process.env — highest priority
  const fromEnv = process.env[KEY_NAME];
  if (fromEnv && fromEnv.trim()) {
    return {
      key: fromEnv.trim(),
      resolution: diagnose(fromEnv.trim(), 'env'),
    };
  }

  // 2. .env file (cwd, walking up to repo root)
  const fromDotenv = readFromDotenv(opts.cwd ?? process.cwd());
  if (fromDotenv) {
    return {
      key: fromDotenv,
      resolution: diagnose(fromDotenv, 'dotenv'),
    };
  }

  // 3. GCP Secret Manager
  if (!opts.skipGcp) {
    const gcpProject = process.env[GCP_PROJECT_ENV];
    if (gcpProject) {
      const fromGcp = readFromGcp(KEY_NAME, gcpProject, opts.gcloudBin ?? 'gcloud');
      if (fromGcp) {
        return {
          key: fromGcp,
          resolution: diagnose(fromGcp, 'gcp'),
        };
      }
    }
  }

  return {
    key: null,
    resolution: { found: false, source: 'none', length: 0 },
  };
}

/**
 * Minimal dotenv parser — handles `KEY=value`, `KEY="value"`, `# comment`.
 * No shell substitution. No quotes-inside-quotes handling. If the user
 * needs more, they should set the var in process.env directly.
 */
function readFromDotenv(cwd: string): string | null {
  let dir = resolve(cwd);
  const tried: string[] = [];
  // Walk up 6 levels max (cwd → repo root)
  for (let i = 0; i < 6; i++) {
    const path = join(dir, '.env');
    tried.push(path);
    if (existsSync(path)) {
      try {
        const contents = readFileSync(path, 'utf-8');
        const value = parseDotenv(contents, KEY_NAME);
        if (value) return value;
      } catch {
        // ignore parse errors — fall through to other sources
      }
    }
    const parent = dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return null;
}

function parseDotenv(contents: string, name: string): string | null {
  for (const rawLine of contents.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;
    const eq = line.indexOf('=');
    if (eq === -1) continue;
    const key = line.slice(0, eq).trim();
    if (key !== name) continue;
    let value = line.slice(eq + 1).trim();
    // Strip surrounding double or single quotes
    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    }
    if (!value || value === 'username:token-goes-here') return null; // placeholder
    return value;
  }
  return null;
}

/**
 * Shell out to `gcloud secrets versions access latest --secret=NAME --project=PROJECT`.
 * Returns null on any failure (gcloud missing, secret not found, auth error).
 * Stderr is intentionally discarded so the caller can decide whether to
 * fall back to mock-mode without surfacing GCP errors.
 */
function readFromGcp(secretName: string, project: string, gcloudBin: string): string | null {
  const r = spawnSync(
    gcloudBin,
    ['secrets', 'versions', 'access', 'latest', `--secret=${secretName}`, `--project=${project}`],
    {
      stdio: ['ignore', 'pipe', 'pipe'],
      encoding: 'utf-8',
      timeout: 15_000,
      shell: false,
    },
  );
  if (r.status !== 0 || !r.stdout) return null;
  const value = r.stdout.trim();
  // Reject placeholder / accidental garbage
  if (!value || value.length < 8) return null;
  return value;
}

function diagnose(key: string, source: KeyResolution['source']): KeyResolution {
  return {
    found: true,
    source,
    length: key.length,
    prefix: key.slice(0, 4) + '…',
  };
}

/**
 * Parse a HACKERONE_API_KEY value into the form the API client expects.
 *
 * Accepted formats:
 *   - "username:token"             → encoded as Basic <base64(username:token)>
 *   - "<pre-encoded-base64>"       → used as Basic <value> directly
 *   - "Basic <pre-encoded>"        → passed through verbatim
 *
 * We DON'T validate the encoded payload itself; HackerOne's API will
 * reject it if malformed, and that error is surfaced upstream.
 */
export function toBasicAuthHeader(key: string): string {
  const trimmed = key.trim();
  if (trimmed.toLowerCase().startsWith('basic ')) return trimmed;
  if (trimmed.includes(':')) {
    return 'Basic ' + Buffer.from(trimmed, 'utf-8').toString('base64');
  }
  // Already base64 — caller's problem if it's wrong
  return 'Basic ' + trimmed;
}
