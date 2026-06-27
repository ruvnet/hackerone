// Extract a flat list of asset identifiers from a Program — the
// stdin-friendly form recon tools (Subfinder, Amass, Nuclei, etc.) expect.
//
// Each tool reads newline-delimited identifiers from stdin/-dL/-df. The
// asset-list extractor lets the harness drop straight into:
//
//   npx hackerone assets <handle> | subfinder -dL -
//   npx hackerone assets <handle> --type URL,DOMAIN | amass enum -df -
//   npx hackerone scope <handle> --format lines | nuclei -l -
//
// This module is pure (no I/O) — the CLI/MCP layer wraps it.

import type { Program, ScopeItem } from '../types.js';

export interface AssetListOptions {
  /** Filter to specific asset types (URL, DOMAIN, API, IOS_APP_STORE, …). */
  assetTypes?: string[];
  /**
   * Whether to include out-of-scope assets in the output. DEFAULT: false —
   * piping out-of-scope identifiers into a recon tool would test forbidden
   * targets, a policy violation. Caller MUST opt in explicitly.
   */
  includeOutOfScope?: boolean;
  /** Whether to expand "*.example.com" wildcards to a normalized form. */
  expandWildcards?: boolean;
  /**
   * Whether to deduplicate (case-insensitive). DEFAULT: true. Some recon
   * tools dedupe themselves but emitting clean lists is the polite thing.
   */
  dedupe?: boolean;
}

/**
 * Extract a flat, deduplicated list of in-scope asset identifiers.
 *
 * SAFETY: by default this returns ONLY in-scope assets. The caller must
 * pass `includeOutOfScope: true` to opt into out-of-scope identifiers,
 * and even then a banner string is the recommended emit path
 * (`formatAssetListWithBanner`) so the operator sees them flagged.
 */
export function extractAssets(program: Program, opts: AssetListOptions = {}): string[] {
  const dedupe = opts.dedupe !== false;
  const sources: ScopeItem[] = [];
  sources.push(...program.scope);
  if (opts.includeOutOfScope) sources.push(...program.outOfScope);

  let items = sources;
  if (opts.assetTypes && opts.assetTypes.length > 0) {
    const allowed = new Set(opts.assetTypes.map((t) => t.toUpperCase()));
    items = items.filter((s) => allowed.has(s.assetType?.toUpperCase()));
  }

  let ids = items.map((s) => normalize(s.identifier, opts));
  if (dedupe) {
    const seen = new Set<string>();
    ids = ids.filter((id) => {
      const k = id.toLowerCase();
      if (seen.has(k)) return false;
      seen.add(k);
      return true;
    });
  }
  return ids;
}

/**
 * Like extractAssets() but renders a leading banner comment block listing
 * any out-of-scope identifiers (when includeOutOfScope is true) so a human
 * piping into a recon tool sees them clearly flagged.
 *
 * The format is:
 *
 *   # @metaharness/hackerone — program=<handle> in-scope=N out-of-scope=M
 *   # OUT-OF-SCOPE (do not test):
 *   #   marketing.example.com
 *   <in-scope identifiers, one per line>
 *
 * Subfinder/Amass/Nuclei all ignore lines starting with `#`, so the
 * banner is a no-op for them but informative for humans.
 */
export function formatAssetListWithBanner(program: Program, opts: AssetListOptions = {}): string {
  const inScope = extractAssets(program, { ...opts, includeOutOfScope: false });
  const outOfScope = opts.includeOutOfScope
    ? extractAssets(program, { ...opts, includeOutOfScope: true }).filter(
        (id) => !inScope.includes(id),
      )
    : [];
  const lines: string[] = [];
  lines.push(
    `# @metaharness/hackerone — program=${program.handle} in-scope=${inScope.length} out-of-scope=${outOfScope.length}`,
  );
  if (outOfScope.length > 0) {
    lines.push('# OUT-OF-SCOPE (do not test):');
    for (const id of outOfScope) lines.push(`#   ${id}`);
  }
  lines.push(...inScope);
  return lines.join('\n');
}

/**
 * Normalize an asset identifier for piping. Strips protocol + trailing
 * slash. Optionally expands `*.foo` → `foo` for tools that don't
 * understand the wildcard (e.g., Subfinder treats `foo` as the apex and
 * enumerates subdomains itself).
 */
function normalize(raw: string, opts: AssetListOptions): string {
  let s = raw.trim();
  s = s.replace(/^https?:\/\//, '').replace(/\/.*$/, '');
  if (opts.expandWildcards && s.startsWith('*.')) {
    s = s.slice(2);
  }
  return s;
}
