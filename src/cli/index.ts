#!/usr/bin/env node
// Bin entry for `metaharness-hackerone` / `hackerone`.
//
// This file is the bin shim. It calls main() unconditionally (NOT gated
// on `import.meta.url === \`file://${process.argv[1]}\`` — that pattern
// breaks under npx's symlinked shim and silently exits 0 with no output;
// observed bug in @metaharness/redblue@0.1.1).
//
// All CLI logic lives in ./dispatch.ts so consumers importing
// `@metaharness/hackerone/cli` get the dispatch() API without side
// effects.

import { dispatch } from './dispatch.js';

const [, , sub, ...rest] = process.argv;
dispatch(sub, rest)
  .then((r) => {
    for (const l of r.lines) console.log(l);
    process.exit(r.code);
  })
  .catch((e) => {
    console.error(`@metaharness/hackerone: ${e instanceof Error ? e.message : String(e)}`);
    process.exit(1);
  });
