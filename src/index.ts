// @metaharness/hackerone — public API.
//
// Side modules (./triage, ./research, ./safety) are also exported for
// callers who only need part of the surface.

export * from './types.js';
export * as safety from './safety.js';
export * as api from './api/index.js';
export * as triage from './triage/index.js';
export * as research from './research/index.js';

// Re-export the most-used surface at the top level so simple callers
// don't have to dive into namespaces.
export { HackerOneClient } from './api/client.js';
export { HackerOneGraphQLClient } from './api/graphql-client.js';
export { MockHackerOneClient, MOCK_FIXTURES } from './api/mock-client.js';
export { resolveApiKey } from './api/key-source.js';
export { triageReport } from './triage/triage.js';
export { buildReconPlan, classifyDescription, formatFinding } from './research/recon.js';
