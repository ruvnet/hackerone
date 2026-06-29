import { describe, it, expect } from 'vitest';
import { checkScope, assetMatches } from '../src/triage/scope-check.js';
import { MOCK_FIXTURES } from '../src/api/mock-client.js';

describe('assetMatches', () => {
  it('exact URL match', () => {
    expect(assetMatches('api.example.com', 'api.example.com', 'URL')).toBe(true);
  });
  it('wildcard prefix matches subdomain', () => {
    expect(assetMatches('foo.example.com', '*.example.com', 'URL')).toBe(true);
    expect(assetMatches('a.b.example.com', '*.example.com', 'URL')).toBe(true);
  });
  it('wildcard prefix does NOT match the bare domain', () => {
    expect(assetMatches('example.com', '*.example.com', 'URL')).toBe(false);
  });
  it('protocol-prefix strips before compare', () => {
    expect(assetMatches('https://api.example.com', 'api.example.com', 'URL')).toBe(true);
    expect(assetMatches('https://api.example.com:8080/path', 'api.example.com', 'URL')).toBe(true);
  });
  it('mobile bundle id is exact-only', () => {
    expect(assetMatches('com.example.android', 'com.example.android', 'ANDROID_PLAY_STORE')).toBe(true);
    expect(assetMatches('com.example.android.debug', 'com.example.android', 'ANDROID_PLAY_STORE')).toBe(false);
  });
});

describe('checkScope', () => {
  const program = MOCK_FIXTURES.programs[0]!; // example-program

  it('matches an in-scope asset', () => {
    const r = checkScope(
      { id: 't', programHandle: program.handle, state: 'new', finding: { id: 't', title: 't', description: '', asset: 'api.example.com' } },
      program,
    );
    expect(r.inScope).toBe(true);
    expect(r.side).toBe('in');
  });

  it('explicit out-of-scope wins over in-scope wildcard', () => {
    const r = checkScope(
      { id: 't', programHandle: program.handle, state: 'new', finding: { id: 't', title: 't', description: '', asset: 'marketing.example.com' } },
      program,
    );
    expect(r.inScope).toBe(false);
    expect(r.side).toBe('out');
  });

  it('unknown asset returns side=none', () => {
    const r = checkScope(
      { id: 't', programHandle: program.handle, state: 'new', finding: { id: 't', title: 't', description: '', asset: 'unknown' } },
      program,
    );
    expect(r.inScope).toBe(false);
    expect(r.side).toBe('none');
  });

  it('asset matching wildcard fires', () => {
    const r = checkScope(
      { id: 't', programHandle: program.handle, state: 'new', finding: { id: 't', title: 't', description: '', asset: 'app.example.com' } },
      program,
    );
    expect(r.inScope).toBe(true);
    expect(r.matchedItem?.identifier).toBe('*.example.com');
  });
});
