import { describe, it, expect } from 'vitest';
import { extractAssets, formatAssetListWithBanner } from '../src/research/asset-list.js';
import { MOCK_FIXTURES } from '../src/api/mock-client.js';

const program = MOCK_FIXTURES.programs[0]!; // example-program

describe('extractAssets', () => {
  it('default returns only in-scope identifiers', () => {
    const list = extractAssets(program);
    expect(list).toContain('*.example.com');
    expect(list).toContain('api.example.com');
    // out-of-scope must be excluded by default
    expect(list).not.toContain('marketing.example.com');
    expect(list).not.toContain('static.example.com');
  });

  it('includes out-of-scope only when opted in', () => {
    const list = extractAssets(program, { includeOutOfScope: true });
    expect(list).toContain('marketing.example.com');
  });

  it('filters by asset type', () => {
    const onlyMobile = extractAssets(program, { assetTypes: ['ANDROID_PLAY_STORE'] });
    expect(onlyMobile).toEqual(['com.example.android']);
  });

  it('asset type filter accepts multiple comma-separated values', () => {
    const urlsAndAndroid = extractAssets(program, { assetTypes: ['URL', 'ANDROID_PLAY_STORE'] });
    expect(urlsAndAndroid).toContain('api.example.com');
    expect(urlsAndAndroid).toContain('com.example.android');
    expect(urlsAndAndroid).not.toContain('id1234.ios');
  });

  it('expandWildcards strips the leading "*." for Subfinder-style tools', () => {
    const expanded = extractAssets(program, {
      assetTypes: ['URL'],
      expandWildcards: true,
    });
    expect(expanded).toContain('example.com');
    expect(expanded).not.toContain('*.example.com');
  });

  it('dedupes by default', () => {
    const dupedProgram = {
      ...program,
      scope: [...program.scope, ...program.scope], // double up
    };
    const list = extractAssets(dupedProgram);
    expect(new Set(list).size).toBe(list.length);
  });

  it('strips https:// + paths from URL identifiers', () => {
    const dirty = {
      ...program,
      scope: [
        { identifier: 'https://foo.example.com/path?q=1', assetType: 'URL' },
      ],
      outOfScope: [],
    };
    const list = extractAssets(dirty);
    expect(list).toEqual(['foo.example.com']);
  });
});

describe('formatAssetListWithBanner', () => {
  it('emits comment banner + in-scope identifiers', () => {
    const text = formatAssetListWithBanner(program);
    const lines = text.split('\n');
    expect(lines[0]).toContain('@metaharness/hackerone');
    expect(lines[0]).toContain(`program=${program.handle}`);
    expect(lines[0]).toContain('in-scope=');
    // Body should include at least one in-scope id
    expect(text).toContain('api.example.com');
  });

  it('includeOutOfScope adds a flagged section', () => {
    const text = formatAssetListWithBanner(program, { includeOutOfScope: true });
    expect(text).toContain('# OUT-OF-SCOPE');
    expect(text).toContain('#   marketing.example.com');
  });

  it('banner survives stdin filters — # lines are comments to Subfinder/Amass/Nuclei', () => {
    const text = formatAssetListWithBanner(program);
    const targetsOnly = text
      .split('\n')
      .filter((l) => !l.startsWith('#') && l.trim());
    expect(targetsOnly.length).toBeGreaterThan(0);
    for (const t of targetsOnly) {
      expect(t.startsWith('#')).toBe(false);
    }
  });
});
