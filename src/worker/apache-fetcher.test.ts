import { describe, it, expect } from 'vitest';
import { parseAffects, findAdvisoryBlocks, findFixedHeadings, parseAdvisoryBlock } from './apache-fetcher.js';

describe('parseAffects', () => {
  it('parses "before X" with no lower bound', () => {
    expect(parseAffects('before 2.4.66')).toEqual({
      versionStart: undefined,
      versionEnd: '2.4.66',
    });
  });

  it('parses "X before Y" with explicit lower bound', () => {
    expect(parseAffects('2.4.0 before 2.4.66')).toEqual({
      versionStart: '2.4.0',
      versionEnd: '2.4.66',
    });
  });

  it('parses "through X" with no lower bound', () => {
    expect(parseAffects('through 2.4.67')).toEqual({
      versionStart: undefined,
      lastAffected: '2.4.67',
    });
  });

  it('parses "X through Y" with explicit lower bound', () => {
    expect(parseAffects('2.4.0 through 2.4.67')).toEqual({
      versionStart: '2.4.0',
      lastAffected: '2.4.67',
    });
  });

  it('parses ">=X, <=Y" inclusive range', () => {
    expect(parseAffects('>=2.4.7, <=2.4.51')).toEqual({
      versionStart: '2.4.7',
      lastAffected: '2.4.51',
    });
  });

  it('parses "<=X" with no lower bound', () => {
    expect(parseAffects('<=2.4.48')).toEqual({
      versionStart: undefined,
      lastAffected: '2.4.48',
    });
  });

  it('parses "<=X, !<Y" using !< as the inclusive lower bound', () => {
    expect(parseAffects('<=2.4.48, !<2.4.17')).toEqual({
      versionStart: '2.4.17',
      lastAffected: '2.4.48',
    });
  });

  it('parses a comma-separated exact version list, keeping only 2.4.x tokens', () => {
    expect(parseAffects('2.4.10, 2.4.9, 2.2.31, 2.0.65')).toEqual({
      affectedVersions: ['2.4.10', '2.4.9'],
    });
  });

  it('returns null when the comma list has no 2.4.x tokens', () => {
    expect(parseAffects('2.2.31, 2.0.65, 1.3.42')).toBeNull();
  });

  it('returns null for unparseable text', () => {
    expect(parseAffects('see vendor advisory')).toBeNull();
  });

  it('returns null for empty input', () => {
    expect(parseAffects('')).toBeNull();
  });
});

describe('findFixedHeadings', () => {
  it('locates every "Fixed in Apache HTTP Server X.Y.Z" heading with its byte offset', () => {
    const html = '<h1 id="2.4.50">Fixed in Apache HTTP Server 2.4.50</h1>...<h1 id="2.4.49">Fixed in Apache HTTP Server 2.4.49</h1>';
    expect(findFixedHeadings(html)).toEqual([
      { index: 0, version: '2.4.50' },
      { index: expect.any(Number), version: '2.4.49' },
    ]);
  });
});

describe('findAdvisoryBlocks', () => {
  it('reads the heading with a linked CVE id and a parenthesised severity, as the page has it since October 2026', () => {
    const html =
      '<dt><h3 id="CVE-2026-42528"><a href="https://www.cve.org/CVERecord?id=CVE-2026-42528">CVE-2026-42528</a> (moderate): <name name="CVE-2026-42528">mod_dav shared lock overflow</name>\n' +
      '<a class="headerlink" href="#CVE-2026-42528" title="Permanent link">&para;</a></h3></dt>\n' +
      '<dd><p>A memory calculation bug in mod_dav.</p><p></p><p>Users are recommended to upgrade to version 2.4.69, which fixes this issue</p>\n' +
      '<table class="table"><tr><td class="cve-header">Affects</td><td class="cve-value"> through 2.4.68</td></tr>\n</table></dd>\n' +
      '<dt><h3 id="CVE-2024-38476"><a href="https://www.cve.org/CVERecord?id=CVE-2024-38476">CVE-2024-38476</a> (important): <name name="CVE-2024-38476">backend output</name>\n' +
      '<a class="headerlink" href="#CVE-2024-38476" title="Permanent link">&para;</a></h3></dt>\n<dd><p>desc</p></dd>';
    const blocks = findAdvisoryBlocks(html);
    expect(blocks.map(b => [b.cveId, b.severity, b.title])).toEqual([
      ['CVE-2026-42528', 'moderate', 'mod_dav shared lock overflow'],
      ['CVE-2024-38476', 'important', 'backend output'],
    ]);

    const advisory = parseAdvisoryBlock(blocks[0], []);
    expect(advisory).toMatchObject({ externalId: 'CVE-2026-42528', severity: 'MEDIUM', description: 'A memory calculation bug in mod_dav.' });
    expect(advisory?.affectedProducts[0]).toMatchObject({ lastAffected: '2.4.68', versionFixed: '2.4.69' });
  });

  it('still reads the older heading without a link, with the severity unparenthesised', () => {
    const html = '<dt><h3 id="CVE-2021-41773">important: <name>Path traversal</name></h3></dt><dd><p>d</p></dd>';
    expect(findAdvisoryBlocks(html).map(b => [b.cveId, b.severity, b.title])).toEqual([['CVE-2021-41773', 'important', 'Path traversal']]);
  });
});

describe('parseAdvisoryBlock', () => {
  function makeBlock(affectsValue: string, extra = ''): ReturnType<typeof findAdvisoryBlocks>[number] {
    const html =
      '<dt><h3 id="CVE-2021-41773">important: <name>Path traversal in Apache HTTP Server 2.4.49</name>' +
      '(<a href="https://cve.mitre.org">cve.mitre.org</a>)</h3></dt>' +
      `<dd><p>desc${extra}</p><table class="table">` +
      `<tr><td class="cve-header">Affects</td><td class="cve-value">${affectsValue}</td></tr>` +
      '</table></dd>';
    return findAdvisoryBlocks(html)[0];
  }

  it('infers a precise range for a single known-affected version, using the nearest preceding heading as the fix version', () => {
    const b = makeBlock('2.4.49');
    const advisory = parseAdvisoryBlock({ ...b, index: 1000 }, [
      { index: 500, version: '2.4.50' },
      { index: 2000, version: '2.4.49' }, // after the block — must not be picked
    ]);
    expect(advisory?.affectedProducts[0]).toMatchObject({
      versionStart: '2.4.49',
      versionFixed: '2.4.50',
      patchAvailable: true,
    });
  });

  it('prefers an explicit "recommended to upgrade to version X" phrase over the heading when both are present', () => {
    const b = makeBlock('2.4.49', ', recommended to upgrade to version 2.4.51 or later.');
    const advisory = parseAdvisoryBlock({ ...b, index: 1000 }, [{ index: 500, version: '2.4.50' }]);
    expect(advisory?.affectedProducts[0].versionFixed).toBe('2.4.51');
  });

  it('uses the heading fix version for an explicit range (e.g. "before X") lacking upgrade prose', () => {
    const b = makeBlock('before 2.4.66');
    const advisory = parseAdvisoryBlock({ ...b, index: 1000 }, [{ index: 500, version: '2.4.66' }]);
    expect(advisory?.affectedProducts[0]).toMatchObject({ versionEnd: '2.4.66', versionFixed: '2.4.66' });
  });

  it('spans a multi-version affected list from its lowest entry up to the fix', () => {
    const b = makeBlock('2.4.46, 2.4.43, 2.4.41');
    const advisory = parseAdvisoryBlock({ ...b, index: 1000 }, [{ index: 500, version: '2.4.47' }]);
    expect(advisory?.affectedProducts[0]).toMatchObject({
      versionStart: '2.4.41',
      versionFixed: '2.4.47',
      affectedVersions: ['2.4.46', '2.4.43', '2.4.41'],
      patchAvailable: true,
    });
  });

  it('orders a list numerically, so 2.4.9 is below 2.4.10', () => {
    const b = makeBlock('2.4.10, 2.4.9');
    const advisory = parseAdvisoryBlock({ ...b, index: 1000 }, [{ index: 500, version: '2.4.11' }]);
    expect(advisory?.affectedProducts[0]).toMatchObject({ versionStart: '2.4.9', versionFixed: '2.4.11' });
  });

  it('keeps a multi-version list exact-only when the fix is not above every listed version', () => {
    const b = makeBlock('2.4.46, 2.4.43, 2.4.41');
    const advisory = parseAdvisoryBlock({ ...b, index: 1000 }, [{ index: 500, version: '2.4.46' }]);
    expect(advisory?.affectedProducts[0].versionStart).toBeUndefined();
    expect(advisory?.affectedProducts[0].versionFixed).toBeUndefined();
    expect(advisory?.affectedProducts[0].patchAvailable).toBe(false);
  });

  it('keeps a multi-version list exact-only when no heading precedes the block', () => {
    const b = makeBlock('2.4.46, 2.4.43, 2.4.41');
    const advisory = parseAdvisoryBlock({ ...b, index: 1000 }, []);
    expect(advisory?.affectedProducts[0].versionFixed).toBeUndefined();
  });

  it('ignores a heading that appears after the block (only the nearest preceding heading counts)', () => {
    const b = makeBlock('2.4.49');
    const advisory = parseAdvisoryBlock({ ...b, index: 1000 }, [{ index: 2000, version: '2.4.50' }]);
    expect(advisory?.affectedProducts[0].versionFixed).toBeUndefined();
  });
});
